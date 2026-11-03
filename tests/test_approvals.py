import json
import socket
import sqlite3
import tempfile
import threading
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

import free_protonmail_mcp.approval_channel as approval_channel_module
from free_protonmail_mcp.approval_channel import ApprovalChannel, approval_request
from free_protonmail_mcp.approvals import ApprovalManager
from free_protonmail_mcp.models import MailError


class MemorySecretStore:
    def __init__(self):
        self.values = {}

    def get(self, name):
        return self.values.get(name)

    def set(self, name, value):
        self.values[name] = value

    def delete(self, name):
        self.values.pop(name, None)


class FailingDeleteSecretStore(MemorySecretStore):
    def __init__(self):
        super().__init__()
        self.fail_deletes = False

    def delete(self, name):
        if self.fail_deletes:
            raise OSError("Credential deletion failed")
        super().delete(name)


class Clock:
    def __init__(self, value=1000.0):
        self.value = value

    def __call__(self):
        return self.value


class AdvancingClock:
    def __init__(self):
        self.value = 0.0

    def monotonic(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


class TrickledConnection:
    def __init__(self, chunks, clock):
        self.chunks = iter(chunks)
        self.clock = clock

    def settimeout(self, seconds):
        self.timeout = seconds

    def recv(self, size):
        self.clock.advance(0.2)
        return next(self.chunks)


def partial_trash_error(completed_move, stopped_ref, destination_ref):
    provider_error = MailError(
        "MOVE_UNCERTAIN",
        "PRIVATE_PROVIDER_ERROR_TEXT",
        {
            "source_present": True,
            "destination_present": True,
            "destination_ref": destination_ref,
            "protocol_succeeded": True,
            "provider_details": {
                "body": "PRIVATE_APPROVED_BODY",
                "subject": "PRIVATE_APPROVED_SUBJECT",
                "sender": "private-sender@example.test",
                "recipients": ["private-recipient@example.test"],
            },
        },
        uncertain=True,
    )
    return MailError(
        "TRASH_INCOMPLETE",
        "Trash operation stopped",
        {
            "completed": [completed_move],
            "stopped": stopped_ref,
            "cause": provider_error.result(),
        },
        uncertain=True,
    )


def partial_trash_recovery_fixture(stopped_ref):
    destination_ref = {
        "mailbox": "Trash",
        "uid_validity": 2,
        "uid": 12,
        "message_id": "<stopped@example.test>",
    }
    completed_move = {
        "moved": True,
        "ref": {
            "mailbox": "Trash",
            "uid_validity": 2,
            "uid": 11,
            "message_id": "<completed@example.test>",
        },
        "source_present": False,
        "destination_present": True,
    }
    expected_recovery = {
        "completed": [completed_move["ref"]],
        "stopped": stopped_ref,
        "source_present": True,
        "destination_present": True,
        "destination_ref": destination_ref,
        "protocol_succeeded": True,
    }
    return completed_move, destination_ref, expected_recovery


def sample_trash_payload():
    return {
        "messages": [
            {
                "mailbox": "INBOX",
                "uid_validity": 1,
                "uid": 1,
                "message_id": "<first@example.test>",
            },
            {
                "mailbox": "INBOX",
                "uid_validity": 1,
                "uid": 2,
                "message_id": "<second@example.test>",
            },
        ],
        "previews": [{"subject": "first"}, {"subject": "second"}],
    }


class ApprovalTestCase(unittest.TestCase):
    def assert_private_values_absent(self, recorded):
        for private_value in (
            "PRIVATE_APPROVED_BODY",
            "PRIVATE_APPROVED_SUBJECT",
            "private-sender@example.test",
            "private-recipient@example.test",
            "PRIVATE_PROVIDER_ERROR_TEXT",
        ):
            self.assertNotIn(private_value, recorded)


class ApprovalManagerTests(ApprovalTestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.state_dir = Path(self.temporary_directory.name)
        self.effects = []
        self.clock = Clock()
        self.manager = self.make_manager()

    def tearDown(self):
        if self.manager is not None:
            self.manager.close()
        self.temporary_directory.cleanup()

    def make_manager(self, executor=None):
        if executor is None:
            executor = self.execute
        return ApprovalManager(self.state_dir, executor, clock=self.clock)

    def execute(self, kind, payload):
        self.effects.append((kind, payload))
        return {"completed": True}

    def send_payload(self, body="Approved body"):
        return {
            "sender": "sender@example.test",
            "message": {
                "to": ["recipient@example.test"],
                "subject": "Approved subject",
                "body": body,
            },
        }

    def trash_payload(self):
        return sample_trash_payload()

    def request_send(self, body="Approved body"):
        return self.manager.request("send", self.send_payload(body))

    def test_request_freezes_payload_without_persisting_mail_body(self):
        payload = self.send_payload("BODY_DO_NOT_PERSIST_3bb47e")
        request = self.manager.request("send", payload)
        payload["message"]["body"] = "mutated after request"
        preview = self.manager.preview(request["action_id"])
        preview["payload"]["message"]["body"] = "mutated preview"

        self.assertEqual(
            self.manager.preview(request["action_id"])["payload"]["message"]["body"],
            "BODY_DO_NOT_PERSIST_3bb47e",
        )
        self.assertNotIn("payload", request)
        self.assertTrue(request["action_id"])
        self.assertEqual(request["status"], "pending")
        self.assertFalse(
            any(
                b"BODY_DO_NOT_PERSIST_3bb47e" in path.read_bytes()
                for path in self.state_dir.iterdir()
                if path.is_file()
            )
        )

    def test_denied_approval_cannot_be_reused(self):
        request = self.request_send()
        digest = self.manager.preview(request["action_id"])["digest"]

        denied = self.manager.decide(request["action_id"], digest, False)

        self.assertEqual(denied["status"], "denied")
        self.assertEqual(self.manager.status(request["action_id"])["status"], "denied")
        self.assertEqual(self.effects, [])
        with self.assertRaises(MailError):
            self.manager.decide(request["action_id"], digest, True)
        self.assertEqual(self.effects, [])

    def test_expired_approval_cannot_execute(self):
        request = self.request_send()
        digest = self.manager.preview(request["action_id"])["digest"]
        self.clock.value += 901

        result = self.manager.decide(request["action_id"], digest, True)

        self.assertEqual(result["status"], "expired")
        self.assertEqual(self.manager.status(request["action_id"])["status"], "expired")
        self.assertEqual(self.effects, [])

    def test_changed_digest_invalidates_approval(self):
        request = self.request_send()

        result = self.manager.decide(request["action_id"], "0" * 64, True)

        self.assertEqual(result["status"], "changed")
        self.assertEqual(self.manager.status(request["action_id"])["status"], "changed")
        self.assertEqual(self.effects, [])
        with self.assertRaises(MailError):
            self.manager.decide(request["action_id"], "0" * 64, True)

    def test_successful_approval_cannot_be_reused(self):
        request = self.request_send()
        digest = self.manager.preview(request["action_id"])["digest"]

        result = self.manager.decide(request["action_id"], digest, True)

        self.assertEqual(result["status"], "succeeded")
        self.assertEqual(len(self.effects), 1)
        with self.assertRaises(MailError):
            self.manager.decide(request["action_id"], digest, True)
        self.assertEqual(len(self.effects), 1)

    def test_concurrent_decisions_execute_exactly_once(self):
        request = self.request_send()
        digest = self.manager.preview(request["action_id"])["digest"]
        start = threading.Barrier(3)
        outcomes = []

        def decide():
            start.wait()
            try:
                outcomes.append(self.manager.decide(request["action_id"], digest, True))
            except MailError as error:
                outcomes.append(error)

        threads = [threading.Thread(target=decide) for _ in range(2)]
        for thread in threads:
            thread.start()
        start.wait()
        for thread in threads:
            thread.join(timeout=2)

        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(len(self.effects), 1)
        self.assertEqual(sum(isinstance(outcome, dict) for outcome in outcomes), 1)
        self.assertEqual(sum(isinstance(outcome, MailError) for outcome in outcomes), 1)

    def test_unknown_outcome_is_reported_without_message_content(self):
        def fail_after_effect(kind, payload):
            raise MailError("send_uncertain", "Submission is uncertain", uncertain=True)

        self.manager.close()
        manager = ApprovalManager(self.state_dir, fail_after_effect, clock=self.clock)
        self.manager = manager
        request = manager.request("send", self.send_payload("PRIVATE_APPROVED_BODY"))
        digest = manager.preview(request["action_id"])["digest"]
        with self.assertLogs("free_protonmail_mcp.approvals", level="WARNING") as recorded:
            with self.assertRaises(MailError):
                manager.decide(request["action_id"], digest, True)

        output = "\n".join(recorded.output)
        self.assertIn(request["action_id"], output)
        self.assertIn("send_uncertain", output)
        self.assert_private_values_absent(output)

    def test_executor_exception_is_unknown_and_not_retried_after_restart(self):
        def fail_after_effect(kind, payload):
            self.effects.append((kind, payload))
            raise RuntimeError("private message body")

        self.manager.close()
        manager = ApprovalManager(self.state_dir, fail_after_effect, clock=self.clock)
        self.manager = manager
        request = manager.request("send", self.send_payload())
        digest = manager.preview(request["action_id"])["digest"]
        with self.assertRaises(MailError) as raised:
            manager.decide(request["action_id"], digest, True)
        self.assertTrue(raised.exception.uncertain)
        self.assertEqual(manager.status(request["action_id"])["status"], "unknown")
        self.assertNotIn("private message body", str(raised.exception))
        manager.close()

        restarted = ApprovalManager(self.state_dir, self.execute, clock=self.clock)
        try:
            self.assertEqual(restarted.status(request["action_id"])["status"], "unknown")
            with self.assertRaises(MailError) as reused:
                restarted.decide(request["action_id"], digest, True)
            self.assertTrue(reused.exception.uncertain)
            self.assertEqual(len(self.effects), 1)
        finally:
            restarted.close()
        self.manager = self.make_manager()

    def test_successful_trash_outcome_keeps_verified_move_refs(self):
        move_result = {
            "moved": True,
            "ref": {
                "mailbox": "Trash",
                "uid_validity": 2,
                "uid": 11,
                "message_id": "<moved@example.test>",
            },
            "source_present": False,
            "destination_present": True,
        }
        self.manager.close()
        self.manager = self.make_manager(executor=lambda kind, payload: {"messages": [move_result]})
        request = self.manager.request("trash", self.trash_payload())
        digest = self.manager.preview(request["action_id"])["digest"]

        result = self.manager.decide(request["action_id"], digest, True)

        self.assertEqual(result["status"], "succeeded")
        self.assertEqual(result["outcome"]["details"]["messages"], [move_result])

    def test_partial_trash_recovery_is_durable_private_and_not_retryable(self):
        stopped_ref = self.trash_payload()["messages"][1]
        completed_move, destination_ref, expected_recovery = partial_trash_recovery_fixture(
            stopped_ref
        )

        def fail_after_one_move(kind, payload):
            self.effects.append((kind, payload))
            raise partial_trash_error(completed_move, stopped_ref, destination_ref)

        self.manager.close()
        self.manager = ApprovalManager(self.state_dir, fail_after_one_move, clock=self.clock)
        request = self.manager.request("trash", self.trash_payload())
        digest = self.manager.preview(request["action_id"])["digest"]
        with self.assertRaises(MailError) as raised:
            self.manager.decide(request["action_id"], digest, True)

        self.assertEqual(raised.exception.details, expected_recovery)
        status = self.manager.status(request["action_id"])
        self.assertEqual(
            status["outcome"],
            {
                "status": "unknown",
                "error_code": "TRASH_INCOMPLETE",
                "details": expected_recovery,
            },
        )
        recorded = json.dumps({"raised": raised.exception.result(), "status": status})
        self.assert_private_values_absent(recorded)

        self.manager.close()
        self.manager = self.make_manager()
        self.assertEqual(self.manager.status(request["action_id"]), status)
        with self.assertRaises(MailError) as reused:
            self.manager.decide(request["action_id"], digest, True)
        self.assertTrue(reused.exception.uncertain)
        self.assertEqual(len(self.effects), 1)

    def test_restart_expires_pending_and_marks_interrupted_work_unknown(self):
        pending = self.request_send()
        interrupted = self.request_send()
        self.manager.close()
        database_path = next(self.state_dir.glob("*.sqlite3"))
        with closing(sqlite3.connect(database_path)) as database:
            database.execute(
                "UPDATE actions SET status = 'in_progress' WHERE action_id = ?",
                (interrupted["action_id"],),
            )
            database.commit()

        self.manager = self.make_manager()

        self.assertEqual(self.manager.status(pending["action_id"])["status"], "expired")
        self.assertEqual(self.manager.status(interrupted["action_id"])["status"], "unknown")
        with self.assertRaises(MailError):
            self.manager.preview(pending["action_id"])
        with self.assertRaises(MailError) as reused:
            self.manager.decide(interrupted["action_id"], "0" * 64, True)
        self.assertTrue(reused.exception.uncertain)
        self.assertEqual(self.effects, [])

    def test_pending_count_and_payload_size_are_bounded(self):
        for _ in range(100):
            self.request_send()
        with self.assertRaises(MailError):
            self.request_send()

        self.manager.close()
        self.manager = self.make_manager()
        large_preview = "x" * 1_100_000
        trash_payload = {
            "messages": [{"mailbox": "INBOX", "uid_validity": 1, "uid": 1, "message_id": None}],
            "previews": [{"subject": large_preview}],
        }
        with self.assertRaises(MailError):
            self.manager.request("trash", trash_payload)

    def test_status_rejects_non_uuid_action_ids(self):
        with self.assertRaises(MailError):
            self.manager.status("not-an-action-id")

    def test_second_manager_for_same_state_directory_is_refused(self):
        with self.assertRaises(MailError):
            ApprovalManager(self.state_dir, self.execute, clock=self.clock)


class ApprovalChannelTests(ApprovalTestCase):
    def test_unauthenticated_preview_is_refused_without_mail_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            state_dir = Path(directory)
            secrets = MemorySecretStore()
            manager = ApprovalManager(state_dir, lambda kind, payload: {"completed": True})
            request = manager.request(
                "send",
                {
                    "sender": "sender@example.test",
                    "message": {
                        "to": ["recipient@example.test"],
                        "subject": "Private subject",
                        "body": "PRIVATE_CHANNEL_BODY",
                    },
                },
            )
            try:
                with ApprovalChannel(manager, state_dir, secrets) as channel:
                    with socket.create_connection(
                        ("127.0.0.1", channel.port), timeout=2
                    ) as connection:
                        connection.sendall(
                            json.dumps(
                                {"operation": "preview", "action_id": request["action_id"]}
                            ).encode()
                            + b"\n"
                        )
                        connection.shutdown(socket.SHUT_WR)
                        response = connection.makefile("rb").readline(4097)
                    self.assertLessEqual(len(response), 4096)
                    self.assertNotIn(b"PRIVATE_CHANNEL_BODY", response)
                    self.assertIn(b"error", response)
            finally:
                manager.close()

    def test_authenticated_preview_and_decision_use_real_loopback(self):
        with tempfile.TemporaryDirectory() as directory:
            state_dir = Path(directory)
            secrets = MemorySecretStore()
            effects = []
            manager = ApprovalManager(
                state_dir,
                lambda kind, payload: effects.append((kind, payload)) or {"completed": True},
            )
            request = manager.request(
                "send",
                {
                    "sender": "sender@example.test",
                    "message": {
                        "to": ["recipient@example.test"],
                        "subject": "Private subject",
                        "body": "Private body",
                    },
                },
            )
            try:
                with ApprovalChannel(manager, state_dir, secrets) as channel:
                    discovery = json.loads(channel.discovery_path.read_text())
                    token = next(iter(secrets.values.values()))
                    self.assertEqual(discovery["port"], channel.port)
                    self.assertEqual(discovery["instance_id"], channel.instance_id)
                    self.assertNotIn(token, channel.discovery_path.read_text())

                    preview = approval_request(state_dir, secrets, "preview", request["action_id"])
                    result = approval_request(
                        state_dir,
                        secrets,
                        "decide",
                        request["action_id"],
                        digest=preview["digest"],
                        approve=True,
                    )
                    status = approval_request(state_dir, secrets, "status", request["action_id"])

                    self.assertEqual(preview["payload"]["message"]["body"], "Private body")
                    self.assertEqual(result["status"], "succeeded")
                    self.assertEqual(status["status"], "succeeded")
                    self.assertEqual(len(effects), 1)
            finally:
                manager.close()

    def test_channel_rejects_unknown_operations_and_extra_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            state_dir = Path(directory)
            secrets = MemorySecretStore()
            manager = ApprovalManager(state_dir, lambda kind, payload: {"completed": True})
            try:
                with ApprovalChannel(manager, state_dir, secrets) as channel:
                    token = next(iter(secrets.values.values()))
                    for payload in [
                        {"token": token, "operation": "approve_anything", "action_id": "x"},
                        {
                            "token": token,
                            "operation": "status",
                            "action_id": "x",
                            "extra": "not allowed",
                        },
                    ]:
                        with socket.create_connection(
                            ("127.0.0.1", channel.port), timeout=2
                        ) as connection:
                            connection.sendall(json.dumps(payload).encode() + b"\n")
                            connection.shutdown(socket.SHUT_WR)
                            response = json.loads(connection.makefile("rb").readline())
                        self.assertIn("error", response)
            finally:
                manager.close()

    def test_loopback_decide_returns_sanitized_recovery_details(self):
        with tempfile.TemporaryDirectory() as directory:
            state_dir = Path(directory)
            secrets = MemorySecretStore()
            stopped_ref = sample_trash_payload()["messages"][1]
            completed_move, destination_ref, expected_recovery = partial_trash_recovery_fixture(
                stopped_ref
            )

            def fail_after_one_move(kind, payload):
                raise partial_trash_error(completed_move, stopped_ref, destination_ref)

            manager = ApprovalManager(state_dir, fail_after_one_move)
            try:
                with ApprovalChannel(manager, state_dir, secrets):
                    request = manager.request("trash", sample_trash_payload())
                    digest = manager.preview(request["action_id"])["digest"]
                    with self.assertRaises(MailError) as raised:
                        approval_request(
                            state_dir,
                            secrets,
                            "decide",
                            request["action_id"],
                            digest,
                            True,
                        )
                    self.assertEqual(raised.exception.code, "TRASH_INCOMPLETE")
                    self.assertEqual(raised.exception.details, expected_recovery)
                    self.assertTrue(raised.exception.uncertain)
                    status = approval_request(state_dir, secrets, "status", request["action_id"])
                    expected_outcome = {
                        "status": "unknown",
                        "error_code": "TRASH_INCOMPLETE",
                        "details": expected_recovery,
                    }
                    self.assertEqual(status["outcome"], expected_outcome)
                    self.assert_private_values_absent(json.dumps(status))
            finally:
                manager.close()

    def test_trickled_request_uses_total_monotonic_deadline(self):
        clock = AdvancingClock()
        connection = TrickledConnection(
            [b'{"token":', b'"secret"', b',"operation":"status"}', b"\n"],
            clock,
        )
        with patch.object(approval_channel_module, "time", clock, create=True):
            with patch.object(approval_channel_module, "_CONNECTION_TIMEOUT_SECONDS", 0.3):
                with patch.object(
                    approval_channel_module,
                    "_REQUEST_TIMEOUT_SECONDS",
                    0.3,
                    create=True,
                ):
                    with self.assertRaises(socket.timeout):
                        approval_channel_module._read_request(connection)

    def test_shutdown_interrupts_idle_accepted_peer(self):
        with tempfile.TemporaryDirectory() as directory:
            state_dir = Path(directory)
            manager = ApprovalManager(state_dir, lambda kind, payload: {"completed": True})
            channel = ApprovalChannel(manager, state_dir, MemorySecretStore())
            peer = None
            stop_thread = None
            handler_started = threading.Event()
            try:
                channel.__enter__()
                original_handler = channel._handle_connection

                def record_accepted_peer(connection, address):
                    handler_started.set()
                    return original_handler(connection, address)

                with patch.object(
                    channel,
                    "_handle_connection",
                    side_effect=record_accepted_peer,
                ):
                    peer = socket.create_connection(("127.0.0.1", channel.port), timeout=1)
                    peer.settimeout(1)
                    self.assertTrue(handler_started.wait(timeout=1))
                    stop_thread = threading.Thread(target=channel._stop_server)
                    stop_thread.start()
                    stop_thread.join(timeout=1)
                    self.assertFalse(stop_thread.is_alive())
                    self.assertEqual(peer.recv(1), b"")
            finally:
                if peer is not None:
                    peer.close()
                if stop_thread is not None:
                    stop_thread.join(timeout=1)
                channel.__exit__(None, None, None)
                manager.close()

    def test_startup_cleanup_retains_discovery_after_token_delete_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            state_dir = Path(directory)
            secrets = FailingDeleteSecretStore()
            manager = ApprovalManager(state_dir, lambda kind, payload: {"completed": True})
            channel = ApprovalChannel(manager, state_dir, secrets)
            secrets.fail_deletes = True
            original_write = channel._write_discovery

            def write_discovery_then_fail():
                original_write()
                raise OSError("Startup failed after discovery")

            try:
                with patch.object(
                    channel, "_write_discovery", side_effect=write_discovery_then_fail
                ):
                    with self.assertRaises(MailError):
                        channel.__enter__()
                discovery = json.loads(channel.discovery_path.read_text())
                self.assertEqual(discovery["instance_id"], channel.instance_id)
                self.assertIn(channel._secret_name, secrets.values)

                secrets.fail_deletes = False
                recovered = ApprovalChannel(manager, state_dir, secrets)
                try:
                    recovered.__enter__()
                    self.assertNotIn(channel._secret_name, secrets.values)
                    self.assertEqual(
                        json.loads(channel.discovery_path.read_text())["instance_id"],
                        recovered.instance_id,
                    )
                finally:
                    recovered.__exit__(None, None, None)
            finally:
                secrets.fail_deletes = False
                manager.close()

    def test_token_delete_failure_preserves_reference_for_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            state_dir = Path(directory)
            secrets = FailingDeleteSecretStore()
            manager = ApprovalManager(state_dir, lambda kind, payload: {"completed": True})
            first = ApprovalChannel(manager, state_dir, secrets)
            try:
                first.__enter__()
                original_discovery = json.loads(first.discovery_path.read_text())
                secrets.fail_deletes = True
                with self.assertRaises(MailError):
                    first.__exit__(None, None, None)
                self.assertEqual(json.loads(first.discovery_path.read_text()), original_discovery)
                self.assertIn(first._secret_name, secrets.values)
                self.assert_stale_delete_failure_is_retryable(
                    manager, state_dir, secrets, first, original_discovery
                )
            finally:
                secrets.fail_deletes = False
                if first._claimed:
                    first.__exit__(None, None, None)
                manager.close()

    def assert_stale_delete_failure_is_retryable(
        self, manager, state_dir, secrets, first, original_discovery
    ):
        failed_restart = ApprovalChannel(manager, state_dir, secrets)
        failed_restart_entered = False
        recovered = None
        try:
            try:
                failed_restart.__enter__()
            except MailError:
                pass
            else:
                failed_restart_entered = True
                self.fail("Stale token deletion failure must stop startup")
            self.assertEqual(json.loads(first.discovery_path.read_text()), original_discovery)
            self.assertIn(first._secret_name, secrets.values)

            secrets.fail_deletes = False
            recovered = ApprovalChannel(manager, state_dir, secrets)
            recovered.__enter__()
            self.assertNotIn(first._secret_name, secrets.values)
            self.assertEqual(
                json.loads(first.discovery_path.read_text())["instance_id"],
                recovered.instance_id,
            )
        finally:
            secrets.fail_deletes = False
            if recovered is not None:
                recovered.__exit__(None, None, None)
            if failed_restart_entered:
                failed_restart.__exit__(None, None, None)


if __name__ == "__main__":
    unittest.main()

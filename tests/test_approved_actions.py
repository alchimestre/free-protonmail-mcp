import contextlib
import email
import email.policy
import tempfile
import unittest
from email.message import EmailMessage
from pathlib import Path

from mcp import Client

from free_protonmail_mcp.approvals import ApprovalManager
from free_protonmail_mcp.mail import MailClient
from free_protonmail_mcp.models import AccountConfig, MailError
from free_protonmail_mcp.server import build_server, execute
from tests.protocol_server import LocalMailProtocolServer


class ApprovedActionIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        resources = contextlib.ExitStack()
        self.addCleanup(resources.close)
        self.protocol = resources.enter_context(LocalMailProtocolServer())
        directory = resources.enter_context(tempfile.TemporaryDirectory())
        self.account = AccountConfig(
            username="account@example.test",
            sender="account@example.test",
            imap_port=self.protocol.imap_port,
            smtp_port=self.protocol.smtp_port,
            timeout=3,
        )
        mail = MailClient(self.account, lambda: "bridge-secret")
        self.manager = ApprovalManager(
            Path(directory),
            lambda kind, payload: execute(mail, self.account, kind, payload),
        )
        resources.callback(self.manager.close)
        server = build_server(mail, self.manager, self.account)
        self.client = Client(server)

    async def test_approved_snapshot_sends_exact_envelope_once_and_retains_draft(self):
        async with self.client:
            composition = {
                "to": ["recipient@example.test"],
                "bcc": ["private@example.test"],
                "subject": "Approved synthetic snapshot",
                "body": "Frozen synthetic message.",
            }
            draft = await self.call("create_draft", {"message": composition})
            action = await self.call("request_send", {"message": composition})
            preview = self.manager.preview(action["action_id"])
            self.assertEqual(preview["payload"]["sender"], self.account.sender)
            changed = self.manager.decide(action["action_id"], "0" * 64, True)
            self.assertEqual(changed["status"], "changed")
            self.assertEqual(self.protocol.smtp_data_attempts, 0)
            action = await self.call("request_send", {"message": composition})
            preview = self.manager.preview(action["action_id"])
            preview["payload"]["message"]["to"] = ["changed@example.test"]
            self.manager.decide(action["action_id"], preview["digest"], True)
            status = await self.call("action_status", {"action_id": action["action_id"]})
            self.assertEqual(status["status"], "succeeded")
            submitted = email.message_from_bytes(
                self.protocol.smtp_message, policy=email.policy.default
            )
            self.assertEqual(str(submitted["From"]), self.account.sender)
            self.assertEqual(str(submitted["To"]), "recipient@example.test")
            self.assertIsNone(submitted["Bcc"])
            self.assertEqual(submitted.get_content().strip(), composition["body"])
            self.assertEqual(
                self.protocol.smtp_envelope_recipients,
                ["recipient@example.test", "private@example.test"],
            )
            with self.assertRaises(MailError):
                self.manager.decide(action["action_id"], preview["digest"], True)
            self.assertEqual(self.protocol.smtp_data_attempts, 1)
            retained = await self.call("read_message", {"message": draft["ref"]})
            self.assertEqual(retained["body"].strip(), composition["body"])

    async def test_approved_trash_moves_only_frozen_fixture_and_can_restore_it(self):
        async with self.client:
            message = EmailMessage(policy=email.policy.SMTP)
            message["From"] = "sender@example.test"
            message["To"] = self.account.sender
            message["Subject"] = "Approved synthetic Trash fixture"
            message["Message-ID"] = "<approved-trash@example.test>"
            message.set_content("Restore this synthetic fixture.")
            self.protocol.add_message("INBOX", message.as_bytes())
            query = {"subject": "Approved synthetic Trash fixture"}
            source = await self.call("search_messages", {"mailbox": "INBOX", "query": query})
            reference = source["messages"][0]["ref"]
            action = await self.call("request_trash", {"messages": [reference]})
            preview = self.manager.preview(action["action_id"])
            self.manager.decide(action["action_id"], preview["digest"], True)
            status = await self.call("action_status", {"action_id": action["action_id"]})
            self.assertEqual(status["status"], "succeeded")
            source = await self.call("search_messages", {"mailbox": "INBOX", "query": query})
            self.assertEqual(source["messages"], [])
            trash = await self.call("search_messages", {"mailbox": "Trash", "query": query})
            restored = await self.call(
                "move_message",
                {
                    "message": trash["messages"][0]["ref"],
                    "destination": "INBOX",
                },
            )
            restored_message = await self.call("read_message", {"message": restored["ref"]})
            self.assertEqual(restored_message["body"].strip(), "Restore this synthetic fixture.")

    async def call(self, tool: str, arguments: dict) -> dict:
        result = await self.client.call_tool(tool, arguments)
        self.assertFalse(result.is_error, result.content)
        return result.structured_content

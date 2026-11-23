import email
import unittest
import unittest.mock
from email.message import EmailMessage
from email.policy import SMTP

import free_protonmail_mcp.mail as mail_module
from free_protonmail_mcp.mail import MAX_TEXT_BYTES, MailClient, _draft_matches
from free_protonmail_mcp.models import (
    AccountConfig,
    MailError,
    MessageRef,
    OutgoingMessage,
    SearchQuery,
)
from tests.protocol_server import LocalMailProtocolServer


class MailClientTests(unittest.TestCase):
    def setUp(self):
        self.server = LocalMailProtocolServer()
        self.server.start()
        self.config = AccountConfig(
            username="account@example.test",
            sender="account@example.test",
            host="127.0.0.1",
            imap_port=self.server.imap_port,
            smtp_port=self.server.smtp_port,
            timeout=2,
        )
        self.client = MailClient(self.config, lambda: "bridge-secret")

    def tearDown(self):
        self.server.stop()

    def make_message(self, message_id, subject="Fixture", body="Fixture body.", flags=()):
        message = EmailMessage(policy=SMTP)
        message["From"] = "sender@example.test"
        message["To"] = "account@example.test"
        message["Subject"] = subject
        message["Message-ID"] = message_id
        message.set_content(body)
        uid = self.server.add_message("INBOX", message.as_bytes(), flags)
        return MessageRef(
            mailbox="INBOX",
            uid_validity=self.server.uid_validity,
            uid=uid,
            message_id=message_id,
        )

    def test_login_failure_is_sanitized(self):
        client = MailClient(self.config, lambda: "wrong-secret")

        with self.assertRaises(MailError) as caught:
            client.health()

        self.assertEqual(caught.exception.code, "authentication_failed")
        self.assertNotIn("wrong-secret", str(caught.exception))
        self.assertNotIn("bridge-secret", str(caught.exception))
        self.assertEqual(self.server.smtp_connections, 0)

    def test_login_transport_loss_is_not_an_authentication_failure(self):
        with unittest.mock.patch("imaplib.IMAP4.login", side_effect=ConnectionResetError):
            with self.assertRaises(MailError) as caught:
                self.client.health()

        result = caught.exception.result()["error"]
        self.assertEqual(result["code"], "imap_unavailable")
        self.assertEqual(result["details"]["reason"], "connection_lost")

    def test_unreachable_bridge_names_the_endpoint(self):
        endpoint = f"{self.config.host}:{self.config.imap_port}"

        with unittest.mock.patch("imaplib.IMAP4.open", side_effect=ConnectionRefusedError):
            with self.assertRaises(MailError) as caught:
                self.client.health()

        result = caught.exception.result()
        self.assertEqual(result["error"]["code"], "imap_unavailable")
        self.assertEqual(result["error"]["details"]["reason"], "connection_refused")
        self.assertEqual(result["error"]["details"]["endpoint"], endpoint)
        self.assertFalse(result["uncertain"])

    def test_transport_loss_after_connect_is_distinguished_from_no_connection(self):
        def reset(status, operation):
            raise ConnectionResetError("peer reset")

        with unittest.mock.patch.object(MailClient, "_check_status", staticmethod(reset)):
            with self.assertRaises(MailError) as caught:
                self.client.list_mailboxes()

        details = caught.exception.result()["error"]["details"]
        self.assertEqual(details["reason"], "connection_lost")
        self.assertFalse(caught.exception.result()["uncertain"])

    def test_ref_identity_mismatch_prevents_flag_change(self):
        original = self.make_message("<fixture-1@example.test>", flags=("\\Seen",))
        wrong_ref = original.model_copy(update={"message_id": "<different@example.test>"})

        with self.assertRaises(MailError) as caught:
            self.client.set_read(wrong_ref, False)

        self.assertEqual(caught.exception.code, "identity_mismatch")

        stale_ref = original.model_copy(update={"uid_validity": original.uid_validity + 1})
        with self.assertRaises(MailError) as caught:
            self.client.set_read(stale_ref, False)
        self.assertEqual(caught.exception.code, "stale_reference")
        self.assertIn("\\Seen", self.server.flags("INBOX", original.uid))
        self.assertFalse(any(" STORE " in command for command in self.server.imap_commands))

    def test_search_limits_results_and_quotes_search_values(self):
        for index in range(4):
            message = EmailMessage(policy=SMTP)
            message.set_content(f"Body {index}")
            message["From"] = "sender@example.test"
            message["To"] = "account@example.test"
            message["Subject"] = 'Alpha " OR ALL'
            message["Message-ID"] = f"<search-{index}@example.test>"
            self.server.add_message("INBOX", message.as_bytes())

        result = self.client.search(
            "INBOX",
            SearchQuery(subject='Alpha " OR ALL', limit=2),
        )

        self.assertEqual(len(result["messages"]), 2)
        self.assertIsNotNone(result["cursor"])
        search_command = next(
            command for command in self.server.imap_commands if " UID SEARCH " in command
        )
        self.assertIn('\\" OR ALL', search_command)
        self.assertFalse(any("BODY.PEEK[1]" in command for command in self.server.imap_commands))

    def test_read_message_uses_peek_without_marking_read(self):
        message = EmailMessage(policy=SMTP)
        message["From"] = "sender@example.test"
        message["To"] = "account@example.test"
        message["Subject"] = "Multipart fixture"
        message["Message-ID"] = "<multipart@example.test>"
        message.set_content("Selected plain text.")
        message.add_attachment(
            b"private attachment payload",
            maintype="application",
            subtype="octet-stream",
            filename="private.bin",
        )
        uid = self.server.add_message("INBOX", message.as_bytes())
        ref = MessageRef(
            mailbox="INBOX",
            uid_validity=self.server.uid_validity,
            uid=uid,
            message_id="<multipart@example.test>",
        )

        result = self.client.read_message(ref)

        self.assertEqual(result["body"], "Selected plain text.\n")
        self.assertEqual(result["attachments"][0]["filename"], "private.bin")
        self.assertNotIn("private attachment payload", result["body"])
        self.assertNotIn("\\Seen", self.server.flags("INBOX", uid))
        self.assertIn("1", self.server.body_fetch_sections)
        self.assertNotIn("2", self.server.body_fetch_sections)
        self.assertTrue(
            any("BODY.PEEK[HEADER.FIELDS" in command for command in self.server.imap_commands)
        )
        self.assertTrue(any("BODY.PEEK[1]<0." in command for command in self.server.imap_commands))
        self.assertFalse(any("BODY[]" in command for command in self.server.imap_commands))

    def test_attached_multipart_container_stays_metadata_only(self):
        message = EmailMessage(policy=SMTP)
        message["From"] = "sender@example.test"
        message["To"] = "account@example.test"
        message["Subject"] = "Attached multipart fixture"
        message["Message-ID"] = "<attached-multipart@example.test>"
        message.set_content("Visible message text.")
        attached = EmailMessage(policy=SMTP)
        attached.set_content("Attached container text.")
        attached.add_alternative("<p>Attached container HTML.</p>", subtype="html")
        attached.add_header(
            "Content-Disposition",
            "attachment",
            filename="attached-container.eml",
        )
        message.make_mixed()
        message.attach(attached)
        uid = self.server.add_message("INBOX", message.as_bytes())
        ref = MessageRef(
            mailbox="INBOX",
            uid_validity=self.server.uid_validity,
            uid=uid,
            message_id="<attached-multipart@example.test>",
        )

        result = self.client.read_message(ref)

        self.assertEqual(result["body"], "Visible message text.\n")
        self.assertEqual(result["attachments"][0]["filename"], "attached-container.eml")
        self.assertEqual(result["attachments"][0]["content_type"], "multipart/alternative")
        self.assertEqual(result["attachments"][0]["disposition"], "attachment")
        self.assertNotIn("Attached container text.", result["body"])
        self.assertNotIn("2.1", self.server.body_fetch_sections)
        self.assertNotIn("2.2", self.server.body_fetch_sections)

    def test_draft_match_accepts_server_stripped_trailing_newline(self):
        outgoing = OutgoingMessage(to=("to@example.test",), subject="S", body="Body")
        verified = {
            "subject": "S",
            "to": ["to@example.test"],
            "cc": [],
            "bcc": [],
            "body": "Body",
            "flags": ["\\Draft"],
        }

        self.assertTrue(_draft_matches(verified, outgoing))

        verified["body"] = "Body changed"
        self.assertFalse(_draft_matches(verified, outgoing))

    def test_nil_header_section_is_retried_before_reading(self):
        self.addCleanup(setattr, mail_module, "SETTLE_DELAY_SECONDS", 2.0)
        mail_module.SETTLE_DELAY_SECONDS = 0
        ref = self.make_message("<nil-header-retry@example.test>")
        self.server.nil_header_fetches = 1

        result = self.client.read_message(ref)

        self.assertEqual(result["message_id"], ref.message_id)
        self.assertEqual(self.server.nil_header_fetches, 0)

    def test_persistent_nil_header_is_not_reported_as_missing(self):
        self.addCleanup(setattr, mail_module, "SETTLE_DELAY_SECONDS", 2.0)
        mail_module.SETTLE_DELAY_SECONDS = 0
        ref = self.make_message("<nil-header-persistent@example.test>")
        self.server.nil_header_fetches = 99

        with self.assertRaises(MailError) as caught:
            self.client.read_message(ref)

        self.assertEqual(caught.exception.code, "message_unavailable")
        self.assertFalse(caught.exception.uncertain)

    def test_move_with_uninspectable_source_is_uncertain(self):
        ref = self.make_message("<move-source-fetch-no@example.test>")
        self.server.move_failure = "both_present_source_fetch_no"

        with self.assertRaises(MailError) as caught:
            self.client.move(ref, "Archive")

        self.assertEqual(caught.exception.code, "move_uncertain")
        self.assertIsNone(caught.exception.details["source_present"])
        self.assertTrue(caught.exception.details["destination_present"])
        self.assertEqual(self.server.move_commands, 1)

    def test_draft_verifies_maximum_accented_body_exactly(self):
        body = "é" * 100000
        outgoing = OutgoingMessage(
            to=("to@example.test",),
            subject="Maximum accented draft",
            body=body,
        )

        result = self.client.create_draft(outgoing)

        stored = email.message_from_bytes(
            self.server.message("Drafts", result["ref"]["uid"]).raw,
            policy=SMTP,
        )
        self.assertTrue(result["verified"])
        stored_body = stored.get_content().replace("\r\n", "\n")
        self.assertEqual(stored_body, body + "\n")

    def test_send_rejects_wrong_smtp_credentials_before_data(self):
        client = MailClient(self.config, lambda: "wrong-secret")
        outgoing = OutgoingMessage(
            to=("to@example.test",),
            subject="Rejected SMTP authentication",
            body="This message must not reach DATA.",
        )

        with self.assertRaises(MailError) as caught:
            client.send(outgoing)

        self.assertEqual(caught.exception.code, "authentication_failed")
        self.assertEqual(self.server.smtp_auth_attempts, 1)
        self.assertEqual(self.server.smtp_authenticated_sessions, 0)
        self.assertEqual(self.server.smtp_data_commands, 0)
        self.assertNotIn("wrong-secret", str(caught.exception))
        self.assertNotIn("bridge-secret", str(caught.exception))

    def test_large_message_text_fetch_uses_partial_limit(self):
        message = EmailMessage(policy=SMTP)
        message["From"] = "sender@example.test"
        message["To"] = "account@example.test"
        message["Subject"] = "Large fixture"
        message["Message-ID"] = "<large@example.test>"
        message.set_content("x" * (MAX_TEXT_BYTES * 2))
        uid = self.server.add_message("INBOX", message.as_bytes())
        ref = MessageRef(
            mailbox="INBOX",
            uid_validity=self.server.uid_validity,
            uid=uid,
            message_id="<large@example.test>",
        )

        result = self.client.read_message(ref)

        self.assertTrue(result["truncated"])
        self.assertLessEqual(len(result["body"].encode("utf-8")), MAX_TEXT_BYTES)

    def test_mailbox_names_round_trip_modified_utf7_and_quotes(self):
        names = {entry["name"] for entry in self.client.list_mailboxes()}
        self.assertIn("Café", names)
        self.assertIn('Archive "work"', names)

        for mailbox, subject in (("Café", "UTF7 mailbox"), ('Archive "work"', "Quoted mailbox")):
            message = EmailMessage(policy=SMTP)
            message["From"] = "sender@example.test"
            message["To"] = "account@example.test"
            message["Subject"] = subject
            message["Message-ID"] = f"<{subject.replace(' ', '-')}@example.test>"
            message.set_content("Mailbox fixture.")
            self.server.add_message(mailbox, message.as_bytes())
            result = self.client.search(mailbox, SearchQuery(subject=subject))
            self.assertEqual(result["messages"][0]["subject"], subject)

    def test_describe_headers_reuses_one_connection_across_mailboxes(self):
        inbox_ref = self.make_message("<preview-inbox@example.test>", subject="Inbox preview")
        message = EmailMessage(policy=SMTP)
        message["From"] = "sender@example.test"
        message["To"] = "account@example.test"
        message["Subject"] = "Archive preview"
        message["Message-ID"] = "<preview-archive@example.test>"
        message.set_content("Archive fixture.")
        archive_uid = self.server.add_message("Archive", message.as_bytes())
        archive_ref = MessageRef(
            mailbox="Archive",
            uid_validity=self.server.uid_validity_for("Archive"),
            uid=archive_uid,
            message_id="<preview-archive@example.test>",
        )

        previews = self.client.describe_headers([inbox_ref, archive_ref, inbox_ref])

        self.assertEqual(
            [preview["subject"] for preview in previews],
            ["Inbox preview", "Archive preview", "Inbox preview"],
        )
        self.assertEqual(self.server.select_calls, 3)
        self.assertEqual(self.server.imap_connections, 1)

    def test_custom_label_discovery_and_restoration(self):
        ref = self.make_message("<label@example.test>")

        labels = self.client.list_labels("INBOX")
        self.assertIn("Project_Review", labels)
        self.assertNotIn("\\Seen", labels)
        self.client.set_label(ref, "Project_Review", True)
        self.assertIn("Project_Review", self.server.flags("INBOX", ref.uid))
        self.client.set_label(ref, "Project_Review", False)
        self.assertNotIn("Project_Review", self.server.flags("INBOX", ref.uid))

        with self.assertRaises(MailError) as caught:
            self.client.set_label(ref, "\\Seen", True)
        self.assertEqual(caught.exception.code, "invalid_label")

    def test_keyword_dropped_by_server_is_reported_as_unsupported(self):
        ref = self.make_message("<label-dropped@example.test>")
        self.server.ignored_keyword_stores = True

        with self.assertRaises(MailError) as caught:
            self.client.set_label(ref, "Project_Review", True)

        self.assertEqual(caught.exception.code, "label_unsupported")
        self.assertFalse(caught.exception.uncertain)

    def test_trash_junk_spam_aliases_are_blocked(self):
        ref = self.make_message("<blocked@example.test>")
        for destination in ("Trash", "trash", "JUNK", "sPaM", "Wastebasket"):
            with self.subTest(destination=destination):
                with self.assertRaises(MailError) as caught:
                    self.client.move(ref, destination)
                self.assertEqual(caught.exception.code, "protected_destination")
        self.assertFalse(any(" UID MOVE " in command for command in self.server.imap_commands))

    def test_move_verifies_new_uid_and_reports_partial_failure(self):
        ref = self.make_message("<move-ok@example.test>")
        result = self.client.move(ref, "Archive")
        self.assertFalse(result["ref"]["uid"] == ref.uid)
        self.assertEqual(result["ref"]["mailbox"], "Archive")
        self.assertFalse(result["source_present"])
        self.assertTrue(result["destination_present"])

        second_ref = self.make_message("<move-partial@example.test>")
        self.server.move_failure = "both_present"
        with self.assertRaises(MailError) as caught:
            self.client.move(second_ref, "Archive")
        self.assertEqual(caught.exception.code, "move_uncertain")
        self.assertTrue(caught.exception.uncertain)
        self.assertTrue(caught.exception.details["source_present"])
        self.assertTrue(caught.exception.details["destination_present"])
        self.assertEqual(self.server.move_commands, 2)

    def test_draft_includes_bcc_and_verifies_plain_text_content(self):
        outgoing = OutgoingMessage(
            to=("to@example.test",),
            cc=("cc@example.test",),
            bcc=("bcc@example.test",),
            subject="Draft fixture",
            body="Keep this as a draft.",
        )

        result = self.client.create_draft(outgoing)

        self.assertTrue(result["verified"])
        self.assertTrue(result["draft"])
        stored = email.message_from_bytes(
            self.server.message("Drafts", result["ref"]["uid"]).raw, policy=SMTP
        )
        self.assertEqual(stored["To"], "to@example.test")
        self.assertEqual(stored["Cc"], "cc@example.test")
        self.assertEqual(stored["Bcc"], "bcc@example.test")
        self.assertEqual(stored["Subject"], "Draft fixture")
        self.assertEqual(stored.get_content().strip(), "Keep this as a draft.")
        self.assertIn("\\Draft", self.server.flags("Drafts", result["ref"]["uid"]))

    def test_append_disconnect_is_verified_without_retry(self):
        self.server.disconnect_after_append = True
        outgoing = OutgoingMessage(
            to=("account@example.test",),
            subject="Append uncertainty",
            body="Keep one verified draft.",
        )

        result = self.client.create_draft(outgoing)

        self.assertTrue(result["verified"])
        self.assertEqual(len(self.server.message_snapshot("Drafts")), 1)
        self.assertEqual(
            sum(" APPEND " in command for command in self.server.imap_commands),
            1,
        )

    def test_send_uses_full_envelope_and_never_exposes_bcc_header(self):
        self.server.refused_recipients.add("bcc@example.test")
        outgoing = OutgoingMessage(
            to=("to@example.test",),
            cc=("cc@example.test",),
            bcc=("bcc@example.test",),
            subject="Send fixture",
            body="Only an explicit send call reaches SMTP.",
        )

        result = self.client.send(outgoing)

        self.assertEqual(result["status"], "partial")
        self.assertTrue(result["uncertain"])
        self.assertEqual(result["accepted_count"], 2)
        self.assertEqual(result["refused_count"], 1)
        self.assertEqual(
            set(self.server.smtp_envelope_recipients),
            {"to@example.test", "cc@example.test", "bcc@example.test"},
        )
        self.assertNotIn("Bcc:", self.server.smtp_message.decode("utf-8"))
        self.assertEqual(self.server.smtp_data_attempts, 1)
        self.assertEqual(self.server.smtp_auth_attempts, 1)
        self.assertEqual(self.server.smtp_authenticated_sessions, 1)

    def test_smtp_disconnect_after_data_is_uncertain_and_not_retried(self):
        self.server.disconnect_after_data = True
        outgoing = OutgoingMessage(
            to=("to@example.test",),
            subject="Uncertain fixture",
            body="The server will disconnect after DATA.",
        )

        with self.assertRaises(MailError) as caught:
            self.client.send(outgoing)

        self.assertEqual(caught.exception.code, "send_uncertain")
        self.assertTrue(caught.exception.uncertain)
        self.assertEqual(self.server.smtp_data_attempts, 1)
        self.assertEqual(self.server.smtp_connections, 1)

    def test_health_does_not_probe_smtp(self):
        result = self.client.health()
        self.assertEqual(result["status"], "ok")
        self.assertEqual(self.server.smtp_connections, 0)


if __name__ == "__main__":
    unittest.main()

import unittest

from pydantic import ValidationError

from free_protonmail_mcp.models import AccountConfig, MessageRef, OutgoingMessage, SearchQuery


class InputBoundaryTests(unittest.TestCase):
    def test_account_refuses_remote_hosts_and_header_injection(self):
        for values in [
            {"host": "example.test"},
            {"host": "0.0.0.0"},
            {"sender": "sender@example.test\r\nBcc: other@example.test"},
        ]:
            settings = {"username": "account", "sender": "sender@example.test"} | values
            with self.assertRaises(ValidationError):
                AccountConfig(**settings)

    def test_outgoing_requires_recipients_and_excludes_model_controlled_sender(self):
        for values in [
            {"to": []},
            {"to": ["a@"]},
            {"to": ["@"]},
            {"to": ["recipient@example.test\nDATA"]},
            {"to": ["recipient@example.test"], "sender": "other@example.test"},
            {"to": ["recipient@example.test"], "cc": ["recipient@example.test"]},
        ]:
            with self.assertRaises(ValidationError):
                OutgoingMessage(subject="Subject", body="Body", **values)

    def test_message_reference_cannot_inject_protocol_commands(self):
        for mailbox in ["INBOX\r\nEXPUNGE", "", "INBOX\x00"]:
            with self.assertRaises(ValidationError):
                MessageRef(mailbox=mailbox, uid_validity=1, uid=1)
        with self.assertRaises(ValidationError):
            MessageRef(mailbox="INBOX", uid_validity=0, uid=1)

    def test_query_limits_bound_work_and_disallow_injected_headers(self):
        for values in [{"limit": 101}, {"before_uid": 0}, {"subject": "x\r\nSTORE"}]:
            with self.assertRaises(ValidationError):
                SearchQuery(**values)

    def test_frozen_message_preserves_approved_envelope(self):
        message = OutgoingMessage(to=["recipient@example.test"], subject="Subject", body="Body")
        with self.assertRaises(ValidationError):
            message.subject = "Changed"
        self.assertEqual(message.to, ("recipient@example.test",))


if __name__ == "__main__":
    unittest.main()

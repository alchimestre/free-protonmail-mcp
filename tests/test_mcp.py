import contextlib
import email.message
import email.policy
import sys
import tempfile
import unittest
from pathlib import Path

from mcp import Client
from mcp.client.stdio import StdioServerParameters

from tests.protocol_server import LocalMailProtocolServer


class StdioMailTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        resources = contextlib.ExitStack()
        self.addCleanup(resources.close)
        self.protocol = resources.enter_context(LocalMailProtocolServer())
        directory = resources.enter_context(tempfile.TemporaryDirectory())
        message = email.message.EmailMessage(policy=email.policy.SMTP)
        message["From"] = "sender@example.test"
        message["To"] = "account@example.test"
        message["Subject"] = "MCP disposable fixture"
        message["Message-ID"] = "<mcp-fixture@example.test>"
        message.set_content("MCP fixture body")
        self.protocol.add_message("INBOX", message.as_bytes())
        launcher = Path(__file__).with_name("stdio_server.py")
        parameters = StdioServerParameters(
            command=sys.executable,
            args=[
                str(launcher),
                "--imap-port",
                str(self.protocol.imap_port),
                "--smtp-port",
                str(self.protocol.smtp_port),
                "--state-dir",
                directory,
            ],
        )
        self.client = Client(parameters)

    async def call(self, tool, arguments=None):
        result = await self.client.call_tool(tool, arguments or {})
        self.assertFalse(result.is_error, result.content)
        return result.structured_content

    async def fixture_reference(self):
        found = await self.call(
            "search_messages",
            {
                "mailbox": "INBOX",
                "query": {"subject": "MCP disposable fixture"},
            },
        )
        matching = [
            item for item in found["messages"] if item["subject"] == "MCP disposable fixture"
        ]
        self.assertEqual(len(matching), 1)
        return matching[0]["ref"]

    async def test_reading_and_organization_through_stdio(self):
        async with self.client:
            await self.call("health")
            self.assertEqual(self.protocol.smtp_connections, 0)
            reference = await self.fixture_reference()
            message = await self.call("read_message", {"message": reference})
            self.assertEqual(message["body"].strip(), "MCP fixture body")
            await self.call("set_read", {"message": reference, "read": True})
            unread = await self.call(
                "search_messages",
                {
                    "mailbox": "INBOX",
                    "query": {"subject": "MCP disposable fixture", "unread": True},
                },
            )
            self.assertNotIn(reference, [item["ref"] for item in unread["messages"]])
            archived = await self.call(
                "move_message", {"message": reference, "destination": "Archive"}
            )
            restored = await self.call(
                "move_message", {"message": archived["ref"], "destination": "INBOX"}
            )
            restored_message = await self.call("read_message", {"message": restored["ref"]})
            self.assertEqual(restored_message["body"].strip(), "MCP fixture body")

    async def test_draft_contents_are_retrievable_without_sending(self):
        async with self.client:
            draft = await self.call(
                "create_draft",
                {
                    "message": {
                        "to": ["account@example.test"],
                        "bcc": ["private@example.test"],
                        "subject": "MCP unsent draft",
                        "body": "Do not send this draft.",
                    }
                },
            )
            retrieved = await self.call("read_message", {"message": draft["ref"]})
            self.assertEqual(retrieved["subject"], "MCP unsent draft")
            self.assertEqual(retrieved["body"].strip(), "Do not send this draft.")
            self.assertEqual(self.protocol.smtp_data_attempts, 0)

    async def test_model_cannot_approve_send_or_bypass_trash_boundary(self):
        async with self.client:
            request = await self.call(
                "request_send",
                {
                    "message": {
                        "to": ["account@example.test"],
                        "subject": "Await human approval",
                        "body": "Unsent.",
                    }
                },
            )
            status = await self.call("action_status", {"action_id": request["action_id"]})
            self.assertEqual(status["status"], "pending")
            for tool in ["approve", "send", "expunge", "raw_imap"]:
                result = await self.client.call_tool(tool, {"confirmed": True})
                self.assertTrue(result.is_error)
            reference = await self.fixture_reference()
            rejected = await self.client.call_tool(
                "move_message", {"message": reference, "destination": "Trash"}
            )
            self.assertTrue(rejected.is_error)
            body = await self.call("read_message", {"message": reference})
            self.assertEqual(body["body"].strip(), "MCP fixture body")
            self.assertEqual(self.protocol.smtp_data_attempts, 0)
            self.assertEqual(self.protocol.smtp_connections, 0)

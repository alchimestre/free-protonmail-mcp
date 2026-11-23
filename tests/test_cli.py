import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from free_protonmail_mcp.cli import main, terminal_text
from free_protonmail_mcp.config import save_account
from free_protonmail_mcp.models import AccountConfig
from tests.protocol_server import LocalMailProtocolServer


class TerminalRenderingTests(unittest.TestCase):
    def test_preview_cannot_emit_terminal_escape_or_bidi_controls(self):
        rendered = terminal_text("Subject\x1b[2J\rforged\u202esend\nBody\ttext")
        self.assertNotIn("\x1b", rendered)
        self.assertNotIn("\r", rendered)
        self.assertNotIn("\u202e", rendered)
        self.assertIn("\n", rendered)
        self.assertIn("Body", rendered)


class CommandLineTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.config_file = Path(self.directory.name) / "account.json"
        self.backend = Mock()
        self.backend.get_password.return_value = None
        backend_patch = patch(
            "free_protonmail_mcp.credentials.native_backend", return_value=self.backend
        )
        backend_patch.start()
        self.addCleanup(backend_patch.stop)

    def run_command(self, arguments, stdin=""):
        output = io.StringIO()
        errors = io.StringIO()
        with (
            patch("sys.stdin", io.StringIO(stdin)),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            code = main(["--config", str(self.config_file), *arguments])
        return code, output.getvalue(), errors.getvalue()

    def account_arguments(self):
        return [
            "setup",
            "--username",
            "account@example.test",
            "--sender",
            "account@example.test",
            "--host",
            "127.0.0.1",
            "--imap-port",
            "1143",
            "--smtp-port",
            "1025",
            "--credential-stdin",
        ]

    def test_setup_accepts_arguments_without_an_interactive_terminal(self):
        code, output, _ = self.run_command(self.account_arguments(), "bridge-secret\n")

        self.assertEqual(code, 0)
        self.assertIn("PASS config", output)
        self.assertIn("PASS credential", output)
        saved = AccountConfig.model_validate_json(self.config_file.read_text(encoding="utf-8"))
        self.assertEqual(saved.sender, "account@example.test")
        name = self.backend.set_password.call_args.args[1]
        self.assertTrue(name.startswith("mail:"))
        self.assertEqual(self.backend.set_password.call_args.args[2], "bridge-secret")

    def test_setup_keeps_existing_configuration_without_replace(self):
        self.run_command(self.account_arguments(), "bridge-secret\n")
        self.backend.get_password.return_value = "bridge-secret"

        code, output, _ = self.run_command(self.account_arguments(), "second-secret\n")

        self.assertEqual(code, 0)
        self.assertIn("existing account kept", output)
        self.assertIn("existing native-store secret kept", output)
        self.assertEqual(self.backend.set_password.call_count, 1)

    def test_failed_replacement_preserves_existing_account(self):
        self.run_command(self.account_arguments(), "bridge-secret\n")
        original = self.config_file.read_bytes()
        arguments = [*self.account_arguments(), "--replace", "--imap-port", "2143"]

        code, _, errors = self.run_command(arguments)

        self.assertEqual(code, 1)
        self.assertIn("INVALID_CREDENTIAL", errors)
        self.assertEqual(self.config_file.read_bytes(), original)
        self.assertEqual(self.backend.set_password.call_count, 1)

    def test_setup_rejects_conflicting_saved_account(self):
        self.run_command(self.account_arguments(), "bridge-secret\n")
        arguments = [*self.account_arguments(), "--username", "other@example.test"]

        code, _, errors = self.run_command(arguments, "second-secret\n")

        self.assertEqual(code, 1)
        self.assertIn("CONFIG_EXISTS", errors)
        self.assertEqual(self.backend.set_password.call_count, 1)

    def test_setup_reports_invalid_host_as_invalid_input(self):
        arguments = [*self.account_arguments(), "--host", "192.0.2.1"]

        code, _, errors = self.run_command(arguments, "bridge-secret\n")

        self.assertEqual(code, 1)
        self.assertIn("INVALID_INPUT", errors)
        self.backend.set_password.assert_not_called()

    def test_setup_without_sender_and_terminal_refuses_to_guess(self):
        arguments = [
            "setup",
            "--username",
            "account@example.test",
            "--credential-stdin",
        ]

        code, _, errors = self.run_command(arguments, "bridge-secret\n")

        self.assertEqual(code, 1)
        self.assertIn("PRIVATE_TERMINAL_REQUIRED", errors)
        self.assertFalse(self.config_file.exists())
        self.backend.set_password.assert_not_called()

    def test_doctor_reports_missing_configuration(self):
        code, output, _ = self.run_command(["doctor"])

        self.assertEqual(code, 1)
        self.assertIn("FAIL config SETUP_REQUIRED", output)

    def test_doctor_skips_imap_when_no_credential_is_stored(self):
        save_account(
            self.config_file,
            AccountConfig(
                username="account@example.test",
                sender="account@example.test",
                host="127.0.0.1",
                imap_port=1143,
                smtp_port=1025,
                timeout=2,
            ),
        )

        code, output, _ = self.run_command(["doctor"])

        self.assertEqual(code, 1)
        self.assertIn("FAIL credential SETUP_REQUIRED", output)
        self.assertIn("SKIP imap", output)

    def test_doctor_reports_live_imap_state(self):
        server = LocalMailProtocolServer()
        server.start()
        self.addCleanup(server.stop)
        save_account(
            self.config_file,
            AccountConfig(
                username="account@example.test",
                sender="account@example.test",
                host="127.0.0.1",
                imap_port=server.imap_port,
                smtp_port=server.smtp_port,
                timeout=2,
            ),
        )
        self.backend.get_password.return_value = "bridge-secret"

        code, output, _ = self.run_command(["doctor"])

        self.assertEqual(code, 0)
        self.assertIn("PASS credential", output)
        self.assertIn(f"PASS imap 127.0.0.1:{server.imap_port}", output)
        self.assertEqual(server.smtp_connections, 0)


if __name__ == "__main__":
    unittest.main()

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from free_protonmail_mcp.config import Paths, load_account, save_account
from free_protonmail_mcp.credentials import CredentialStore
from free_protonmail_mcp.models import AccountConfig, MailError


class PortableConfigurationTests(unittest.TestCase):
    def test_custom_profiles_do_not_share_action_state(self):
        with tempfile.TemporaryDirectory() as directory:
            first = Paths.for_config(Path(directory) / "one.json")
            second = Paths.for_config(Path(directory) / "two.json")
            self.assertNotEqual(first.state_dir, second.state_dir)

    def test_configuration_roundtrip_and_overwrite_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "account.json"
            account = AccountConfig(username="account", sender="sender@example.test")
            save_account(path, account)
            self.assertEqual(load_account(path), account)
            with self.assertRaises(MailError):
                save_account(path, account)
            stored = json.loads(path.read_text())
            self.assertNotIn("password", stored)

    def test_configuration_created_during_setup_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "account.json"
            account = AccountConfig(username="first", sender="first@example.test")
            competing = AccountConfig(username="second", sender="second@example.test")
            original_temporary_file = tempfile.NamedTemporaryFile

            def competing_write(*args, **kwargs):
                handle = original_temporary_file(*args, **kwargs)
                path.write_text(competing.model_dump_json(), encoding="utf-8")
                return handle

            with patch("tempfile.NamedTemporaryFile", side_effect=competing_write):
                with self.assertRaises(MailError) as caught:
                    save_account(path, account)
            self.assertEqual(caught.exception.code, "CONFIG_EXISTS")
            self.assertEqual(load_account(path), competing)

    def test_invalid_account_file_never_leaks_its_contents(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "account.json"
            path.write_text('{"password": "do-not-print"}')
            with self.assertRaises(MailError) as caught:
                load_account(path)
            self.assertNotIn("do-not-print", str(caught.exception))

    def test_plaintext_or_unknown_keyring_is_rejected_before_use(self):
        class UntrustedBackend:
            def get_password(self, service, name):
                raise AssertionError("must not reach untrusted backend")

        with patch("keyring.get_keyring", return_value=UntrustedBackend()):
            with self.assertRaises(MailError) as caught:
                CredentialStore().get("credential")
        self.assertEqual(caught.exception.code, "CREDENTIAL_STORE_UNAVAILABLE")


if __name__ == "__main__":
    unittest.main()

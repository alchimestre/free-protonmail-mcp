import unittest
from unittest.mock import Mock, patch

from keyring.errors import PasswordDeleteError

from free_protonmail_mcp.credentials import CredentialStore
from free_protonmail_mcp.models import MailError


class CredentialDeletionTests(unittest.TestCase):
    def test_failed_native_deletion_does_not_claim_retained_secret_was_removed(self):
        backend = Mock()
        backend.delete_password.side_effect = PasswordDeleteError("Native deletion failed")
        backend.get_password.return_value = "retained-synthetic-secret"
        with patch("free_protonmail_mcp.credentials.native_backend", return_value=backend):
            with self.assertRaises(MailError) as caught:
                CredentialStore().delete("synthetic-credential")
        self.assertEqual(caught.exception.code, "CREDENTIAL_STORE_UNAVAILABLE")
        self.assertNotIn("retained-synthetic-secret", str(caught.exception))


if __name__ == "__main__":
    unittest.main()

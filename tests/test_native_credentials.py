import hmac
import secrets
import unittest
import uuid

from free_protonmail_mcp.credentials import CredentialStore


@unittest.skipUnless(
    __name__ == "__main__",
    "Run this module directly with an unlocked native credential service",
)
class NativeCredentialTests(unittest.TestCase):
    def test_native_store_roundtrip_and_removal(self):
        store = CredentialStore()
        name = "native-test:" + str(uuid.uuid4())
        secret = secrets.token_urlsafe(32)
        try:
            store.set(name, secret)
            observed = store.get(name)
            self.assertTrue(hmac.compare_digest(observed or "", secret), "Native roundtrip failed")
        finally:
            store.delete(name)
        self.assertTrue(store.get(name) is None, "Native test credential was not removed")


if __name__ == "__main__":
    unittest.main()

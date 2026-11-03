import hashlib

import keyring
from keyring.errors import PasswordDeleteError

from .config import APP_NAME
from .models import AccountConfig, MailError

NATIVE_BACKENDS = frozenset(
    {
        "keyring.backends.macOS",
        "keyring.backends.Windows",
        "keyring.backends.SecretService",
        "keyring.backends.kwallet",
    }
)


class CredentialStore:
    def get(self, name: str) -> str | None:
        try:
            return native_backend().get_password(APP_NAME, name)
        except MailError:
            raise
        except Exception:
            raise store_error() from None

    def set(self, name: str, value: str) -> None:
        try:
            native_backend().set_password(APP_NAME, name, value)
        except MailError:
            raise
        except Exception:
            raise store_error() from None

    def delete(self, name: str) -> None:
        try:
            native_backend().delete_password(APP_NAME, name)
        except PasswordDeleteError:
            if self.get(name) is not None:
                raise store_error() from None
        except MailError:
            raise
        except Exception:
            raise store_error() from None

    def password(self, account: AccountConfig) -> str:
        value = self.get(mail_credential_name(account))
        if not value:
            raise MailError(
                "SETUP_REQUIRED", "Mail credential missing; run setup in a private terminal"
            )
        return value


def native_backend():
    try:
        backend = keyring.get_keyring()
    except Exception:
        raise store_error() from None
    if type(backend).__module__ not in NATIVE_BACKENDS:
        raise store_error()
    return backend


def mail_credential_name(account: AccountConfig) -> str:
    identity = "\x00".join([account.username, account.sender, account.host, str(account.imap_port)])
    return "mail:" + hashlib.sha256(identity.encode("utf-8")).hexdigest()


def store_error() -> MailError:
    return MailError(
        "CREDENTIAL_STORE_UNAVAILABLE",
        "Configure an unlocked native Keychain, Windows Credential Locker, "
        "Secret Service or KWallet "
        "backend using keyring; plaintext, null and chained fallback backends are refused",
    )

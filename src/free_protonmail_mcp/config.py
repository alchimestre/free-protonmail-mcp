import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from platformdirs import user_config_path, user_state_path

from .models import AccountConfig, MailError

APP_NAME = "free-protonmail-mcp"


@dataclass(frozen=True)
class Paths:
    config_file: Path
    state_dir: Path

    @classmethod
    def for_config(cls, path: Path | None = None):
        config_file = (
            path or user_config_path(APP_NAME, appauthor=False) / "account.json"
        ).resolve()
        profile = hashlib.sha256(str(config_file).encode("utf-8")).hexdigest()[:24]
        state_dir = user_state_path(APP_NAME, appauthor=False) / profile
        return cls(config_file, state_dir)


def load_account(path: Path) -> AccountConfig:
    try:
        if path.stat().st_size > 16384:
            raise ValueError("Configuration exceeds size limit")
        return AccountConfig.model_validate_json(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise MailError(
            "SETUP_REQUIRED", "Run setup in a private terminal before serving"
        ) from None
    except (OSError, ValueError):
        raise MailError(
            "INVALID_CONFIG", "Account configuration is invalid or unreadable"
        ) from None


def save_account(path: Path, account: AccountConfig, overwrite: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists() and not overwrite:
        raise MailError(
            "CONFIG_EXISTS", "Account configuration already exists; setup must confirm replacement"
        )
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, delete=False
        ) as handle:
            temporary = Path(handle.name)
            json.dump(account.model_dump(), handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if overwrite:
            os.replace(temporary, path)
        else:
            os.link(temporary, path)
    except FileExistsError:
        raise MailError(
            "CONFIG_EXISTS", "Another setup saved this configuration; nothing was replaced"
        ) from None
    except OSError:
        raise MailError("CONFIG_WRITE_FAILED", "Could not save account configuration") from None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)

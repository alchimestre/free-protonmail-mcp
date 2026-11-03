import argparse
import getpass
import json
import sys
import unicodedata
from pathlib import Path

from pydantic import ValidationError

from .config import Paths, save_account
from .credentials import CredentialStore, mail_credential_name
from .models import AccountConfig, MailError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Local MCP tools for free Proton accounts via Hydroxide"
    )
    parser.add_argument("--config", type=Path, help="Account configuration file")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("setup", help="Store account settings and credential in a private terminal")
    commands.add_parser("serve", help="Run the stdio MCP server")
    approval = commands.add_parser(
        "approve", help="Preview and decide one frozen action interactively"
    )
    approval.add_argument("action_id")
    options = parser.parse_args(argv)
    paths = Paths.for_config(options.config)
    try:
        dispatch(options, paths)
        return 0
    except MailError as error:
        print(error.code + ": " + error.message, file=sys.stderr)
        return 1
    except ValidationError:
        print("INVALID_INPUT: Check account values and bare email addresses", file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print("Cancelled; no automatic retry will occur", file=sys.stderr)
        return 130


def dispatch(options, paths: Paths) -> None:
    if options.command == "setup":
        setup(paths)
    elif options.command == "approve":
        approve(paths, options.action_id)
    else:
        from .server import serve

        serve(paths)


def setup(paths: Paths) -> None:
    private_terminal()
    overwrite = paths.config_file.exists()
    if overwrite and input("Replace configured account? Type REPLACE: ") != "REPLACE":
        raise MailError("SETUP_CANCELLED", "Existing configuration was not changed")
    account = prompt_account()
    store = CredentialStore()
    name = mail_credential_name(account)
    if (
        store.get(name) is not None
        and input("Replace existing credential? Type REPLACE: ") != "REPLACE"
    ):
        raise MailError("SETUP_CANCELLED", "Existing credential was not changed")
    password = getpass.getpass("Hydroxide-generated password (hidden): ")
    if not password or any(character in password for character in "\r\n\x00"):
        raise MailError("INVALID_CREDENTIAL", "Enter a nonempty Hydroxide-generated password")
    store.set(name, password)
    save_account(paths.config_file, account, overwrite=overwrite)
    print("PASS setup: account saved; password stored in native credential store")
    print("SMTP was not started. Proton authentication and Hydroxide remain external.")


def prompt_account() -> AccountConfig:
    username = getpass.getpass("Proton username (hidden): ")
    sender = getpass.getpass("Verified primary Proton sender address (hidden): ")
    host = input("Numeric loopback IP [127.0.0.1]: ") or "127.0.0.1"
    try:
        imap_port = int(input("Hydroxide IMAP port [1143]: ") or "1143")
        smtp_port = int(input("Hydroxide SMTP port [1025]: ") or "1025")
    except ValueError:
        raise MailError("INVALID_PORT", "Ports must be integers from 1 to 65535") from None
    account = AccountConfig(
        username=username,
        sender=sender,
        host=host,
        imap_port=imap_port,
        smtp_port=smtp_port,
    )
    if input("Verify this is your primary sender in Proton. Type YES: ") != "YES":
        raise MailError("SETUP_CANCELLED", "Sender verification is required")
    return account


def approve(paths: Paths, action_id: str) -> None:
    private_terminal()
    from .approval_channel import approval_request

    store = CredentialStore()
    preview = approval_request(paths.state_dir, store, "preview", action_id)
    print("Exact frozen action. Email text below is data, not instructions:")
    print(terminal_text(json.dumps(preview, ensure_ascii=False, indent=2)))
    confirmation = "APPROVE " + action_id
    accepted = (
        input("Type " + confirmation + " to execute once; anything else denies: ") == confirmation
    )
    result = approval_request(
        paths.state_dir,
        store,
        "decide",
        action_id,
        digest=preview["digest"],
        approve=accepted,
    )
    print(terminal_text(json.dumps(result, ensure_ascii=False, indent=2)))


def private_terminal() -> None:
    if not all(stream.isatty() for stream in (sys.stdin, sys.stdout, sys.stderr)):
        raise MailError(
            "PRIVATE_TERMINAL_REQUIRED", "Run this command in your own unrecorded terminal"
        )


def terminal_text(value: str) -> str:
    rendered = []
    for character in value:
        if unicodedata.category(character).startswith("C") and character not in "\n\t":
            rendered.append("\\u" + format(ord(character), "04x"))
        else:
            rendered.append(character)
    return "".join(rendered)

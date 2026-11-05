import argparse
import getpass
import json
import sys
import unicodedata
from pathlib import Path

from pydantic import ValidationError

from .config import Paths, load_account, save_account
from .credentials import CredentialStore, mail_credential_name
from .mail import MailClient
from .models import AccountConfig, MailError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Local MCP tools for free Proton accounts via Hydroxide"
    )
    parser.add_argument("--config", type=Path, help="Account configuration file")
    commands = parser.add_subparsers(dest="command", required=True)
    setup_command = commands.add_parser(
        "setup", help="Store account settings and the Hydroxide password"
    )
    setup_command.add_argument("--username", help="Proton username")
    setup_command.add_argument("--sender", help="Verified primary Proton sender address")
    setup_command.add_argument("--host", help="Numeric loopback IP")
    setup_command.add_argument("--imap-port", type=int, help="Hydroxide IMAP port")
    setup_command.add_argument("--smtp-port", type=int, help="Hydroxide SMTP port")
    setup_command.add_argument(
        "--credential-stdin",
        action="store_true",
        help="Read the Hydroxide password from standard input instead of a hidden prompt",
    )
    setup_command.add_argument(
        "--replace", action="store_true", help="Replace existing configuration and credential"
    )
    commands.add_parser("doctor", help="Report configuration, credential and IMAP state")
    commands.add_parser("serve", help="Run the stdio MCP server")
    approval = commands.add_parser(
        "approve", help="Preview and decide one frozen action interactively"
    )
    approval.add_argument("action_id")
    options = parser.parse_args(argv)
    paths = Paths.for_config(options.config)
    try:
        return dispatch(options, paths)
    except MailError as error:
        print(error.code + ": " + error.message, file=sys.stderr)
        return 1
    except ValidationError:
        print("INVALID_INPUT: Check account values and bare email addresses", file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print("Cancelled; no automatic retry will occur", file=sys.stderr)
        return 130


def dispatch(options, paths: Paths) -> int:
    if options.command == "setup":
        setup(paths, options)
    elif options.command == "doctor":
        return doctor(paths)
    elif options.command == "approve":
        approve(paths, options.action_id)
    else:
        from .server import serve

        serve(paths)
    return 0


def setup(paths: Paths, options) -> None:
    existing = paths.config_file.exists()
    if existing and not options.replace:
        account = load_account(paths.config_file)
        print("PASS config: existing account kept; pass --replace to change it")
    else:
        account = prompt_account(options)
        save_account(paths.config_file, account, overwrite=existing)
        print("PASS config: account saved")

    store = CredentialStore()
    name = mail_credential_name(account)
    if store.get(name) is not None and not options.replace:
        print("PASS credential: existing native-store secret kept; pass --replace to change it")
        return
    store.set(name, read_credential(options))
    print("PASS credential: Hydroxide password stored in the native credential store")
    print("Proton authentication and the Hydroxide listener remain external.")


def prompt_account(options) -> AccountConfig:
    values = {
        "username": options.username,
        "sender": options.sender,
        "host": options.host,
        "imap_port": options.imap_port,
        "smtp_port": options.smtp_port,
    }
    defaults = {"host": "127.0.0.1", "imap_port": 1143, "smtp_port": 1025}
    labels = {
        "username": "Proton username",
        "sender": "Verified primary Proton sender address",
        "host": "Numeric loopback IP",
        "imap_port": "Hydroxide IMAP port",
        "smtp_port": "Hydroxide SMTP port",
    }
    for name in ("username", "sender"):
        if values[name] is not None:
            continue
        if not sys.stdin.isatty():
            raise MailError(
                "PRIVATE_TERMINAL_REQUIRED",
                f"Pass --{name} or run setup in an interactive terminal",
            )
        values[name] = getpass.getpass(labels[name] + " (hidden): ")
    for name, default in defaults.items():
        if values[name] is None:
            if not sys.stdin.isatty():
                values[name] = default
            else:
                entered = input(f"{labels[name]} [{default}]: ")
                values[name] = entered or default
    try:
        account = AccountConfig(
            username=values["username"],
            sender=values["sender"],
            host=values["host"],
            imap_port=int(values["imap_port"]),
            smtp_port=int(values["smtp_port"]),
        )
    except (TypeError, ValueError):
        raise MailError("INVALID_PORT", "Ports must be integers from 1 to 65535") from None
    if options.sender is None:
        if input("Verify this is your primary sender in Proton. Type YES: ") != "YES":
            raise MailError("SETUP_CANCELLED", "Sender verification is required")
    return account


def read_credential(options) -> str:
    if options.credential_stdin:
        password = sys.stdin.readline()
    else:
        private_terminal()
        password = getpass.getpass("Hydroxide-generated password (hidden): ") + "\n"
    password = password.rstrip("\r\n")
    if not password or any(character in password for character in "\r\n\x00"):
        raise MailError("INVALID_CREDENTIAL", "Enter a nonempty Hydroxide-generated password")
    return password


def doctor(paths: Paths) -> int:
    failures = 0
    try:
        account = load_account(paths.config_file)
    except MailError as error:
        print(f"FAIL config {error.code}: {error.message}")
        print("SKIP credential, imap; pass --config or run setup")
        return 1
    print(f"PASS config {paths.config_file}")
    store = CredentialStore()
    try:
        stored = store.get(mail_credential_name(account)) is not None
    except MailError as error:
        print(f"FAIL credential {error.code}: {error.message}")
        failures += 1
    else:
        if stored:
            print("PASS credential native store holds the Hydroxide password")
        else:
            print("FAIL credential SETUP_REQUIRED: store the Hydroxide password with setup")
            failures += 1
    if failures:
        print("SKIP imap: IMAP login needs a stored credential")
        print("SKIP smtp never connected by this project")
        return 1
    mail = MailClient(account, lambda: store.password(account))
    try:
        report = mail.health()
    except MailError as error:
        details = error.result()["error"]["details"]
        print(f"FAIL imap {error.code} {json.dumps(details, ensure_ascii=False)}")
        failures += 1
    else:
        capabilities = " ".join(report["capabilities"])
        print(f"PASS imap {account.host}:{account.imap_port} {capabilities}".rstrip())
    print("SKIP smtp never connected by this project")
    return 1 if failures else 0


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

import argparse
from pathlib import Path

from free_protonmail_mcp.approvals import ApprovalManager
from free_protonmail_mcp.mail import MailClient
from free_protonmail_mcp.models import AccountConfig
from free_protonmail_mcp.server import build_server, execute


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--imap-port", required=True, type=int)
    parser.add_argument("--smtp-port", required=True, type=int)
    parser.add_argument("--state-dir", required=True, type=Path)
    options = parser.parse_args()
    account = AccountConfig(
        username="account@example.test",
        sender="account@example.test",
        imap_port=options.imap_port,
        smtp_port=options.smtp_port,
        timeout=3,
    )
    mail = MailClient(account, lambda: "bridge-secret")
    manager = ApprovalManager(
        options.state_dir,
        lambda kind, payload: execute(mail, account, kind, payload),
    )
    try:
        build_server(mail, manager, account).run(transport="stdio")
    finally:
        manager.close()


if __name__ == "__main__":
    main()

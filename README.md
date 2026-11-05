# free-protonmail-mcp

Local MCP tools for free Proton Mail accounts through [Hydroxide](https://codeberg.org/emersion/hydroxide). Proton's paid Bridge is not required; desktop mail clients run independently.

| Operation | Authority |
|---|---|
| Search, read, read state, existing labels, permitted moves, plain-text drafts | Autonomous within the requested task |
| Send a content snapshot | Exact human approval in a separate terminal |
| Move messages to Trash | Exact human approval in a separate terminal |
| Permanent deletion, mailbox management, arbitrary IMAP/SMTP commands | Unavailable |

## Install

1. Install Python 3.12 or later and [uv](https://docs.astral.sh/uv/getting-started/installation/).
2. Check out this project and open a terminal in its directory.
3. Install the locked dependencies.

```sh
uv sync --frozen
```

| Platform | Runtime |
|---|---|
| Linux | Python with an unlocked Secret Service or KWallet backend |
| macOS | Python with access to native Keychain |
| Windows | Python with access to native Credential Locker |

`uv` creates the environment on all three platforms; shell activation is unnecessary.

| Optional activation | Command |
|---|---|
| Linux or macOS, Bash/Zsh | `source .venv/bin/activate` |
| Windows, PowerShell | `.venv\Scripts\Activate.ps1` |

Use `uv run` without activation if shell policy blocks activation.

## Connect Hydroxide

1. Install Hydroxide from [Codeberg](https://codeberg.org/emersion/hydroxide). Reference source revision: `02b3b6c8aff726d2404b6ed5f6ba1b7937e1f30e`. Keep the built binary outside temporary directories, and invoke it by absolute path; a shell variable from one terminal does not survive into the next.

```sh
git clone https://codeberg.org/emersion/hydroxide.git
git -C hydroxide checkout --detach 02b3b6c8aff726d2404b6ed5f6ba1b7937e1f30e
cd hydroxide && go build -mod=readonly -o ~/.local/bin/hydroxide ./cmd/hydroxide
```
2. Authenticate in a private terminal. Enter Proton passwords, verification challenges and two-factor codes there. Keep the generated Hydroxide password private.

```sh
hydroxide auth USERNAME
```

3. Start only the loopback IMAP listener. Keep debug disabled.

```sh
hydroxide -imap-host 127.0.0.1 -imap-port 1143 imap
```

4. Store the account settings and the Hydroxide password. Choose one path:

```sh
uv run --frozen free-protonmail-mcp setup
```

The interactive form prompts for missing values, hides the username, sender and password, and requires a terminal check that fails when input or output is redirected.

```sh
uv run --frozen free-protonmail-mcp setup --username USERNAME --sender ADDRESS --credential-stdin
```

The non-interactive form reads the Hydroxide password from standard input and defaults the loopback address and ports. Use it when a script or agent runs setup; pipe the password, never pass it as an argument.

| `setup` option | Effect |
|---|---|
| `--username`, `--sender` | Account identity; a terminal is required for any value not supplied |
| `--host`, `--imap-port`, `--smtp-port` | Override the `127.0.0.1`, `1143`, `1025` defaults |
| `--credential-stdin` | Read the Hydroxide password from standard input instead of a hidden prompt |
| `--replace` | Replace an existing configuration or credential; without it both are kept |

5. Confirm the bridge from the same shell that will start the server.

```sh
uv run --frozen free-protonmail-mcp doctor
```

`doctor` prints one line per check and exits nonzero on failure: configuration file, stored credential, IMAP login and advertised capabilities. It never contacts SMTP and prints no secret. The lines name the failing code, so `FAIL imap imap_unavailable {"endpoint": "127.0.0.1:1143", "reason": "connection_refused"}` means the listener is not running, not that the credential is wrong.

6. Start loopback SMTP in another terminal only when sending is wanted.

```sh
hydroxide -smtp-host 127.0.0.1 -smtp-port 1025 smtp
```

Substitute the installed executable path if Hydroxide is not on `PATH`. Leave occupied ports alone; choose unused ports in Hydroxide and enter matching values during setup. Do not use Hydroxide's combined `serve` command for this setup.

## Configure an MCP host

```json
{
  "mcpServers": {
    "free-protonmail-mcp": {
      "command": "uv",
      "args": ["--directory", "PROJECT_DIRECTORY", "run", "--frozen", "free-protonmail-mcp", "serve"]
    }
  }
}
```

Replace `PROJECT_DIRECTORY` with the checkout directory. Use the host's standard MCP configuration format if it differs. Host registration is manual; setup does not modify a host configuration.

The server inherits the launching environment. On Linux that must include the user D-Bus session address so the native credential service is reachable; a host that starts servers with a minimal environment passes it explicitly.

| Command | Effect |
|---|---|
| `free-protonmail-mcp setup` | Save account settings and the native-store credential |
| `free-protonmail-mcp doctor` | Report configuration, credential and live IMAP state; no SMTP |
| `free-protonmail-mcp serve` | Start stdio MCP and an authenticated loopback approval endpoint |
| `free-protonmail-mcp approve ACTION_ID` | Display the complete frozen action and ask for an interactive decision |
| `free-protonmail-mcp --config FILE serve` | Use another account configuration and isolated action state |

Run these commands through `uv run --frozen` from the project directory. Server stdout is reserved for MCP protocol traffic.

## Use the tools

| Tool | Result |
|---|---|
| `health`, `list_mailboxes`, `list_labels` | IMAP capability, mailbox and observed keyword discovery; no SMTP connection |
| `search_messages`, `read_message` | Bounded headers and selected text without marking messages read; attachment metadata only |
| `set_read`, `set_label`, `move_message` | Verified organization with stable message references; autonomous Trash/junk moves refused |
| `create_draft` | Verified unsent plain-text draft from the configured sender |
| `request_send`, `request_trash`, `action_status` | Frozen approval requests and recorded outcomes; no MCP approval tool |

1. Request an action through MCP.
2. Open a separate private terminal and inspect the complete action.

```sh
uv run --frozen free-protonmail-mcp approve ACTION_ID
```

3. Type the displayed approval phrase to execute once, or deny it. Approval expires after 15 minutes.
4. Check `action_status` before reporting success. Do not retry an unknown outcome with a new action ID.

The send preview includes the configured sender, all To/Cc/Bcc recipients, subject and body. Trash approval identifies the exact messages and moves them to Trash; it never permanently deletes. Changed content or target references require a fresh approval. Sending a content snapshot retains any original draft.

Use [the host-neutral mail skill](skills/proton-mail/SKILL.md) with a host-enforced MCP-only tool allowlist. Deny the mail agent shell, filesystem, GUI, browser, credential-store and approval-channel access. A same-user agent with unrestricted local access can operate a terminal approval flow; instructions do not provide OS isolation.

## Credentials and local state

| Data | Storage |
|---|---|
| Username, verified sender, numeric loopback address, ports | Platform-standard user configuration directory; see `account.example.json` |
| Hydroxide-generated password and approval-channel token | Native OS credential store through `keyring` |
| Pending message and approval payloads | Process memory; restart invalidates pending actions |
| Action IDs, payload digests and outcomes | SQLite in the platform-standard user state directory |
| Mailbox mirror, message bodies, raw protocol logs | Not retained |

Hydroxide's own `auth` command needs a human terminal for the Proton password, verification challenge and two-factor code; nothing else in this project does. Setup needs a terminal only for values not supplied as options and for the hidden password prompt. Credentials never belong in command arguments, environment variables, repository files or MCP arguments. Configuration and action-state paths come from `platformdirs`; custom configuration paths isolate action state.

Only native `keyring` backends are accepted. Plaintext, null, third-party and chained fallback backends are refused. Select a native backend in the `keyring` configuration when automatic selection chooses a chain. Use `uv run --frozen python -m keyring diagnose` to locate its configuration.

| Platform | Native backend class |
|---|---|
| Linux Secret Service | `keyring.backends.SecretService.Keyring` |
| Linux KWallet | `keyring.backends.kwallet.DBusKeyring` |
| macOS | `keyring.backends.macOS.Keyring` |
| Windows | `keyring.backends.Windows.WinVaultKeyring` |

Headless Linux needs a running user D-Bus session, an installed native credential service and an unlocked collection. Failure to obtain a secure backend stops setup; there is no plaintext fallback. Hydroxide separately stores encrypted Proton passwords and tokens. This project does not read its cache or desktop-client storage.

Selected mail content returned through MCP enters the calling model's context. Email text is untrusted data, not permission to call tools. No provider-enforced draft-only or send-only permission boundary is established.

## Limits

| Limit | Behavior |
|---|---|
| Hydroxide IMAP maturity | Upstream documents IMAP as work in progress |
| Folders and labels | Existing mailboxes/keywords only; no creation, rename or deletion. A server that accepts a keyword store without keeping it yields `label_unsupported` |
| Replies and attachments | Plain-text composition; no reply-thread placement guarantee or attachment upload |
| Partial MOVE | Inspect source and destination; never emulate with COPY and deletion flags |
| Draft append or SMTP timeout | Report unknown outcome; never automatically retry |
| Local sync lag | A read or draft check waits up to 12 s for Hydroxide to index the message, then reports `message_unavailable` or `draft_uncertain` |
| Restart during an approved effect | Record unknown outcome; do not execute that action again |
| Hydroxide IMAP not running | Mail tools fail with `imap_unavailable` and details `endpoint` and `reason` (`connection_refused`, `timed_out`, `connection_lost`, `protocol_error`, `network_error`) |
| Authentication refresh failure | Reauthenticate Hydroxide interactively; do not weaken 2FA |
| Background processing | No scheduled mailbox activity |

## Verify

```sh
uv run --frozen python -m unittest discover -s tests
```

```sh
uv run --frozen ruff format --check .
```

```sh
uv run --frozen ruff check .
```

```sh
uv run --frozen pip-audit --skip-editable
```

Run the native credential test with an unlocked OS credential service. It creates and removes one random test credential; no Proton account is needed.

```sh
uv run --frozen python tests/test_native_credentials.py
```

The behavioral suite uses local synthetic IMAP/SMTP servers and contains no real account credentials. Native credential-store and live Proton verification require the corresponding operating system and an explicitly authorized account. A CI matrix is not evidence that an unrun platform passed.

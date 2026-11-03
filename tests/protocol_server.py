import base64
import re
import socket
import socketserver
import threading
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesHeaderParser, BytesParser


@dataclass
class StoredMessage:
    uid: int
    raw: bytes
    flags: set[str] = field(default_factory=set)


class _ThreadingServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, handler, fixture):
        super().__init__(address, handler)
        self.fixture = fixture


class _IMAPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self._send("* OK local protocol fixture ready")
        while True:
            line = self.rfile.readline()
            if not line:
                return
            command = line.decode("utf-8", "replace").rstrip("\r\n")
            self.server.fixture.record_imap(command)
            parts = command.split(None, 2)
            if len(parts) < 2:
                return
            tag, name = parts[0], parts[1].upper()
            arguments = parts[2] if len(parts) == 3 else ""
            if name == "CAPABILITY":
                self._send("* CAPABILITY IMAP4rev1 UIDPLUS MOVE")
                self._send(f"{tag} OK CAPABILITY completed")
            elif name == "LOGIN":
                self._login(tag, arguments)
            elif name == "LIST":
                self._list(tag)
            elif name in {"SELECT", "EXAMINE"}:
                self._select(tag, arguments, name == "EXAMINE")
            elif name == "UID":
                self._uid(tag, arguments)
            elif name == "APPEND":
                self._append(tag, arguments)
            elif name == "NOOP":
                self._send(f"{tag} OK NOOP completed")
            elif name == "LOGOUT":
                self._send("* BYE logging out")
                self._send(f"{tag} OK LOGOUT completed")
                return
            else:
                self._send(f"{tag} BAD unsupported command")

    def _send(self, line):
        self.wfile.write(line.encode("utf-8") + b"\r\n")
        self.wfile.flush()

    def _login(self, tag, arguments):
        values = _split_imap_values(arguments)
        password = values[1] if len(values) > 1 else ""
        if password != self.server.fixture.expected_password:
            self._send(f"{tag} NO [AUTHENTICATIONFAILED] invalid bridge password")
            return
        self._send(f"{tag} OK LOGIN completed")

    def _list(self, tag):
        for name, attributes in self.server.fixture.mailbox_snapshot():
            flags = " ".join(attributes)
            encoded_name = encode_modified_utf7(name)
            self._send(f'* LIST ({flags}) "/" {_imap_quote(encoded_name)}')
        self._send(f"{tag} OK LIST completed")

    def _select(self, tag, arguments, readonly):
        name = _split_imap_values(arguments)[0]
        mailbox = decode_modified_utf7(name)
        fixture = self.server.fixture
        if not fixture.has_mailbox(mailbox):
            self._send(f"{tag} NO no such mailbox")
            return
        self.selected_mailbox = mailbox
        attrs = " ".join(fixture.permanent_flags(mailbox))
        messages = fixture.message_snapshot(mailbox)
        uidvalidity = fixture.uid_validity_for(mailbox)
        uidnext = fixture.next_uid_for(mailbox)
        self._send(f"* FLAGS ({attrs})")
        self._send(f"* {len(messages)} EXISTS")
        self._send("* 0 RECENT")
        self._send(f"* OK [UIDVALIDITY {uidvalidity}] UIDs valid")
        self._send(f"* OK [UIDNEXT {uidnext}] predicted next UID")
        self._send(f"* OK [PERMANENTFLAGS ({attrs})] flags permitted")
        mode = "READ-ONLY" if readonly else "READ-WRITE"
        self._send(f"{tag} OK [{mode}] SELECT completed")

    def _uid(self, tag, arguments):
        parts = arguments.split(None, 1)
        if len(parts) != 2:
            self._send(f"{tag} BAD missing UID command")
            return
        action, args = parts[0].upper(), parts[1]
        if action == "SEARCH":
            self._search(tag, args)
        elif action == "FETCH":
            self._fetch(tag, args)
        elif action == "STORE":
            self._store(tag, args)
        elif action == "MOVE":
            self._move(tag, args)
        else:
            self._send(f"{tag} BAD unsupported UID command")

    def _search(self, tag, criteria):
        mailbox = getattr(self, "selected_mailbox", "INBOX")
        fixture = self.server.fixture
        matches = []
        subject = _quoted_search_value(criteria, "SUBJECT")
        sender = _quoted_search_value(criteria, "FROM")
        message_id = _quoted_search_value(criteria, "HEADER\\s+MESSAGE-ID")
        uid_range = re.search(r"\bUID\s+(\d+):(?:(\d+)|\*)", criteria, re.IGNORECASE)
        for message in fixture.message_snapshot(mailbox):
            parsed = BytesParser(policy=policy.default).parsebytes(message.raw)
            if re.search(r"\bUNSEEN\b", criteria, re.IGNORECASE) and "\\Seen" in message.flags:
                continue
            if re.search(r"\bSEEN\b", criteria, re.IGNORECASE) and "\\Seen" not in message.flags:
                continue
            if (
                subject is not None
                and subject.casefold() not in str(parsed.get("Subject", "")).casefold()
            ):
                continue
            if (
                sender is not None
                and sender.casefold() not in str(parsed.get("From", "")).casefold()
            ):
                continue
            if (
                message_id is not None
                and message_id.casefold() != str(parsed.get("Message-ID", "")).casefold()
            ):
                continue
            if uid_range:
                lower = int(uid_range.group(1))
                upper = int(uid_range.group(2)) if uid_range.group(2) else 4294967295
                if not lower <= message.uid <= upper:
                    continue
            matches.append(message.uid)
        payload = " ".join(str(uid) for uid in sorted(matches))
        self._send(f"* SEARCH{(' ' + payload) if payload else ''}")
        self._send(f"{tag} OK UID SEARCH completed")

    def _fetch(self, tag, arguments):
        parts = arguments.split(None, 1)
        uid = int(parts[0])
        items = parts[1] if len(parts) > 1 else ""
        mailbox = getattr(self, "selected_mailbox", "INBOX")
        stored = self.server.fixture.find_message(mailbox, uid)
        if stored is None:
            self._send(f"{tag} OK UID FETCH completed")
            return
        if self.server.fixture.fetch_failure_mailbox == mailbox:
            self.server.fixture.fetch_failure_mailbox = None
            self._send(f"{tag} NO simulated candidate FETCH failure")
            return
        if (
            "BODYSTRUCTURE" in items.upper()
            or "FLAGS" in items.upper()
            or "RFC822.SIZE" in items.upper()
        ):
            self._send_metadata(stored, items)
        body_match = re.search(
            r"BODY\.PEEK\[(.+?)\](?:<(?:0\.)?(\d+)>)?",
            items,
            re.IGNORECASE,
        )
        if body_match:
            selector = body_match.group(1)
            cap = int(body_match.group(2)) if body_match.group(2) else None
            self._send_body(stored, selector, cap)
        self._send(f"{tag} OK UID FETCH completed")

    def _send_metadata(self, stored, items):
        values = [f"UID {stored.uid}"]
        if "FLAGS" in items.upper():
            flags = " ".join(sorted(stored.flags, key=str.casefold))
            values.append(f"FLAGS ({flags})")
        if "RFC822.SIZE" in items.upper():
            values.append(f"RFC822.SIZE {len(stored.raw)}")
        if "BODYSTRUCTURE" in items.upper():
            parsed = BytesParser(policy=policy.default).parsebytes(stored.raw)
            values.append(f"BODYSTRUCTURE {_body_structure(parsed)}")
        self._send(f"* {stored.uid} FETCH ({' '.join(values)})")

    def _send_body(self, stored, selector, cap):
        self.server.fixture.record_body_fetch(selector)
        parsed = BytesParser(policy=policy.default).parsebytes(stored.raw)
        upper_selector = selector.upper()
        if upper_selector.startswith("HEADER"):
            if self.server.fixture.nil_header_fetches > 0:
                self.server.fixture.nil_header_fetches -= 1
                self._send(f"* {stored.uid} FETCH (UID {stored.uid} BODY[{selector}] NIL)")
                return
            if upper_selector == "HEADER":
                header = stored.raw.partition(b"\r\n\r\n")[0] + b"\r\n\r\n"
            else:
                names_match = re.search(r"\(([^)]*)\)", selector)
                names = names_match.group(1).split() if names_match else []
                header = _selected_headers(stored.raw, names)
            descriptor = f"BODY[{selector}]"
        else:
            body = _body_for_section(parsed, selector)
            descriptor = f"BODY[{selector}]"
            header = body
        if cap is not None:
            header = header[:cap]
        self._send(f"* {stored.uid} FETCH (UID {stored.uid} {descriptor} {{{len(header)}}}")
        self.wfile.write(header + b")\r\n")
        self.wfile.flush()

    def _store(self, tag, arguments):
        match = re.fullmatch(
            r"(\d+)\s+([+-])FLAGS\.SILENT\s+\((.*)\)",
            arguments,
            re.IGNORECASE,
        )
        if not match:
            self._send(f"{tag} BAD invalid STORE")
            return
        uid = int(match.group(1))
        operation = match.group(2)
        flags = match.group(3).split()
        mailbox = getattr(self, "selected_mailbox", "INBOX")
        stored = self.server.fixture.find_message(mailbox, uid)
        if stored is not None:
            if self.server.fixture.ignored_keyword_stores:
                flags = [flag for flag in flags if flag.startswith("\\")]
            if operation == "+":
                stored.flags.update(flags)
            else:
                stored.flags.difference_update(flags)
        self._send(f"{tag} OK UID STORE completed")

    def _move(self, tag, arguments):
        parts = _split_imap_values(arguments)
        if len(parts) < 2:
            self._send(f"{tag} BAD invalid MOVE")
            return
        uid = int(parts[0])
        destination = decode_modified_utf7(parts[1])
        source = getattr(self, "selected_mailbox", "INBOX")
        self.server.fixture.move_commands += 1
        moved = self.server.fixture.move_message(source, destination, uid)
        if not moved:
            self._send(f"{tag} NO no message to move")
            return
        if self.server.fixture.move_failure == "both_present_source_fetch_no":
            self.server.fixture.fetch_failure_mailbox = source
        if self.server.fixture.move_failure in {
            "destination_only",
            "both_present",
            "both_present_source_fetch_no",
        }:
            self._send(f"{tag} NO simulated partial MOVE failure")
            return
        self._send(f"{tag} OK UID MOVE completed")

    def _append(self, tag, arguments):
        match = re.match(
            r'^("(?:\\.|[^"])*"|[^ ]+)\s+(?:\(([^)]*)\)|NIL)\s+\{(\d+)\+?\}$',
            arguments,
        )
        if not match:
            self._send(f"{tag} BAD invalid APPEND")
            return
        mailbox_name = _unquote(match.group(1))
        mailbox = decode_modified_utf7(mailbox_name)
        flags = set(match.group(2).split()) if match.group(2) else set()
        length = int(match.group(3))
        self._send("+ continue")
        raw = self.rfile.read(length)
        self.rfile.read(2)
        uid = self.server.fixture.add_message(mailbox, raw, flags)
        if self.server.fixture.disconnect_after_append:
            self.request.shutdown(socket.SHUT_RDWR)
            return
        self._send(
            f"{tag} OK [APPENDUID {self.server.fixture.uid_validity_for(mailbox)} "
            f"{uid}] APPEND completed"
        )


class _SMTPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        fixture = self.server.fixture
        fixture.record_smtp_connection()
        self.wfile.write(b"220 local SMTP fixture ready\r\n")
        self.wfile.flush()
        _serve_smtp(self, fixture)


def _serve_smtp(handler, fixture):
    authenticated = False
    while True:
        line = handler.rfile.readline()
        if not line:
            return
        command = line.decode("ascii", "replace").rstrip("\r\n")
        authenticated, finished = _handle_smtp_command(
            handler,
            fixture,
            command,
            authenticated,
        )
        if finished:
            return


def _handle_smtp_command(handler, fixture, command, authenticated):
    upper = command.upper()
    if upper.startswith("EHLO") or upper.startswith("HELO"):
        handler.wfile.write(b"250-localhost\r\n250-AUTH PLAIN\r\n250 SIZE 5000000\r\n")
    elif upper.startswith("AUTH "):
        authenticated = _smtp_authenticate(handler, fixture, command)
    elif upper.startswith("MAIL FROM:"):
        response = (
            b"250 sender accepted\r\n" if authenticated else b"530 authentication required\r\n"
        )
        handler.wfile.write(response)
    elif upper.startswith("RCPT TO:"):
        if not authenticated:
            handler.wfile.write(b"530 authentication required\r\n")
        else:
            recipient = _smtp_address(command)
            fixture.record_smtp_recipient(recipient)
            response = (
                b"550 recipient refused\r\n"
                if recipient in fixture.refused_recipients
                else b"250 recipient accepted\r\n"
            )
            handler.wfile.write(response)
    elif upper == "DATA":
        fixture.record_smtp_data_command()
        if not authenticated:
            handler.wfile.write(b"530 authentication required\r\n")
        else:
            handler.wfile.write(b"354 send message content\r\n")
            handler.wfile.flush()
            if not _read_smtp_data(handler, fixture):
                return authenticated, True
            handler.wfile.write(b"250 message accepted\r\n")
    elif upper == "QUIT":
        handler.wfile.write(b"221 closing connection\r\n")
        handler.wfile.flush()
        return authenticated, True
    elif upper == "RSET":
        handler.wfile.write(b"250 reset\r\n")
    else:
        handler.wfile.write(b"250 ok\r\n")
    handler.wfile.flush()
    return authenticated, False


def _smtp_authenticate(handler, fixture, command):
    match = re.fullmatch(r"AUTH PLAIN (\S+)", command, re.IGNORECASE)
    authenticated = False
    if match is not None:
        try:
            _, username, password = base64.b64decode(
                match.group(1),
                validate=True,
            ).split(b"\x00", 2)
            authenticated = (
                username.decode("utf-8") == fixture.expected_username
                and password.decode("utf-8") == fixture.expected_password
            )
        except (UnicodeDecodeError, ValueError):
            pass
    fixture.record_smtp_auth(authenticated)
    response = (
        b"235 2.7.0 authentication successful\r\n"
        if authenticated
        else b"535 5.7.8 authentication failed\r\n"
    )
    handler.wfile.write(response)
    return authenticated


def _read_smtp_data(handler, fixture):
    data = bytearray()
    while True:
        data_line = handler.rfile.readline()
        if not data_line:
            return False
        if data_line == b".\r\n":
            break
        if data_line.startswith(b".."):
            data_line = data_line[1:]
        data.extend(data_line)
    fixture.record_smtp_data(bytes(data))
    return not fixture.disconnect_after_data


def _split_imap_values(text):
    values = []
    index = 0
    while index < len(text):
        while index < len(text) and text[index].isspace():
            index += 1
        if index >= len(text):
            break
        if text[index] == '"':
            value, index = _read_quoted(text, index)
            values.append(value)
        else:
            end = index
            while end < len(text) and not text[end].isspace():
                end += 1
            values.append(text[index:end])
            index = end
    return values


def _read_quoted(text, start):
    value = []
    index = start + 1
    while index < len(text):
        character = text[index]
        if character == "\\" and index + 1 < len(text):
            value.append(text[index + 1])
            index += 2
            continue
        if character == '"':
            return "".join(value), index + 1
        value.append(character)
        index += 1
    return "".join(value), index


def _unquote(value):
    if value.startswith('"') and value.endswith('"'):
        return _read_quoted(value, 0)[0]
    return value


def _imap_quote(value):
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def encode_modified_utf7(value):
    result = []
    buffered = []

    def flush():
        if buffered:
            encoded = base64.b64encode("".join(buffered).encode("utf-16-be"))
            result.append("&" + encoded.decode("ascii").rstrip("=").replace("/", ",") + "-")
            buffered.clear()

    for character in value:
        codepoint = ord(character)
        if 0x20 <= codepoint <= 0x7E:
            flush()
            result.append("&-" if character == "&" else character)
        else:
            buffered.append(character)
    flush()
    return "".join(result)


def decode_modified_utf7(value):
    pattern = re.compile(r"&([^-]*)-")

    def replace(match):
        if not match.group(1):
            return "&"
        encoded = match.group(1).replace(",", "/")
        encoded += "=" * ((4 - len(encoded) % 4) % 4)
        return base64.b64decode(encoded).decode("utf-16-be")

    return pattern.sub(replace, value)


def _quoted_search_value(criteria, key):
    match = re.search(r"\b" + key + r'\s+"((?:\\.|[^"])*)"', criteria, re.IGNORECASE)
    if not match:
        return None
    return re.sub(r"\\(.)", r"\1", match.group(1))


def _selected_headers(raw, names):
    header, separator, _ = raw.partition(b"\r\n\r\n")
    parsed = BytesHeaderParser(policy=policy.default).parsebytes(header + separator)
    selected = bytearray()
    wanted = {name.casefold() for name in names}
    for name, value in parsed.raw_items():
        if name.casefold() in wanted:
            selected.extend(f"{name}: {value}\r\n".encode("utf-8"))
    selected.extend(b"\r\n")
    return bytes(selected)


def _body_structure(message):
    if message.is_multipart():
        children = " ".join(_body_structure(part) for part in message.iter_parts())
        subtype = message.get_content_subtype().upper()
        return f"({children} {subtype} {_parameter_list(message)} {_disposition(message)} NIL NIL)"
    content_type, subtype = message.get_content_type().split("/", 1)
    encoding = str(message.get("Content-Transfer-Encoding", "7BIT")).upper()
    decoded = message.get_payload(decode=True) or b""
    fields = [
        _imap_quote(content_type.upper()),
        _imap_quote(subtype.upper()),
        _parameter_list(message),
        "NIL",
        "NIL",
        _imap_quote(encoding),
        str(len(_body_for_section(message, "TEXT"))),
    ]
    if content_type.casefold() == "text":
        fields.append(str(decoded.count(b"\n") + 1))
    fields.extend(("NIL", _disposition(message), "NIL", "NIL"))
    return "(" + " ".join(fields) + ")"


def _parameter_list(message):
    parameters = message.get_params()[1:]
    if not parameters:
        return "NIL"
    values = []
    for name, value in parameters:
        values.extend((_imap_quote(str(name).upper()), _imap_quote(str(value))))
    return "(" + " ".join(values) + ")"


def _disposition(message):
    disposition = message.get_content_disposition()
    if not disposition:
        return "NIL"
    values = []
    for name, value in message.get_params(header="content-disposition")[1:]:
        values.extend((_imap_quote(str(name).upper()), _imap_quote(str(value))))
    parameters = "(" + " ".join(values) + ")" if values else "NIL"
    return f"({_imap_quote(disposition.upper())} {parameters})"


def _body_for_section(message, section):
    if section.upper() == "TEXT":
        part = message
    else:
        part = _part_for_path(message, [int(index) for index in section.split(".")])
    if part is None:
        return b""
    payload = part.get_payload(decode=False)
    if isinstance(payload, list):
        return b""
    if isinstance(payload, bytes):
        return payload
    return str(payload or "").encode("ascii", "replace")


def _part_for_path(message, path):
    current = message
    for index in path:
        if not current.is_multipart():
            return None
        children = current.get_payload()
        if index < 1 or index > len(children):
            return None
        current = children[index - 1]
    return current


def _smtp_address(command):
    match = re.search(r"<([^>]*)>", command)
    return match.group(1) if match else command.split(":", 1)[-1].strip()


class LocalMailProtocolServer:
    def __init__(self):
        self.expected_password = "bridge-secret"
        self._lock = threading.RLock()
        self._mailboxes = {
            "INBOX": ["\\NoInferiors", "\\Inbox"],
            "Archive": ["\\NoInferiors", "\\Archive"],
            "Drafts": ["\\NoInferiors", "\\Drafts"],
            "Trash": ["\\NoInferiors", "\\Trash"],
            "Junk": ["\\NoInferiors", "\\Junk"],
            "Spam": ["\\NoInferiors", "\\Junk"],
            "Wastebasket": ["\\NoInferiors", "\\Trash"],
            "Café": ["\\NoInferiors"],
            'Archive "work"': ["\\NoInferiors"],
        }
        self._messages = {name: [] for name in self._mailboxes}
        self._next_uid = {name: 1 for name in self._mailboxes}
        self._uid_validity = {name: 1000 + index for index, name in enumerate(self._mailboxes)}
        self.uid_validity = self._uid_validity["INBOX"]
        self.default_message_id = "<fixture-1@example.test>"
        self.default_subject = "Fixture message"
        self.default_uid = None
        self._imap_server = None
        self._smtp_server = None
        self._threads = []
        self.imap_commands = []
        self.body_fetch_sections = set()
        self.move_failure = None
        self.fetch_failure_mailbox = None
        self.nil_header_fetches = 0
        self.ignored_keyword_stores = False
        self.disconnect_after_append = False
        self.move_commands = 0
        self.refused_recipients = set()
        self.disconnect_after_data = False
        self.smtp_connections = 0
        self.smtp_envelope_recipients = []
        self.smtp_message = b""
        self.smtp_submissions = []
        self.smtp_data_attempts = 0
        self.expected_username = "account@example.test"
        self.smtp_auth_attempts = 0
        self.smtp_authenticated_sessions = 0
        self.smtp_data_commands = 0

    @property
    def imap_port(self):
        return self._imap_server.server_address[1]

    @property
    def smtp_port(self):
        return self._smtp_server.server_address[1]

    def start(self):
        if self._imap_server is not None:
            return self
        fixture = EmailMessage(policy=policy.SMTP)
        fixture["From"] = "sender@example.test"
        fixture["To"] = "account@example.test"
        fixture["Date"] = "Tue, 01 Jan 2030 00:00:00 +0000"
        fixture["Subject"] = self.default_subject
        fixture["Message-ID"] = self.default_message_id
        fixture.set_content("Deterministic local fixture message.")
        if self.default_uid is None:
            self.default_uid = self.add_message("INBOX", fixture.as_bytes())
        self._imap_server = _ThreadingServer(("127.0.0.1", 0), _IMAPHandler, self)
        self._smtp_server = _ThreadingServer(("127.0.0.1", 0), _SMTPHandler, self)
        for server in (self._imap_server, self._smtp_server):
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self._threads.append(thread)
        return self

    def __enter__(self):
        return self.start()

    def __exit__(self, exception_type, exception, traceback):
        self.stop()

    def stop(self):
        for server in (self._imap_server, self._smtp_server):
            if server is not None:
                server.shutdown()
                server.server_close()
        for thread in self._threads:
            thread.join(timeout=2)
        self._threads.clear()
        self._imap_server = None
        self._smtp_server = None

    def record_imap(self, command):
        with self._lock:
            self.imap_commands.append(command)

    def record_body_fetch(self, section):
        with self._lock:
            match = re.match(r"\d+(?:\.\d+)*", section)
            self.body_fetch_sections.add(match.group(0) if match else section.upper())

    def record_smtp_connection(self):
        with self._lock:
            self.smtp_connections += 1

    def record_smtp_recipient(self, recipient):
        with self._lock:
            self.smtp_envelope_recipients.append(recipient)

    def record_smtp_data(self, data):
        with self._lock:
            self.smtp_data_attempts += 1
            self.smtp_message = data
            self.smtp_submissions.append(data)

    def record_smtp_auth(self, authenticated):
        with self._lock:
            self.smtp_auth_attempts += 1
            if authenticated:
                self.smtp_authenticated_sessions += 1

    def record_smtp_data_command(self):
        with self._lock:
            self.smtp_data_commands += 1

    def mailbox_snapshot(self):
        with self._lock:
            return [(name, list(attributes)) for name, attributes in self._mailboxes.items()]

    def has_mailbox(self, name):
        with self._lock:
            return name in self._mailboxes

    def add_mailbox(self, name, attributes=()):
        with self._lock:
            self._mailboxes[name] = list(attributes)
            self._messages.setdefault(name, [])
            self._next_uid.setdefault(name, 1)
            self._uid_validity.setdefault(name, max(self._uid_validity.values(), default=1000) + 1)

    def add_message(self, mailbox, raw, flags=()):
        with self._lock:
            uid = self._next_uid[mailbox]
            self._next_uid[mailbox] += 1
            self._messages[mailbox].append(StoredMessage(uid, raw, set(flags)))
            return uid

    def message(self, mailbox, uid):
        stored = self.find_message(mailbox, uid)
        if stored is None:
            raise KeyError(uid)
        return stored

    def find_message(self, mailbox, uid):
        with self._lock:
            return next((item for item in self._messages.get(mailbox, []) if item.uid == uid), None)

    def message_snapshot(self, mailbox):
        with self._lock:
            return list(self._messages.get(mailbox, []))

    def flags(self, mailbox, uid):
        stored = self.find_message(mailbox, uid)
        return set(stored.flags) if stored is not None else set()

    def permanent_flags(self, mailbox):
        system = ["\\Answered", "\\Flagged", "\\Deleted", "\\Seen", "\\Draft"]
        custom = ["Project_Review"]
        return system + custom

    def uid_validity_for(self, mailbox):
        return self._uid_validity[mailbox]

    def next_uid_for(self, mailbox):
        return self._next_uid[mailbox]

    def move_message(self, source, destination, uid):
        with self._lock:
            if destination not in self._messages:
                return False
            message = next((item for item in self._messages[source] if item.uid == uid), None)
            if message is None:
                return False
            if self.move_failure not in {
                "both_present",
                "both_present_source_fetch_no",
            }:
                self._messages[source].remove(message)
            new_uid = self._next_uid[destination]
            self._next_uid[destination] += 1
            self._messages[destination].append(
                StoredMessage(new_uid, message.raw, set(message.flags))
            )
            return True

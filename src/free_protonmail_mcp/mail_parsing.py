import base64
import re
import unicodedata
from dataclasses import dataclass
from html.parser import HTMLParser


@dataclass(frozen=True)
class MailboxEntry:
    name: str
    attributes: tuple[str, ...]


@dataclass(frozen=True)
class BodyPart:
    section: str
    content_type: str
    size: int
    transfer_encoding: str
    charset: str
    filename: str | None
    disposition: str | None
    attachment: bool


_LIST_PATTERN = re.compile(
    rb'^\((?P<attributes>[^)]*)\)\s+(?P<delimiter>NIL|"(?:\\.|[^"])*")\s+'
    rb'(?P<name>"(?:\\.|[^"])*"|[^\s]+)$'
)
_TOKEN_PATTERN = re.compile(r'\s*(\(|\)|"(?:\\.|[^"\\])*"|[^\s()]+)')


def encode_modified_utf7(value: str) -> str:
    encoded = []
    buffered = []

    def flush_buffer():
        if not buffered:
            return
        data = "".join(buffered).encode("utf-16-be")
        base64_value = base64.b64encode(data).decode("ascii").rstrip("=").replace("/", ",")
        encoded.append(f"&{base64_value}-")
        buffered.clear()

    for character in value:
        if " " <= character <= "~":
            flush_buffer()
            encoded.append("&-" if character == "&" else character)
        else:
            buffered.append(character)
    flush_buffer()
    return "".join(encoded)


def decode_modified_utf7(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        payload = match.group(1)
        if not payload:
            return "&"
        base64_value = payload.replace(",", "/")
        base64_value += "=" * ((4 - len(base64_value) % 4) % 4)
        try:
            return base64.b64decode(base64_value, validate=True).decode("utf-16-be")
        except (ValueError, UnicodeDecodeError):
            return match.group(0)

    return re.sub(r"&([^-]*)-", replace, value)


def quote_mailbox(value: str) -> str:
    encoded = encode_modified_utf7(value)
    return '"' + encoded.replace("\\", "\\\\").replace('"', '\\"') + '"'


def quote_search_value(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def parse_mailbox_entry(response: bytes) -> MailboxEntry | None:
    match = _LIST_PATTERN.fullmatch(response.strip())
    if match is None:
        return None
    attributes = tuple(
        value.decode("ascii", "replace") for value in match.group("attributes").split()
    )
    name = _decode_quoted(match.group("name").decode("utf-8", "replace"))
    return MailboxEntry(decode_modified_utf7(name), attributes)


def _decode_quoted(value: str) -> str:
    if not value.startswith('"') or not value.endswith('"'):
        return value
    result = []
    index = 1
    while index < len(value) - 1:
        character = value[index]
        if character == "\\" and index + 1 < len(value) - 1:
            index += 1
            character = value[index]
        result.append(character)
        index += 1
    return "".join(result)


def extract_parenthesized(data: bytes, label: bytes) -> str | None:
    start = data.upper().find(label.upper())
    if start < 0:
        return None
    start = data.find(b"(", start + len(label))
    if start < 0:
        return None
    depth = 0
    quoted = False
    escaped = False
    for index in range(start, len(data)):
        byte = data[index]
        if escaped:
            escaped = False
            continue
        if quoted and byte == 92:
            escaped = True
            continue
        if byte == 34:
            quoted = not quoted
        elif not quoted and byte == 40:
            depth += 1
        elif not quoted and byte == 41:
            depth -= 1
            if depth == 0:
                return data[start : index + 1].decode("latin-1")
    return None


def parse_imap_value(value: str):
    tokens = _TOKEN_PATTERN.findall(value)
    if not tokens:
        return None
    parsed, next_index = _parse_value(tokens, 0, 0)
    if next_index != len(tokens):
        raise ValueError("Invalid IMAP value")
    return parsed


def _parse_value(tokens: list[str], index: int, depth: int):
    if depth > 32 or index >= len(tokens):
        raise ValueError("Invalid IMAP value")
    token = tokens[index]
    if token != "(":
        return _parse_atom(token), index + 1
    values = []
    index += 1
    while index < len(tokens) and tokens[index] != ")":
        child, index = _parse_value(tokens, index, depth + 1)
        values.append(child)
    if index >= len(tokens):
        raise ValueError("Invalid IMAP value")
    return values, index + 1


def _parse_atom(token: str):
    if token.startswith('"') and token.endswith('"'):
        return _decode_quoted(token)
    if token.casefold() == "nil":
        return None
    return token


def parse_body_parts(structure: str) -> list[BodyPart]:
    tree = parse_imap_value(structure)
    if not isinstance(tree, list):
        return []
    if _is_multipart(tree):
        attachment = _multipart_attachment(tree, "TEXT")
        if attachment is not None:
            return [attachment]
        parts = []
        child_index = 0
        while child_index < len(tree) and isinstance(tree[child_index], list):
            parts.extend(_collect_body_parts(tree[child_index], str(child_index + 1)))
            child_index += 1
        return parts
    return _collect_body_parts(tree, "TEXT")


def _is_multipart(node: list) -> bool:
    return bool(node) and isinstance(node[0], list)


def _collect_body_parts(node: list, section: str) -> list[BodyPart]:
    if _is_multipart(node):
        attachment = _multipart_attachment(node, section)
        if attachment is not None:
            return [attachment]
        parts = []
        child_index = 0
        while child_index < len(node) and isinstance(node[child_index], list):
            child_section = f"{section}.{child_index + 1}"
            parts.extend(_collect_body_parts(node[child_index], child_section))
            child_index += 1
        return parts
    part = _leaf_body_part(node, section)
    return [part] if part is not None else []


def _multipart_attachment(node: list, section: str) -> BodyPart | None:
    child_index = 0
    while child_index < len(node) and isinstance(node[child_index], list):
        child_index += 1
    if child_index >= len(node) or not isinstance(node[child_index], str):
        return None
    subtype = node[child_index].casefold()
    parameters_index = child_index + 1
    parameters = _parameter_map(node[parameters_index]) if parameters_index < len(node) else {}
    disposition_index = child_index + 2
    disposition_value = node[disposition_index] if disposition_index < len(node) else None
    disposition = None
    disposition_parameters = {}
    if isinstance(disposition_value, list) and disposition_value:
        disposition = str(disposition_value[0]).casefold()
        if len(disposition_value) > 1:
            disposition_parameters = _parameter_map(disposition_value[1])
    filename = disposition_parameters.get("filename") or parameters.get("name")
    if disposition != "attachment" and filename is None:
        return None
    return BodyPart(
        section=section,
        content_type=f"multipart/{subtype}",
        size=0,
        transfer_encoding="7bit",
        charset=parameters.get("charset", "utf-8"),
        filename=filename,
        disposition=disposition,
        attachment=True,
    )


def _leaf_body_part(node: list, section: str) -> BodyPart | None:
    if len(node) < 7 or not isinstance(node[0], str) or not isinstance(node[1], str):
        return None
    content_type = f"{node[0]}/{node[1]}".casefold()
    parameters = _parameter_map(node[2])
    transfer_encoding = str(node[5] or "7bit").casefold()
    try:
        size = max(0, int(node[6]))
    except (TypeError, ValueError):
        size = 0
    extension_index = 8 if node[0].casefold() == "text" else 7
    if content_type == "message/rfc822":
        extension_index = 10
    disposition_value = node[extension_index + 1] if len(node) > extension_index + 1 else None
    disposition = None
    disposition_parameters = {}
    if isinstance(disposition_value, list) and disposition_value:
        disposition = str(disposition_value[0]).casefold()
        if len(disposition_value) > 1:
            disposition_parameters = _parameter_map(disposition_value[1])
    filename = disposition_parameters.get("filename") or parameters.get("name")
    attachment = (
        disposition == "attachment"
        or filename is not None
        or content_type == "message/rfc822"
        or not content_type.startswith("text/")
    )
    return BodyPart(
        section=section,
        content_type=content_type,
        size=size,
        transfer_encoding=transfer_encoding,
        charset=parameters.get("charset", "utf-8"),
        filename=filename,
        disposition=disposition,
        attachment=attachment,
    )


def _parameter_map(value) -> dict[str, str]:
    if not isinstance(value, list):
        return {}
    result = {}
    for index in range(0, len(value) - 1, 2):
        if value[index] is not None and value[index + 1] is not None:
            result[str(value[index]).casefold()] = str(value[index + 1])
    return result


def safe_text(value: str, keep_newlines: bool = False) -> str:
    cleaned = []
    for character in value:
        if character in "\r\n\t" and keep_newlines:
            cleaned.append(character)
            continue
        if unicodedata.category(character) in {"Cc", "Cf", "Cs"}:
            continue
        cleaned.append(character)
    return "".join(cleaned)


class _HTMLTextParser(HTMLParser):
    _BLOCK_ELEMENTS = {"br", "div", "li", "p", "section", "tr"}
    _HIDDEN_ELEMENTS = {"head", "script", "style"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.hidden_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag in self._HIDDEN_ELEMENTS:
            self.hidden_depth += 1
        elif self.hidden_depth == 0 and tag in self._BLOCK_ELEMENTS:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in self._HIDDEN_ELEMENTS and self.hidden_depth:
            self.hidden_depth -= 1
        elif self.hidden_depth == 0 and tag in self._BLOCK_ELEMENTS:
            self.parts.append("\n")

    def handle_data(self, data):
        if self.hidden_depth == 0:
            self.parts.append(data)


def html_to_text(value: str) -> str:
    parser = _HTMLTextParser()
    parser.feed(value)
    parser.close()
    return safe_text("".join(parser.parts), keep_newlines=True).strip()

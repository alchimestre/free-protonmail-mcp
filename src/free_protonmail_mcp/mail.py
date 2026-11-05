import base64
import hashlib
import imaplib
import json
import quopri
import re
import smtplib
import time
import uuid
from contextlib import contextmanager
from email import policy
from email.header import decode_header, make_header
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses

from free_protonmail_mcp.mail_parsing import (
    BodyPart,
    extract_parenthesized,
    html_to_text,
    parse_body_parts,
    parse_mailbox_entry,
    quote_mailbox,
    quote_search_value,
    safe_text,
)
from free_protonmail_mcp.models import (
    AccountConfig,
    MailError,
    MessageRef,
    OutgoingMessage,
    SearchQuery,
)

MAX_SEARCH_RESULTS = 100
MAX_HEADER_BYTES = 65536
MAX_TEXT_BYTES = 131072
DRAFT_SCAN_LIMIT = 5
HEADER_FETCH_ITEMS = (
    "(BODY.PEEK[HEADER.FIELDS ({fields})]<0.{limit}>)",
    "(BODY.PEEK[HEADER]<0.{limit}>)",
    "(RFC822.HEADER)",
)
SETTLE_ATTEMPTS = 7
SETTLE_DELAY_SECONDS = 2.0
SYSTEM_FLAGS = {
    "\\answered",
    "\\deleted",
    "\\draft",
    "\\flagged",
    "\\recent",
    "\\seen",
}
PROTECTED_MAILBOX_NAMES = {"trash", "junk", "spam"}
PROTECTED_MAILBOX_ATTRIBUTES = {"\\trash", "\\junk", "\\spam"}


def _transport_reason(error, connected):
    if connected:
        return "connection_lost"
    if isinstance(error, ConnectionRefusedError):
        return "connection_refused"
    if isinstance(error, TimeoutError):
        return "timed_out"
    if isinstance(error, imaplib.IMAP4.error):
        return "protocol_error"
    return "network_error"


class MailClient:
    def __init__(self, config: AccountConfig, password):
        self.config = config
        self.password = password

    @contextmanager
    def _imap(self):
        connection = None
        connected = False
        endpoint = f"{self.config.host}:{self.config.imap_port}"
        try:
            connection = imaplib.IMAP4(
                self.config.host,
                self.config.imap_port,
                timeout=self.config.timeout,
            )
            try:
                password = self.password()
            except Exception as error:
                raise MailError(
                    "credential_unavailable",
                    "The stored Hydroxide credential is unavailable.",
                ) from error
            try:
                connection.login(self.config.username, password)
            except (imaplib.IMAP4.error, OSError, TimeoutError) as error:
                raise MailError("authentication_failed", "IMAP authentication failed.") from error
            connected = True
            yield connection
        except MailError:
            raise
        except (imaplib.IMAP4.error, OSError, TimeoutError) as error:
            raise MailError(
                "imap_unavailable",
                "The local IMAP service did not complete the operation.",
                {"endpoint": endpoint, "reason": _transport_reason(error, connected)},
            ) from error
        finally:
            if connection is not None:
                self._logout(connection)

    @staticmethod
    def _logout(connection):
        try:
            connection.logout()
        except (imaplib.IMAP4.error, OSError, TimeoutError):
            try:
                connection.shutdown()
            except OSError:
                pass

    @staticmethod
    def _check_status(status, operation):
        if str(status).upper() != "OK":
            raise MailError("imap_operation_failed", f"IMAP {operation} failed.")

    def _select(self, connection, mailbox, readonly):
        status, _ = connection.select(quote_mailbox(mailbox), readonly=readonly)
        self._check_status(status, "mailbox selection")
        _, values = connection.response("UIDVALIDITY")
        validity = _first_number(values)
        if validity is None:
            raise MailError("invalid_mailbox_state", "The mailbox did not provide UIDVALIDITY.")
        return validity

    def health(self):
        with self._imap() as connection:
            status, response = connection.capability()
            self._check_status(status, "capability check")
        capabilities = sorted(
            {
                value.decode("ascii", "replace").upper()
                for entry in response or []
                for value in entry.split()
            }
        )
        return {
            "status": "ok",
            "imap": "connected",
            "smtp": "not_checked",
            "capabilities": capabilities,
        }

    def list_mailboxes(self):
        with self._imap() as connection:
            status, responses = connection.list()
            self._check_status(status, "mailbox listing")
        entries = []
        for response in responses or []:
            if not isinstance(response, bytes):
                continue
            entry = parse_mailbox_entry(response)
            if entry is not None:
                entries.append({"name": entry.name, "attributes": list(entry.attributes)})
        return sorted(entries, key=lambda entry: entry["name"].casefold())

    def list_labels(self, mailbox="INBOX"):
        with self._imap() as connection:
            self._select(connection, mailbox, readonly=True)
            _, response = connection.response("PERMANENTFLAGS")
        response_text = b" ".join(
            value if isinstance(value, bytes) else str(value).encode("ascii", "replace")
            for value in response or []
        ).decode("ascii", "replace")
        match = re.search(r"\(([^)]*)\)", response_text)
        if match is None:
            return []
        return sorted(
            {flag for flag in match.group(1).split() if _is_custom_keyword(flag)},
            key=str.casefold,
        )

    def search(self, mailbox: str, query: SearchQuery):
        if query.before_uid == 1:
            return {"messages": [], "cursor": None}
        with self._imap() as connection:
            uid_validity = self._select(connection, mailbox, readonly=True)
            criteria = ["ALL"]
            if query.unread is True:
                criteria.append("UNSEEN")
            elif query.unread is False:
                criteria.append("SEEN")
            if query.sender is not None:
                criteria.extend(("FROM", quote_search_value(query.sender)))
            if query.subject is not None:
                criteria.extend(("SUBJECT", quote_search_value(query.subject)))
            if query.before_uid is not None:
                criteria.extend(("UID", f"1:{query.before_uid - 1}"))
            status, response = connection.uid("SEARCH", *criteria)
            self._check_status(status, "message search")
            uids = _search_uids(response)
            selected_uids = sorted(set(uids), reverse=True)[: min(query.limit, MAX_SEARCH_RESULTS)]
            messages = []
            for uid in selected_uids:
                reference, header, metadata = self._read_reference(
                    connection,
                    mailbox,
                    uid_validity,
                    uid,
                    None,
                    require_message_id=False,
                )
                messages.append(_public_metadata(reference, header, metadata))
        cursor = None
        if len(set(uids)) > len(selected_uids) and selected_uids:
            cursor = {"before_uid": min(selected_uids)}
        return {"messages": messages, "cursor": cursor}

    def read_message(self, ref: MessageRef):
        return self._read_message(ref, MAX_TEXT_BYTES)

    def _read_message(self, ref, text_limit):
        with self._imap() as connection:
            uid_validity = self._select(connection, ref.mailbox, readonly=True)
            reference, header, metadata = self._read_reference(
                connection,
                ref.mailbox,
                uid_validity,
                ref.uid,
                ref.message_id,
                require_message_id=False,
                expected_uid_validity=ref.uid_validity,
                include_structure=True,
            )
            if not metadata["structure"]:
                raise MailError(
                    "message_body_unavailable",
                    "The IMAP server did not provide a supported message body.",
                )
            body, attachments, truncated = self._read_text_parts(
                connection,
                ref.uid,
                metadata["structure"],
                text_limit,
            )
        result = _public_metadata(reference, header, metadata)
        result.update({"body": body, "attachments": attachments, "truncated": truncated})
        return result

    def describe_headers(self, refs):
        previews = []
        with self._imap() as connection:
            selected = None
            uid_validity = None
            for ref in refs:
                if ref.mailbox != selected:
                    uid_validity = self._select(connection, ref.mailbox, readonly=True)
                    selected = ref.mailbox
                reference, header, metadata = self._read_reference(
                    connection,
                    ref.mailbox,
                    uid_validity,
                    ref.uid,
                    ref.message_id,
                    require_message_id=False,
                    expected_uid_validity=ref.uid_validity,
                )
                message = _public_metadata(reference, header, metadata)
                previews.append(
                    {
                        "ref": message["ref"],
                        "message_id": message["message_id"],
                        "subject": message["subject"],
                        "from": message["from"],
                        "to": message["to"],
                        "date": message["date"],
                    }
                )
        return previews

    def _read_reference(
        self,
        connection,
        mailbox,
        uid_validity,
        uid,
        expected_message_id,
        require_message_id,
        include_structure=False,
        expected_uid_validity=None,
    ):
        if expected_uid_validity is not None and uid_validity != expected_uid_validity:
            raise MailError(
                "stale_reference",
                "The mailbox UIDVALIDITY no longer matches the reference.",
            )
        metadata = self._fetch_metadata(connection, uid, include_structure)
        if metadata is None:
            raise MailError("message_not_found", "The referenced message is not present.")
        header = self._fetch_header(connection, uid)
        message_id = _header_value(header, "Message-ID")
        if require_message_id and expected_message_id is None:
            raise MailError(
                "message_identity_required",
                "A Message-ID is required for this operation.",
            )
        if expected_message_id is not None and message_id != expected_message_id:
            raise MailError(
                "identity_mismatch",
                "The UID no longer identifies the referenced message.",
            )
        reference = MessageRef(
            mailbox=mailbox,
            uid_validity=uid_validity,
            uid=uid,
            message_id=message_id,
        )
        return reference, header, metadata

    def _fetch_metadata(self, connection, uid, include_structure=False):
        items = (
            "(UID FLAGS RFC822.SIZE BODYSTRUCTURE)"
            if include_structure
            else "(UID FLAGS RFC822.SIZE)"
        )
        status, response = connection.uid("FETCH", str(uid), items)
        self._check_status(status, "message metadata fetch")
        data = _response_bytes(response)
        if not re.search(rb"\bUID\s+" + str(uid).encode("ascii") + rb"\b", data):
            return None
        flags_match = re.search(rb"\bFLAGS\s+\(([^)]*)\)", data, re.IGNORECASE)
        flags = set()
        if flags_match:
            flags = set(flags_match.group(1).decode("ascii", "replace").split())
        size_match = re.search(rb"\bRFC822\.SIZE\s+(\d+)", data, re.IGNORECASE)
        structure_value = (
            extract_parenthesized(data, b"BODYSTRUCTURE") if include_structure else None
        )
        structure = None
        if structure_value is not None:
            try:
                structure = parse_body_parts(structure_value)
            except ValueError:
                structure = None
        return {
            "flags": flags,
            "size": int(size_match.group(1)) if size_match else None,
            "structure": structure or [],
        }

    def _fetch_header(self, connection, uid):
        fields = "SUBJECT FROM TO CC BCC DATE MESSAGE-ID"
        for attempt in range(SETTLE_ATTEMPTS):
            for template in HEADER_FETCH_ITEMS:
                item = template.format(fields=fields, limit=MAX_HEADER_BYTES)
                status, response = connection.uid("FETCH", str(uid), item)
                self._check_status(status, "message header fetch")
                literal = _response_literal(response)
                if literal is not None:
                    return BytesParser(policy=policy.default).parsebytes(literal[:MAX_HEADER_BYTES])
            if attempt + 1 < SETTLE_ATTEMPTS:
                time.sleep(SETTLE_DELAY_SECONDS)
        # Hydroxide answers NIL for a section it cannot produce yet, so the message
        # exists but its headers are not readable; do not report it as missing.
        raise MailError(
            "message_unavailable",
            "The local IMAP server did not return this message's headers; "
            "the mailbox may still be syncing. Retry the read.",
        )

    def _read_text_parts(self, connection, uid, parts, text_limit=MAX_TEXT_BYTES):
        attachments = [_attachment_metadata(part) for part in parts if part.attachment]
        plain_parts = [
            part for part in parts if part.content_type == "text/plain" and not part.attachment
        ]
        selected_parts = (
            plain_parts
            or [part for part in parts if part.content_type == "text/html" and not part.attachment][
                :1
            ]
        )
        remaining = text_limit
        body_parts = []
        truncated = False
        for part in selected_parts:
            if remaining <= 0:
                truncated = True
                break
            requested = min(part.size, remaining) if part.size else remaining
            data = self._fetch_text_part(connection, uid, part, requested)
            if len(data) > requested:
                data = data[:requested]
            truncated = truncated or (
                len(data) >= requested and (part.size > requested or requested == remaining)
            )
            decoded = _decode_part(data, part)
            if part.content_type == "text/html":
                body_parts.append(html_to_text(decoded))
            else:
                body_parts.append(decoded)
            remaining -= len(data)
        return "\n\n".join(body_parts), attachments, truncated

    def _fetch_text_part(self, connection, uid, part: BodyPart, limit):
        section = f"BODY.PEEK[{part.section}]<0.{limit}>"
        status, response = connection.uid("FETCH", str(uid), f"({section})")
        self._check_status(status, "message body fetch")
        literal = _response_literal(response)
        if literal is None:
            raise MailError(
                "message_body_unavailable",
                "The IMAP server did not return the selected text body.",
            )
        return literal[:limit]

    def set_read(self, ref: MessageRef, read: bool):
        return self._set_flag(ref, "\\Seen", read)

    def set_label(self, ref: MessageRef, keyword: str, present: bool):
        if not _is_custom_keyword(keyword):
            raise MailError("invalid_label", "Only discovered custom labels can be changed.")
        labels = self.list_labels(ref.mailbox)
        if keyword not in labels:
            raise MailError("invalid_label", "Only discovered custom labels can be changed.")
        return self._set_flag(ref, keyword, present)

    def _set_flag(self, ref, flag, present):
        initially_present, store_succeeded = self._store_flag(ref, flag, present)
        try:
            current_flags = self._reference_flags(ref)
        except MailError as error:
            raise MailError(
                "mutation_uncertain",
                "The flag mutation could not be verified in a fresh connection.",
                uncertain=True,
            ) from error
        is_present = flag.casefold() in {value.casefold() for value in current_flags}
        if is_present != present:
            if store_succeeded and is_present == initially_present:
                raise MailError(
                    "label_unsupported",
                    "The local IMAP server accepted the keyword but did not store it; "
                    "labels cannot be changed on this server.",
                )
            raise MailError(
                "mutation_failed",
                "The requested flag state was not verified.",
                {"flag_present": is_present, "store_succeeded": store_succeeded},
                uncertain=is_present != initially_present,
            )
        if flag.casefold() == "\\seen":
            return {"ref": ref.model_dump(mode="json"), "read": present, "verified": True}
        return {
            "ref": ref.model_dump(mode="json"),
            "label": flag,
            "present": present,
            "verified": True,
        }

    def _store_flag(self, ref, flag, present):
        attempted = False
        initially_present = False
        store_succeeded = False
        try:
            with self._imap() as connection:
                uid_validity = self._select(connection, ref.mailbox, readonly=False)
                _, _, initial = self._read_reference(
                    connection,
                    ref.mailbox,
                    uid_validity,
                    ref.uid,
                    ref.message_id,
                    require_message_id=True,
                    expected_uid_validity=ref.uid_validity,
                )
                initially_present = flag.casefold() in {
                    value.casefold() for value in initial["flags"]
                }
                command = "+FLAGS.SILENT" if present else "-FLAGS.SILENT"
                attempted = True
                try:
                    status, _ = connection.uid("STORE", str(ref.uid), command, f"({flag})")
                    store_succeeded = str(status).upper() == "OK"
                except (imaplib.IMAP4.error, OSError, TimeoutError):
                    store_succeeded = False
        except MailError:
            if not attempted:
                raise
        return initially_present, store_succeeded

    def _reference_flags(self, ref):
        with self._imap() as connection:
            uid_validity = self._select(connection, ref.mailbox, readonly=True)
            _, _, metadata = self._read_reference(
                connection,
                ref.mailbox,
                uid_validity,
                ref.uid,
                ref.message_id,
                require_message_id=True,
                expected_uid_validity=ref.uid_validity,
            )
            return metadata["flags"]

    def move(self, ref: MessageRef, destination: str, allow_trash: bool = False):
        source_entry, destination_entry = self._move_mailboxes(ref, destination, allow_trash)
        protocol_succeeded = self._move_once(ref, source_entry, destination_entry)
        return self._verify_move(ref, source_entry, destination_entry, protocol_succeeded)

    def _move_mailboxes(self, ref, destination, allow_trash):
        entries = self.list_mailboxes()
        source_entry = _find_mailbox(entries, ref.mailbox)
        destination_entry = _find_mailbox(entries, destination)
        if source_entry is None or destination_entry is None:
            raise MailError(
                "mailbox_not_found",
                "The source or destination mailbox is unavailable.",
            )
        if source_entry["name"].casefold() == destination_entry["name"].casefold():
            raise MailError(
                "invalid_destination",
                "The source and destination mailboxes must differ.",
            )
        if _is_protected(destination_entry) and not _is_approved_trash(
            destination_entry,
            destination,
            allow_trash,
        ):
            raise MailError(
                "protected_destination",
                "Moving to Trash, Junk, or Spam requires the internal approval path.",
            )
        if _is_junk_or_spam(destination_entry):
            raise MailError("protected_destination", "Moving to Junk or Spam is unavailable.")
        return source_entry, destination_entry

    def _move_once(self, ref, source_entry, destination_entry):
        attempted = False
        try:
            with self._imap() as connection:
                uid_validity = self._select(connection, source_entry["name"], readonly=False)
                self._read_reference(
                    connection,
                    source_entry["name"],
                    uid_validity,
                    ref.uid,
                    ref.message_id,
                    require_message_id=True,
                    expected_uid_validity=ref.uid_validity,
                )
                status, response = connection.capability()
                self._check_status(status, "capability check")
                if "MOVE" not in _capability_set(response):
                    raise MailError(
                        "move_unsupported",
                        "The local IMAP service does not advertise UID MOVE.",
                    )
                attempted = True
                status, _ = connection.uid(
                    "MOVE",
                    str(ref.uid),
                    quote_mailbox(destination_entry["name"]),
                )
                return str(status).upper() == "OK"
        except MailError:
            if not attempted:
                raise
            return False

    def _verify_move(self, ref, source_entry, destination_entry, protocol_succeeded):
        source_present, _ = self._inspect_message(source_entry["name"], ref.message_id)
        destination_present, destination_ref = self._inspect_message(
            destination_entry["name"],
            ref.message_id,
        )
        if source_present is False and destination_present is True and destination_ref is not None:
            return {
                "moved": True,
                "ref": destination_ref.model_dump(mode="json"),
                "source_present": False,
                "destination_present": True,
            }
        details = {
            "source_present": source_present,
            "destination_present": destination_present,
            "destination_ref": destination_ref.model_dump(mode="json") if destination_ref else None,
            "protocol_succeeded": protocol_succeeded,
        }
        if source_present is True and destination_present is False:
            raise MailError(
                "move_failed",
                "The message remains in the source mailbox; no retry was attempted.",
                details,
            )
        raise MailError(
            "move_uncertain",
            "The move did not reach a verified destination state. No retry was attempted.",
            details,
            uncertain=True,
        )

    def _inspect_message(self, mailbox, message_id):
        try:
            with self._imap() as connection:
                uid_validity = self._select(connection, mailbox, readonly=True)
                uids = self._search_message_id(connection, message_id)
                found = []
                for uid in uids:
                    try:
                        reference, _, _ = self._read_reference(
                            connection,
                            mailbox,
                            uid_validity,
                            uid,
                            message_id,
                            require_message_id=True,
                        )
                    except MailError as error:
                        if error.code == "identity_mismatch":
                            continue
                        return None, None
                    found.append(reference)
            return bool(found), found[0] if len(found) == 1 else None
        except MailError:
            return None, None

    def _search_message_id(self, connection, message_id):
        status, response = connection.uid(
            "SEARCH",
            "HEADER",
            "MESSAGE-ID",
            quote_search_value(message_id),
        )
        self._check_status(status, "message identity search")
        return _search_uids(response)

    def create_draft(self, message: OutgoingMessage):
        draft_id = f"<draft-{uuid.uuid4().hex}@free-protonmail-mcp.invalid>"
        mime_message = _build_mime_message(
            self.config.sender,
            message,
            draft_id,
            include_bcc=True,
        )
        draft_mailbox = self._draft_mailbox()
        mime_bytes = mime_message.as_bytes(policy=policy.SMTP)
        self._append_draft(draft_mailbox, mime_bytes)
        reference = self._find_appended_draft(draft_mailbox, message, len(mime_bytes))
        return {
            "ref": reference.model_dump(mode="json"),
            "message_id": reference.message_id,
            "draft": True,
            "verified": True,
        }

    def _draft_mailbox(self):
        draft_mailbox = next(
            (
                entry["name"]
                for entry in self.list_mailboxes()
                if entry["name"].casefold() == "drafts"
            ),
            None,
        )
        if draft_mailbox is None:
            raise MailError("drafts_unavailable", "The Drafts mailbox is unavailable.")
        return draft_mailbox

    def _append_draft(self, draft_mailbox, mime_bytes):
        append_attempted = False
        try:
            with self._imap() as connection:
                self._select(connection, draft_mailbox, readonly=False)
                append_attempted = True
                status, _ = connection.append(
                    quote_mailbox(draft_mailbox),
                    "(\\Draft)",
                    None,
                    mime_bytes,
                )
                self._check_status(status, "draft append")
        except MailError:
            if not append_attempted:
                raise

    def _find_appended_draft(self, draft_mailbox, message, text_limit):
        for attempt in range(SETTLE_ATTEMPTS):
            try:
                matches = self._match_recent_drafts(draft_mailbox, message, text_limit)
            except MailError as error:
                if error.code != "message_unavailable":
                    raise self._draft_inspection_error() from error
                matches = []
            if len(matches) == 1:
                return matches[0]
            if len(matches) > 1:
                raise MailError(
                    "draft_uncertain",
                    "The appended draft could not be identified exactly once; "
                    "no retry or deletion was attempted.",
                    {"matching_messages": len(matches)},
                    uncertain=True,
                )
            if attempt + 1 == SETTLE_ATTEMPTS:
                break
            time.sleep(SETTLE_DELAY_SECONDS)
        raise MailError(
            "draft_uncertain",
            "The appended draft could not be identified exactly once; "
            "no retry or deletion was attempted.",
            {"matching_messages": 0},
            uncertain=True,
        )

    def _match_recent_drafts(self, draft_mailbox, message, text_limit):
        with self._imap() as connection:
            uid_validity = self._select(connection, draft_mailbox, readonly=True)
            status, response = connection.uid("SEARCH", "ALL")
            self._check_status(status, "draft listing")
            recent_uids = _search_uids(response)[-DRAFT_SCAN_LIMIT:]
            matches = []
            for uid in recent_uids:
                try:
                    reference, header, _ = self._read_reference(
                        connection,
                        draft_mailbox,
                        uid_validity,
                        uid,
                        None,
                        False,
                    )
                    if not _draft_headers_match(header, message):
                        continue
                    if _draft_matches(self._read_message(reference, text_limit), message):
                        matches.append(reference)
                except MailError as error:
                    if error.code == "message_unavailable":
                        raise
            return matches

    @staticmethod
    def _draft_inspection_error():
        return MailError(
            "draft_uncertain",
            "The draft could not be inspected after APPEND; no retry or deletion was attempted.",
            uncertain=True,
        )

    def _inspect_message_refs(self, mailbox, message_id):
        with self._imap() as connection:
            uid_validity = self._select(connection, mailbox, readonly=True)
            uids = self._search_message_id(connection, message_id)
            references = []
            for uid in uids:
                try:
                    reference, _, _ = self._read_reference(
                        connection,
                        mailbox,
                        uid_validity,
                        uid,
                        message_id,
                        require_message_id=True,
                    )
                except MailError:
                    continue
                references.append(reference)
            return references

    def send(self, message: OutgoingMessage):
        message_id = _deterministic_message_id(self.config.sender, message)
        mime_message = _build_mime_message(
            self.config.sender,
            message,
            message_id,
            include_bcc=False,
        )
        recipients = list(message.to + message.cc + message.bcc)
        connection = self._open_smtp()
        refused = self._submit_message(connection, message_id, recipients, mime_message)
        return self._submission_result(message_id, recipients, refused)

    def _open_smtp(self):
        try:
            return smtplib.SMTP(
                self.config.host,
                self.config.smtp_port,
                timeout=self.config.timeout,
            )
        except (OSError, smtplib.SMTPException, TimeoutError) as error:
            raise MailError(
                "smtp_unavailable",
                "The local SMTP service is unavailable.",
            ) from error

    def _authenticate_smtp(self, connection):
        try:
            password = self.password()
        except Exception as error:
            raise MailError(
                "credential_unavailable",
                "The configured bridge credential is unavailable.",
            ) from error
        try:
            connection.login(self.config.username, password)
        except smtplib.SMTPAuthenticationError as error:
            raise MailError(
                "authentication_failed",
                "SMTP authentication failed.",
            ) from error
        except (smtplib.SMTPException, OSError, TimeoutError) as error:
            raise MailError(
                "smtp_authentication_failed",
                "SMTP authentication failed.",
            ) from error

    def _submit_message(self, connection, message_id, recipients, mime_message):
        try:
            self._authenticate_smtp(connection)
            return connection.sendmail(
                self.config.sender,
                recipients,
                mime_message.as_bytes(policy=policy.SMTP),
            )
        except smtplib.SMTPRecipientsRefused as error:
            raise MailError(
                "recipients_refused",
                "The SMTP service refused all recipients.",
                {"accepted_count": 0, "refused_count": len(error.recipients)},
            ) from error
        except (smtplib.SMTPSenderRefused, smtplib.SMTPDataError) as error:
            raise MailError(
                "submission_rejected",
                "The SMTP service rejected the submission.",
            ) from error
        except (OSError, smtplib.SMTPException, TimeoutError) as error:
            raise MailError(
                "send_uncertain",
                "The SMTP submission outcome is unknown. Do not retry automatically.",
                {"message_id": message_id},
                uncertain=True,
            ) from error
        finally:
            try:
                connection.quit()
            except (OSError, smtplib.SMTPException, TimeoutError):
                pass

    def _submission_result(self, message_id, recipients, refused):
        refused_count = len(refused)
        accepted_count = len(recipients) - refused_count
        if refused_count:
            return {
                "status": "partial",
                "accepted_count": accepted_count,
                "refused_count": refused_count,
                "message_id": message_id,
                "uncertain": True,
                "existing_draft_removed": False,
            }
        return {
            "status": "sent",
            "accepted_count": accepted_count,
            "refused_count": 0,
            "message_id": message_id,
            "uncertain": False,
            "existing_draft_removed": False,
        }


def _first_number(values):
    for value in values or []:
        match = re.search(
            rb"\d+",
            value if isinstance(value, bytes) else str(value).encode("ascii", "ignore"),
        )
        if match:
            return int(match.group(0))
    return None


def _response_bytes(response):
    values = []
    for item in response or []:
        if isinstance(item, bytes):
            values.append(item)
        elif isinstance(item, tuple) and item and isinstance(item[0], bytes):
            values.append(item[0])
    return b" ".join(values)


def _response_literal(response):
    for item in response or []:
        if isinstance(item, tuple) and len(item) == 2 and isinstance(item[1], bytes):
            return item[1]
    return None


def _search_uids(response):
    uids = []
    for item in response or []:
        if not isinstance(item, bytes):
            continue
        for value in re.findall(rb"\d+", item):
            try:
                uids.append(int(value))
            except ValueError:
                continue
    return uids


def _capability_set(response):
    return {
        value.decode("ascii", "replace").upper()
        for item in response or []
        if isinstance(item, bytes)
        for value in item.split()
    }


def _is_custom_keyword(value):
    if not value or value.casefold() in SYSTEM_FLAGS or value == "\\*":
        return False
    return all(33 <= ord(character) <= 126 and character not in '(){%*"\\]' for character in value)


def _public_metadata(reference, header, metadata):
    return {
        "ref": reference.model_dump(mode="json"),
        "message_id": reference.message_id,
        "subject": _header_value(header, "Subject"),
        "from": _header_addresses(header, "From"),
        "to": _header_addresses(header, "To"),
        "cc": _header_addresses(header, "Cc"),
        "bcc": _header_addresses(header, "Bcc"),
        "date": _header_value(header, "Date"),
        "size": metadata["size"],
        "unread": "\\seen" not in {flag.casefold() for flag in metadata["flags"]},
        "flags": sorted(metadata["flags"], key=str.casefold),
    }


def _header_value(header, name):
    value = header.get(name)
    if value is None:
        return None
    try:
        decoded = str(make_header(decode_header(str(value))))
    except (LookupError, UnicodeError, ValueError):
        decoded = str(value)
    return safe_text(decoded).strip()


def _header_addresses(header, name):
    raw_values = header.get_all(name, [])
    addresses = []
    for _, address in getaddresses([str(value) for value in raw_values]):
        cleaned = safe_text(address).strip()
        if cleaned:
            addresses.append(cleaned)
    return addresses


def _header_addresses_from_result(message):
    return {name: list(message.get(name, [])) for name in ("to", "cc", "bcc")}


def _draft_headers_match(header, message):
    if safe_text(header.get("Subject") or "") != message.subject:
        return False
    return all(
        {value.casefold() for value in _header_addresses(header, name)}
        == {value.casefold() for value in getattr(message, name)}
        for name in ("to", "cc", "bcc")
    )


def _draft_matches(verified, message):
    recipients = _header_addresses_from_result(verified)
    actual_body = verified["body"].replace("\r\n", "\n").replace("\r", "\n")
    draft_flag = "\\draft" in {flag.casefold() for flag in verified["flags"]}
    expected_recipients = {
        name: {value.casefold() for value in getattr(message, name)} for name in ("to", "cc", "bcc")
    }
    return (
        verified["subject"] == message.subject
        and all(
            {value.casefold() for value in recipients[name]} == expected_recipients[name]
            for name in ("to", "cc", "bcc")
        )
        # Proton re-serialises the draft and drops the trailing newline it received.
        and actual_body.rstrip("\n") == _expected_body(message.body).rstrip("\n")
        and draft_flag
    )


def _attachment_metadata(part: BodyPart):
    return {
        "filename": safe_text(part.filename or "").strip() or None,
        "content_type": safe_text(part.content_type).strip(),
        "size": part.size,
        "disposition": safe_text(part.disposition or "attachment").strip(),
    }


def _decode_part(data, part):
    try:
        if part.transfer_encoding == "base64":
            data += b"=" * ((4 - len(data) % 4) % 4)
            data = base64.b64decode(data, validate=False)
        elif part.transfer_encoding == "quoted-printable":
            data = quopri.decodestring(data)
    except (ValueError, base64.binascii.Error):
        data = b""
    try:
        text = data.decode(part.charset or "utf-8", "replace")
    except LookupError:
        text = data.decode("utf-8", "replace")
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    return safe_text(normalized, keep_newlines=True)


def _find_mailbox(entries, name):
    folded = name.casefold()
    return next((entry for entry in entries if entry["name"].casefold() == folded), None)


def _is_protected(entry):
    name = entry["name"].casefold()
    attributes = {value.casefold() for value in entry["attributes"]}
    return name in PROTECTED_MAILBOX_NAMES or bool(attributes & PROTECTED_MAILBOX_ATTRIBUTES)


def _is_junk_or_spam(entry):
    name = entry["name"].casefold()
    attributes = {value.casefold() for value in entry["attributes"]}
    return name in {"junk", "spam"} or "\\junk" in attributes or "\\spam" in attributes


def _is_approved_trash(entry, destination, allow_trash):
    if not allow_trash or destination != "Trash" or entry["name"] != "Trash":
        return False
    return "\\trash" in {value.casefold() for value in entry["attributes"]}


def _expected_body(body):
    normalized = body.replace("\r\n", "\n").replace("\r", "\n")
    return normalized if normalized.endswith("\n") else normalized + "\n"


def _build_mime_message(sender, outgoing, message_id, include_bcc):
    message = EmailMessage(policy=policy.SMTP)
    message["From"] = sender
    message["To"] = ", ".join(outgoing.to)
    if outgoing.cc:
        message["Cc"] = ", ".join(outgoing.cc)
    if include_bcc and outgoing.bcc:
        message["Bcc"] = ", ".join(outgoing.bcc)
    message["Subject"] = outgoing.subject
    message["Message-ID"] = message_id
    message.set_content(outgoing.body, subtype="plain", charset="utf-8")
    return message


def _deterministic_message_id(sender, outgoing):
    payload = {
        "sender": sender,
        "to": outgoing.to,
        "cc": outgoing.cc,
        "bcc": outgoing.bcc,
        "subject": outgoing.subject,
        "body": outgoing.body,
    }
    serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    return f"<{digest}@free-protonmail-mcp.invalid>"

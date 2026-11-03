import hashlib
import hmac
import json
import logging
import math
import sqlite3
import threading
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

from filelock import FileLock, Timeout
from pydantic import ValidationError

from free_protonmail_mcp.models import AccountConfig, MailError, MessageRef, OutgoingMessage

EXPIRY_SECONDS = 900
MAX_PENDING_ACTIONS = 100
MAX_PAYLOAD_BYTES = 1_000_000
MAX_TRASH_MESSAGES = 20
_ALLOWED_KINDS = frozenset({"send", "trash"})

logger = logging.getLogger(__name__)


class ApprovalManager:
    def __init__(
        self,
        state_dir: Path,
        executor: Callable[[str, dict], dict],
        clock: Callable[[], float] = time.time,
    ):
        self.state_dir = Path(state_dir).expanduser().resolve()
        self._executor = executor
        self._clock = clock
        self._mutex = threading.RLock()
        self._channel_active = False
        self._closed = False
        self._pending_payloads: dict[str, str] = {}
        self._file_lock = None
        self._database = None
        self._open_state()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False

    def _open_state(self) -> None:
        self._acquire_state_lock()
        self._initialize_database()

    def _acquire_state_lock(self) -> None:
        try:
            self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            self._file_lock = FileLock(str(self.state_dir / ".approval-manager.lock"), timeout=0)
            self._file_lock.acquire(timeout=0)
        except Timeout:
            raise MailError("APPROVAL_STATE_IN_USE", "Approval state is already in use") from None
        except OSError:
            raise MailError("APPROVAL_STATE_UNAVAILABLE", "Approval state is unavailable") from None

    def _initialize_database(self) -> None:
        try:
            database_path = self.state_dir / "approvals.sqlite3"
            self._database = sqlite3.connect(
                database_path,
                timeout=5,
                isolation_level=None,
                check_same_thread=False,
            )
            database_path.chmod(0o600)
            self._database.execute("PRAGMA synchronous = FULL")
            self._database.execute("PRAGMA journal_mode = DELETE")
            self._database.execute(
                """
                CREATE TABLE IF NOT EXISTS actions (
                    action_id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL CHECK (kind IN ('send', 'trash')),
                    digest TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (
                        status IN (
                            'pending', 'denied', 'expired', 'changed', 'in_progress',
                            'succeeded', 'failed', 'unknown'
                        )
                    ),
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    outcome_json TEXT
                )
                """
            )
            self._recover_interrupted_actions()
        except (OSError, sqlite3.Error):
            self._close_resources()
            raise MailError("APPROVAL_STATE_UNAVAILABLE", "Approval state is unavailable") from None

    def _recover_interrupted_actions(self) -> None:
        self._database.execute("BEGIN IMMEDIATE")
        try:
            self._database.execute("UPDATE actions SET status = 'expired' WHERE status = 'pending'")
            self._database.execute(
                "UPDATE actions SET status = 'unknown', outcome_json = ? "
                "WHERE status = 'in_progress'",
                (self._encode_outcome("unknown"),),
            )
            self._database.commit()
        except sqlite3.Error:
            self._database.rollback()
            raise

    def request(self, kind: str, payload: dict) -> dict:
        if not isinstance(kind, str) or kind not in _ALLOWED_KINDS:
            raise MailError("APPROVAL_INVALID_KIND", "Approval action kind is not supported")
        try:
            frozen_payload = self._freeze_payload(kind, payload)
            payload_json = self._canonical_json(frozen_payload)
            payload_bytes = payload_json.encode("utf-8")
        except (TypeError, UnicodeError, ValueError):
            raise MailError("APPROVAL_INVALID_PAYLOAD", "Approval payload is invalid") from None
        if len(payload_bytes) > MAX_PAYLOAD_BYTES:
            raise MailError("APPROVAL_PAYLOAD_TOO_LARGE", "Approval payload exceeds the size limit")
        digest = hashlib.sha256(kind.encode("ascii") + b"\0" + payload_bytes).hexdigest()

        with self._mutex:
            self._ensure_open()
            now = self._now()
            self._expire_pending(now)
            pending_count = self._database.execute(
                "SELECT COUNT(*) FROM actions WHERE status = 'pending'"
            ).fetchone()[0]
            if pending_count >= MAX_PENDING_ACTIONS:
                raise MailError("APPROVAL_QUEUE_FULL", "Too many pending approvals")

            action_id = str(uuid.uuid4())
            expires_at = now + EXPIRY_SECONDS
            self._database.execute(
                """
                INSERT INTO actions (
                    action_id, kind, digest, status, created_at, expires_at, outcome_json
                )
                VALUES (?, ?, ?, 'pending', ?, ?, NULL)
                """,
                (action_id, kind, digest, now, expires_at),
            )
            self._pending_payloads[action_id] = payload_json
            return {"action_id": action_id, "status": "pending", "expires_at": expires_at}

    def status(self, action_id: str) -> dict:
        action_id = self._validate_action_id(action_id)
        with self._mutex:
            self._ensure_open()
            self._expire_pending(self._now())
            row = self._action_row(action_id)
            if row is None:
                raise MailError("APPROVAL_NOT_FOUND", "Approval action was not found")
            return self._status_result(row)

    def preview(self, action_id: str) -> dict:
        action_id = self._validate_action_id(action_id)
        with self._mutex:
            self._ensure_open()
            self._expire_pending(self._now())
            row = self._action_row(action_id)
            if row is None:
                raise MailError("APPROVAL_NOT_FOUND", "Approval action was not found")
            if row[3] != "pending":
                raise self._not_pending_error(row[3])
            payload_json = self._pending_payloads.get(action_id)
            if payload_json is None:
                raise MailError("APPROVAL_PAYLOAD_UNAVAILABLE", "Approval preview is unavailable")
            return {
                "action_id": action_id,
                "kind": row[1],
                "digest": row[2],
                "status": row[3],
                "expires_at": row[5],
                "payload": json.loads(payload_json),
            }

    def decide(self, action_id: str, digest: str, approve: bool) -> dict:
        action_id = self._validate_action_id(action_id)
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise MailError("APPROVAL_INVALID_DIGEST", "Approval digest is invalid")
        if type(approve) is not bool:
            raise MailError("APPROVAL_INVALID_DECISION", "Approval decision must be boolean")

        with self._mutex:
            self._ensure_open()
            now = self._now()
            self._expire_pending(now)
            settled, kind, payload = self._claim_pending_action(action_id, digest, approve, now)
            if settled is not None:
                return settled
            return self._run_approved_action(action_id, kind, payload)

    def _claim_pending_action(
        self, action_id: str, digest: str, approve: bool, now: float
    ) -> tuple[dict | None, str | None, dict | None]:
        """Mark the action in progress, or return the result of a decision with no effect."""
        row = self._action_row(action_id)
        if row is None:
            raise MailError("APPROVAL_NOT_FOUND", "Approval action was not found")
        if row[3] == "expired":
            return self._status_result(row), None, None
        if row[3] != "pending":
            raise self._not_pending_error(row[3])
        if not hmac.compare_digest(row[2], digest):
            self._transition(action_id, "pending", "changed", self._encode_outcome("changed"))
            self._pending_payloads.pop(action_id, None)
            return self._status_result(self._action_row(action_id)), None, None
        if not approve:
            self._transition(action_id, "pending", "denied", self._encode_outcome("denied"))
            self._pending_payloads.pop(action_id, None)
            return self._status_result(self._action_row(action_id)), None, None
        if not self._claim_in_progress(action_id, digest, now):
            self._expire_pending(now)
            row = self._action_row(action_id)
            if row is not None and row[3] == "expired":
                return self._status_result(row), None, None
            raise self._not_pending_error(row[3] if row is not None else "unknown")
        payload_json = self._pending_payloads.pop(action_id, None)
        if payload_json is None:
            self._set_outcome(action_id, "unknown")
            raise MailError(
                "APPROVAL_RESULT_UNKNOWN",
                "Approved action outcome is unknown; do not retry it",
                uncertain=True,
            )
        return None, row[1], json.loads(payload_json)

    def _claim_in_progress(self, action_id: str, digest: str, now: float) -> bool:
        claimed = self._database.execute(
            """
            UPDATE actions SET status = 'in_progress'
            WHERE action_id = ? AND status = 'pending' AND digest = ? AND expires_at > ?
            """,
            (action_id, digest, now),
        )
        if claimed.rowcount != 1:
            return False
        self._database.commit()
        return True

    def _run_approved_action(self, action_id: str, kind: str, payload: dict) -> dict:
        try:
            result = self._executor(kind, payload)
            outcome_status = self._result_status(kind, result)
        except MailError as error:
            raise self._record_failed_outcome(action_id, kind, error) from None
        except BaseException as error:
            self._set_outcome(action_id, "unknown")
            if not isinstance(error, Exception):
                raise
            raise MailError(
                "APPROVAL_RESULT_UNKNOWN",
                "Approved action outcome is unknown; do not retry it",
                uncertain=True,
            ) from None
        details = None
        if outcome_status == "succeeded":
            details = self._success_details(kind, result)
        self._set_outcome(action_id, outcome_status, details=details)
        if outcome_status == "unknown":
            raise MailError(
                "APPROVAL_RESULT_UNKNOWN",
                "Approved action outcome is unknown; do not retry it",
                uncertain=True,
            )
        return self._status_result(self._action_row(action_id))

    def _record_failed_outcome(self, action_id: str, kind: str, error: MailError) -> MailError:
        outcome_status = "unknown" if error.uncertain else "failed"
        details = self._recovery_details(kind, error.details)
        self._set_outcome(action_id, outcome_status, error.code, details)
        return MailError(
            error.code,
            "Approved action outcome is unknown; do not retry it"
            if error.uncertain
            else "Approved action failed without a known side effect",
            details,
            uncertain=error.uncertain,
        )

    def _recovery_details(self, kind: str, error_details: Any) -> dict | None:
        if kind != "trash" or not isinstance(error_details, dict):
            return None
        observed = _observed_move_states(error_details.get("cause"))
        if observed is None:
            return None
        return sanitize_recovery_details(
            {
                "completed": _move_references(error_details.get("completed")),
                "stopped": error_details.get("stopped"),
                **observed,
            }
        )

    def _success_details(self, kind: str, result: Any) -> dict | None:
        if kind != "trash" or not isinstance(result, dict):
            return None
        messages = result.get("messages")
        if not isinstance(messages, list) or not messages:
            return None
        if len(messages) > MAX_TRASH_MESSAGES:
            return None
        moves = []
        for message in messages:
            move = _verified_move(message)
            if move is None:
                return None
            moves.append(move)
        return {"messages": moves}

    def close(self) -> None:
        with self._mutex:
            if self._closed:
                return
            if self._channel_active:
                raise MailError(
                    "APPROVAL_CHANNEL_ACTIVE", "Stop the approval channel before closing"
                )
            self._closed = True
            self._pending_payloads.clear()
            self._close_resources()

    def _freeze_payload(self, kind: str, payload: dict) -> dict:
        if not isinstance(payload, dict):
            raise MailError("APPROVAL_INVALID_PAYLOAD", "Approval payload must be an object")
        try:
            if kind == "send":
                if set(payload) != {"sender", "message"} or not isinstance(
                    payload["message"], dict
                ):
                    raise ValueError
                account = AccountConfig(username="approval", sender=payload["sender"])
                message = OutgoingMessage.model_validate(payload["message"])
                return {
                    "sender": account.sender,
                    "message": message.model_dump(mode="json"),
                }

            if set(payload) != {"messages", "previews"}:
                raise ValueError
            messages = payload["messages"]
            previews = payload["previews"]
            if (
                not isinstance(messages, list)
                or not 1 <= len(messages) <= MAX_TRASH_MESSAGES
                or not isinstance(previews, list)
                or len(previews) != len(messages)
            ):
                raise ValueError
            frozen_messages = [
                MessageRef.model_validate(message).model_dump(mode="json") for message in messages
            ]
            preview_budget = [MAX_PAYLOAD_BYTES, 100_000]
            frozen_previews = [
                self._copy_json_value(preview, budget=preview_budget) for preview in previews
            ]
            if any(not isinstance(preview, dict) for preview in frozen_previews):
                raise ValueError
            return {"messages": frozen_messages, "previews": frozen_previews}
        except (KeyError, TypeError, ValueError, UnicodeError, ValidationError):
            raise MailError("APPROVAL_INVALID_PAYLOAD", "Approval payload is invalid") from None

    def _copy_json_value(
        self,
        value: Any,
        depth: int = 0,
        budget: list[int] | None = None,
    ) -> Any:
        if budget is None:
            budget = [MAX_PAYLOAD_BYTES, 100_000]
        if depth > 20:
            raise ValueError
        budget[1] -= 1
        if budget[1] < 0:
            raise ValueError
        if isinstance(value, str):
            self._charge_budget(budget, value)
            return value
        if value is None or isinstance(value, bool):
            return value
        if isinstance(value, int):
            if value.bit_length() > 64:
                raise ValueError
            return value
        if isinstance(value, float):
            if not math.isfinite(value):
                raise ValueError
            return value
        if isinstance(value, list):
            if len(value) > 10_000:
                raise ValueError
            return [self._copy_json_value(item, depth + 1, budget) for item in value]
        if isinstance(value, dict):
            if len(value) > 10_000 or any(not isinstance(key, str) for key in value):
                raise ValueError
            for key in value:
                self._charge_budget(budget, key)
            return {
                key: self._copy_json_value(item, depth + 1, budget) for key, item in value.items()
            }
        raise ValueError

    @staticmethod
    def _charge_budget(budget: list[int], text: str) -> None:
        budget[0] -= len(text.encode("utf-8"))
        if budget[0] < 0:
            raise ValueError

    def _canonical_json(self, value: dict) -> str:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )

    def _validate_action_id(self, action_id: str) -> str:
        if not isinstance(action_id, str):
            raise MailError("APPROVAL_INVALID_ID", "Approval action ID is invalid")
        try:
            parsed = uuid.UUID(action_id)
        except (ValueError, AttributeError):
            raise MailError("APPROVAL_INVALID_ID", "Approval action ID is invalid") from None
        if str(parsed) != action_id or parsed.version != 4:
            raise MailError("APPROVAL_INVALID_ID", "Approval action ID is invalid")
        return action_id

    def _now(self) -> float:
        now = self._clock()
        if not isinstance(now, (int, float)) or not math.isfinite(now):
            raise MailError("APPROVAL_CLOCK_INVALID", "Approval clock is unavailable")
        return float(now)

    def _expire_pending(self, now: float) -> None:
        rows = self._database.execute(
            "SELECT action_id FROM actions WHERE status = 'pending' AND expires_at <= ?",
            (now,),
        ).fetchall()
        if not rows:
            return
        self._database.execute("BEGIN IMMEDIATE")
        try:
            self._database.execute(
                "UPDATE actions SET status = 'expired' "
                "WHERE status = 'pending' AND expires_at <= ?",
                (now,),
            )
            self._database.commit()
        except sqlite3.Error:
            self._database.rollback()
            raise
        for row in rows:
            self._pending_payloads.pop(row[0], None)

    def _action_row(self, action_id: str):
        return self._database.execute(
            "SELECT action_id, kind, digest, status, created_at, expires_at, outcome_json "
            "FROM actions WHERE action_id = ?",
            (action_id,),
        ).fetchone()

    def _status_result(self, row) -> dict:
        result = {
            "action_id": row[0],
            "kind": row[1],
            "status": row[3],
            "created_at": row[4],
            "expires_at": row[5],
        }
        if row[6] is not None:
            result["outcome"] = json.loads(row[6])
        return result

    def _transition(self, action_id: str, current: str, target: str, outcome_json: str) -> None:
        updated = self._database.execute(
            "UPDATE actions SET status = ?, outcome_json = ? WHERE action_id = ? AND status = ?",
            (target, outcome_json, action_id, current),
        )
        if updated.rowcount != 1:
            raise MailError("APPROVAL_STATE_CHANGED", "Approval state changed; no action was taken")
        self._database.commit()

    def _set_outcome(
        self,
        action_id: str,
        status: str,
        error_code: str | None = None,
        details: dict | None = None,
    ) -> None:
        outcome_json = self._encode_outcome(status, error_code, details)
        try:
            updated = self._database.execute(
                "UPDATE actions SET status = ?, outcome_json = ? "
                "WHERE action_id = ? AND status = 'in_progress'",
                (status, outcome_json, action_id),
            )
            if updated.rowcount != 1:
                raise sqlite3.IntegrityError
            self._database.commit()
        except sqlite3.Error:
            self._database.rollback()
            raise MailError(
                "APPROVAL_RESULT_UNKNOWN",
                "Approved action outcome is unknown; do not retry it",
                uncertain=True,
            ) from None
        if status == "unknown":
            logger.warning(
                "Approved action outcome unknown: action_id=%s code=%s; inspect before retrying",
                action_id,
                error_code,
            )

    def _result_status(self, kind: str, result: Any) -> str:
        if not isinstance(result, dict):
            return "unknown"
        if result.get("uncertain") is True:
            return "unknown"
        status = result.get("status")
        if isinstance(status, str):
            if status.casefold() in {"unknown", "partial", "in_progress"}:
                return "unknown"
            if status.casefold() in {"failed", "error"}:
                return "failed"
        if kind == "trash":
            messages = result.get("messages")
            if not isinstance(messages, list) or not messages:
                return "unknown"
        return "succeeded"

    def _encode_outcome(
        self,
        status: str,
        error_code: str | None = None,
        details: dict | None = None,
    ) -> str:
        outcome = {"status": status}
        if error_code is not None and error_code.isascii() and len(error_code) <= 64:
            outcome["error_code"] = error_code
        if details is not None:
            outcome["details"] = details
        return json.dumps(outcome, separators=(",", ":"), sort_keys=True)

    def _not_pending_error(self, status: str) -> MailError:
        uncertain = status in {"in_progress", "unknown"}
        return MailError(
            "APPROVAL_NOT_PENDING",
            "Approval action cannot be executed again",
            uncertain=uncertain,
        )

    def _claim_channel(self) -> None:
        with self._mutex:
            self._ensure_open()
            if self._channel_active:
                raise MailError("APPROVAL_CHANNEL_ACTIVE", "Approval channel is already active")
            self._channel_active = True

    def _release_channel(self) -> None:
        with self._mutex:
            self._channel_active = False

    def _ensure_open(self) -> None:
        if self._closed or self._database is None:
            raise MailError("APPROVAL_MANAGER_CLOSED", "Approval manager is closed")

    def _close_resources(self) -> None:
        database = self._database
        self._database = None
        file_lock = self._file_lock
        self._file_lock = None
        try:
            if database is not None:
                database.close()
        finally:
            if file_lock is not None and file_lock.is_locked:
                file_lock.release()


_RECOVERY_FIELDS = frozenset(
    {
        "completed",
        "stopped",
        "source_present",
        "destination_present",
        "destination_ref",
        "protocol_succeeded",
    }
)


def sanitize_recovery_details(details: Any) -> dict | None:
    """Return only allowlisted recovery fields with provider text discarded."""
    if not isinstance(details, dict) or set(details) != _RECOVERY_FIELDS:
        return None
    completed = _reference_list(details.get("completed"))
    stopped = _message_reference(details.get("stopped"))
    destination_ref = details.get("destination_ref")
    if destination_ref is not None:
        destination_ref = _message_reference(destination_ref)
        if destination_ref is None:
            return None
    if completed is None or stopped is None:
        return None
    return {
        "completed": completed,
        "stopped": stopped,
        "source_present": _optional_bool(details.get("source_present")),
        "destination_present": _optional_bool(details.get("destination_present")),
        "destination_ref": destination_ref,
        "protocol_succeeded": _optional_bool(details.get("protocol_succeeded")),
    }


def _move_references(values: Any) -> list[Any] | None:
    if not isinstance(values, list) or len(values) > MAX_TRASH_MESSAGES:
        return None
    references = []
    for value in values:
        if not isinstance(value, dict):
            return None
        references.append(value.get("ref"))
    return references


def _reference_list(values: Any) -> list[dict] | None:
    if not isinstance(values, list) or len(values) > MAX_TRASH_MESSAGES:
        return None
    references = []
    for value in values:
        reference = _message_reference(value)
        if reference is None:
            return None
        references.append(reference)
    return references


def _message_reference(value: Any) -> dict | None:
    if not isinstance(value, dict):
        return None
    try:
        return MessageRef.model_validate(value).model_dump(mode="json")
    except ValidationError:
        return None


def _optional_bool(value: Any) -> bool | None:
    return value if type(value) is bool else None


def _observed_move_states(cause: Any) -> dict | None:
    if not isinstance(cause, dict):
        return None
    error = cause.get("error")
    details = error.get("details") if isinstance(error, dict) else None
    if not isinstance(details, dict):
        return None
    return {
        "source_present": details.get("source_present"),
        "destination_present": details.get("destination_present"),
        "destination_ref": details.get("destination_ref"),
        "protocol_succeeded": details.get("protocol_succeeded"),
    }


def _verified_move(message: Any) -> dict | None:
    if not isinstance(message, dict):
        return None
    reference = _message_reference(message.get("ref"))
    if reference is None:
        return None
    return {
        "moved": message.get("moved") is True,
        "ref": reference,
        "source_present": _optional_bool(message.get("source_present")),
        "destination_present": _optional_bool(message.get("destination_present")),
    }

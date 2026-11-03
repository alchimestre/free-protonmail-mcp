import hmac
import ipaddress
import json
import os
import secrets
import socket
import threading
import time
import uuid
from pathlib import Path
from typing import Protocol

from free_protonmail_mcp.approvals import sanitize_recovery_details
from free_protonmail_mcp.models import MailError

_MAX_REQUEST_BYTES = 64 * 1024
_MAX_RESPONSE_BYTES = 1_100_000
_CONNECTION_TIMEOUT_SECONDS = 5
_REQUEST_TIMEOUT_SECONDS = 5
_DISCOVERY_NAME = "approval-channel.json"
_SECRET_PREFIX = "free-protonmail-mcp-approval-"
_RESPONSE_FIELDS = {
    "preview": {"action_id", "kind", "digest", "status", "expires_at", "payload"},
    "status": {"action_id", "kind", "status", "created_at", "expires_at"},
    "decide": {"action_id", "kind", "status", "created_at", "expires_at"},
}


class SecretStore(Protocol):
    def get(self, name: str) -> str | None: ...

    def set(self, name: str, value: str) -> None: ...

    def delete(self, name: str) -> None: ...


class ApprovalChannel:
    def __init__(self, manager, state_dir: Path, secret_store: SecretStore):
        self.manager = manager
        self.state_dir = Path(state_dir).expanduser().resolve()
        self.secret_store = secret_store
        self.discovery_path = self.state_dir / _DISCOVERY_NAME
        self.instance_id = str(uuid.uuid4())
        self.port = None
        self._token = secrets.token_urlsafe(32)
        self._secret_name = _secret_name(self.instance_id)
        self._listener = None
        self._thread = None
        self._stop = threading.Event()
        self._connection_lock = threading.Lock()
        self._connection = None
        self._effect_active = False
        self._claimed = False

        if self.manager.state_dir != self.state_dir:
            raise MailError(
                "APPROVAL_CHANNEL_STATE_MISMATCH", "Approval channel state does not match"
            )

    def __enter__(self):
        self.manager._claim_channel()
        self._claimed = True
        try:
            self._remove_stale_secret()
            self._start_listener()
            self.secret_store.set(self._secret_name, self._token)
            self._write_discovery()
            self._thread = threading.Thread(target=self._serve, daemon=True)
            self._thread.start()
            return self
        except Exception:
            self._release_resources()
            raise MailError(
                "APPROVAL_CHANNEL_UNAVAILABLE",
                "Approval channel could not start",
            ) from None

    def __exit__(self, exc_type, exc_value, traceback):
        cleanup_error = self._release_resources()
        if cleanup_error is not None and exc_type is None:
            raise cleanup_error
        return False

    def _release_resources(self) -> MailError | None:
        self._stop_server()
        cleanup_error = self._delete_owned_secret()
        if cleanup_error is None:
            self._remove_owned_discovery()
        self._release_manager_claim()
        return cleanup_error

    def _remove_stale_secret(self) -> None:
        old_instance = _read_instance_id(self.discovery_path)
        if old_instance is None or old_instance == self.instance_id:
            return
        try:
            self.secret_store.delete(_secret_name(old_instance))
        except Exception:
            raise MailError(
                "APPROVAL_CHANNEL_CLEANUP_FAILED",
                "Approval channel credential could not be removed",
            ) from None

    def _start_listener(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.settimeout(0.2)
            listener.bind(("127.0.0.1", 0))
            listener.listen(8)
            host, self.port = listener.getsockname()
            if host != "127.0.0.1":
                raise OSError("Loopback bind did not use IPv4 localhost")
            self._listener = listener
        except OSError:
            listener.close()
            raise

    def _write_discovery(self) -> None:
        data = json.dumps(
            {"port": self.port, "instance_id": self.instance_id},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        temporary_path = self.state_dir / f".{_DISCOVERY_NAME}.{uuid.uuid4().hex}.tmp"
        descriptor = os.open(temporary_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as discovery_file:
                discovery_file.write(data)
                discovery_file.flush()
                os.fsync(discovery_file.fileno())
            os.replace(temporary_path, self.discovery_path)
        except Exception:
            try:
                temporary_path.unlink()
            except OSError:
                pass
            raise

    def _serve(self) -> None:
        while not self._stop.is_set():
            listener = self._listener
            if listener is None:
                return
            try:
                connection, address = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            if not self._track_connection(connection):
                connection.close()
                return
            try:
                with connection:
                    connection.settimeout(_CONNECTION_TIMEOUT_SECONDS)
                    response = self._handle_connection(connection, address)
                    connection.settimeout(_CONNECTION_TIMEOUT_SECONDS)
                    self._send_response(connection, response)
            except Exception:
                continue
            finally:
                self._untrack_connection(connection)

    def _track_connection(self, connection: socket.socket) -> bool:
        with self._connection_lock:
            if self._stop.is_set():
                return False
            self._connection = connection
            self._effect_active = False
            return True

    def _untrack_connection(self, connection: socket.socket) -> None:
        with self._connection_lock:
            if self._connection is connection:
                self._connection = None
            self._effect_active = False

    def _begin_effect(self, connection: socket.socket) -> bool:
        with self._connection_lock:
            if self._stop.is_set() or self._connection is not connection:
                return False
            self._effect_active = True
            return True

    def _handle_connection(self, connection: socket.socket, address) -> dict:
        try:
            peer_address = ipaddress.ip_address(address[0])
            if not peer_address.is_loopback:
                return _error_response("APPROVAL_CHANNEL_AUTH_FAILED", "Authentication failed")
            request = _read_request(connection)
        except (OSError, ValueError, UnicodeError, json.JSONDecodeError):
            return _error_response(
                "APPROVAL_CHANNEL_INVALID_REQUEST", "Approval request is invalid"
            )

        if not isinstance(request, dict):
            return _error_response("APPROVAL_CHANNEL_AUTH_FAILED", "Authentication failed")
        supplied_token = request.get("token")
        if not isinstance(supplied_token, str):
            return _error_response("APPROVAL_CHANNEL_AUTH_FAILED", "Authentication failed")
        try:
            supplied_token_bytes = supplied_token.encode("utf-8")
        except UnicodeError:
            return _error_response("APPROVAL_CHANNEL_AUTH_FAILED", "Authentication failed")
        expected_token_bytes = self._token.encode("ascii")
        if not hmac.compare_digest(supplied_token_bytes, expected_token_bytes):
            return _error_response("APPROVAL_CHANNEL_AUTH_FAILED", "Authentication failed")
        if not self._begin_effect(connection):
            return _error_response(
                "APPROVAL_CHANNEL_UNAVAILABLE", "Approval channel is unavailable"
            )

        try:
            return self._dispatch(request)
        except MailError as error:
            return error.result()
        except Exception:
            return _error_response("APPROVAL_CHANNEL_ERROR", "Approval request failed")

    def _dispatch(self, request: dict) -> dict:
        operation = request.get("operation")
        if operation not in {"preview", "status", "decide"}:
            return _error_response(
                "APPROVAL_CHANNEL_INVALID_OPERATION", "Approval operation is invalid"
            )
        expected_fields = {"token", "operation", "action_id"}
        if operation == "decide":
            expected_fields |= {"digest", "approve"}
        if set(request) != expected_fields:
            return _error_response(
                "APPROVAL_CHANNEL_INVALID_REQUEST", "Approval request is invalid"
            )

        action_id = request["action_id"]
        if operation == "preview":
            return self.manager.preview(action_id)
        if operation == "status":
            return self.manager.status(action_id)
        return self.manager.decide(action_id, request["digest"], request["approve"])

    def _send_response(self, connection: socket.socket, response: dict) -> None:
        try:
            response_bytes = json.dumps(
                response,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            if len(response_bytes) > _MAX_RESPONSE_BYTES:
                response_bytes = json.dumps(
                    _error_response("APPROVAL_CHANNEL_ERROR", "Approval request failed"),
                    separators=(",", ":"),
                ).encode("ascii")
            connection.sendall(response_bytes + b"\n")
        except (OSError, TypeError, ValueError):
            return

    def _stop_server(self) -> None:
        self._stop.set()
        listener = self._listener
        self._listener = None
        if listener is not None:
            try:
                listener.close()
            except OSError:
                pass
        self._interrupt_connection()
        thread = self._thread
        self._thread = None
        if thread is not None and thread is not threading.current_thread():
            thread.join()

    def _interrupt_connection(self) -> None:
        with self._connection_lock:
            connection = self._connection
            if connection is None or self._effect_active:
                return
            self._connection = None
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def _remove_owned_discovery(self) -> None:
        try:
            with self.discovery_path.open("rb") as discovery_file:
                content = discovery_file.read(4097)
            if len(content) > 4096:
                return
            discovery = json.loads(content)
        except (OSError, ValueError, UnicodeError):
            return
        if discovery == {"port": self.port, "instance_id": self.instance_id}:
            try:
                self.discovery_path.unlink()
            except OSError:
                return

    def _delete_owned_secret(self) -> MailError | None:
        try:
            stored_token = self.secret_store.get(self._secret_name)
            if not isinstance(stored_token, str):
                return None
            if hmac.compare_digest(stored_token.encode("utf-8"), self._token.encode("ascii")):
                self.secret_store.delete(self._secret_name)
            return None
        except Exception:
            return MailError(
                "APPROVAL_CHANNEL_CLEANUP_FAILED",
                "Approval channel credential could not be removed",
            )

    def _release_manager_claim(self) -> None:
        if not self._claimed:
            return
        self._claimed = False
        self.manager._release_channel()


def approval_request(
    state_dir: Path,
    secret_store: SecretStore,
    operation: str,
    action_id: str,
    digest: str | None = None,
    approve: bool | None = None,
) -> dict:
    request = _client_request(operation, action_id, digest, approve)
    discovery = _read_discovery(Path(state_dir).expanduser().resolve() / _DISCOVERY_NAME)
    request["token"] = _discovery_token(secret_store, discovery)
    response = _exchange(discovery["port"], _encode_request(request), operation)
    return _validated_response(operation, response)


def _discovery_token(secret_store: SecretStore, discovery: dict) -> str:
    try:
        token = secret_store.get(_secret_name(discovery["instance_id"]))
    except Exception:
        raise MailError("APPROVAL_CHANNEL_UNAVAILABLE", "Approval channel is unavailable") from None
    if not isinstance(token, str) or not 32 <= len(token) <= 128:
        raise MailError("APPROVAL_CHANNEL_UNAVAILABLE", "Approval channel is unavailable")
    return token


def _encode_request(request: dict) -> bytes:
    request_bytes = json.dumps(
        request,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if len(request_bytes) > _MAX_REQUEST_BYTES:
        raise MailError("APPROVAL_CHANNEL_INVALID_REQUEST", "Approval request is invalid")
    return request_bytes


def _exchange(port: int, request_bytes: bytes, operation: str) -> dict:
    try:
        with socket.create_connection(
            ("127.0.0.1", port), timeout=_CONNECTION_TIMEOUT_SECONDS
        ) as connection:
            connection.settimeout(_CONNECTION_TIMEOUT_SECONDS)
            connection.sendall(request_bytes + b"\n")
            connection.shutdown(socket.SHUT_WR)
            return _read_response(connection)
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError):
        raise MailError(
            "APPROVAL_CHANNEL_UNAVAILABLE",
            "Approval channel is unavailable",
            uncertain=operation == "decide",
        ) from None


def _validated_response(operation: str, response: dict) -> dict:
    if not isinstance(response, dict):
        raise MailError(
            "APPROVAL_CHANNEL_INVALID_RESPONSE",
            "Approval channel response is invalid",
            uncertain=operation == "decide",
        )
    if "error" in response:
        _raise_channel_error(response)
    if not _RESPONSE_FIELDS[operation].issubset(response):
        raise MailError(
            "APPROVAL_CHANNEL_INVALID_RESPONSE",
            "Approval channel response is invalid",
            uncertain=operation == "decide",
        )
    return response


def _client_request(
    operation: str,
    action_id: str,
    digest: str | None,
    approve: bool | None,
) -> dict:
    if not isinstance(operation, str) or operation not in {"preview", "status", "decide"}:
        raise MailError("APPROVAL_CHANNEL_INVALID_OPERATION", "Approval operation is invalid")
    if not isinstance(action_id, str):
        raise MailError("APPROVAL_INVALID_ID", "Approval action ID is invalid")
    try:
        parsed_action_id = uuid.UUID(action_id)
    except (ValueError, AttributeError):
        raise MailError("APPROVAL_INVALID_ID", "Approval action ID is invalid") from None
    if str(parsed_action_id) != action_id or parsed_action_id.version != 4:
        raise MailError("APPROVAL_INVALID_ID", "Approval action ID is invalid")
    request = {"operation": operation, "action_id": action_id}
    if operation == "decide":
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or type(approve) is not bool
        ):
            raise MailError("APPROVAL_CHANNEL_INVALID_REQUEST", "Approval request is invalid")
        request["digest"] = digest
        request["approve"] = approve
    elif digest is not None or approve is not None:
        raise MailError("APPROVAL_CHANNEL_INVALID_REQUEST", "Approval request is invalid")
    return request


def _read_request(connection: socket.socket) -> dict:
    deadline = time.monotonic() + _REQUEST_TIMEOUT_SECONDS
    data = bytearray()
    while len(data) <= _MAX_REQUEST_BYTES:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise socket.timeout("Approval request deadline exceeded")
        connection.settimeout(remaining)
        chunk = connection.recv(min(4096, _MAX_REQUEST_BYTES + 1 - len(data)))
        if not chunk:
            raise ValueError("Request frame ended before newline")
        data.extend(chunk)
        newline_index = data.find(b"\n")
        if newline_index >= 0:
            if newline_index > _MAX_REQUEST_BYTES or newline_index + 1 != len(data):
                raise ValueError("Request frame is invalid")
            return json.loads(
                data[:newline_index].decode("utf-8"), object_pairs_hook=_unique_object
            )
    raise ValueError("Request frame is too large")


def _read_response(connection: socket.socket) -> dict:
    data = bytearray()
    while len(data) <= _MAX_RESPONSE_BYTES:
        chunk = connection.recv(min(4096, _MAX_RESPONSE_BYTES + 1 - len(data)))
        if not chunk:
            raise ValueError("Response frame ended before newline")
        data.extend(chunk)
        newline_index = data.find(b"\n")
        if newline_index >= 0:
            if newline_index > _MAX_RESPONSE_BYTES or newline_index + 1 != len(data):
                raise ValueError("Response frame is invalid")
            return json.loads(
                data[:newline_index].decode("utf-8"), object_pairs_hook=_unique_object
            )
    raise ValueError("Response frame is too large")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate field")
        result[key] = value
    return result


def _read_discovery(path: Path) -> dict:
    try:
        with path.open("rb") as discovery_file:
            content = discovery_file.read(4097)
        if len(content) > 4096:
            raise ValueError
        discovery = json.loads(content)
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError) as error:
        raise MailError(
            "APPROVAL_CHANNEL_UNAVAILABLE", "Approval channel is unavailable"
        ) from error
    if not isinstance(discovery, dict) or set(discovery) != {"port", "instance_id"}:
        raise MailError("APPROVAL_CHANNEL_UNAVAILABLE", "Approval channel is unavailable")
    port = discovery["port"]
    if type(port) is not int or not 1 <= port <= 65535:
        raise MailError("APPROVAL_CHANNEL_UNAVAILABLE", "Approval channel is unavailable")
    instance_id = discovery["instance_id"]
    if _canonical_instance_id(instance_id) is None:
        raise MailError("APPROVAL_CHANNEL_UNAVAILABLE", "Approval channel is unavailable")
    return {"port": port, "instance_id": instance_id}


def _read_instance_id(path: Path) -> str | None:
    try:
        discovery = _read_discovery(path)
    except MailError:
        return None
    return discovery["instance_id"]


def _canonical_instance_id(instance_id) -> str | None:
    if not isinstance(instance_id, str):
        return None
    try:
        parsed = uuid.UUID(instance_id)
    except ValueError:
        return None
    if str(parsed) != instance_id or parsed.version != 4:
        return None
    return instance_id


def _secret_name(instance_id: str) -> str:
    return _SECRET_PREFIX + instance_id


def _error_response(code: str, message: str) -> dict:
    return {"error": {"code": code, "message": message}, "uncertain": False}


def _raise_channel_error(response: dict) -> None:
    error = response.get("error")
    if not isinstance(error, dict):
        raise MailError("APPROVAL_CHANNEL_ERROR", "Approval request failed")
    code = error.get("code")
    if not isinstance(code, str) or not code.isascii() or len(code) > 64:
        code = "APPROVAL_CHANNEL_ERROR"
    messages = {
        "APPROVAL_NOT_PENDING": "Approval action cannot be executed again",
        "APPROVAL_NOT_FOUND": "Approval action was not found",
        "APPROVAL_CHANNEL_AUTH_FAILED": "Authentication failed",
        "APPROVAL_CHANNEL_INVALID_OPERATION": "Approval operation is invalid",
        "APPROVAL_CHANNEL_INVALID_REQUEST": "Approval request is invalid",
        "APPROVAL_CHANNEL_INVALID_RESPONSE": "Approval channel response is invalid",
        "APPROVAL_CHANNEL_UNAVAILABLE": "Approval channel is unavailable",
        "APPROVAL_RESULT_UNKNOWN": "Approved action outcome is unknown; do not retry it",
    }
    uncertain = response.get("uncertain") is True
    raise MailError(
        code,
        messages.get(code, "Approval request failed"),
        sanitize_recovery_details(error.get("details")),
        uncertain=uncertain,
    )

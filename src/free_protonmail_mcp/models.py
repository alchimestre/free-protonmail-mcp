from email.errors import HeaderParseError
from email.headerregistry import Address
from ipaddress import ip_address
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

PositiveId = Annotated[int, Field(ge=1, le=4294967295, strict=True)]


class BoundaryModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class AccountConfig(BoundaryModel):
    username: str = Field(min_length=1, max_length=320)
    sender: str = Field(min_length=3, max_length=320)
    host: str = "127.0.0.1"
    imap_port: int = Field(default=1143, ge=1, le=65535)
    smtp_port: int = Field(default=1025, ge=1, le=65535)
    timeout: int = Field(default=30, ge=1, le=120)

    @field_validator("host")
    @classmethod
    def loopback_host(cls, value: str) -> str:
        if not ip_address(value).is_loopback:
            raise ValueError("Use a numeric loopback address")
        return value

    @field_validator("username")
    @classmethod
    def account_name(cls, value: str) -> str:
        return header_text(value)

    @field_validator("sender")
    @classmethod
    def sender_address(cls, value: str) -> str:
        return address(value)


class MessageRef(BoundaryModel):
    mailbox: str = Field(min_length=1, max_length=1024)
    uid_validity: PositiveId
    uid: PositiveId
    message_id: str | None = Field(default=None, max_length=998)

    @field_validator("mailbox", "message_id")
    @classmethod
    def protocol_text(cls, value: str | None) -> str | None:
        return header_text(value) if value is not None else None


class SearchQuery(BoundaryModel):
    subject: str | None = Field(default=None, max_length=256)
    sender: str | None = Field(default=None, max_length=320)
    unread: bool | None = None
    limit: int = Field(default=20, ge=1, le=100)
    before_uid: PositiveId | None = None

    @field_validator("subject", "sender")
    @classmethod
    def search_text(cls, value: str | None) -> str | None:
        return header_text(value) if value is not None else None


class OutgoingMessage(BoundaryModel):
    to: tuple[str, ...] = Field(min_length=1, max_length=50)
    cc: tuple[str, ...] = Field(default=(), max_length=50)
    bcc: tuple[str, ...] = Field(default=(), max_length=50)
    subject: str = Field(min_length=1, max_length=256)
    body: str = Field(min_length=1, max_length=100000)

    @field_validator("to", "cc", "bcc")
    @classmethod
    def recipient_addresses(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(address(value) for value in values)

    @field_validator("subject")
    @classmethod
    def subject_text(cls, value: str) -> str:
        return header_text(value)

    @field_validator("body")
    @classmethod
    def body_text(cls, value: str) -> str:
        if "\x00" in value:
            raise ValueError("Message body contains a null character")
        value.encode("utf-8")
        return value

    @model_validator(mode="after")
    def distinct_recipients(self):
        recipients = self.to + self.cc + self.bcc
        if len(recipients) > 50 or len({value.casefold() for value in recipients}) != len(
            recipients
        ):
            raise ValueError("Use at most 50 distinct recipients")
        return self


class MailError(Exception):
    def __init__(
        self, code: str, message: str, details: dict | None = None, uncertain: bool = False
    ):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}
        self.uncertain = uncertain

    def result(self) -> dict:
        return {
            "error": {"code": self.code, "message": self.message, "details": self.details},
            "uncertain": self.uncertain,
        }


def header_text(value: str) -> str:
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError("Header contains a control character")
    value.encode("utf-8")
    return value


def address(value: str) -> str:
    header_text(value)
    value.encode("ascii")
    try:
        parsed = Address(addr_spec=value)
    except HeaderParseError:
        raise ValueError("Use a bare ASCII email address") from None
    if parsed.addr_spec != value or not parsed.username or not parsed.domain:
        raise ValueError("Use a bare ASCII email address")
    return value

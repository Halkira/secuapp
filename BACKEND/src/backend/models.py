import base64
import uuid
from enum import StrEnum, auto
from typing import Annotated

from pydantic import BaseModel, Field, GetCoreSchemaHandler, StringConstraints
from pydantic_core import core_schema

from backend import utils

Username = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=3,
        max_length=20,
        pattern=r"^[a-zA-Z0-9_]+$",
    ),
]

class Base64Str(str):
    __slots__ = ()

    @classmethod
    def __get_pydantic_core_schema__(
        cls,
        source_type: type,
        handler: GetCoreSchemaHandler,
    ) -> core_schema.CoreSchema:
        schema = handler(str)
        return core_schema.with_info_after_validator_function(
            cls.validate,
            schema,
            serialization=core_schema.to_string_ser_schema(),
            metadata={"type": "string", "format": "base64"},
        )

    @classmethod
    def validate(cls, value: str, info: core_schema.ValidationInfo) -> str:
        if not isinstance(value, str):
            msg = "Base64Str must be a string"
            raise TypeError(msg)

        # Normalize to standard Base64
        normalized = value.replace("-", "+").replace("_", "/")
        padding = (4 - len(normalized) % 4) % 4
        normalized += "=" * padding

        try:
            decoded = base64.b64decode(normalized, validate=True)
        except Exception as e:
            msg = "Value must be a valid Base64 or Base64URL-encoded string"
            raise ValueError(msg) from e

        # Optional: re-encode to canonical standard Base64 and compare
        canonical = base64.b64encode(decoded).decode("utf-8")
        if canonical != normalized:
            msg = "Value is not a canonical Base64 encoding"
            raise ValueError(msg)

        return value

class UuidStr(str):
    __slots__ = ()

    @classmethod
    def __get_pydantic_core_schema__(
        cls,
        source_type: type,
        handler: GetCoreSchemaHandler,
    ) -> core_schema.CoreSchema:
        schema = handler(str)
        return core_schema.with_info_after_validator_function(
            cls.validate,
            schema,
            serialization=core_schema.to_string_ser_schema(),
            metadata={"type": "string", "format": "uuid"},
        )

    @classmethod
    def validate(cls, value: str, info: core_schema.ValidationInfo) -> str:
        if not isinstance(value, str):
            msg = "Value must be a string"
            raise TypeError(msg)
        try:
            uuid.UUID(value)
        except (ValueError, AttributeError, TypeError) as e:
            msg = "Value must be a valid UUID string"
            raise ValueError(msg) from e
        return value


Base64Encoded = Annotated[Base64Str, "Base64-encoded string"]
UUIDStr = Annotated[UuidStr, "Valid UUID string"]


class UserRole(StrEnum):
    REGULAR = auto()
    TRUSTED = auto()


class WebAuthnChallenge(BaseModel):
    challenge_b64: str
    timeout: int  # in milliseconds
    timestamp: int = Field(
        default_factory=utils.get_utc_now_milliseconds,
    )  # in milliseconds

    @property
    def challenge(self) -> bytes:
        return base64.b64decode(self.challenge_b64)

    @property
    def expiration_time(self) -> int:
        return self.timestamp + self.timeout

    @property
    def is_expired(self) -> bool:
        return utils.get_utc_now_milliseconds() > self.expiration_time


class SessionDataRegistration(BaseModel):
    user_id_str: str
    user_id_webauthn_base64: str
    webauthn_challenge: WebAuthnChallenge

    @property
    def user_id(self) -> uuid.UUID:
        return uuid.UUID(self.user_id_str)

    @property
    def user_id_webauthn(self) -> bytes:
        return base64.b64decode(self.user_id_webauthn_base64)


class SessionDataAuthentication(BaseModel):
    user_id_str: str
    webauthn_challenge: WebAuthnChallenge

    @property
    def user_id(self) -> uuid.UUID:
        return uuid.UUID(self.user_id_str)


class AuthJwtData(BaseModel):
    role: UserRole

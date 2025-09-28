import json
from datetime import datetime
from typing import Any, Self

from pydantic import field_validator
from sqlmodel import Field, Session, SQLModel

from backend import cryptography, utils


class RevokedToken(SQLModel, table=True):
    jwt_token_digest: str = Field(
        primary_key=True,
        index=True,
    )
    revocation_date: datetime = Field(default_factory=utils.get_utc_now)

    @classmethod
    def _parse_jwt_dict(cls, value: Any) -> str:  # noqa: ANN401
        if not isinstance(value, dict):
            msg = "Expected a dictionary"
            raise TypeError(msg)

        return cryptography.computer_hash(
            json.dumps(value, sort_keys=True).encode("utf-8"),
        )

    @field_validator("jwt_token_digest", mode="before")
    @classmethod
    def _parse_jwt_token_digest(cls, value: Any) -> str:  # noqa: ANN401
        if isinstance(value, str):
            return value

        return cls._parse_jwt_dict(value)

    @classmethod
    def from_token(cls, token: dict) -> Self:
        """Create a RevokedToken instance from a token.

        :param token: The token to create the instance from.
        :return: The RevokedToken instance.
        :raise TypeError: If the token is not a dictionary.
        """
        return cls(
            jwt_token_digest=cls._parse_jwt_dict(value=token),
        )

    def add(self, db: Session) -> Self:
        """Add the revoked token to the database.

        :param db: The database session.
        :return: The revoked token instance.
        :raise ValidationError: If the token is invalid.
        :raise ValueError: If the token is already revoked.
        """
        RevokedToken.model_validate(self)

        if db.get(RevokedToken, self.jwt_token_digest) is not None:
            msg = "Token already revoked"
            raise ValueError(msg)

        db.add(self)
        db.commit()
        db.refresh(self)

        return self

    @classmethod
    def is_revoked(
        cls,
        token: dict,
        db: Session,
    ) -> bool:
        """Check if the token is revoked.

        :param token: The token to check.
        :param db: The database session.
        :return: True if the token is revoked, False otherwise.
        :raise TypeError: If the token is not a dictionary.
        """
        jwt: RevokedToken = cls.from_token(token=token)
        return db.get(RevokedToken, jwt.jwt_token_digest) is not None

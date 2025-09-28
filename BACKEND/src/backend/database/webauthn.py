import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Self

from sqlmodel import (
    UUID,
    Column,
    Field,
    ForeignKey,
    Relationship,
    Session,
    SQLModel,
    select,
)

from backend import utils

if TYPE_CHECKING:
    from backend.database.user import User


class WebAuthn(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    user_id_webauthn: bytes = Field(unique=True)
    credential_id: bytes
    credential_public_key: bytes
    sign_count: int

    created_at: datetime = Field(default_factory=utils.get_utc_now)
    updated_at: datetime | None = Field(default_factory=utils.get_utc_now)

    user_id: uuid.UUID = Field(
        sa_column=Column(
            UUID(as_uuid=True),
            ForeignKey("user.id", ondelete="CASCADE"),
            nullable=False,
        ),
    )

    user: "User" = Relationship(back_populates="webauthn")

    def add(self, db: Session) -> Self:
        """Add the WebAuthn credential to the database.

        :param db: The database session.
        :return: The WebAuthn instance.
        :raise ValidationError: If the WebAuthn credential is invalid.
        :raise ValueError: If the WebAuthn credential already exists.
        """
        WebAuthn.model_validate(self)

        if (
            WebAuthn.get_by_user_id_webauthn(
                user_id_webauthn=self.user_id_webauthn,
                db=db,
            )
            is not None
        ):
            msg = "WebAuthn credential already exists"
            raise ValueError(msg)

        db.add(self)
        db.commit()
        db.refresh(self)

        return self

    @classmethod
    def get_by_user_id_webauthn(
        cls,
        user_id_webauthn: bytes,
        db: Session,
    ) -> Self | None:
        """Get a WebAuthn credential by user ID.

        :param user_id_webauthn: The user ID of the WebAuthn credential.
        :param db: The database session.
        :return: The WebAuthn instance.
        """
        statement = select(WebAuthn).where(
            WebAuthn.user_id_webauthn == user_id_webauthn,
        )
        return db.exec(statement).first()

    def update_sign_count(
        self,
        new_sign_count: int,
        db: Session,
    ) -> Self:
        """Update the sign count of the WebAuthn credential.

        :param new_sign_count: The new sign count.
        :param db: The database session.
        :return: The updated WebAuthn instance.
        """
        self.sign_count = new_sign_count
        self.updated_at = utils.get_utc_now()

        db.add(self)
        db.commit()
        db.refresh(self)

        return self

import uuid
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Self

from pydantic import EmailStr, SecretStr
from sqlalchemy import not_
from sqlmodel import Field, Relationship, Session, SQLModel, or_, select

from backend import models, utils
from backend.cryptography import decrypt_secret, encrypt_secret
from backend.database.shared_stream import SharedStream
from backend.database.shared_video import SharedVideo
from backend.database.stream import Stream
from backend.database.stream_key import StreamKey
from backend.database.video import Video
from backend.database.webauthn import WebAuthn

if TYPE_CHECKING:
    from backend.database.device import Device
    from backend.database.masterkey import MasterKey
    from backend.database.shared_stream import SharedStream
    from backend.database.shared_video import SharedVideo
    from backend.database.stream import Stream
    from backend.database.stream_key import StreamKey
    from backend.database.video import Video


class User(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    email: EmailStr = Field(unique=True)
    username: models.Username
    email_verified: bool = Field(default=False)
    # Unfortunately, SQLModel does not support SecretStr
    totp_secret: str | None = Field(default=None)
    role: models.UserRole | None = Field(default=models.UserRole.REGULAR)

    created_at: datetime = Field(default_factory=utils.get_utc_now)
    updated_at: datetime | None = Field(default_factory=utils.get_utc_now)

    webauthn: list["WebAuthn"] | None = Relationship(
        back_populates="user",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"},
    )

    streams: list["Stream"] | None = Relationship(
        back_populates="user",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"},
    )

    stream_key: list["StreamKey"] | None = Relationship(
        back_populates="user",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"},
    )

    video: list["Video"] | None = Relationship(
        back_populates="user",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"},
    )

    masterkey: list["MasterKey"] | None = Relationship(
        back_populates="user",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"},
    )

    device: list["Device"] | None = Relationship(
        back_populates="user",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"},
    )

    # RELATIONS POUR SHARED_STREAM
    shared_streams_as_owner: list["SharedStream"] | None = Relationship(
        back_populates="owner",
        sa_relationship_kwargs={
            "foreign_keys": "SharedStream.owner_id",
            "cascade": "all, delete-orphan",
        },
    )
    shared_streams_as_recipient: list["SharedStream"] | None = Relationship(
        back_populates="recipient",
        sa_relationship_kwargs={
            "foreign_keys": "SharedStream.recipient_id",
            "cascade": "all, delete-orphan",
        },
    )

    # RELATIONS POUR SHARED_VIDEO
    shared_videos_as_owner: list["SharedVideo"] | None = Relationship(
        back_populates="owner",
        sa_relationship_kwargs={
            "foreign_keys": "SharedVideo.owner_id",
            "cascade": "all, delete-orphan",
        },
    )
    shared_videos_as_recipient: list["SharedVideo"] | None = Relationship(
        back_populates="recipient",
        sa_relationship_kwargs={
            "foreign_keys": "SharedVideo.recipient_id",
            "cascade": "all, delete-orphan",
        },
    )

    def add(self, db: Session) -> Self:
        """Add the user to the database.

        :param db: The database session.
        :return: The user instance.
        :raise ValidationError: If the user is invalid.
        :raise ValueError: If the user already exists.
        """
        User.model_validate(self)

        if User.get_user_by_email(self.email, db) is not None:
            msg = "User already exists"
            raise ValueError(msg)

        db.add(self)
        db.commit()
        db.refresh(self)

        return self

    def get_totp_secret(self) -> SecretStr | None:
        """Get the TOTP secret.

        :return: The TOTP secret.
        """
        if self.totp_secret is None:
            return None

        return decrypt_secret(
            encrypted_secret=self.totp_secret,
            user_id=str(self.id),
        )

    @classmethod
    def get_user_by_id(cls, user_id: uuid.UUID, db: Session) -> Self | None:
        """Get a user by ID.

        :param user_id: The ID of the user.
        :param db: The database session.
        :return: The user instance.
        :raise ValidationError: If the user ID is invalid.
        """
        return db.get(User, user_id)

    @classmethod
    def get_user_by_username_and_email(
        cls,
        username: str,
        email: EmailStr,
        db: Session,
    ) -> Self | None:
        """Get a user by username and email.

        :param username: The username of the user.
        :param email: The email of the user.
        :param db: The database session.
        :return: The user instance.
        :raise ValidationError: If the username or email is invalid.
        """
        statement = select(User).where(
            User.username == username,
            User.email == email,
        )
        return db.exec(statement).first()

    @classmethod
    def get_user_by_email(cls, email: EmailStr, db: Session) -> Self | None:
        """Get a user by email.

        :param email: The email of the user.
        :param db: The database session.
        :return: The user instance.
        :raise ValidationError: If the email is invalid.
        """
        statement = select(User).where(User.email == email)
        return db.exec(statement).first()

    @classmethod
    def get_user_id_by_email(
        cls,
        email: EmailStr,
        db: Session,
    ) -> uuid.UUID | None:
        """Get a user's ID by email.

        :param email: The email of the user.
        :param db: The database session.
        :return: The user's ID (UUID) or None if not found.
        """
        statement = select(User.id).where(User.email == email)
        return db.exec(statement).first()

    def add_webauthn(self, webauthn: "WebAuthn", db: Session) -> Self:
        """Add a WebAuthn credential to the user.

        :param webauthn: The WebAuthn credential to add.
        :param db: The database session.
        :return: The user instance.
        :raise ValidationError: If the WebAuthn credential is invalid.
        """
        webauthn.add(db=db)

        if self.webauthn is None:
            self.webauthn = [webauthn]
        else:
            self.webauthn.append(webauthn)

        self.updated_at = utils.get_utc_now()

        db.add(self)
        db.commit()
        db.refresh(self)

        return self

    def set_totp_secret(self, secret: SecretStr, db: Session) -> Self:
        """Set a TOTP secret to the user.

        :param secret: The TOTP secret to add.
        :param db: The database session.
        :return: The user instance.
        :raise ValueError: If the TOTP secret already exists.
        """
        self.totp_secret = encrypt_secret(
            secret=secret,
            user_id=str(self.id),
        )
        self.updated_at = utils.get_utc_now()

        db.add(self)
        db.commit()
        db.refresh(self)

        return self

    def set_verified_email(self, db: Session) -> Self:
        """Set the email as verified.

        :param db: The database session.
        :return: The user instance.
        """
        if self.email_verified:
            msg = "Email already verified"
            raise ValueError(msg)

        self.email_verified = True
        self.updated_at = utils.get_utc_now()

        db.add(self)
        db.commit()
        db.refresh(self)

        return self

    def set_new_username(self, new_username: str, db: Session) -> Self:
        """Set a new username for the user.

        :param new_username: The new username to set.
        :param db: The database session.
        :return: The user instance.
        """
        self.username = new_username
        self.updated_at = utils.get_utc_now()

        db.add(self)
        db.commit()
        db.refresh(self)

        return self

    def get_webauthn_from_raw_id(self, raw_id: bytes) -> WebAuthn | None:
        """Get a WebAuthn credential by raw ID.

        :param raw_id: The raw ID of the WebAuthn credential.
        :return: The WebAuthn credential instance.
        """
        if self.webauthn is None:
            return None

        for webauthn in self.webauthn:
            if webauthn.credential_id == raw_id:
                return webauthn

        return None

    def is_usable(self) -> bool:
        """Check if the user is usable.

        :return: True if the user is usable, False otherwise.
        """
        return self.email_verified and self.totp_secret and self.webauthn

    def is_trusted(self) -> bool:
        """Check if the user is trusted.

        :return: True if the user is trusted, False otherwise.
        """
        return self.role == models.UserRole.TRUSTED

    @classmethod
    def clear_unusable_users(cls, db: Session) -> None:
        """Clear all unusable users that have not completed the registration
        process within the 5 minutes.

        :param db: The database session.
        """
        five_minutes_ago = utils.get_utc_now() - timedelta(minutes=5)

        statement = select(User).where(
            or_(
                not_(User.email_verified),
                User.totp_secret.is_(None),
                not_(User.webauthn.any()),
            ),
            User.created_at < five_minutes_ago,
        )

        unusable_users = db.exec(statement).all()

        for user in unusable_users:
            db.delete(user)

        db.commit()

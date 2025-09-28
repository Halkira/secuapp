import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Optional  # Ajout de List

from pydantic import BaseModel, ValidationError
from sqlalchemy.dialects.postgresql import JSONB
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
    from backend.database.stream import Stream
    from backend.database.user import User


class SharedEncryptionKey(BaseModel):
    device_id: str
    encrypted_key: str


class SharedStream(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    shared_at: datetime = Field(default_factory=utils.get_utc_now)
    shared_encryption_key: list | None = Field(
        default=None,
        sa_column=Column(JSONB),
    )

    # Relation avec le stream original
    stream_id: uuid.UUID = Field(
        sa_column=Column(
            UUID(as_uuid=True),
            ForeignKey("stream.id", ondelete="CASCADE"),
            nullable=False,
        ),
    )
    stream: "Stream" = Relationship(back_populates="shared_streams")

    # Renommé sharer_id en owner_id
    owner_id: uuid.UUID = Field(  # C'est l'utilisateur qui a INITIÉ le partage
        sa_column=Column(
            UUID(as_uuid=True),
            ForeignKey("user.id", ondelete="CASCADE"),
            nullable=False,
        ),
    )
    owner: "User" = (
        Relationship(  # Relation pour l'utilisateur qui partage (owner)
            back_populates="shared_streams_as_owner",
            sa_relationship_kwargs={"foreign_keys": "SharedStream.owner_id"},
        )
    )

    recipient_id: uuid.UUID = (
        Field(  # C'est l'utilisateur qui REÇOIT le partage
            sa_column=Column(
                UUID(as_uuid=True),
                ForeignKey("user.id", ondelete="CASCADE"),
                nullable=False,
            ),
        )
    )
    recipient: "User" = (
        Relationship(  # Relation pour l'utilisateur qui reçoit (recipient)
            back_populates="shared_streams_as_recipient",
            sa_relationship_kwargs={
                "foreign_keys": "SharedStream.recipient_id",
            },
        )
    )

    # --- CRUD operations (mise à jour des noms de colonnes) ---

    @classmethod
    def add_shared_stream(
        cls,
        db: Session,
        shared_stream: "SharedStream",
    ) -> None:
        """Ajoute un stream partagé à la base de données."""
        db.add(shared_stream)
        db.commit()
        db.refresh(shared_stream)

    @classmethod
    def get_shared_streams_for_recipient(
        cls,
        db: Session,
        user_id: uuid.UUID,
    ) -> list["SharedStream"]:
        """Récupère tous les streams partagés AVEC un utilisateur donné (recipient)."""  # noqa: E501
        statement = select(SharedStream).where(
            SharedStream.recipient_id == user_id,
        )
        return db.exec(statement).all()

    @classmethod
    def get_shared_streams_by_owner(
        cls,
        db: Session,
        owner_id: uuid.UUID,
    ) -> list["SharedStream"]:
        """Récupère tous les streams partagés PAR un utilisateur donné (owner)."""  # noqa: E501
        statement = select(SharedStream).where(
            SharedStream.owner_id == owner_id,
        )
        return db.exec(statement).all()

    @classmethod
    def get_existing_shared_stream(
        cls,
        db: Session,
        owner_id: uuid.UUID,
        recipient_id: uuid.UUID,
        stream_id: uuid.UUID,  # Notez bien stream_id ici
    ) -> Optional["SharedStream"]:
        """Vérifie si un stream spécifique a déjà été partagé par un propriétaire à un destinataire.
        Retourne l'objet SharedStream s'il existe, sinon None.
        """  # noqa: E501
        statement = select(SharedStream).where(
            SharedStream.owner_id == owner_id,
            SharedStream.recipient_id == recipient_id,
            SharedStream.stream_id == stream_id,  # Filtrer par stream_id
        )
        return db.exec(statement).first()

    @classmethod
    def get_shared_stream_by_ids(
        cls,
        db: Session,
        shared_stream_id: uuid.UUID,
    ) -> Optional["SharedStream"]:
        """Récupère un stream partagé par son ID."""
        statement = select(SharedStream).where(
            SharedStream.id == shared_stream_id,
        )
        return db.exec(statement).first()

    @classmethod
    def delete_shared_stream(
        cls,
        db: Session,
        shared_stream_id: uuid.UUID,
    ) -> bool:
        """Supprime un stream partagé par son ID."""
        shared_stream = db.get(cls, shared_stream_id)
        if shared_stream:
            db.delete(shared_stream)
            db.commit()
            return True
        return False

    @classmethod
    def is_recipient_trusted(
        cls,
        db: Session,
        recipient_id: uuid.UUID,
    ) -> bool:
        """Vérifie si le destinataire d'un partage a le rôle 'trusted'."""
        from backend.database.user import (
            User,
        )  # Importer la classe User si nécessaire

        statement = select(User).where(
            User.id == recipient_id,
            User.role == "TRUSTED",  # Vérifie si le rôle est 'trusted'
        )
        return db.exec(statement).first() is not None

    @classmethod
    def get_shared_stream_key(
        cls,
        db: Session,
        shared_stream_id: uuid.UUID,
        recipient_id: uuid.UUID,
        device_id: str,
    ) -> str | None:
        statement = select(SharedStream).where(
            SharedStream.stream_id == shared_stream_id,
            SharedStream.recipient_id == recipient_id,
        )

        shared_stream = db.exec(statement).first()

        if not shared_stream or not shared_stream.shared_encryption_key:
            return None

        for shared_encryption_key in shared_stream.shared_encryption_key:
            try:
                _shared_encryption_key = SharedEncryptionKey(
                    **shared_encryption_key,
                )
                if _shared_encryption_key.device_id == device_id:
                    return _shared_encryption_key.encrypted_key
            except ValidationError:
                continue
        return None

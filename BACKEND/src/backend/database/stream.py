import uuid
from datetime import datetime
from typing import TYPE_CHECKING

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
    from backend.database import StreamKey
    from backend.database.shared_stream import SharedStream
    from backend.database.user import User


class Stream(SQLModel, table=True):
    id: uuid.UUID = Field(primary_key=True)
    created_at: datetime = Field(default_factory=utils.get_utc_now)
    owner_id: uuid.UUID = Field(
        sa_column=Column(
            UUID(as_uuid=True),
            ForeignKey("user.id", ondelete="CASCADE"),
            nullable=False,
        ),
    )

    user: "User" = Relationship(back_populates="streams")

    stream_key: "StreamKey" = Relationship(back_populates="stream")

    # RELATION POUR SHARED_STREAM
    shared_streams: list["SharedStream"] | None = Relationship(
        back_populates="stream",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"},
    )

    @classmethod
    def add_stream(cls, db: Session, stream: "Stream") -> None:
        """Ajoute le flux à la base de données.

        :param db: La session de base de données.
        :param stream: L'instance du flux à ajouter.
        :raise ValueError: Si le flux existe déjà.
        """
        cls.model_validate(stream)

        existing_stream = db.get(cls, stream.id)
        if existing_stream is not None:
            msg = "Flow already exists"
            raise ValueError(msg)

        db.add(stream)
        db.commit()

    @classmethod
    def exists_and_is_owned_by(
        cls,
        db: Session,
        stream_id: uuid.UUID,
        owner_id: uuid.UUID,
    ) -> bool:
        """Vérifie si un stream existe et appartient à l'utilisateur spécifié.
        Retourne True si oui, False sinon.
        """
        statement = select(Stream).where(
            Stream.id == stream_id,
            Stream.owner_id == owner_id,
        )
        return db.exec(statement).first() is not None

import uuid
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

if TYPE_CHECKING:
    from backend.database.stream import Stream
    from backend.database.user import User


class StreamKey(SQLModel, table=True):
    id: uuid.UUID = Field(primary_key=True)
    encrypted_key: str

    stream_id: uuid.UUID = Field(
        sa_column=Column(
            UUID(as_uuid=True),
            ForeignKey("stream.id", ondelete="CASCADE"),
            nullable=False,
        ),
    )

    stream: "Stream" = Relationship(back_populates="stream_key")

    owner_id: uuid.UUID = Field(
        sa_column=Column(
            UUID(as_uuid=True),
            ForeignKey("user.id", ondelete="CASCADE"),
            nullable=False,
        ),
    )

    user: "User" = Relationship(back_populates="stream_key")

    @classmethod
    def add_stream_key(cls, db: Session, stream_key: "StreamKey") -> None:
        """Ajoute une nouvelle clé de stream à la base de données."""
        db.add(stream_key)
        db.commit()
        db.refresh(stream_key)

    @classmethod
    def get_stream_key(
        cls,
        db: Session,
        stream_id: uuid.UUID,
    ) -> "StreamKey":
        """Récupère une clé de stream par son ID de stream."""
        statement = select(cls).where(cls.stream_id == stream_id)
        return db.exec(statement).first()

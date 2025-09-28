import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Optional, List  # Ajout de List

from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import aliased
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

from backend import models, utils

if TYPE_CHECKING:
    from backend.database.user import User
    from backend.database.video import Video


class SharedVideo(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    shared_at: datetime = Field(default_factory=utils.get_utc_now)
    shared_encryption_key: Optional[List] = Field(
        default=None,
        sa_column=Column(JSONB)
    )

    # Relation avec la vidéo originale
    video_id: uuid.UUID = Field(
        sa_column=Column(
            UUID(as_uuid=True),
            ForeignKey("video.id", ondelete="CASCADE"),
            nullable=False,
        ),
    )
    video: "Video" = Relationship(back_populates="shared_videos")

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
            back_populates="shared_videos_as_owner",
            sa_relationship_kwargs={"foreign_keys": "SharedVideo.owner_id"},
        )
    )

    # Renommé shared_with_id en recipient_id
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
            back_populates="shared_videos_as_recipient",
            sa_relationship_kwargs={
                "foreign_keys": "SharedVideo.recipient_id",
            },
        )
    )

    # --- CRUD operations (mise à jour des noms de colonnes) ---

    @classmethod
    def add_shared_video(
        cls,
        db: Session,
        shared_video: "SharedVideo",
    ) -> None:
        """Ajoute une vidéo partagée à la base de données."""
        db.add(shared_video)
        db.commit()
        db.refresh(shared_video)

    @classmethod
    def get_shared_videos_for_recipient(
        cls,
        db: Session,
        user_id: uuid.UUID,
    ) -> list["SharedVideo"]:
        """Récupère toutes les vidéos partagées AVEC un utilisateur donné (recipient)."""  # noqa: E501
        from backend.database.user import User

        Recipient = aliased(User)  # noqa: N806

        statement = (
            select(SharedVideo)
            .join(Recipient, SharedVideo.recipient)
            .where(
                SharedVideo.recipient_id == user_id,
                Recipient.role == models.UserRole.TRUSTED,
            )
        )
        return db.exec(statement).all()

    @classmethod
    def get_shared_videos_by_owner(
        cls,
        db: Session,
        owner_id: uuid.UUID,
    ) -> list["SharedVideo"]:
        """Récupère toutes les vidéos partagées PAR un utilisateur donné (owner)."""  # noqa: E501
        from backend.database.user import User

        Owner = aliased(User)  # noqa: N806

        statement = (
            select(SharedVideo)
            .join(Owner, SharedVideo.owner)
            .where(
                SharedVideo.owner_id == owner_id,
                Owner.role == models.UserRole.REGULAR,
            )
        )
        return db.exec(statement).all()

    @classmethod
    def get_existing_shared_video(
        cls,
        db: Session,
        owner_id: uuid.UUID,
        recipient_id: uuid.UUID,
        video_id: uuid.UUID,
    ) -> Optional["SharedVideo"]:
        """Vérifie si une vidéo spécifique a déjà été partagée par un propriétaire à un destinataire.
        Retourne l'objet SharedVideo s'il existe, sinon None.
        """  # noqa: E501
        statement = select(SharedVideo).where(
            SharedVideo.owner_id == owner_id,
            SharedVideo.recipient_id == recipient_id,
            SharedVideo.video_id == video_id,
        )
        return db.exec(statement).first()

    @classmethod
    def get_shared_video_by_ids(
        cls,
        db: Session,
        shared_video_id: uuid.UUID,
    ) -> Optional["SharedVideo"]:
        """Récupère une vidéo partagée par son ID."""
        statement = select(SharedVideo).where(
            SharedVideo.id == shared_video_id,
        )
        return db.exec(statement).first()

    @classmethod
    def delete_shared_video(
        cls,
        db: Session,
        shared_video_id: uuid.UUID,
    ) -> bool:
        """Supprime une vidéo partagée par son ID."""
        shared_video = db.get(cls, shared_video_id)
        if shared_video:
            db.delete(shared_video)
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
            User,  # Importer la classe User si nécessaire
        )

        statement = select(User).where(
            User.id == recipient_id,
            User.role == "TRUSTED",  # Vérifie si le rôle est 'trusted'
        )
        return db.exec(statement).first() is not None

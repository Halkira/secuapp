import uuid
from datetime import datetime
from typing import (  # Assurez-vous que Optional est importé
    TYPE_CHECKING,
    Optional,
)

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
    from backend.database.shared_video import SharedVideo
    from backend.database.user import User


class Video(SQLModel, table=True):
    id: uuid.UUID = Field(primary_key=True)
    timestamp: datetime = Field(default_factory=utils.get_utc_now)
    size: int

    owner_id: uuid.UUID = Field(
        sa_column=Column(
            UUID(as_uuid=True),
            ForeignKey("user.id", ondelete="CASCADE"),
            nullable=False,
        ),
    )

    user: "User" = Relationship(back_populates="video")

    # RELATION POUR SHARED_VIDEO
    shared_videos: list["SharedVideo"] | None = Relationship(
        back_populates="video",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"},
    )

    @classmethod
    def add_video(cls, db: Session, video: "Video") -> None:
        """Ajoute la vidéo à la base de données.

        :param db: La session de base de données.
        :param video: L'instance de la vidéo à ajouter.
        """
        cls.model_validate(video)

        existing_video = db.get(cls, video.id)
        if existing_video is not None:
            msg = "Video already exists"
            raise ValueError(msg)

        db.add(video)
        db.commit()
        db.refresh(video)

    @classmethod
    def get_video_by_id(
        cls,
        db: Session,
        video_id: uuid.UUID,
    ) -> Optional["Video"]:
        """Récupère une vidéo par son ID.

        :param db: La session de base de données.
        :param video_id: L'ID de la vidéo à récupérer.
        :return: L'instance de la vidéo si trouvée, sinon None.
        """
        return db.get(Video, video_id)

    @classmethod
    def get_video_by_id_and_user_id(
        cls,
        user_id: uuid.UUID,
        video_id: uuid.UUID,
        db: Session,
    ) -> "Video | None":
        """Récupère une vidéo par son ID et l'ID de l'utilisateur.

        :param db: La session de base de données.
        :param video_id: L'ID de la vidéo à récupérer.
        :param user_id: L'ID de l'utilisateur propriétaire de la vidéo.
        :return: L'instance de la vidéo si trouvée, sinon None.
        """
        statement = select(Video).where(
            Video.id == video_id,
            Video.owner_id == user_id,
        )
        return db.exec(statement).one_or_none()

    @classmethod
    def get_videos_by_user_id(
        cls,
        user_id: uuid.UUID,
        db: Session,
    ) -> list["Video"]:
        """Récupère toutes les vidéos d'un utilisateur par son ID.

        :param user_id: L'ID de l'utilisateur.
        :param db: La session de base de données.
        :return: Une liste d'instances de vidéos.
        """
        statement = select(Video).where(Video.owner_id == user_id)
        return db.exec(statement).all()

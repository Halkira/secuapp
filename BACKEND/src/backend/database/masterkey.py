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
    from backend.database.encrypted_master_key import EncMasterKey
    from backend.database.user import User


# Maybe remove this class
class MasterKey(SQLModel, table=True):
    id: bytes = Field(primary_key=True)  # Should be a device_id
    master_key: str = Field(nullable=False)
    created_at: datetime = Field(default_factory=utils.get_utc_now)
    user_id: uuid.UUID = Field(
        sa_column=Column(
            UUID(as_uuid=True),
            ForeignKey("user.id", ondelete="CASCADE"),
            nullable=False,
        ),
    )

    user: "User" = Relationship(back_populates="masterkey")
    encrypted_master_key: "EncMasterKey" = Relationship(
        back_populates="master_key",
    )

    @classmethod
    def add_masterkey(cls, db: Session, masterkey: "MasterKey") -> "MasterKey":
        """Ajoute la masterkey à la base de données.

        :param db: La session de base de données.
        :param masterkey: L'instance de la masterkey à ajouter.
        :return: L'instance de la masterkey ajoutée.
        :raise ValueError: Si la masterkey existe déjà ou si l'utilisateur possède déjà une masterkey.
        """  # noqa: E501
        cls.model_validate(masterkey)

        existing_masterkey = db.get(cls, masterkey.id)
        if existing_masterkey is not None:
            msg = "La masterkey existe déjà"
            raise ValueError(msg)

        statement = select(cls).where(cls.user_id == masterkey.user_id)
        existing_user_masterkey = db.exec(statement).first()
        if existing_user_masterkey is not None:
            msg = "L'utilisateur possède déjà une masterkey"
            raise ValueError(msg)

        db.add(masterkey)
        db.commit()
        db.refresh(masterkey)

        return masterkey

    @classmethod
    def get_masterkey_by_id_and_user(
        cls,
        db: Session,
        masterkey_id: bytes,
        user_id: uuid.UUID,
    ) -> "MasterKey":
        """Récupère la masterkey à partir de l'ID et de l'ID de l'utilisateur.

        :param db: La session de base de données.
        :param masterkey_id: L'ID de la masterkey.
        :param user_id: L'ID de l'utilisateur.
        :return: L'instance de la masterkey ou None si elle n'existe pas.
        """
        statement = select(cls).where(
            cls.id == masterkey_id,
            cls.user_id == user_id,
        )
        return db.exec(statement).first()

    @classmethod
    def rm_masterkey(cls, db: Session, user_id: uuid.UUID) -> "MasterKey":
        """Supprime la masterkey à partir de l'ID de l'utilisateur.

        :param db: La session de base de données.
        :param user_id: L'ID de l'utilisateur.
        :return: L'instance de la masterkey.
        """
        statement = select(cls).where(cls.user_id == user_id)
        masterkey = db.exec(statement).first()
        if masterkey is None:
            msg = "La masterkey n'existe pas"
            raise ValueError(msg)

        db.delete(masterkey)
        db.commit()

        return masterkey

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


class Device(SQLModel, table=True):
    id: bytes = Field(primary_key=True)
    pub_key: str = Field(nullable=False)
    created_at: datetime = Field(default_factory=utils.get_utc_now)
    user_id: uuid.UUID = Field(
        sa_column=Column(
            UUID(as_uuid=True),
            ForeignKey("user.id", ondelete="CASCADE"),
            nullable=False,
        ),
    )

    user: "User" = Relationship(back_populates="device")
    encrypted_master_key: "EncMasterKey" = Relationship(
        back_populates="device",
    )

    @classmethod
    def add_new_device(cls, db: Session, device: "Device") -> "Device":
        """Ajoute un nouvel appareil à la base de données.

        :param db: La session de base de données.
        :param device: L'instance de l'appareil à ajouter.
        :return: L'instance de l'appareil ajoutée.
        :raise ValueError: Si l'appareil existe déjà.
        """
        cls.model_validate(device)

        existing_device = db.get(cls, device.id)
        if existing_device is not None:
            msg = "L'appareil existe déjà"
            raise ValueError(msg)

        db.add(device)
        db.commit()

        return device

    @classmethod
    def get_pub_keys_by_user_id(cls, db: Session, user_id: uuid.UUID) -> list[tuple[str, str]]:
        """Récupère tous les couples (id, clé publique) des appareils d'un utilisateur, id encodé en base64."""
        statement = select(cls.id, cls.pub_key).where(cls.user_id == user_id)
        return [
            (row[0], row[1])
            for row in db.exec(statement).all()
        ]

    @classmethod
    def get_device(cls, db: Session, device: "Device") -> "Device":
        """Récupère un appareil à partir de sa clé publique.

        :param db: La session de base de données.
        :param device: L'instance de l'appareil à récupérer.
        :return: L'instance de l'appareil.
        """
        cls.model_validate(device)
        webauthn_cred_id = device.id
        statement = select(cls).where(cls.id == webauthn_cred_id)
        return db.exec(statement).first()

    @classmethod
    def rm_device(cls, db: Session, device: "Device") -> "Device":
        """Supprime un appareil à partir de sa clé publique.

        :param db: La session de base de données.
        :param device: La clé publique de l'appareil.
        :return: L'instance de l'appareil.
        """
        cls.model_validate(device)
        webauthn_cred_id = device.id
        statement = select(cls).where(cls.id == webauthn_cred_id)
        device = db.exec(statement).first()
        if device is None:
            msg = "L'appareil n'existe pas"
            raise ValueError(msg)

        db.delete(device)
        db.commit()

        return device

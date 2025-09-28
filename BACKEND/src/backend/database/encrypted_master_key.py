from typing import TYPE_CHECKING, Self

from sqlmodel import (
    Column,
    Field,
    ForeignKey,
    Relationship,
    Session,
    SQLModel,
)

if TYPE_CHECKING:
    from backend.database import MasterKey
    from backend.database.device import Device


class EncMasterKey(SQLModel, table=True):
    encrypted_master_key: str = Field(nullable=False, unique=True)
    master_key_id: bytes = Field(
        sa_column=Column(
            ForeignKey("masterkey.id", ondelete="CASCADE"),
            nullable=False,
            primary_key=True,
        ),
    )
    device_id: bytes = Field(
        sa_column=Column(
            ForeignKey("device.id", ondelete="CASCADE"),
            nullable=False,
            primary_key=True,
        ),
    )

    device: "Device" = Relationship(back_populates="encrypted_master_key")
    master_key: "MasterKey" = Relationship(
        back_populates="encrypted_master_key",
    )

    def add(self, db: Session) -> Self:
        """Add a new encrypted master key to the database."""
        EncMasterKey.model_validate(self)
        db.add(self)
        db.commit()
        db.refresh(self)
        return self

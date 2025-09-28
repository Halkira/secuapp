from collections.abc import Generator

from sqlalchemy import Engine
from sqlmodel import Session, SQLModel, create_engine

from backend.config import settings
from backend.database.device import Device
from backend.database.encrypted_master_key import EncMasterKey
from backend.database.masterkey import MasterKey
from backend.database.shared_stream import SharedStream
from backend.database.shared_video import SharedVideo
from backend.database.stream import Stream
from backend.database.stream_key import StreamKey
from backend.database.token import RevokedToken
from backend.database.user import User
from backend.database.video import Video
from backend.database.webauthn import WebAuthn

__all__ = [
    "Device",
    "EncMasterKey",
    "MasterKey",
    "RevokedToken",
    "SharedStream",
    "SharedVideo",
    "Stream",
    "StreamKey",
    "User",
    "Video",
    "WebAuthn",
    "create_db_and_tables",
    "get_db_engine",
]

db_engine: Engine = create_engine(url=settings.db_url)


def create_db_and_tables() -> None:
    SQLModel.metadata.create_all(db_engine)


def get_db_engine() -> Generator[Session]:
    with Session(db_engine) as session:
        yield session

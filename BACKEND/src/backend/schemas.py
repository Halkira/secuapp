import uuid
from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, EmailStr, StringConstraints
from webauthn.helpers.structs import (
    AuthenticationCredential,
    RegistrationCredential,
)

from backend import models


######
# IN #
######
class PostRegistrationOptionsIn(BaseModel):
    email: EmailStr
    username: models.Username
    role: models.UserRole | None = None


class PostRegistrationVerifyIn(BaseModel):
    credential: RegistrationCredential | dict
    device_id: models.Base64Encoded
    master_key: models.Base64Encoded
    public_key: models.Base64Encoded


class PostAuthenticationOptionsIn(BaseModel):
    email: EmailStr
    username: models.Username


class PostAuthenticationVerifyIn(BaseModel):
    credential: AuthenticationCredential | dict
    otp: Annotated[
        str,
        StringConstraints(
            strip_whitespace=True,
            min_length=6,
            max_length=6,
            pattern=r"^\d{6}$",
        ),
    ]


class PostUserUsernameIn(BaseModel):
    new_username: models.Username


class ShareStreamIn(BaseModel):
    stream_id: uuid.UUID
    recipient_email: EmailStr
    shared_encryption_key: list[dict] | None = None


class ShareVideoIn(BaseModel):
    video_id: uuid.UUID
    recipient_email: EmailStr
    shared_encryption_key: list[dict] | None = None


class PostPubKeyIn(BaseModel):
    pub_key: models.Base64Encoded
    master_key: models.Base64Encoded | None = None


class PostDeviceIn(BaseModel):
    pub_key: models.Base64Encoded
    webauthn_cred_id: bytes
    status: str


class DeleteDevice(BaseModel):
    webauthn_cred_id: bytes


class PostMasterKeyIn(BaseModel):
    master_key: models.Base64Encoded


class DeleteMasterKey(BaseModel):
    master_key: models.Base64Encoded


class GetDeviceIn(BaseModel):
    webauthn_cred_id: bytes


#######
# OUT #
#######
class PostRegistrationVerifyOut(BaseModel):
    totp_provisioning_uri: str


class SharedStreamOut(BaseModel):
    id: uuid.UUID
    stream_id: uuid.UUID
    owner_id: uuid.UUID
    recipient_id: uuid.UUID
    shared_at: datetime
    shared_encryption_key: list[dict] | None = None  # shared_encryption_key: str

class ShareVideoOut(BaseModel):
    id: uuid.UUID
    video_id: uuid.UUID
    owner_id: uuid.UUID
    recipient_id: uuid.UUID
    shared_at: datetime
    shared_encryption_key: list[dict] | None = None  # shared_encryption_key: str

class SharedVideoOut(BaseModel):
    id: uuid.UUID
    video_id: uuid.UUID
    owner_id: uuid.UUID
    recipient_id: uuid.UUID
    shared_at: datetime
    shared_encryption_key: str | None = None  # shared_encryption_key: str


class GetSharedStreamsOut(BaseModel):
    shared_streams: list[SharedStreamOut]


class GetSharedVideosOut(BaseModel):
    shared_videos: list[SharedVideoOut]


class GetMasterKeyIn(BaseModel):
    device_id: models.Base64Encoded


class AddDeviceRequest(BaseModel):
    pubkey_device: str
    device_id: models.Base64Encoded


class DeleteDeviceRequest(BaseModel):
    temp_device_id: models.Base64Encoded


class ApproveDeviceRequest(BaseModel):
    device_id: models.Base64Encoded
    pubkey: str
    encrypted_master_key: str


class ApproveDeviceOptions(BaseModel):
    email: EmailStr
    username: models.Username


class ApproveDeviceVerify(BaseModel):
    credential: AuthenticationCredential | dict
    otp: Annotated[
        str,
        StringConstraints(
            strip_whitespace=True,
            min_length=6,
            max_length=6,
            pattern=r"^\d{6}$",
        ),
    ]

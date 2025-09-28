import hashlib

import pyotp
from pydantic import (
    BaseModel,
    EmailStr,
    Field,
    SecretStr,
)

from backend.constants import RP_NAME


class TOTP(BaseModel):
    secret: SecretStr | None = Field(
        default_factory=lambda: SecretStr(pyotp.random_base32()),
    )

    def new_totp(
        self,
        email: EmailStr,
    ) -> str:
        totp: pyotp.TOTP = pyotp.TOTP(
            self.secret.get_secret_value(),
            digest=hashlib.sha512,  # SHA-512 is more secure than SHA-1
            name=email,
            issuer=RP_NAME,
        )

        return totp.provisioning_uri()

    def verify_totp(
        self,
        otp: str,
    ) -> bool:
        totp: pyotp.TOTP = pyotp.TOTP(
            self.secret.get_secret_value(),
            digest=hashlib.sha512,
        )  # SHA-512 is more secure than SHA-1

        return totp.verify(otp)

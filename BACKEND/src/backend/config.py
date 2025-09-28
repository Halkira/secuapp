import os

from pydantic import EmailStr, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import URL
from starlette.datastructures import Secret as StarletteSecret


class Settings(BaseSettings):
    # API settings
    api_prefix: str = "/api/dashcam"
    api_version: str = "v0"
    api_title: str = "Dashcam API"

    # Secure cookies settings
    secure_cookies_secret: StarletteSecret

    # CSRF settings
    csrf_secret_key: StarletteSecret

    # Redis Settings
    redis_url: str | None = "redis://localhost:6379"

    # Session cookie settings
    session_secret_key: StarletteSecret
    session_ttl: int = 5 * 60  # 5 minutes

    # JWT settings
    authjwt_token_location: set[str] = {"cookies"}
    authjwt_secret_key: str
    authjwt_algorithm: str = "HS512"
    authjwt_denylist_enabled: bool = True
    authjwt_denylist_token_checks: set = {"access", "refresh"}
    authjwt_access_expires: int = 15 * 60  # 15 minutes
    authjwt_refresh_expires: int = 12 * 60 * 60  # 12 hours
    authjwt_access_csrf_header_name: str = "X-CSRF-Access-Token"
    authjwt_refresh_csrf_header_name: str = "X-CSRF-Refresh-Token"
    authjwt_csrf_methods: set[str] = {
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "HEAD",
    }

    # Database settings
    db_driver: str = "postgresql+psycopg2"
    db_username: SecretStr
    db_password: SecretStr
    db_host: str = "localhost"
    db_port: int | None = None
    db_database: str = "dashcam"

    # Key settings
    public_key_path: str = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "public_key_log.pem",
    )

    private_key_path: str = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "private_key.key",
    )

    # Resend settings
    resend_api_key: SecretStr
    resend_api_email: EmailStr = "no-reply@secuapp.be"

    # Cryptography settings
    master_key: SecretStr
    hmac_key: SecretStr

    @field_validator(
        "secure_cookies_secret",
        "csrf_secret_key",
        "session_secret_key",
        mode="before",
    )
    @classmethod
    def str_into_starlette_secret(cls, v: str) -> StarletteSecret:
        if isinstance(v, str):
            return StarletteSecret(v)
        msg = "The value must be a string"
        raise TypeError(msg)

    debug_mode: bool = False

    model_config = SettingsConfigDict(env_file=".env")

    @property
    def api_prefix_version(self) -> str:
        return f"{self.api_prefix}/{self.api_version}"

    @property
    def db_url(self) -> URL:
        return URL.create(
            drivername=self.db_driver,
            username=self.db_username.get_secret_value(),
            password=self.db_password.get_secret_value(),
            host=self.db_host,
            port=self.db_port,
            database=self.db_database,
        )

    @property
    def master_key_bytes(self) -> bytes:
        return bytes.fromhex(self.master_key.get_secret_value())

    @property
    def hmac_key_bytes(self) -> bytes:
        return bytes.fromhex(self.hmac_key.get_secret_value())


settings = Settings()

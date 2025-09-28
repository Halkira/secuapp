from pydantic_settings import BaseSettings
from pydantic import EmailStr

class Settings(BaseSettings):
    resend_api_key: str
    resend_api_email: EmailStr

    class Config:
        env_file = ".env"

settings = Settings()

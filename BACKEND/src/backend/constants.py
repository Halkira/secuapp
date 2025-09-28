from enum import IntEnum, StrEnum

SCHEME = "https"

RP_ID: str = "localhost"


class Port(IntEnum):
    FRONTEND = 5175
    BACKEND = 8080
    NGINX = 443


class Origin(StrEnum):
    BASE = f"{SCHEME}://{RP_ID}"
    FRONTEND = f"{SCHEME}://{RP_ID}:{Port.FRONTEND}"
    BACKEND = f"{SCHEME}://{RP_ID}:{Port.BACKEND}"
    NGINX = f"{SCHEME}://{RP_ID}:{Port.NGINX}"


ORIGINS: list[str] = [origin.value for origin in list(Origin)]


RP_NAME: str = "SecuApp"
RP_ORIGINS: list[str] = ORIGINS

REDIS_TEMP_KEY_TTL_SECONDS: int = 10 * 60  # 10 minutes

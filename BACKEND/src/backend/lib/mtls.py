from enum import StrEnum, auto
from typing import Any, Self

from pydantic import (
    BaseModel,
    EmailStr,
    Field,
    field_validator,
    model_validator,
)

COUNTRY_CODE_LENGTH = 2


class MTLSClientVerify(StrEnum):
    SUCCESS = auto()
    FAILED = auto()

    @classmethod
    def from_str(cls, value: str) -> Self:
        try:
            return cls[value.upper()]
        except ValueError:
            return cls.FAILED


class MTLSClientDistinguishedName(BaseModel):
    email_address: EmailStr = Field(alias="emailAddress")
    state: str = Field(alias="ST")
    country: str = Field(alias="C")
    organization: str = Field(alias="O")
    common_name: str = Field(alias="CN")

    @model_validator(mode="before")
    @classmethod
    def parse_input(cls, data: Any) -> dict[str, Any]:  # noqa: ANN401
        if isinstance(data, dict):
            inner = data.get("data", None)

            if not isinstance(inner, str):
                return data

            return {
                k.strip(): v.strip()
                for item in (i.strip() for i in inner.split(","))
                if "=" in item
                for k, v in [item.split("=", 1)]
            }
        return data

    @field_validator("country")
    @classmethod
    def validate_country(cls, v: str) -> str:
        if not v:
            msg = "Country code is required"
            raise ValueError(msg)

        if len(v) != COUNTRY_CODE_LENGTH:
            msg = "Country code must be 2 characters"
            raise ValueError(msg)

        if not v.isalpha():
            msg = "Country code must be alphabetic"
            raise ValueError(msg)

        if not v.isupper():
            msg = "Country code must be uppercase"
            raise ValueError(msg)

        return v

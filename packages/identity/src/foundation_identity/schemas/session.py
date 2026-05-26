"""Session schemas — align with contracts/openapi/identity.yaml."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, SecretStr
from pydantic.types import StringConstraints


class EmailPasswordCredential(BaseModel):
    model_config = ConfigDict(extra="forbid")

    method: Literal["EMAIL_PASSWORD"]
    email: EmailStr
    password: SecretStr
    device_id: str | None = None


class OidcCredential(BaseModel):
    model_config = ConfigDict(extra="forbid")

    method: Literal["OIDC"]
    provider: Annotated[str, StringConstraints(min_length=1, max_length=100)]
    code: str
    redirect_uri: str


class SamlCredential(BaseModel):
    model_config = ConfigDict(extra="forbid")

    method: Literal["SAML"]
    provider: str
    saml_response: str


CreateSessionRequest = EmailPasswordCredential | OidcCredential | SamlCredential


class SessionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str = Field(pattern=r"^sess_[0-9A-Z]{26}$")
    user_id: str = Field(pattern=r"^usr_[0-9A-Z]{26}$")
    tenant_id: str = Field(pattern=r"^tnt_[0-9A-Z]{26}$")
    access_token: str
    refresh_token: str
    token_type: Literal["BEARER"] = "BEARER"
    expires_at: datetime
    issued_at: datetime
    scopes: list[str] = Field(default_factory=list)
    device_id: str | None = None

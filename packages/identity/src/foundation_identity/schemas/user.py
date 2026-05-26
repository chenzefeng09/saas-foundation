"""User schemas — align with contracts/openapi/identity.yaml `User`."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field

USER_ID_PATTERN = r"^usr_[0-9A-Z]{26}$"
TENANT_ID_PATTERN = r"^tnt_[0-9A-Z]{26}$"

UserStatus = Literal["ACTIVE", "INVITED", "SUSPENDED", "LOCKED", "DEACTIVATED", "FROZEN"]


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str = Field(pattern=USER_ID_PATTERN)
    tenant_id: str = Field(pattern=TENANT_ID_PATTERN)
    email: EmailStr
    display_name: str | None = None
    status: UserStatus
    roles: list[str] = Field(default_factory=list)
    last_login_at: datetime | None = None
    mfa_enabled: bool = False
    external_id: str | None = None
    created_at: datetime
    updated_at: datetime
    deleted_at: datetime | None = None


class InviteUserRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    display_name: str | None = Field(default=None, max_length=200)
    roles: list[str] = Field(default_factory=list)
    send_invite_email: bool = True


class UpdateUserRequest(BaseModel):
    """JSON Merge Patch — all fields optional."""

    model_config = ConfigDict(extra="forbid")

    display_name: str | None = None
    status: UserStatus | None = None
    roles: list[str] | None = None


class FreezeUserRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=5, max_length=500)

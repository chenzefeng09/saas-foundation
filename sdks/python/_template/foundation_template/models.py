"""Pydantic models — should ideally be generated from contracts/openapi/*.yaml.

For the template we hand-write a few examples. Real SDKs run:
    datamodel-codegen --input ../../contracts/openapi/<service>.yaml \\
                      --output foundation_<service>/models.py \\
                      --output-model-type pydantic_v2.BaseModel
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserStatus(StrEnum):
    ACTIVE = "ACTIVE"
    INVITED = "INVITED"
    SUSPENDED = "SUSPENDED"
    LOCKED = "LOCKED"
    DEACTIVATED = "DEACTIVATED"


class User(BaseModel):
    """User resource — mirrors OpenAPI Schema User."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    id: str = Field(pattern=r"^usr_[0-9A-Z]{26}$")
    tenant_id: str = Field(pattern=r"^tnt_[0-9A-Z]{26}$")
    email: EmailStr
    display_name: str | None = None
    status: UserStatus
    roles: list[str] = Field(default_factory=list)
    last_login_at: datetime | None = None
    mfa_enabled: bool = False
    created_at: datetime
    updated_at: datetime
    deleted_at: datetime | None = None


class CreateUserRequest(BaseModel):
    email: EmailStr
    display_name: str | None = None
    send_invite: bool = True
    roles: list[str] = Field(default_factory=list)


class UpdateUserRequest(BaseModel):
    """JSON Merge Patch — None means delete the field."""

    display_name: str | None = None
    status: UserStatus | None = None


class UserListPage(BaseModel):
    items: list[User]
    next_cursor: str | None = None

"""Role schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

ROLE_ID_PATTERN = r"^rol_[0-9A-Z]{26}$"
TENANT_ID_PATTERN = r"^tnt_[0-9A-Z]{26}$"

RoleScope = Literal["TENANT", "ORG_UNIT", "TEAM", "RESOURCE"]


class RoleRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str = Field(pattern=ROLE_ID_PATTERN)
    tenant_id: str = Field(pattern=TENANT_ID_PATTERN)
    name: str
    display_name: str
    description: str | None = None
    is_system: bool = False
    immutable: bool = False
    permissions: list[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class CreateRoleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[a-z][a-z0-9_]{1,99}$")
    display_name: str = Field(min_length=1, max_length=200)
    description: str | None = None
    permissions: list[str] = Field(default_factory=list)


class UpdateRoleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    display_name: str | None = None
    description: str | None = None
    permissions: list[str] | None = None

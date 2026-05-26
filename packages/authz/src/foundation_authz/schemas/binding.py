"""Role binding schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

PrincipalKind = Literal["USER", "TEAM", "ORG_UNIT", "API_KEY", "SERVICE_ACCOUNT"]
ScopeKind = Literal["TENANT", "ORG_UNIT", "TEAM", "RESOURCE", "GLOBAL_SYSTEM"]


class RoleBindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str = Field(pattern=r"^rbd_[0-9A-Z]{26}$")
    tenant_id: str = Field(pattern=r"^tnt_[0-9A-Z]{26}$")
    principal_kind: PrincipalKind
    principal_id: str
    role_id: str = Field(pattern=r"^rol_[0-9A-Z]{26}$")
    scope_kind: ScopeKind
    scope_id: str | None = None
    granted_at: datetime
    expires_at: datetime | None = None
    granted_by: str
    grant_reason: str | None = None
    revoked_at: datetime | None = None


class CreateBindingRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    principal_kind: PrincipalKind
    principal_id: str = Field(min_length=1, max_length=64)
    role_id: str = Field(pattern=r"^rol_[0-9A-Z]{26}$")
    scope_kind: ScopeKind = "TENANT"
    scope_id: str | None = None
    expires_at: datetime | None = None
    grant_reason: str | None = Field(default=None, max_length=500)

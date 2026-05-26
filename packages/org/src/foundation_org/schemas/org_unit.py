"""Org-unit API schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from foundation_org.schemas.common import (
    OU_CODE_PATTERN,
    OU_ID_PATTERN,
    TENANT_ID_PATTERN,
    USER_ID_PATTERN,
)

OrgUnitKind = Literal["BU", "DEPARTMENT", "CENTER", "OFFICE", "VIRTUAL"]


class OrgUnitRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str = Field(pattern=OU_ID_PATTERN)
    tenant_id: str = Field(pattern=TENANT_ID_PATTERN)
    parent_id: str | None = Field(default=None, pattern=OU_ID_PATTERN)
    code: str = Field(pattern=OU_CODE_PATTERN)
    name: str
    name_en: str | None = None
    description: str | None = None
    manager_user_id: str | None = Field(default=None, pattern=USER_ID_PATTERN)
    kind: OrgUnitKind = "DEPARTMENT"
    path: str
    depth: int
    sort_order: int = 0
    is_archived: bool = False
    created_at: datetime
    updated_at: datetime


class CreateOrgUnitRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    parent_id: str | None = Field(default=None, pattern=OU_ID_PATTERN)
    code: str = Field(pattern=OU_CODE_PATTERN)
    name: str = Field(min_length=1, max_length=200)
    name_en: str | None = Field(default=None, max_length=200)
    description: str | None = None
    manager_user_id: str | None = Field(default=None, pattern=USER_ID_PATTERN)
    kind: OrgUnitKind = "DEPARTMENT"
    sort_order: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)


class UpdateOrgUnitRequest(BaseModel):
    """Patches: NOTE `code` is immutable (use move + alias)."""

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=200)
    name_en: str | None = Field(default=None, max_length=200)
    description: str | None = None
    manager_user_id: str | None = Field(default=None, pattern=USER_ID_PATTERN)
    sort_order: int | None = None
    metadata: dict[str, Any] | None = None


class MoveOrgUnitRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    new_parent_id: str | None = Field(default=None, pattern=OU_ID_PATTERN)
    preserve_managers: bool = True
    reason: str | None = Field(default=None, max_length=500)


class ArchiveOrgUnitRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str | None = Field(default=None, max_length=500)


class OrgUnitTreeNode(BaseModel):
    """Recursive node for the full-tree endpoint."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    code: str
    name: str
    kind: OrgUnitKind
    depth: int
    sort_order: int
    is_archived: bool
    children: list[OrgUnitTreeNode] = Field(default_factory=list)


OrgUnitTreeNode.model_rebuild()

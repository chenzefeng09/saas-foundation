"""Team API schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from foundation_org.schemas.common import (
    OU_ID_PATTERN,
    TEAM_CODE_PATTERN,
    TEAM_ID_PATTERN,
    TENANT_ID_PATTERN,
    USER_ID_PATTERN,
)

TeamKind = Literal["PROJECT", "SQUAD", "GUILD", "VIRTUAL"]
TeamRole = Literal["MEMBER", "LEAD", "OBSERVER"]


class TeamRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str = Field(pattern=TEAM_ID_PATTERN)
    tenant_id: str = Field(pattern=TENANT_ID_PATTERN)
    org_unit_id: str = Field(pattern=OU_ID_PATTERN)
    code: str = Field(pattern=TEAM_CODE_PATTERN)
    name: str
    description: str | None = None
    lead_user_id: str | None = Field(default=None, pattern=USER_ID_PATTERN)
    kind: TeamKind = "PROJECT"
    is_archived: bool = False
    created_at: datetime
    updated_at: datetime


class CreateTeamRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    org_unit_id: str = Field(pattern=OU_ID_PATTERN)
    code: str = Field(pattern=TEAM_CODE_PATTERN)
    name: str = Field(min_length=1, max_length=200)
    description: str | None = None
    lead_user_id: str | None = Field(default=None, pattern=USER_ID_PATTERN)
    kind: TeamKind = "PROJECT"
    metadata: dict[str, Any] = Field(default_factory=dict)


class UpdateTeamRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = None
    lead_user_id: str | None = Field(default=None, pattern=USER_ID_PATTERN)
    metadata: dict[str, Any] | None = None


class TeamMemberRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    user_id: str = Field(pattern=USER_ID_PATTERN)
    team_id: str = Field(pattern=TEAM_ID_PATTERN)
    role_in_team: TeamRole = "MEMBER"
    joined_at: datetime
    left_at: datetime | None = None


class AddTeamMemberRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: str = Field(pattern=USER_ID_PATTERN)
    role_in_team: TeamRole = "MEMBER"

"""User membership + secondary OU schemas."""

from __future__ import annotations

from datetime import date, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from foundation_org.schemas.common import (
    OU_ID_PATTERN,
    TEAM_ID_PATTERN,
    TENANT_ID_PATTERN,
    USER_ID_PATTERN,
)

EmploymentKind = Literal["EMPLOYEE", "CONTRACTOR", "INTERN", "EXTERNAL"]
SecondaryReason = Literal["TEMP_ASSIGN", "DOTTED_LINE", "CROSS_TEAM"]


class UserMembershipRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    user_id: str = Field(pattern=USER_ID_PATTERN)
    tenant_id: str = Field(pattern=TENANT_ID_PATTERN)
    primary_org_unit_id: str = Field(pattern=OU_ID_PATTERN)
    job_title: str | None = None
    employee_no: str | None = None
    join_date: date
    leave_date: date | None = None
    manager_user_id: str | None = Field(default=None, pattern=USER_ID_PATTERN)
    employment_kind: EmploymentKind = "EMPLOYEE"
    created_at: datetime
    updated_at: datetime


class UpsertUserMembershipRequest(BaseModel):
    """PUT semantics: full replacement of the membership row."""

    model_config = ConfigDict(extra="forbid")

    primary_org_unit_id: str = Field(pattern=OU_ID_PATTERN)
    job_title: str | None = Field(default=None, max_length=200)
    employee_no: str | None = Field(default=None, max_length=64)
    join_date: date | None = None
    manager_user_id: str | None = Field(default=None, pattern=USER_ID_PATTERN)
    employment_kind: EmploymentKind = "EMPLOYEE"
    metadata: dict[str, Any] = Field(default_factory=dict)


class TransferUserRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    to_org_unit_id: str = Field(pattern=OU_ID_PATTERN)
    to_team_ids: list[str] = Field(default_factory=list)
    effective_date: date | None = None
    reason: str | None = Field(default=None, max_length=500)


class SecondaryAssignmentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    user_id: str
    org_unit_id: str
    tenant_id: str
    reason: SecondaryReason
    valid_from: datetime
    valid_until: datetime | None = None
    granted_by: str


class CreateSecondaryAssignmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    org_unit_id: str = Field(pattern=OU_ID_PATTERN)
    reason: SecondaryReason = "TEMP_ASSIGN"
    valid_until: datetime | None = None

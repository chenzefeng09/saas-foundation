"""Shared ID patterns + pagination + problem-detail schema.

Mirrors `contracts/openapi/_common.yaml` and the sibling authz package's
common module so SDKs can share the wrapper shapes.
"""

from __future__ import annotations

from datetime import datetime
from typing import Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field

TENANT_ID_PATTERN = r"^tnt_[0-9A-Z]{26}$"
OU_ID_PATTERN = r"^ou_[0-9A-Z]{26}$"
TEAM_ID_PATTERN = r"^tm_[0-9A-Z]{26}$"
USER_ID_PATTERN = r"^usr_[0-9A-Z]{26}$"
REQUEST_ID_PATTERN = r"^req_[0-9A-Z]{26}$"

# Org-unit `code` is ASCII slug — used to build ltree path labels.
# Letters/digits/underscore/hyphen, 1-32 chars, must start with [a-z].
OU_CODE_PATTERN = r"^[a-z][a-z0-9_-]{0,31}$"
TEAM_CODE_PATTERN = OU_CODE_PATTERN


T = TypeVar("T")


class CursorPage(BaseModel, Generic[T]):
    """Cursor-paginated response wrapper."""

    model_config = ConfigDict(arbitrary_types_allowed=True)
    items: list[T]
    next_cursor: str | None = None


class HealthStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["OK", "DEGRADED", "UNHEALTHY"] = "OK"
    service: str
    version: str
    uptime_seconds: int = 0
    dependencies: dict[str, dict[str, str | int]] | None = None


class ProblemDetails(BaseModel):
    model_config = ConfigDict(extra="allow")
    type: str
    title: str
    status: int
    code: str = Field(pattern=r"^[A-Z][A-Z_]+\.[A-Z][A-Z_]+\.[A-Z][A-Z_]+\.[A-Z][A-Z_]+$")
    detail: str
    user_message: str | None = None
    instance: str
    request_id: str
    trace_id: str | None = None
    timestamp: datetime

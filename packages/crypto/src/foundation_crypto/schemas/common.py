"""Shared ID patterns + pagination + health + problem-detail.

Mirrors `contracts/openapi/_common.yaml` and the sibling authz/org common
modules so SDKs can share the wrapper shapes.
"""

from __future__ import annotations

from datetime import datetime
from typing import Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field

TENANT_ID_PATTERN = r"^tnt_[0-9A-Z]{26}$"
USER_ID_PATTERN = r"^usr_[0-9A-Z]{26}$"
REQUEST_ID_PATTERN = r"^req_[0-9A-Z]{26}$"

KEK_ID_PATTERN = r"^kek_[0-9A-Z]{26}$"
KEK_LABEL_PATTERN = r"^[a-z][a-z0-9._-]{1,119}$"
ALGORITHM_ID_PATTERN = r"^[A-Za-z][A-Za-z0-9._-]{1,59}$"


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

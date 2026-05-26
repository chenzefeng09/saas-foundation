"""Shared response shapes — mirror contracts/openapi/_common.yaml."""

from __future__ import annotations

from datetime import datetime
from typing import Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


class CursorPage(BaseModel, Generic[T]):
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


class _FieldError(BaseModel):
    field: str
    code: str
    detail: str
    user_message: str | None = None


class ValidationProblemDetails(ProblemDetails):
    errors: list[_FieldError] = Field(default_factory=list)

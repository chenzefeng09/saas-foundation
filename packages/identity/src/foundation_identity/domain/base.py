"""Declarative base + tenant context propagation primitive."""

from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass
from typing import Literal

from sqlalchemy import Column, MetaData, String, Table
from sqlalchemy.orm import DeclarativeBase

ActorKind = Literal["USER", "SERVICE", "SYSTEM", "MIGRATOR", "ADMIN"]


@dataclass(frozen=True, slots=True)
class FoundationContext:
    """Per-request context that survives all layers.

    Populated by API middleware from JWT / X-* headers.
    Consumed by:
      - DB session factory  → `SET LOCAL app.tenant_id = ...`
      - audit publisher     → actor / request_id
      - logger              → bound context
    """

    tenant_id: str
    user_id: str | None
    actor: ActorKind
    request_id: str
    trace_id: str | None = None


# Per-asyncio-task contextvar (FastAPI request lifecycle)
foundation_context: ContextVar[FoundationContext | None] = ContextVar(
    "foundation_context",
    default=None,
)


class Base(DeclarativeBase):
    """Project-wide declarative base. All identity ORM models inherit from this."""

    pass


# Stub declaration for `tenant.tenant` — owned by `org-service`, but our FKs
# reference it. Registering as a Table (no mapper) gives SQLAlchemy enough to
# resolve FK targets without us having to reflect or import the org package.
tenant_stub = Table(
    "tenant",
    Base.metadata,
    Column("id", String(30), primary_key=True),
    schema="tenant",
)

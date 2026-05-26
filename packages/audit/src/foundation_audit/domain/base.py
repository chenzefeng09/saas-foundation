"""Declarative base + tenant context propagation."""

from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass
from typing import Literal

from sqlalchemy import Column, MetaData, String, Table
from sqlalchemy.orm import DeclarativeBase

ActorKind = Literal["USER", "SERVICE", "SYSTEM", "MIGRATOR", "ADMIN"]


@dataclass(frozen=True, slots=True)
class FoundationContext:
    tenant_id: str
    user_id: str | None
    actor: ActorKind
    request_id: str
    trace_id: str | None = None


foundation_context: ContextVar[FoundationContext | None] = ContextVar("foundation_context", default=None)


class Base(DeclarativeBase):
    pass


tenant_stub = Table("tenant", Base.metadata, Column("id", String(30), primary_key=True), schema="tenant")

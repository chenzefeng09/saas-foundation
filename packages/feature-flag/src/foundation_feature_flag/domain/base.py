"""Declarative base and context helpers."""
from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass
from typing import Literal

from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase

# ---------------------------------------------------------------------------
# Foundation request context
# ---------------------------------------------------------------------------
ActorKind = Literal["USER", "SERVICE", "SYSTEM", "MIGRATOR", "ADMIN"]


@dataclass(frozen=True, slots=True)
class FoundationContext:
    tenant_id: str
    user_id: str | None = None
    actor: str = "USER"
    request_id: str = ""


foundation_context: ContextVar[FoundationContext | None] = ContextVar(
    "foundation.context", default=None
)

# ---------------------------------------------------------------------------
# SQLAlchemy declarative base (naming convention mirrors billing)
# ---------------------------------------------------------------------------
_NAMING_CONVENTION: dict[str, str] = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=_NAMING_CONVENTION)

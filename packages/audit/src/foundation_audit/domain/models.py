"""SQLAlchemy ORM models — audit schema (audit-v1 §3.4)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, DateTime, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from foundation_audit.domain.base import Base


class Outbox(Base):
    """Transactional outbox: events land here before ClickHouse ingestion."""

    __tablename__ = "outbox"
    __table_args__ = (
        Index("ix_audit_outbox_pending", "id", postgresql_where="delivered_at IS NULL"),
        {"schema": "audit"},
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(30), nullable=False)
    event_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    enqueued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_error: Mapped[str | None] = mapped_column(Text)

"""SQLAlchemy ORM models — dlp schema (dlp-classification-v1 §2-4)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from sqlalchemy import (
    BigInteger, Boolean, DateTime, ForeignKey, Index, Integer,
    String, Text, UniqueConstraint, func,
)
from sqlalchemy.dialects.postgresql import JSONB, ARRAY
from sqlalchemy.orm import Mapped, mapped_column

from foundation_dlp.domain.base import Base

# 5-level sensitivity: L1=公开, L2=内部, L3=秘密, L4=机密, L5=绝密
SensitivityLevel = Literal["L1", "L2", "L3", "L4", "L5"]


# ---------------------------------------------------------------------------
# Classification — resource sensitivity tags
# ---------------------------------------------------------------------------
class Classification(Base):
    __tablename__ = "classification"
    __table_args__ = (
        UniqueConstraint("tenant_id", "resource_type", "resource_id", name="uq_classification_resource"),
        Index("class_tenant_idx", "tenant_id"),
        Index("class_sensitivity_idx", "sensitivity"),
        {"schema": "dlp"},
    )

    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(30), ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(50), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(64), nullable=False)
    sensitivity: Mapped[str] = mapped_column(
        String(2), nullable=False, default="L2",
        comment="L1/L2/L3/L4/L5")
    tags: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    reason: Mapped[str | None] = mapped_column(Text)
    auto_upgraded: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    tagged_by: Mapped[str | None] = mapped_column(String(30))
    tagged_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    # Whether the classification can be downgraded (L5 cannot)
    downgradable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


# ---------------------------------------------------------------------------
# DLP Rule — per-tenant pattern rule for sensitive content detection
# ---------------------------------------------------------------------------
class DLPRule(Base):
    __tablename__ = "dlp_rule"
    __table_args__ = (
        Index("dlp_rule_tenant_idx", "tenant_id"),
        {"schema": "dlp"},
    )

    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    tenant_id: Mapped[str | None] = mapped_column(
        String(30), ForeignKey("tenant.tenant.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    rule_type: Mapped[str] = mapped_column(
        String(30), nullable=False,
        comment="REGEX / KEYWORD / ML_MODEL / COMPOSITE")
    pattern: Mapped[str] = mapped_column(Text, nullable=False)  # regex or keyword JSON array
    min_sensitivity: Mapped[str] = mapped_column(
        String(2), nullable=False, default="L3",
        comment="Minimum sensitivity triggered when this rule matches")
    description: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    created_by: Mapped[str | None] = mapped_column(String(30))


# ---------------------------------------------------------------------------
# DLP Event — audit log of DLP decisions
# ---------------------------------------------------------------------------
class DLPEvent(Base):
    __tablename__ = "dlp_event"
    __table_args__ = (
        Index("dlp_event_tenant_time_idx", "tenant_id", "occurred_at"),
        {"schema": "dlp"},
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(30), nullable=False)
    decision: Mapped[str] = mapped_column(
        String(20), nullable=False, comment="ALLOW / DENY / SCAN_REQUIRED / QUARANTINE")
    check_type: Mapped[str] = mapped_column(
        String(30), nullable=False, comment="READ / DOWNLOAD / EXPORT / SCAN_UPLOAD")
    user_id: Mapped[str | None] = mapped_column(String(30))
    resource_type: Mapped[str | None] = mapped_column(String(50))
    resource_id: Mapped[str | None] = mapped_column(String(64))
    reason_code: Mapped[str | None] = mapped_column(String(100))
    detail: Mapped[str | None] = mapped_column(Text)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False)
    request_id: Mapped[str | None] = mapped_column(String(64))


# ---------------------------------------------------------------------------
# Outbox
# ---------------------------------------------------------------------------
class Outbox(Base):
    __tablename__ = "dlp_event_outbox"
    __table_args__ = ({"schema": "dlp"},)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str | None] = mapped_column(String(30))
    event_type: Mapped[str] = mapped_column(String(200), nullable=False)
    aggregate_id: Mapped[str | None] = mapped_column(String(64))
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    request_id: Mapped[str | None] = mapped_column(String(64))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

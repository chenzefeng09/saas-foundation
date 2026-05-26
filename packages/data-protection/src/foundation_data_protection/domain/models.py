"""SQLAlchemy ORM models — data_protection schema."""

from __future__ import annotations
from datetime import datetime; from typing import Any

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, ARRAY
from sqlalchemy.orm import Mapped, mapped_column

from foundation_data_protection.domain.base import Base


class CrossBorderTransfer(Base):
    __tablename__ = "cross_border_transfer"
    __table_args__ = (Index("cbt_tenant_idx", "tenant_id"), {"schema": "data_protection"})
    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(30), ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False)
    data_country: Mapped[str] = mapped_column(String(10), nullable=False)
    destination_country: Mapped[str] = mapped_column(String(10), nullable=False)
    data_type: Mapped[str] = mapped_column(String(100), nullable=False)
    data_size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    has_standard_contract: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    has_safety_assessment: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    decision: Mapped[str] = mapped_column(String(20), nullable=False)
    risks: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    request_id: Mapped[str | None] = mapped_column(String(64))


class DataDestructionRequest(Base):
    __tablename__ = "data_destruction_request"
    __table_args__ = (Index("ddr_tenant_idx", "tenant_id"), {"schema": "data_protection"})
    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(30), ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(50), nullable=False)
    resource_ids: Mapped[list[str] | None] = mapped_column(JSONB)
    destruction_method: Mapped[str] = mapped_column(String(30), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    requested_by: Mapped[str] = mapped_column(String(30), nullable=False)
    witness_user_id: Mapped[str | None] = mapped_column(String(30))
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="PENDING_APPROVAL")
    approved_by: Mapped[str | None] = mapped_column(String(30))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    request_id: Mapped[str | None] = mapped_column(String(64))


class ConsentRecord(Base):
    __tablename__ = "consent_record"
    __table_args__ = (Index("cr_tenant_user_idx", "tenant_id", "user_id"), {"schema": "data_protection"})
    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(30), ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[str] = mapped_column(String(30), nullable=False)
    consent_type: Mapped[str] = mapped_column(String(50), nullable=False)
    purpose: Mapped[str] = mapped_column(Text, nullable=False)
    granted: Mapped[bool] = mapped_column(Boolean, nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(45))
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    request_id: Mapped[str | None] = mapped_column(String(64))


class Outbox(Base):
    __tablename__ = "dp_event_outbox"
    __table_args__ = ({"schema": "data_protection"},)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str | None] = mapped_column(String(30))
    event_type: Mapped[str] = mapped_column(String(200), nullable=False)
    aggregate_id: Mapped[str | None] = mapped_column(String(64))
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    request_id: Mapped[str | None] = mapped_column(String(64))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

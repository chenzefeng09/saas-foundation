"""Compliance models."""
from __future__ import annotations
from datetime import datetime; from typing import Any
from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, ARRAY
from sqlalchemy.orm import Mapped, mapped_column
from foundation_compliance.domain.base import Base

class ROPARecord(Base):
    __tablename__ = "ropa_record"
    __table_args__ = (Index("ropa_tenant_idx", "tenant_id"), {"schema": "compliance"})
    id: Mapped[str] = mapped_column(String(40), primary_key=True)  # ULID-prefixed (5-char prefix + 26 = 31)
    tenant_id: Mapped[str] = mapped_column(String(30), ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False)
    service: Mapped[str] = mapped_column(String(50), nullable=False)
    data_category: Mapped[str] = mapped_column(String(100), nullable=False)
    purpose: Mapped[str] = mapped_column(Text, nullable=False)
    legal_basis: Mapped[str] = mapped_column(String(100), nullable=False)
    data_subjects: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    recipients: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    retention_days: Mapped[int] = mapped_column(Integer, nullable=False, default=365)
    cross_border: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    destination_countries: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

class DPIA(Base):
    __tablename__ = "dpia"
    __table_args__ = ({"schema": "compliance"},)
    id: Mapped[str] = mapped_column(String(40), primary_key=True)  # ULID-prefixed (5-char prefix + 26 = 31)
    tenant_id: Mapped[str] = mapped_column(String(30), ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False)
    project_name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    data_categories: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    risks: Mapped[list[dict] | None] = mapped_column(JSONB)
    mitigations: Mapped[list[dict] | None] = mapped_column(JSONB)
    conclusion: Mapped[str] = mapped_column(String(50), nullable=False)
    residual_risks: Mapped[str | None] = mapped_column(Text)
    assessed_by: Mapped[str] = mapped_column(String(30), nullable=False)
    approved_by: Mapped[str | None] = mapped_column(String(30))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

class DSARRequest(Base):
    __tablename__ = "dsar_request"
    __table_args__ = (Index("dsar_tenant_user_idx", "tenant_id", "user_id"), {"schema": "compliance"})
    id: Mapped[str] = mapped_column(String(40), primary_key=True)  # ULID-prefixed (5-char prefix + 26 = 31)
    tenant_id: Mapped[str] = mapped_column(String(30), ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[str] = mapped_column(String(30), nullable=False)
    request_type: Mapped[str] = mapped_column(String(30), nullable=False)
    details: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="RECEIVED")
    sla_deadline: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    response: Mapped[str | None] = mapped_column(Text)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

class ComplianceReport(Base):
    __tablename__ = "compliance_report"
    __table_args__ = ({"schema": "compliance"},)
    id: Mapped[str] = mapped_column(String(40), primary_key=True)  # ULID-prefixed (5-char prefix + 26 = 31)
    tenant_id: Mapped[str] = mapped_column(String(30), ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False)
    report_type: Mapped[str] = mapped_column(String(50), nullable=False)
    compliance_modes: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    content_json: Mapped[dict[str, Any]] = mapped_column("content", JSONB, nullable=False, default=dict)
    generated_by: Mapped[str] = mapped_column(String(30), nullable=False)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

class Outbox(Base):
    __tablename__ = "compliance_event_outbox"
    __table_args__ = ({"schema": "compliance"},)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str | None] = mapped_column(String(30))
    event_type: Mapped[str] = mapped_column(String(200), nullable=False)
    aggregate_id: Mapped[str | None] = mapped_column(String(64))
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    request_id: Mapped[str | None] = mapped_column(String(64))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

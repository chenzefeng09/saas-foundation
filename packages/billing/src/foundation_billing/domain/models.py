"""Billing models."""
from __future__ import annotations
from datetime import datetime; from typing import Any
from sqlalchemy import Boolean, Date, DateTime, Float, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from foundation_billing.domain.base import Base

class SubscriptionPlan(Base):
    __tablename__ = "subscription_plan"
    __table_args__ = ({"schema": "billing"},)
    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    tier: Mapped[str] = mapped_column(String(20), nullable=False)
    quotas: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    price_monthly_usd: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

class TenantSubscription(Base):
    __tablename__ = "tenant_subscription"
    __table_args__ = (Index("ts_tenant_idx", "tenant_id"), {"schema": "billing"})
    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(30), ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False)
    plan_id: Mapped[str] = mapped_column(String(30), nullable=False)
    mode: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="ACTIVE")
    current_period_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    current_period_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

class QuotaUsage(Base):
    __tablename__ = "quota_usage"
    __table_args__ = (Index("qu_tenant_dim_idx", "tenant_id", "dimension"), {"schema": "billing"})
    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(30), ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False)
    dimension: Mapped[str] = mapped_column(String(30), nullable=False)
    current_value: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    last_updated: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

class Invoice(Base):
    __tablename__ = "invoice"
    __table_args__ = (Index("inv_tenant_idx", "tenant_id"), {"schema": "billing"})
    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(30), ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False)
    invoice_number: Mapped[str] = mapped_column(String(100), nullable=False)
    items: Mapped[list[dict] | None] = mapped_column(JSONB)
    total_amount: Mapped[float] = mapped_column(Float, nullable=False)
    currency: Mapped[str] = mapped_column(String(10), nullable=False, default="CNY")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="DRAFT")
    due_date: Mapped[datetime] = mapped_column(Date, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

class Outbox(Base):
    __tablename__ = "billing_event_outbox"
    __table_args__ = ({"schema": "billing"},)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str | None] = mapped_column(String(30))
    event_type: Mapped[str] = mapped_column(String(200), nullable=False)
    aggregate_id: Mapped[str | None] = mapped_column(String(64))
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    request_id: Mapped[str | None] = mapped_column(String(64))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

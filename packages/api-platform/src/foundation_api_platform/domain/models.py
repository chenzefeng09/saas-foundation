"""API Platform models."""
from __future__ import annotations
from datetime import datetime; from typing import Any
from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, ARRAY
from sqlalchemy.orm import Mapped, mapped_column
from foundation_api_platform.domain.base import Base

class APIKey(Base):
    __tablename__ = "api_key"
    __table_args__ = (Index("apk_tenant_idx", "tenant_id"), {"schema": "api_platform"})
    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(30), ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    scopes: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    ip_whitelist: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    rate_limit_rpm: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str] = mapped_column(String(30), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

class OAuthApp(Base):
    __tablename__ = "oauth_app"
    __table_args__ = ({"schema": "api_platform"},)
    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(30), ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    client_id: Mapped[str] = mapped_column(String(100), nullable=False)
    client_secret_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    redirect_uris: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    scopes: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    created_by: Mapped[str] = mapped_column(String(30), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

class WebhookSubscription(Base):
    __tablename__ = "webhook_subscription"
    __table_args__ = (Index("whs_tenant_idx", "tenant_id"), {"schema": "api_platform"})
    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(30), ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False)
    url: Mapped[str] = mapped_column(String(500), nullable=False)
    event_types: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    secret: Mapped[str] = mapped_column(String(200), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

class WebhookDelivery(Base):
    __tablename__ = "webhook_delivery"
    __table_args__ = ({"schema": "api_platform"},)
    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    subscription_id: Mapped[str] = mapped_column(String(30), nullable=False)
    event_type: Mapped[str] = mapped_column(String(200), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    response_status: Mapped[int | None] = mapped_column(Integer)
    response_body: Mapped[str | None] = mapped_column(Text)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

class Outbox(Base):
    __tablename__ = "api_platform_event_outbox"
    __table_args__ = ({"schema": "api_platform"},)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str | None] = mapped_column(String(30))
    event_type: Mapped[str] = mapped_column(String(200), nullable=False)
    aggregate_id: Mapped[str | None] = mapped_column(String(64))
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    request_id: Mapped[str | None] = mapped_column(String(64))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

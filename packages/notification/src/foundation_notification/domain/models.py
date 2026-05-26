"""SQLAlchemy ORM models — notification schema."""

from __future__ import annotations
from datetime import datetime; from typing import Any
from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, ARRAY
from sqlalchemy.orm import Mapped, mapped_column
from foundation_notification.domain.base import Base


class NotificationTemplate(Base):
    __tablename__ = "notification_template"
    __table_args__ = (Index("nt_tenant_event_idx", "tenant_id", "event_type"), {"schema": "notification"})
    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(30), ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False)
    event_type: Mapped[str] = mapped_column(String(200), nullable=False)
    locale: Mapped[str] = mapped_column(String(10), nullable=False, default="zh-CN")
    subject_template: Mapped[str] = mapped_column(Text, nullable=False)
    body_template: Mapped[str] = mapped_column(Text, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class NotificationChannel(Base):
    __tablename__ = "notification_channel"
    __table_args__ = (UniqueConstraint("tenant_id", "channel", name="uq_channel"), {"schema": "notification"})
    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(30), ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False)
    channel: Mapped[str] = mapped_column(String(20), nullable=False)
    config: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class NotificationSubscription(Base):
    __tablename__ = "notification_subscription"
    __table_args__ = (Index("nsub_tenant_idx", "tenant_id"), {"schema": "notification"})
    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(30), ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False)
    subscriber_kind: Mapped[str] = mapped_column(String(20), nullable=False)
    subscriber_id: Mapped[str] = mapped_column(String(64), nullable=False)
    event_types: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    channel: Mapped[str] = mapped_column(String(20), nullable=False, default="EMAIL")
    config: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class NotificationLog(Base):
    __tablename__ = "notification_log"
    __table_args__ = (Index("nlog_tenant_time_idx", "tenant_id", "sent_at"), {"schema": "notification"})
    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(30), nullable=False)
    event_type: Mapped[str] = mapped_column(String(200), nullable=False)
    recipient: Mapped[str] = mapped_column(String(200), nullable=False)
    channel: Mapped[str] = mapped_column(String(20), nullable=False)
    subject: Mapped[str] = mapped_column(String(500), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    detail: Mapped[str | None] = mapped_column(Text)
    sent_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    request_id: Mapped[str | None] = mapped_column(String(64))


class Outbox(Base):
    __tablename__ = "notification_event_outbox"
    __table_args__ = ({"schema": "notification"},)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str | None] = mapped_column(String(30))
    event_type: Mapped[str] = mapped_column(String(200), nullable=False)
    aggregate_id: Mapped[str | None] = mapped_column(String(64))
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    request_id: Mapped[str | None] = mapped_column(String(64))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

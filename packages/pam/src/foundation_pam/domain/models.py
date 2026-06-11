"""PAM models."""
from __future__ import annotations
from datetime import datetime; from typing import Any
from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, ARRAY
from sqlalchemy.orm import Mapped, mapped_column
from foundation_pam.domain.base import Base

class PAMElevationRequest(Base):
    __tablename__ = "pam_elevation_request"
    __table_args__ = (Index("pam_req_tenant_idx", "tenant_id"), {"schema": "pam"})
    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(30), ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[str] = mapped_column(String(30), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    target_permissions: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    duration_minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    ticket_reference: Mapped[str | None] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="PENDING")
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    approved_by: Mapped[str | None] = mapped_column(String(30))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    approval_reason: Mapped[str | None] = mapped_column(Text)

class PAMSession(Base):
    __tablename__ = "pam_session"
    __table_args__ = (Index("pam_sess_active_idx", "tenant_id", "is_active"), {"schema": "pam"})
    id: Mapped[str] = mapped_column(String(40), primary_key=True)  # "pams_" + 26-char ULID = 31 chars
    tenant_id: Mapped[str] = mapped_column(String(30), ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False)
    elevation_request_id: Mapped[str] = mapped_column(String(30), nullable=False)
    user_id: Mapped[str] = mapped_column(String(30), nullable=False)
    approved_by: Mapped[str] = mapped_column(String(30), nullable=False)
    permissions: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_by: Mapped[str | None] = mapped_column(String(30))
    revocation_reason: Mapped[str | None] = mapped_column(Text)

class Outbox(Base):
    __tablename__ = "pam_event_outbox"
    __table_args__ = ({"schema": "pam"},)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str | None] = mapped_column(String(30))
    event_type: Mapped[str] = mapped_column(String(200), nullable=False)
    aggregate_id: Mapped[str | None] = mapped_column(String(64))
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    request_id: Mapped[str | None] = mapped_column(String(64))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

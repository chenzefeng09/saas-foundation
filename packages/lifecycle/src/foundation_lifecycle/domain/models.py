"""SQLAlchemy ORM models — lifecycle schema (lifecycle-v1 §3)."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import (
    BigInteger, Boolean, Date, DateTime, ForeignKey, Index, Integer,
    SmallInteger, String, Text, UniqueConstraint, func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from foundation_lifecycle.domain.base import Base


# ---------------------------------------------------------------------------
# ResourceType — platform-level; each service registers its deletable resources
# ---------------------------------------------------------------------------
class ResourceType(Base):
    __tablename__ = "resource_type"
    __table_args__ = ({"schema": "lifecycle"},)

    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    service: Mapped[str] = mapped_column(String(50), nullable=False)
    kind: Mapped[str] = mapped_column(String(50), nullable=False)  # "org_unit" / "user_data" / "document"
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    # Default retention (days after created_at or last_modified, depending on anchor)
    retention_days_default: Mapped[int] = mapped_column(Integer, nullable=False, default=365)
    retention_anchor: Mapped[str] = mapped_column(
        String(20), nullable=False, default="created_at",
        comment="created_at / last_modified / explicit_expiry",
    )
    recycle_bin_days: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    # How to destroy: crypto_key_destroy / dod_overwrite / truncate / none
    destruction_method: Mapped[str] = mapped_column(String(30), nullable=False, default="truncate")
    # Whether this type demands a destruction certificate
    requires_destruction_certificate: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_system: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    created_by: Mapped[str | None] = mapped_column(String(30))


# ---------------------------------------------------------------------------
# RetentionPolicyOverride — per-tenant override on defaults
# ---------------------------------------------------------------------------
class RetentionPolicyOverride(Base):
    __tablename__ = "retention_policy_override"
    __table_args__ = (
        UniqueConstraint("tenant_id", "resource_type_id", name="uq_retention_override"),
        {"schema": "lifecycle"},
    )

    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(30), ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False)
    resource_type_id: Mapped[str] = mapped_column(
        String(30), ForeignKey("lifecycle.resource_type.id"), nullable=False)
    retention_days: Mapped[int | None] = mapped_column(Integer)  # null = use default
    recycle_bin_days: Mapped[int | None] = mapped_column(Integer)
    locked_by_compliance: Mapped[str | None] = mapped_column(String(50))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    updated_by: Mapped[str | None] = mapped_column(String(30))


# ---------------------------------------------------------------------------
# RecycleBin — soft-deleted resources awaiting hard-delete
# ---------------------------------------------------------------------------
class RecycleBin(Base):
    __tablename__ = "recycle_bin"
    __table_args__ = (
        Index("rb_tenant_type_idx", "tenant_id", "resource_type_id"),
        Index("rb_expires_idx", "expires_at", postgresql_where="restored_at IS NULL AND hard_deleted_at IS NULL"),
        {"schema": "lifecycle"},
    )

    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(30), ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False)
    resource_type_id: Mapped[str] = mapped_column(
        String(30), ForeignKey("lifecycle.resource_type.id"), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_name: Mapped[str | None] = mapped_column(String(500))
    deleted_by: Mapped[str] = mapped_column(String(30), nullable=False)
    deleted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    restored_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    restored_by: Mapped[str | None] = mapped_column(String(30))
    hard_deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    original_location: Mapped[str | None] = mapped_column(Text)  # JSON: where to find the original data


# ---------------------------------------------------------------------------
# LegalHold — preserves a resource from any deletion
# ---------------------------------------------------------------------------
class LegalHold(Base):
    __tablename__ = "legal_hold"
    __table_args__ = (
        Index("lh_tenant_resource_idx", "tenant_id", "resource_type_id", "resource_id"),
        Index("lh_released_idx", "released_at", postgresql_where="released_at IS NULL"),
        {"schema": "lifecycle"},
    )

    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(30), ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False)
    resource_type_id: Mapped[str] = mapped_column(String(30), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(64), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    placed_by: Mapped[str] = mapped_column(String(30), nullable=False)
    placed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False)
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    released_by: Mapped[str | None] = mapped_column(String(30))
    case_reference: Mapped[str | None] = mapped_column(String(200))  # e.g. court case number


# ---------------------------------------------------------------------------
# DestructionCertificate — proof of data destruction
# ---------------------------------------------------------------------------
class DestructionCertificate(Base):
    __tablename__ = "destruction_certificate"
    __table_args__ = (
        Index("dc_tenant_idx", "tenant_id"),
        {"schema": "lifecycle"},
    )

    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(30), ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False)
    resource_type_id: Mapped[str] = mapped_column(String(30), nullable=False)
    resource_ids: Mapped[list[str] | None] = mapped_column(JSONB)
    destruction_method: Mapped[str] = mapped_column(String(30), nullable=False)
    destroyed_by: Mapped[str] = mapped_column(String(30), nullable=False)
    witness_user_id: Mapped[str | None] = mapped_column(String(30))  # four-eyes
    destroyed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    certificate_hash: Mapped[str] = mapped_column(String(64), nullable=False)  # SHA-256
    certificate_pdf_uri: Mapped[str | None] = mapped_column(String(500))
    audit_event_id: Mapped[str | None] = mapped_column(String(30))


# ---------------------------------------------------------------------------
# DestructionJob — scheduled destruction task runs
# ---------------------------------------------------------------------------
class DestructionJob(Base):
    __tablename__ = "destruction_job"
    __table_args__ = ({"schema": "lifecycle"},)

    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="SCHEDULED",
        comment="SCHEDULED / RUNNING / COMPLETED / FAILED / CANCELLED")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resources_destroyed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    errors_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_detail: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# ---------------------------------------------------------------------------
# OrphanReconcileReport — one row per S3↔DB orphan reconcile sweep (Phase 7)
# Cross-tenant (no RLS) — populated by the scheduler with the 3 counters
# from OrphanReconcileReport plus run metadata.
# ---------------------------------------------------------------------------
class OrphanReconcileReport(Base):
    __tablename__ = "orphan_reconcile_report"
    __table_args__ = (
        Index("idx_orphan_report_started_at", "started_at"),
        {"schema": "lifecycle"},
    )

    id: Mapped[str] = mapped_column(String(30), primary_key=True)  # "orr_<ULID>"
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    duration_ms: Mapped[int] = mapped_column(BigInteger, nullable=False)
    dry_run: Mapped[bool] = mapped_column(Boolean, nullable=False)
    grace_period_days: Mapped[int] = mapped_column(Integer, nullable=False)
    direction_a_orphans: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    direction_a_deleted: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    direction_b_missing: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


# ---------------------------------------------------------------------------
# TenantStorageQuota — per-tenant, per-bucket-purpose storage allowance
# ---------------------------------------------------------------------------
class TenantStorageQuota(Base):
    __tablename__ = "tenant_storage_quota"
    __table_args__ = (
        UniqueConstraint("tenant_id", "bucket_purpose", name="uq_storage_quota_tenant_purpose"),
        Index("idx_storage_quota_tenant", "tenant_id"),
        {"schema": "lifecycle"},
    )

    id: Mapped[str] = mapped_column(String(30), primary_key=True)  # "sqt_<ULID>"
    tenant_id: Mapped[str] = mapped_column(
        String(30), ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False)
    bucket_purpose: Mapped[str] = mapped_column(String(32), nullable=False)
    limit_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=10_737_418_240)
    used_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    soft_warn_pct: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=80)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


# ---------------------------------------------------------------------------
# Large-attachment entitlement (two-layer BOOLEAN admission — not a quota)
# ---------------------------------------------------------------------------
class TenantLargeAttachmentSetting(Base):
    """Tenant-wide switch: may ANY user in this tenant use large attachments."""

    __tablename__ = "tenant_large_attachment_setting"
    __table_args__ = (
        UniqueConstraint("tenant_id", name="uq_large_attach_setting_tenant"),
        Index("idx_large_attach_setting_tenant", "tenant_id"),
        {"schema": "lifecycle"},
    )

    id: Mapped[str] = mapped_column(String(30), primary_key=True)  # "tla_<ULID>"
    tenant_id: Mapped[str] = mapped_column(
        String(30), ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False)
    large_attachment_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    updated_by: Mapped[str | None] = mapped_column(Text, nullable=True)


class UserLargeAttachmentAllow(Base):
    """Per-user allowlist row — which users are permitted once tenant is on."""

    __tablename__ = "user_large_attachment_allow"
    __table_args__ = (
        UniqueConstraint("tenant_id", "user_id", name="uq_large_attach_allow_tenant_user"),
        Index("idx_large_attach_allow_tenant", "tenant_id"),
        {"schema": "lifecycle"},
    )

    id: Mapped[str] = mapped_column(String(30), primary_key=True)  # "ula_<ULID>"
    tenant_id: Mapped[str] = mapped_column(
        String(30), ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[str] = mapped_column(String(30), nullable=False)
    allowed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    updated_by: Mapped[str | None] = mapped_column(Text, nullable=True)


# ---------------------------------------------------------------------------
# Outbox
# ---------------------------------------------------------------------------
class Outbox(Base):
    __tablename__ = "lifecycle_event_outbox"
    __table_args__ = (
        Index("lc_outbox_pending_idx", "id", postgresql_where="published_at IS NULL"),
        {"schema": "lifecycle"},
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str | None] = mapped_column(String(30))
    event_type: Mapped[str] = mapped_column(String(200), nullable=False)
    aggregate_id: Mapped[str | None] = mapped_column(String(64))
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    request_id: Mapped[str | None] = mapped_column(String(64))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_error: Mapped[str | None] = mapped_column(Text)

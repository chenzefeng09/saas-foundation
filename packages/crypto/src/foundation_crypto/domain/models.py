"""SQLAlchemy ORM models — crypto schema (crypto-v1 §3, §4)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from foundation_crypto.domain.base import Base


# -----------------------------------------------------------------------------
# Algorithm — global catalogue (not tenant-scoped)
# -----------------------------------------------------------------------------
class Algorithm(Base):
    __tablename__ = "algorithm"
    __table_args__ = (
        Index("algorithm_kind_idx", "kind"),
        Index("algorithm_provider_idx", "provider"),
        {"schema": "crypto"},
    )

    id: Mapped[str] = mapped_column(String(60), primary_key=True)  # 'AES-256-GCM'
    kind: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        comment="SYMMETRIC / ASYMMETRIC_SIGN / ASYMMETRIC_ENCRYPT / HASH / HMAC / KDF / PASSWORD_HASH / TLS_SUITE / RNG",
    )
    family: Mapped[str] = mapped_column(String(20), nullable=False)  # AES / RSA / SM2
    provider: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        comment="openssl / tongsuo / gmssl / hsm / vault",
    )
    key_size_bits: Mapped[int | None] = mapped_column(Integer)
    fips_140: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    gm_certified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    deprecated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    description: Mapped[str | None] = mapped_column(Text)
    min_compliance_modes: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, default=dict
    )


# -----------------------------------------------------------------------------
# TenantAlgorithmPolicy — per-tenant default algorithm overrides
# -----------------------------------------------------------------------------
class TenantAlgorithmPolicy(Base):
    __tablename__ = "tenant_algorithm_policy"
    __table_args__ = ({"schema": "crypto"},)

    tenant_id: Mapped[str] = mapped_column(
        String(30),
        ForeignKey("tenant.tenant.id", ondelete="CASCADE"),
        primary_key=True,
    )
    symmetric_default: Mapped[str | None] = mapped_column(
        String(60), ForeignKey("crypto.algorithm.id")
    )
    sign_default: Mapped[str | None] = mapped_column(String(60))
    hash_default: Mapped[str | None] = mapped_column(String(60))
    password_hash_default: Mapped[str | None] = mapped_column(String(60))
    locked_by_compliance: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
    updated_by: Mapped[str | None] = mapped_column(String(30))


# -----------------------------------------------------------------------------
# KEK — Key Encryption Key metadata (the actual key bytes live in Vault/HSM)
# -----------------------------------------------------------------------------
class KEK(Base):
    __tablename__ = "kek"
    __table_args__ = (
        UniqueConstraint("tenant_id", "label", name="uq_kek_tenant_label"),
        Index("kek_tenant_idx", "tenant_id"),
        Index("kek_status_idx", "status", postgresql_where="status != 'ACTIVE'"),
        {"schema": "crypto"},
    )

    id: Mapped[str] = mapped_column(String(60), primary_key=True)  # kek_<ULID>
    tenant_id: Mapped[str] = mapped_column(
        String(30),
        ForeignKey("tenant.tenant.id", ondelete="CASCADE"),
        nullable=False,
    )
    label: Mapped[str] = mapped_column(String(120), nullable=False)  # 'pii.phone'
    purpose: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        comment="FIELD_ENCRYPT / AUDIT_HMAC / JWT_SIGN / FILE_ENCRYPT",
    )
    algorithm_id: Mapped[str] = mapped_column(
        String(60),
        ForeignKey("crypto.algorithm.id"),
        nullable=False,
    )
    vault_path: Mapped[str] = mapped_column(String(255), nullable=False)
    pkcs11_label: Mapped[str | None] = mapped_column(String(120))
    current_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    min_decryption_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    auto_rotate_days: Mapped[int] = mapped_column(Integer, nullable=False, default=90)
    last_rotated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="ACTIVE",
        comment="ACTIVE / SUSPENDED / MARKED_FOR_DESTRUCTION / DESTROYED",
    )
    destruction_scheduled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    destruction_marked_by: Mapped[str | None] = mapped_column(String(30))
    destruction_marked_reason: Mapped[str | None] = mapped_column(Text)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
    created_by: Mapped[str | None] = mapped_column(String(30))


# -----------------------------------------------------------------------------
# KEKHistory — state-machine transitions for audit + post-mortem
# -----------------------------------------------------------------------------
class KEKHistory(Base):
    __tablename__ = "kek_history"
    __table_args__ = (
        Index("kekh_kek_time_idx", "kek_id", "changed_at"),
        {"schema": "crypto"},
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(30), nullable=False)
    kek_id: Mapped[str] = mapped_column(String(60), nullable=False)
    changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )
    changed_by: Mapped[str] = mapped_column(String(30), nullable=False)
    transition: Mapped[str] = mapped_column(
        String(60),
        nullable=False,
        comment="CREATED / ROTATED / SUSPENDED / RESUMED / MARKED_FOR_DESTRUCTION / DESTRUCTION_ABORTED / DESTROYED",
    )
    from_status: Mapped[str | None] = mapped_column(String(30))
    to_status: Mapped[str | None] = mapped_column(String(30))
    reason: Mapped[str | None] = mapped_column(Text)
    approver_user_id: Mapped[str | None] = mapped_column(String(30))  # four-eyes
    audit_event_id: Mapped[str | None] = mapped_column(String(30))


# -----------------------------------------------------------------------------
# Outbox — transactional event publication
# -----------------------------------------------------------------------------
class Outbox(Base):
    __tablename__ = "outbox"
    __table_args__ = (
        Index(
            "ix_crypto_outbox_unpublished",
            "published_at", "created_at",
        ),
        {"schema": "crypto"},
    )

    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    tenant_id: Mapped[str | None] = mapped_column(String(30))
    event_type: Mapped[str] = mapped_column(String(200), nullable=False)
    aggregate_id: Mapped[str | None] = mapped_column(String(64))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    request_id: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    publish_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_error: Mapped[str | None] = mapped_column(Text)

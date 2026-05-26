"""SQLAlchemy ORM models — authz schema (authz-v1 §3)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column, relationship

from foundation_authz.domain.base import Base


# -----------------------------------------------------------------------------
# PermissionDefinition — global catalogue (not tenant-scoped); registered by
# business services at startup.
# -----------------------------------------------------------------------------
class PermissionDefinition(Base):
    __tablename__ = "permission_definition"
    __table_args__ = (
        Index("permission_service_idx", "service"),
        {"schema": "authz"},
    )

    id: Mapped[str] = mapped_column(String(120), primary_key=True)  # 'billing.invoice.read'
    service: Mapped[str] = mapped_column(String(50), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(50), nullable=False)
    action: Mapped[str] = mapped_column(String(50), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    risk_level: Mapped[str] = mapped_column(
        String(10),
        nullable=False,
        default="LOW",
        comment="LOW / MEDIUM / HIGH / CRITICAL",
    )
    requires_mfa: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    requires_4eyes: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    requires_pam_jit: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    requires_business_hours: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    is_system: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    deprecated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )


# -----------------------------------------------------------------------------
# Role — tenant-scoped
# -----------------------------------------------------------------------------
class Role(Base):
    __tablename__ = "role"
    __table_args__ = (
        # WHERE clause defers to migration since SQLAlchemy partial-unique
        # syntax is awkward; we declare in DDL there.
        {"schema": "authz"},
    )

    id: Mapped[str] = mapped_column(String(30), primary_key=True)  # rol_<ULID>
    tenant_id: Mapped[str] = mapped_column(
        String(30),
        ForeignKey("tenant.tenant.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    is_system: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    immutable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Permission set granted by the role (denormalised; canonical is bindings + DAG)
    permissions: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str | None] = mapped_column(String(30))

    bindings: Mapped[list[RoleBinding]] = relationship(back_populates="role", lazy="raise")


# -----------------------------------------------------------------------------
# RoleBinding — the hot table; partial indices critical (see migration)
# -----------------------------------------------------------------------------
class RoleBinding(Base):
    __tablename__ = "role_binding"
    __table_args__ = ({"schema": "authz"},)

    id: Mapped[str] = mapped_column(String(30), primary_key=True)  # rbd_<ULID>
    tenant_id: Mapped[str] = mapped_column(
        String(30),
        ForeignKey("tenant.tenant.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # principal
    principal_kind: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        comment="USER / TEAM / ORG_UNIT / API_KEY / SERVICE_ACCOUNT",
    )
    principal_id: Mapped[str] = mapped_column(String(64), nullable=False)
    # role
    role_id: Mapped[str] = mapped_column(
        String(30),
        ForeignKey("authz.role.id", ondelete="RESTRICT"),
        nullable=False,
    )
    # scope
    scope_kind: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        comment="TENANT / ORG_UNIT / TEAM / RESOURCE / GLOBAL_SYSTEM",
    )
    scope_id: Mapped[str | None] = mapped_column(String(64))
    # lifecycle
    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    granted_by: Mapped[str] = mapped_column(String(30), nullable=False)
    grant_reason: Mapped[str | None] = mapped_column(Text)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_by: Mapped[str | None] = mapped_column(String(30))
    revoked_reason: Mapped[str | None] = mapped_column(Text)
    audit_event_id: Mapped[str | None] = mapped_column(String(30))

    role: Mapped[Role] = relationship(back_populates="bindings", lazy="raise")


# -----------------------------------------------------------------------------
# RoleInherit — DAG (parent ⊆ child means child has all parent's permissions)
# -----------------------------------------------------------------------------
class RoleInherit(Base):
    __tablename__ = "role_inherit"
    __table_args__ = ({"schema": "authz"},)

    tenant_id: Mapped[str] = mapped_column(String(30), nullable=False)
    parent_role_id: Mapped[str] = mapped_column(
        String(30),
        ForeignKey("authz.role.id", ondelete="CASCADE"),
        primary_key=True,
    )
    child_role_id: Mapped[str] = mapped_column(
        String(30),
        ForeignKey("authz.role.id", ondelete="CASCADE"),
        primary_key=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )


# -----------------------------------------------------------------------------
# Outbox — transactional events
# -----------------------------------------------------------------------------
class Outbox(Base):
    __tablename__ = "outbox"
    __table_args__ = (
        Index("ix_authz_outbox_unpublished", "published_at", "created_at"),
        {"schema": "authz"},
    )

    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    tenant_id: Mapped[str | None] = mapped_column(String(30))
    event_type: Mapped[str] = mapped_column(String(200), nullable=False)
    aggregate_id: Mapped[str | None] = mapped_column(String(64))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    request_id: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    publish_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_error: Mapped[str | None] = mapped_column(Text)

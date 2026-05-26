"""SQLAlchemy ORM models — org schema (org-v1 §3).

ltree-typed columns use `sqlalchemy_utils.LtreeType`. The triggers that
maintain `path` and `depth` live in the Alembic migration (DDL only).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy_utils import LtreeType  # type: ignore[import-untyped]

from foundation_org.domain.base import Base


# -----------------------------------------------------------------------------
# OrgUnit — adjacency-list + ltree path (path/depth maintained by triggers)
# -----------------------------------------------------------------------------
class OrgUnit(Base):
    __tablename__ = "org_unit"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "parent_id", "code", name="uq_org_unit_parent_code"
        ),
        Index("ou_tenant_id_idx", "tenant_id"),
        Index("ou_parent_idx", "tenant_id", "parent_id"),
        Index(
            "ou_manager_idx",
            "manager_user_id",
            postgresql_where="manager_user_id IS NOT NULL",
        ),
        {"schema": "org"},
    )

    id: Mapped[str] = mapped_column(String(30), primary_key=True)  # ou_<ULID>
    tenant_id: Mapped[str] = mapped_column(
        String(30),
        ForeignKey("tenant.tenant.id", ondelete="CASCADE"),
        nullable=False,
    )
    parent_id: Mapped[str | None] = mapped_column(
        String(30),
        ForeignKey("org.org_unit.id", ondelete="RESTRICT"),
    )

    code: Mapped[str] = mapped_column(String(32), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    name_en: Mapped[str | None] = mapped_column(String(200))
    description: Mapped[str | None] = mapped_column(Text)
    manager_user_id: Mapped[str | None] = mapped_column(String(30))
    kind: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="DEPARTMENT",
        comment="BU / DEPARTMENT / CENTER / OFFICE / VIRTUAL",
    )

    # Maintained by trigger:
    path: Mapped[Any] = mapped_column(LtreeType, nullable=False)
    depth: Mapped[int] = mapped_column(SmallInteger, nullable=False)

    sort_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    is_archived: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, default=dict
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(), onupdate=func.now(), nullable=False,
    )
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str | None] = mapped_column(String(30))
    updated_by: Mapped[str | None] = mapped_column(String(30))

    parent: Mapped[OrgUnit | None] = relationship(
        "OrgUnit", remote_side="OrgUnit.id", lazy="raise"
    )


# -----------------------------------------------------------------------------
# Team — always belongs to one OU; leaves of the org tree
# -----------------------------------------------------------------------------
class Team(Base):
    __tablename__ = "team"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "org_unit_id", "code", name="uq_team_ou_code"
        ),
        Index("team_tenant_idx", "tenant_id"),
        Index("team_ou_idx", "tenant_id", "org_unit_id"),
        Index(
            "team_lead_idx",
            "lead_user_id",
            postgresql_where="lead_user_id IS NOT NULL",
        ),
        {"schema": "org"},
    )

    id: Mapped[str] = mapped_column(String(30), primary_key=True)  # tm_<ULID>
    tenant_id: Mapped[str] = mapped_column(
        String(30),
        ForeignKey("tenant.tenant.id", ondelete="CASCADE"),
        nullable=False,
    )
    org_unit_id: Mapped[str] = mapped_column(
        String(30),
        ForeignKey("org.org_unit.id", ondelete="RESTRICT"),
        nullable=False,
    )

    code: Mapped[str] = mapped_column(String(32), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    lead_user_id: Mapped[str | None] = mapped_column(String(30))
    kind: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="PROJECT",
        comment="PROJECT / SQUAD / GUILD / VIRTUAL",
    )

    is_archived: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, default=dict
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(), onupdate=func.now(), nullable=False,
    )
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str | None] = mapped_column(String(30))
    updated_by: Mapped[str | None] = mapped_column(String(30))


# -----------------------------------------------------------------------------
# UserMembership — user's primary OU (1:1 with identity.user)
# -----------------------------------------------------------------------------
class UserMembership(Base):
    __tablename__ = "user_membership"
    __table_args__ = (
        Index("um_tenant_idx", "tenant_id"),
        Index("um_primary_ou_idx", "tenant_id", "primary_org_unit_id"),
        Index(
            "um_manager_idx",
            "manager_user_id",
            postgresql_where="manager_user_id IS NOT NULL",
        ),
        {"schema": "org"},
    )

    user_id: Mapped[str] = mapped_column(String(30), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(30),
        ForeignKey("tenant.tenant.id", ondelete="CASCADE"),
        nullable=False,
    )
    primary_org_unit_id: Mapped[str] = mapped_column(
        String(30),
        ForeignKey("org.org_unit.id", ondelete="RESTRICT"),
        nullable=False,
    )
    job_title: Mapped[str | None] = mapped_column(String(200))
    employee_no: Mapped[str | None] = mapped_column(String(64))
    join_date: Mapped[datetime] = mapped_column(
        Date, nullable=False, server_default=func.current_date()
    )
    leave_date: Mapped[datetime | None] = mapped_column(Date)
    manager_user_id: Mapped[str | None] = mapped_column(String(30))
    employment_kind: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="EMPLOYEE",
        comment="EMPLOYEE / CONTRACTOR / INTERN / EXTERNAL",
    )
    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, default=dict
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(), onupdate=func.now(), nullable=False,
    )
    updated_by: Mapped[str | None] = mapped_column(String(30))


# -----------------------------------------------------------------------------
# UserTeamMembership — user ↔ team N:N
# -----------------------------------------------------------------------------
class UserTeamMembership(Base):
    __tablename__ = "user_team_membership"
    __table_args__ = (
        Index(
            "utm_team_idx",
            "tenant_id", "team_id",
            postgresql_where="left_at IS NULL",
        ),
        Index("utm_user_idx", "tenant_id", "user_id"),
        {"schema": "org"},
    )

    user_id: Mapped[str] = mapped_column(String(30), primary_key=True)
    team_id: Mapped[str] = mapped_column(
        String(30),
        ForeignKey("org.team.id", ondelete="RESTRICT"),
        primary_key=True,
    )
    tenant_id: Mapped[str] = mapped_column(
        String(30),
        ForeignKey("tenant.tenant.id", ondelete="CASCADE"),
        nullable=False,
    )
    role_in_team: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="MEMBER",
        comment="MEMBER / LEAD / OBSERVER",
    )
    joined_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )
    left_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    granted_by: Mapped[str | None] = mapped_column(String(30))


# -----------------------------------------------------------------------------
# UserOrgUnitSecondary — secondary OU assignments (matrix / temp transfer)
# -----------------------------------------------------------------------------
class UserOrgUnitSecondary(Base):
    __tablename__ = "user_org_unit_secondary"
    __table_args__ = (
        Index(
            "uos_ou_idx",
            "tenant_id", "org_unit_id",
            postgresql_where="valid_until IS NULL OR valid_until > now()",
        ),
        Index("uos_user_idx", "tenant_id", "user_id"),
        {"schema": "org"},
    )

    user_id: Mapped[str] = mapped_column(String(30), primary_key=True)
    org_unit_id: Mapped[str] = mapped_column(
        String(30),
        ForeignKey("org.org_unit.id", ondelete="RESTRICT"),
        primary_key=True,
    )
    valid_from: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        primary_key=True,
        server_default=func.now(),
    )
    tenant_id: Mapped[str] = mapped_column(
        String(30),
        ForeignKey("tenant.tenant.id", ondelete="CASCADE"),
        nullable=False,
    )
    reason: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="TEMP_ASSIGN",
        comment="TEMP_ASSIGN / DOTTED_LINE / CROSS_TEAM",
    )
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    granted_by: Mapped[str] = mapped_column(String(30), nullable=False)


# -----------------------------------------------------------------------------
# OrgUnitHistory — key-field change log
# -----------------------------------------------------------------------------
class OrgUnitHistory(Base):
    __tablename__ = "org_unit_history"
    __table_args__ = (
        Index("ouh_ou_time_idx", "tenant_id", "org_unit_id", "changed_at"),
        {"schema": "org"},
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(30), nullable=False)
    org_unit_id: Mapped[str] = mapped_column(String(30), nullable=False)
    changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )
    changed_by: Mapped[str] = mapped_column(String(30), nullable=False)
    field: Mapped[str] = mapped_column(String(50), nullable=False)
    old_value: Mapped[str | None] = mapped_column(Text)
    new_value: Mapped[str | None] = mapped_column(Text)
    audit_event_id: Mapped[str | None] = mapped_column(String(30))


# -----------------------------------------------------------------------------
# Outbox — transactional event publication
# -----------------------------------------------------------------------------
class Outbox(Base):
    __tablename__ = "org_event_outbox"
    __table_args__ = (
        Index(
            "outbox_pending_idx", "id",
            postgresql_where="published_at IS NULL",
        ),
        {"schema": "org"},
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str | None] = mapped_column(String(30))
    event_type: Mapped[str] = mapped_column(String(200), nullable=False)
    aggregate_id: Mapped[str | None] = mapped_column(String(64))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    request_id: Mapped[str | None] = mapped_column(String(64))
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_error: Mapped[str | None] = mapped_column(Text)

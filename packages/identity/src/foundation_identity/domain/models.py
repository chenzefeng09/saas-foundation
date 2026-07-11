"""SQLAlchemy ORM models — identity schema.

All tables MUST:
  * carry `tenant_id` (TEXT NOT NULL FK → tenant.tenant.id)
  * have `(tenant_id, ...)` leading composite index
  * enable RLS + FORCE RLS (done in Alembic migration, not in Python)
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column, relationship

from foundation_identity.domain.base import Base

DEFAULT_USER_CLEARANCE = "L3"
VALID_USER_CLEARANCES = frozenset({"L1", "L2", "L3", "L4", "L5"})


# -----------------------------------------------------------------------------
# Mix-in: tenant column with FK + audit timestamps
# -----------------------------------------------------------------------------
class _TenantBound:
    """Add `tenant_id` + `created_at` / `updated_at` to every model."""

    tenant_id: Mapped[str] = mapped_column(
        String(30),
        ForeignKey("tenant.tenant.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
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


# -----------------------------------------------------------------------------
# User
# -----------------------------------------------------------------------------
class User(_TenantBound, Base):
    __tablename__ = "user"
    __table_args__ = (
        UniqueConstraint("tenant_id", "email", name="uq_user_tenant_email"),
        Index("ix_user_tenant_status", "tenant_id", "status"),
        Index("ix_user_external_id", "tenant_id", "external_id"),
        CheckConstraint(
            "clearance IN ('L1','L2','L3','L4','L5')",
            name="ck_user_clearance",
        ),
        {"schema": "identity"},
    )

    id: Mapped[str] = mapped_column(String(30), primary_key=True)  # usr_<ULID>
    email: Mapped[str] = mapped_column(String(254), nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="INVITED",
        comment="ACTIVE / INVITED / SUSPENDED / LOCKED / DEACTIVATED / FROZEN",
    )
    keycloak_user_id: Mapped[str | None] = mapped_column(String(64), unique=False)
    external_id: Mapped[str | None] = mapped_column(String(255))  # SCIM externalId
    roles: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    # "L1".."L5"; ordinary employees default to L3.  API serialization still
    # treats legacy NULL values as L3 while migration 0011 backfills them.
    clearance: Mapped[str] = mapped_column(
        String(2),
        nullable=False,
        default=DEFAULT_USER_CLEARANCE,
        server_default=DEFAULT_USER_CLEARANCE,
    )
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failed_login_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    metadata_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, name="metadata")

    sessions: Mapped[list[Session]] = relationship(back_populates="user", lazy="raise")
    mfa_methods: Mapped[list[MfaMethod]] = relationship(back_populates="user", lazy="raise")
    recovery_codes: Mapped[list[RecoveryCode]] = relationship(
        back_populates="user", lazy="raise"
    )


# -----------------------------------------------------------------------------
# Session
# -----------------------------------------------------------------------------
class Session(_TenantBound, Base):
    __tablename__ = "session"
    __table_args__ = (
        Index("ix_session_user_active", "tenant_id", "user_id", "revoked_at"),
        Index("ix_session_expires", "tenant_id", "expires_at"),
        {"schema": "identity"},
    )

    id: Mapped[str] = mapped_column(String(40), primary_key=True)  # sess_<ULID>
    user_id: Mapped[str] = mapped_column(
        String(30),
        ForeignKey("identity.user.id", ondelete="CASCADE"),
        nullable=False,
    )
    keycloak_session_id: Mapped[str | None] = mapped_column(String(64))
    # ``jti`` of the refresh token currently bound to this session.  Used by
    # logout (to blacklist the token) and refresh-rotation (to relink the row
    # to the freshly-issued refresh token).  NULL for sessions created before
    # rotation tracking, or for paths that never receive a refresh token.
    refresh_token_jti: Mapped[str | None] = mapped_column(String(64))
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoke_reason: Mapped[str | None] = mapped_column(String(100))
    # True once the session has satisfied any required MFA step.  Password-only
    # logins for MFA-enabled users complete via the challenge → mfa-verify flow,
    # which only issues a session row with this set.  Sensitive operations may
    # additionally require a fresh step-up even when this is True.
    mfa_satisfied: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # Risk score at the time the session was issued (0-100, higher = riskier).
    # Set by RiskEvaluator at login; LOGIN_DENIED_RISK is raised before a row
    # is ever written, so anything in this column comes from a session that
    # passed the gate (possibly after step-up MFA).
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    ip: Mapped[str | None] = mapped_column(String(45))
    user_agent: Mapped[str | None] = mapped_column(String(500))
    device_id: Mapped[str | None] = mapped_column(String(100))
    scopes: Mapped[list[str] | None] = mapped_column(ARRAY(String))

    user: Mapped[User] = relationship(back_populates="sessions", lazy="raise")


# -----------------------------------------------------------------------------
# MFA Method
# -----------------------------------------------------------------------------
class MfaMethod(_TenantBound, Base):
    __tablename__ = "mfa_method"
    __table_args__ = (
        Index("ix_mfa_method_user", "tenant_id", "user_id"),
        {"schema": "identity"},
    )

    id: Mapped[str] = mapped_column(String(40), primary_key=True)  # mfa_<ULID>
    user_id: Mapped[str] = mapped_column(
        String(30),
        ForeignKey("identity.user.id", ondelete="CASCADE"),
        nullable=False,
    )
    kind: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        comment="TOTP / SMS_OTP / WEBAUTHN / PUSH",
    )
    label: Mapped[str | None] = mapped_column(String(100))
    secret_ref: Mapped[str | None] = mapped_column(
        String(200),
        comment="Vault path or Keycloak credential id; NEVER stores plaintext secret",
    )
    enrolled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    user: Mapped[User] = relationship(back_populates="mfa_methods", lazy="raise")


# -----------------------------------------------------------------------------
# Recovery codes (one-time MFA fallback)
# -----------------------------------------------------------------------------
class RecoveryCode(_TenantBound, Base):
    """One-time recovery code — fallback second factor when the primary is lost.

    Generated in a batch when a user first enrols MFA.  Only the SHA-256 hash is
    stored; the plaintext is shown to the user exactly once at generation time.
    Each code is single-use (``used_at`` stamped on redemption).
    """

    __tablename__ = "recovery_code"
    __table_args__ = (
        Index("ix_recovery_code_user_active", "tenant_id", "user_id", "used_at"),
        {"schema": "identity"},
    )

    id: Mapped[str] = mapped_column(String(40), primary_key=True)  # rec_<ULID>
    user_id: Mapped[str] = mapped_column(
        String(30),
        ForeignKey("identity.user.id", ondelete="CASCADE"),
        nullable=False,
    )
    code_hash: Mapped[str] = mapped_column(String(64), nullable=False)  # sha256 hex
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    user: Mapped[User] = relationship(back_populates="recovery_codes", lazy="raise")


# -----------------------------------------------------------------------------
# Risk signals (anomalous-login telemetry)
# -----------------------------------------------------------------------------
class RiskSignal(_TenantBound, Base):
    """Persisted detection signal from RiskEvaluator.

    One row per (login attempt, rule that fired).  Decoupled from Session so
    we can also record signals for *rejected* logins (no session row was ever
    written) and for re-evaluations after the fact.  Indexed for cheap
    per-user / per-rule retrospective queries.
    """

    __tablename__ = "risk_signal"
    __table_args__ = (
        Index("ix_risk_signal_user_time", "tenant_id", "user_id", "created_at"),
        Index("ix_risk_signal_rule_time", "tenant_id", "rule", "created_at"),
        {"schema": "identity"},
    )

    id: Mapped[str] = mapped_column(String(40), primary_key=True)  # rsk_<ULID>
    user_id: Mapped[str | None] = mapped_column(
        String(30),
        ForeignKey("identity.user.id", ondelete="CASCADE"),
        nullable=True,
    )
    rule: Mapped[str] = mapped_column(String(40), nullable=False)
    weight: Mapped[int] = mapped_column(Integer, nullable=False)
    decision: Mapped[str] = mapped_column(String(20), nullable=False)  # ALLOW / STEP_UP / DENY
    ip: Mapped[str | None] = mapped_column(String(45))
    user_agent: Mapped[str | None] = mapped_column(String(500))
    detail: Mapped[str | None] = mapped_column(String(500))


# -----------------------------------------------------------------------------
# SSO Provider (per-tenant)
# -----------------------------------------------------------------------------
class SsoProvider(_TenantBound, Base):
    __tablename__ = "sso_provider"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_sso_provider_tenant_name"),
        {"schema": "identity"},
    )

    id: Mapped[str] = mapped_column(String(40), primary_key=True)  # sso_<ULID>
    # Override the _TenantBound tenant_id: platform-scoped providers carry NULL.
    # Redeclaring the mixin column on the subclass is the supported way to relax
    # nullability for one model without touching the shared mixin.
    tenant_id: Mapped[str | None] = mapped_column(
        String(30),
        ForeignKey("tenant.tenant.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    kind: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        comment="OIDC / SAML / AD / LDAP / DINGTALK_ENTERPRISE / FEISHU_ENTERPRISE / WECOM",
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    scope: Mapped[str] = mapped_column(
        String(10),
        nullable=False,
        default="TENANT",
        comment="TENANT (per-tenant provider) / PLATFORM (shared, tenant_id NULL)",
    )
    default_tenant_id: Mapped[str | None] = mapped_column(
        String(30),
        ForeignKey("tenant.tenant.id", ondelete="SET NULL"),
        comment="Fallback tenant when no routing rule matches at login",
    )
    keycloak_idp_alias: Mapped[str | None] = mapped_column(String(100))
    config: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
        comment="Non-sensitive config; secrets live in Vault, referenced by ref",
    )


# -----------------------------------------------------------------------------
# SSO Routing Rule (PLATFORM config — NOT tenant-bound)
# -----------------------------------------------------------------------------
class SsoRoutingRule(Base):
    """Maps an incoming SSO identity (by email domain / claim) to a target tenant.

    Platform-scoped configuration: these rows are NOT subject to per-tenant RLS
    (they live behind platform-admin endpoints) and therefore do NOT use the
    _TenantBound mixin.  At login time they are read under a tenant session via
    a permissive SELECT policy.
    """

    __tablename__ = "sso_routing_rule"
    __table_args__ = (
        Index("ix_sso_routing_rule_provider_priority", "provider_id", "priority"),
        {"schema": "identity"},
    )

    id: Mapped[str] = mapped_column(String(40), primary_key=True)  # ssor_<ULID>
    provider_id: Mapped[str] = mapped_column(
        String(40),
        ForeignKey("identity.sso_provider.id", ondelete="CASCADE"),
        nullable=False,
    )
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    match_attribute: Mapped[str] = mapped_column(String(100), nullable=False)
    match_type: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        comment="EMAIL_DOMAIN / EQUALS / CONTAINS / REGEX",
    )
    match_value: Mapped[str] = mapped_column(Text, nullable=False)
    target_tenant_id: Mapped[str] = mapped_column(
        String(30),
        ForeignKey("tenant.tenant.id", ondelete="CASCADE"),
        nullable=False,
    )
    default_role: Mapped[str | None] = mapped_column(String(50))
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
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


# -----------------------------------------------------------------------------
# Password Policy (per-tenant; override the global floor)
# -----------------------------------------------------------------------------
class PasswordPolicy(Base):
    __tablename__ = "password_policy"
    __table_args__ = ({"schema": "identity"},)

    tenant_id: Mapped[str] = mapped_column(
        String(30),
        ForeignKey("tenant.tenant.id", ondelete="CASCADE"),
        primary_key=True,
    )
    min_length: Mapped[int] = mapped_column(Integer, nullable=False, default=12)
    require_upper: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    require_lower: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    require_digit: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    require_symbol: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    max_age_days: Mapped[int] = mapped_column(Integer, nullable=False, default=90)
    history_size: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    max_failed_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    lockout_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    breach_check_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


# -----------------------------------------------------------------------------
# Outbox — transactional events; published by background worker to audit/notify
# -----------------------------------------------------------------------------
class Outbox(Base):
    __tablename__ = "outbox"
    __table_args__ = (
        Index("ix_outbox_unpublished", "published_at", "created_at"),
        {"schema": "identity"},
    )

    id: Mapped[str] = mapped_column(String(40), primary_key=True)  # evt_<ULID>
    tenant_id: Mapped[str | None] = mapped_column(String(30))  # nullable for system events
    event_type: Mapped[str] = mapped_column(
        String(200),
        nullable=False,
        comment="foundation.identity.<entity>.<action>",
    )
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

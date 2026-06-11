"""Feature-flag domain models."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from foundation_feature_flag.domain.base import Base


class Flag(Base):
    """A feature flag definition (source of truth, synced from Unleash)."""

    __tablename__ = "flag"
    __table_args__ = ({"schema": "feature_flag"},)

    # Natural key — matches Unleash toggle name
    key: Mapped[str] = mapped_column(String(200), primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    # Fallback when Unleash is unreachable
    default_value: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    # If True, any kill-switch log entry for this flag immediately overrides Unleash
    fail_open: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    owner_team: Mapped[str | None] = mapped_column(String(100))
    tags: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    unleash_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    user_overridable: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="false"
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class UserFlagOverride(Base):
    """Per-user override for a feature flag (personal preference)."""

    __tablename__ = "user_flag_override"
    __table_args__ = ({"schema": "feature_flag"},)

    tenant_id: Mapped[str] = mapped_column(String(30), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(200), primary_key=True)
    flag_key: Mapped[str] = mapped_column(String(200), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class KillSwitchLog(Base):
    """Audit trail for manual kill-switch / restore actions on a flag."""

    __tablename__ = "kill_switch_log"
    __table_args__ = (
        Index("ksl_flag_key_idx", "flag_key"),
        Index("ksl_tenant_idx", "tenant_id"),
        {"schema": "feature_flag"},
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    flag_key: Mapped[str] = mapped_column(String(200), nullable=False)
    tenant_id: Mapped[str | None] = mapped_column(String(30))
    reason: Mapped[str | None] = mapped_column(Text)
    actor: Mapped[str] = mapped_column(String(200), nullable=False)
    # KILL = force-off; RESTORE = back to normal evaluation
    action: Mapped[str] = mapped_column(String(10), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

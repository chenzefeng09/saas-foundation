"""Password policy + strength checker.

Rules summary (identity-v1 §密码策略基线 + compliance-v1 §3):
  * Server enforces a *baseline floor* per compliance mode; tenants can tighten but
    not relax below the floor.
  * Tenant admins editing policy must satisfy `is_at_least(...)` for the active modes.

The strength check is also reused by Keycloak's password validator via SPI in M1; here
we provide an in-process check for use in tests and pre-flight UI hints.
"""

from __future__ import annotations

import re
import string
from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession

from foundation_identity.config import get_settings
from foundation_identity.domain.models import PasswordPolicy
from foundation_identity.errors import (
    PASSWORD_TOO_WEAK,
    POLICY_NOT_ALLOWED_TO_RELAX,
    FoundationError,
)


@dataclass(frozen=True, slots=True)
class PolicyFloor:
    """Compliance-mode-driven minimum. Tenants may only set values stricter than these."""

    min_length: int
    max_failed_attempts: int  # smaller = stricter
    max_age_days: int  # smaller = stricter
    history_size: int  # larger = stricter
    lockout_minutes: int  # larger = stricter


# Hard baseline; matches identity-v1 + compliance-v1 §3 default for equal_protection_3.
DEFAULT_FLOOR = PolicyFloor(
    min_length=8,
    max_failed_attempts=5,
    max_age_days=90,
    history_size=3,
    lockout_minutes=30,
)

# Tightened floor for finance/JR-T-0071 + equal_protection_4 etc.
STRICT_FLOOR = PolicyFloor(
    min_length=12,
    max_failed_attempts=3,
    max_age_days=60,
    history_size=6,
    lockout_minutes=30,
)


class PasswordPolicyService:
    """Pure-Python — no I/O outside the AsyncSession argument."""

    # ------------------------------------------------------------------ check
    @staticmethod
    def check_strength(
        password: str,
        policy: PasswordPolicy | PolicyFloor,
    ) -> None:
        """Raises FoundationError(PASSWORD_TOO_WEAK) on first failure."""
        if isinstance(policy, PolicyFloor):
            checks = {
                "min_length": policy.min_length,
                "require_upper": True,
                "require_lower": True,
                "require_digit": True,
                "require_symbol": True,
            }
        else:
            checks = {
                "min_length": policy.min_length,
                "require_upper": policy.require_upper,
                "require_lower": policy.require_lower,
                "require_digit": policy.require_digit,
                "require_symbol": policy.require_symbol,
            }

        if len(password) < int(checks["min_length"]):
            raise FoundationError(
                PASSWORD_TOO_WEAK,
                detail=f"Password must be at least {checks['min_length']} characters.",
            )
        if checks["require_upper"] and not re.search(r"[A-Z]", password):
            raise FoundationError(PASSWORD_TOO_WEAK, detail="Password must contain an uppercase letter.")
        if checks["require_lower"] and not re.search(r"[a-z]", password):
            raise FoundationError(PASSWORD_TOO_WEAK, detail="Password must contain a lowercase letter.")
        if checks["require_digit"] and not re.search(r"\d", password):
            raise FoundationError(PASSWORD_TOO_WEAK, detail="Password must contain a digit.")
        if checks["require_symbol"] and not any(c in string.punctuation for c in password):
            raise FoundationError(
                PASSWORD_TOO_WEAK, detail="Password must contain a special symbol."
            )

    # ------------------------------------------------------------------ baseline
    @staticmethod
    def floor_for_modes(modes: list[str]) -> PolicyFloor:
        """Take strictest applicable floor.

        Real implementation would call `compliance-service.is_at_least()`; the
        skeleton has a local map for unit-testability.
        """
        if any(m in {"finance_jrt0071", "equal_protection_4"} for m in modes):
            return STRICT_FLOOR
        return DEFAULT_FLOOR

    # ------------------------------------------------------------------ load
    async def get(self, session: AsyncSession, tenant_id: str) -> PasswordPolicy:
        existing = await session.get(PasswordPolicy, tenant_id)
        if existing is not None:
            return existing
        # Fall back to server-side floor; build a transient (not persisted) instance.
        floor = self.floor_for_modes(modes=[])  # caller can recompute with tenant modes
        return PasswordPolicy(
            tenant_id=tenant_id,
            min_length=floor.min_length,
            require_upper=True,
            require_lower=True,
            require_digit=True,
            require_symbol=True,
            max_age_days=floor.max_age_days,
            history_size=floor.history_size,
            max_failed_attempts=floor.max_failed_attempts,
            lockout_minutes=floor.lockout_minutes,
            breach_check_enabled=False,
        )

    # ------------------------------------------------------------------ update
    async def update(
        self,
        session: AsyncSession,
        tenant_id: str,
        *,
        proposed: PasswordPolicy,
        compliance_modes: list[str],
    ) -> PasswordPolicy:
        floor = self.floor_for_modes(compliance_modes)
        self._enforce_only_tighten(proposed, floor)

        existing = await session.get(PasswordPolicy, tenant_id)
        if existing is None:
            proposed.tenant_id = tenant_id
            session.add(proposed)
            await session.flush()
            return proposed

        for field in (
            "min_length",
            "require_upper",
            "require_lower",
            "require_digit",
            "require_symbol",
            "max_age_days",
            "history_size",
            "max_failed_attempts",
            "lockout_minutes",
            "breach_check_enabled",
        ):
            setattr(existing, field, getattr(proposed, field))
        await session.flush()
        return existing

    # ------------------------------------------------------------------ guard
    @staticmethod
    def _enforce_only_tighten(proposed: PasswordPolicy, floor: PolicyFloor) -> None:
        if proposed.min_length < floor.min_length:
            raise FoundationError(
                POLICY_NOT_ALLOWED_TO_RELAX,
                detail=f"min_length {proposed.min_length} < floor {floor.min_length}",
            )
        if proposed.max_failed_attempts > floor.max_failed_attempts:
            raise FoundationError(
                POLICY_NOT_ALLOWED_TO_RELAX,
                detail=(
                    f"max_failed_attempts {proposed.max_failed_attempts} > "
                    f"floor {floor.max_failed_attempts}"
                ),
            )
        if proposed.max_age_days > floor.max_age_days:
            raise FoundationError(
                POLICY_NOT_ALLOWED_TO_RELAX,
                detail=f"max_age_days {proposed.max_age_days} > floor {floor.max_age_days}",
            )
        if proposed.history_size < floor.history_size:
            raise FoundationError(
                POLICY_NOT_ALLOWED_TO_RELAX,
                detail=f"history_size {proposed.history_size} < floor {floor.history_size}",
            )
        if proposed.lockout_minutes < floor.lockout_minutes:
            raise FoundationError(
                POLICY_NOT_ALLOWED_TO_RELAX,
                detail=f"lockout_minutes {proposed.lockout_minutes} < floor {floor.lockout_minutes}",
            )
        # Compliance baseline always requires all four character classes
        for flag in ("require_upper", "require_lower", "require_digit", "require_symbol"):
            if not getattr(proposed, flag):
                raise FoundationError(
                    POLICY_NOT_ALLOWED_TO_RELAX,
                    detail=f"{flag} cannot be relaxed below compliance baseline",
                )

    # Service settings reference (kept for symmetry with rest of layer)
    def __init__(self) -> None:
        _ = get_settings()  # touch to validate env at construction time

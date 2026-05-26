"""Password strength + 'only tighten' policy enforcement."""

from __future__ import annotations

import pytest

from foundation_identity.domain.models import PasswordPolicy
from foundation_identity.errors import (
    PASSWORD_TOO_WEAK,
    POLICY_NOT_ALLOWED_TO_RELAX,
    FoundationError,
)
from foundation_identity.services.password_policy_service import (
    DEFAULT_FLOOR,
    STRICT_FLOOR,
    PasswordPolicyService,
)


def _make_policy(**overrides):  # type: ignore[no-untyped-def]
    base = {
        "tenant_id": "tnt_01J5TEST0000000000000000XX",
        "min_length": 12,
        "require_upper": True,
        "require_lower": True,
        "require_digit": True,
        "require_symbol": True,
        "max_age_days": 90,
        "history_size": 3,
        "max_failed_attempts": 5,
        "lockout_minutes": 30,
        "breach_check_enabled": False,
    }
    base.update(overrides)
    return PasswordPolicy(**base)


# ------------------------------------------------------------- check_strength
@pytest.mark.unit
@pytest.mark.parametrize(
    "password",
    [
        "Abcdefgh1!",                    # too short for strict
        "ABCDEFGH1!",                    # no lowercase
        "abcdefgh1!",                    # no uppercase
        "Abcdefghi!",                    # no digit
        "Abcdefghi1",                    # no symbol
    ],
)
def test_strength_rejects_weak(password: str) -> None:
    with pytest.raises(FoundationError) as exc_info:
        PasswordPolicyService.check_strength(password, STRICT_FLOOR)
    assert exc_info.value.error_code is PASSWORD_TOO_WEAK


@pytest.mark.unit
def test_strength_accepts_strong() -> None:
    PasswordPolicyService.check_strength("Abcdefgh1!XY", STRICT_FLOOR)


# ------------------------------------------------------------- floor selection
@pytest.mark.unit
def test_floor_default_for_pipl_only() -> None:
    assert PasswordPolicyService.floor_for_modes(["pipl"]) is DEFAULT_FLOOR


@pytest.mark.unit
@pytest.mark.parametrize("mode", ["finance_jrt0071", "equal_protection_4"])
def test_floor_strict_for_higher_modes(mode: str) -> None:
    assert PasswordPolicyService.floor_for_modes([mode]) is STRICT_FLOOR


# ------------------------------------------------------------- only-tighten
@pytest.mark.unit
def test_relaxing_min_length_rejected() -> None:
    proposed = _make_policy(min_length=6)
    with pytest.raises(FoundationError) as ei:
        PasswordPolicyService._enforce_only_tighten(proposed, DEFAULT_FLOOR)
    assert ei.value.error_code is POLICY_NOT_ALLOWED_TO_RELAX


@pytest.mark.unit
def test_relaxing_require_upper_rejected() -> None:
    proposed = _make_policy(require_upper=False)
    with pytest.raises(FoundationError) as ei:
        PasswordPolicyService._enforce_only_tighten(proposed, DEFAULT_FLOOR)
    assert ei.value.error_code is POLICY_NOT_ALLOWED_TO_RELAX


@pytest.mark.unit
def test_tightening_min_length_accepted() -> None:
    proposed = _make_policy(min_length=20)
    # must not raise
    PasswordPolicyService._enforce_only_tighten(proposed, DEFAULT_FLOOR)


@pytest.mark.unit
def test_relaxing_max_failed_attempts_rejected() -> None:
    # Lower number is stricter; floor=5, propose=10 → relaxing
    proposed = _make_policy(max_failed_attempts=10)
    with pytest.raises(FoundationError):
        PasswordPolicyService._enforce_only_tighten(proposed, DEFAULT_FLOOR)

"""P2-D tests: HIBP gateway + password_policy_service breach check."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
import respx
from httpx import Response

from foundation_identity.adapters.hibp_gateway import (
    HibpGateway,
    OnlineHibpGateway,
)
from foundation_identity.errors import (
    KEYCLOAK_UNAVAILABLE,
    PASSWORD_BREACHED,
    FoundationError,
)
from foundation_identity.services.password_policy_service import (
    DEFAULT_FLOOR,
    PasswordPolicyService,
)


# --------------------------------------------------------------------------- #
# Offline gateway — always 0
# --------------------------------------------------------------------------- #
async def test_offline_hibp_always_returns_zero() -> None:
    assert await HibpGateway().breach_count("hunter2") == 0


# --------------------------------------------------------------------------- #
# Online gateway — k-anonymity protocol
# --------------------------------------------------------------------------- #
@respx.mock
async def test_online_hibp_parses_match() -> None:
    # SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
    # prefix=5BAA6, suffix=1E4C9B93F3F0682250B6CF8331B7EE68FD8
    body = (
        "1E4C9B93F3F0682250B6CF8331B7EE68FD8:123456\n"
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:1\n"
    )
    respx.get("https://api.pwnedpasswords.com/range/5BAA6").mock(
        return_value=Response(200, text=body)
    )
    assert await OnlineHibpGateway().breach_count("password") == 123456


@respx.mock
async def test_online_hibp_no_match_returns_zero() -> None:
    respx.get("https://api.pwnedpasswords.com/range/5BAA6").mock(
        return_value=Response(200, text="DEADBEEF:9\n")
    )
    assert await OnlineHibpGateway().breach_count("password") == 0


@respx.mock
async def test_online_hibp_network_error_fails_secure_to_caller() -> None:
    """HIBP outage raises so the policy service can decide whether to fail open."""
    import httpx

    respx.get("https://api.pwnedpasswords.com/range/5BAA6").mock(
        side_effect=httpx.ConnectError("simulated outage")
    )
    with pytest.raises(FoundationError) as exc:
        await OnlineHibpGateway().breach_count("password")
    assert exc.value.error_code is KEYCLOAK_UNAVAILABLE  # generic dep-unavailable


# --------------------------------------------------------------------------- #
# PasswordPolicyService.check_breach_if_enabled
# --------------------------------------------------------------------------- #
class _StubPolicy:
    """Pose as a PasswordPolicy row with a breach_check_enabled attribute."""

    def __init__(self, *, breach_check_enabled: bool) -> None:
        self.breach_check_enabled = breach_check_enabled


async def test_breach_check_skipped_for_floor() -> None:
    svc = PasswordPolicyService(hibp=AsyncMock(spec=HibpGateway))
    await svc.check_breach_if_enabled("anything", DEFAULT_FLOOR)  # no raise, no call


async def test_breach_check_skipped_when_policy_disabled() -> None:
    hibp = AsyncMock(spec=HibpGateway)
    svc = PasswordPolicyService(hibp=hibp)
    await svc.check_breach_if_enabled("pw", _StubPolicy(breach_check_enabled=False))
    hibp.breach_count.assert_not_awaited()


async def test_breach_check_raises_when_breached() -> None:
    hibp = AsyncMock(spec=HibpGateway)
    hibp.breach_count = AsyncMock(return_value=42)
    svc = PasswordPolicyService(hibp=hibp)
    with pytest.raises(FoundationError) as exc:
        await svc.check_breach_if_enabled(
            "pwned-pw", _StubPolicy(breach_check_enabled=True)
        )
    assert exc.value.error_code is PASSWORD_BREACHED


async def test_breach_check_fails_open_on_hibp_outage() -> None:
    """When HIBP is down the password change is allowed through (with a log).

    A strict deny would block all password changes during a third-party outage
    — worse than letting one possibly-breached password through.
    """
    hibp = AsyncMock(spec=HibpGateway)
    hibp.breach_count = AsyncMock(
        side_effect=FoundationError(KEYCLOAK_UNAVAILABLE, detail="down")
    )
    svc = PasswordPolicyService(hibp=hibp)
    # Must NOT raise.
    await svc.check_breach_if_enabled(
        "pw", _StubPolicy(breach_check_enabled=True)
    )


async def test_breach_check_passes_when_clean() -> None:
    hibp = AsyncMock(spec=HibpGateway)
    hibp.breach_count = AsyncMock(return_value=0)
    svc = PasswordPolicyService(hibp=hibp)
    await svc.check_breach_if_enabled(
        "fresh-strong-pw", _StubPolicy(breach_check_enabled=True)
    )

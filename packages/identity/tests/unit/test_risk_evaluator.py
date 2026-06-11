"""P3-G tests: RiskEvaluator rules + login-flow integration.

Unit-level: each rule fires when its precondition matches, decision aggregates
into ALLOW / STEP_UP / DENY thresholds, helpers behave on edge cases.

Integration-level: hooked into the create_session endpoint via the shared
client fixture — DENY responds 401 LOGIN_DENIED_RISK, STEP_UP forces 202 MFA
challenge even when the user has no MFA enabled.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import AsyncClient

from foundation_identity.errors import LOGIN_DENIED_RISK, FoundationError
from foundation_identity.services.risk_evaluator import (
    FAILURE_FLOOR,
    RiskContext,
    RiskEvaluator,
    RiskOutcome,
    _ip_prefix,
    _ua_class,
)

_TENANT = "tnt_01J5DEV00000000000000000A1"
_USER = "usr_01J5DEVUSER000000000000001"


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def test_ip_prefix_ipv4_normalises_to_slash24() -> None:
    assert _ip_prefix("192.168.1.42") == "192.168.1.0"
    assert _ip_prefix("192.168.1.99") == "192.168.1.0"
    assert _ip_prefix("192.168.2.1") == "192.168.2.0"  # different subnet


def test_ip_prefix_ipv6_normalises_to_slash64() -> None:
    # 2001:db8::42 → /64 prefix == 2001:db8::
    assert _ip_prefix("2001:db8::42") == "2001:db8::"


def test_ip_prefix_tolerates_garbage() -> None:
    assert _ip_prefix("not-an-ip") is None
    assert _ip_prefix("") is None
    assert _ip_prefix(None) is None


def test_ua_class_extracts_browser_and_os() -> None:
    assert _ua_class("Mozilla/5.0 (Macintosh) Chrome/120 Safari/537") == "chrome:macos"
    assert _ua_class("Mozilla/5.0 (Windows NT) Firefox/120") == "firefox:windows"
    assert _ua_class("Mozilla/5.0 (iPhone) Safari/604") == "safari:ios"


def test_ua_class_empty_input() -> None:
    assert _ua_class(None) == ""
    assert _ua_class("") == ""


# --------------------------------------------------------------------------- #
# Rule-by-rule
# --------------------------------------------------------------------------- #
def _result(*, scalar: object = None, rows: list | None = None) -> MagicMock:
    r = MagicMock()
    r.scalar_one_or_none.return_value = scalar
    scalars = MagicMock()
    scalars.all.return_value = rows or []
    r.scalars.return_value = scalars
    return r


def _db(execute_results: list[MagicMock]) -> MagicMock:
    db = MagicMock()
    db.execute = AsyncMock(side_effect=execute_results)
    db.flush = AsyncMock()
    db.add = MagicMock()
    return db


async def test_consecutive_failures_fires_when_count_at_floor() -> None:
    """When only CONSECUTIVE_FAILURES could fire, NEW_DEVICE piggybacks because
    no previous Session row carries this exact UA — score lands in DENY range.
    """
    user = MagicMock(failed_login_count=FAILURE_FLOOR)
    db = _db([
        _result(scalar=user),    # user lookup for consecutive-failures
        _result(scalar=None),    # latest_session — no history
        _result(scalar=None),    # new_device probe — UA never seen
    ])

    evaluator = RiskEvaluator()
    outcome = await evaluator.evaluate(
        db, ctx=RiskContext(tenant_id=_TENANT, user_id=_USER, ip="1.2.3.4", user_agent="ua")
    )

    assert "CONSECUTIVE_FAILURES" in outcome.fired
    # CONSECUTIVE(60) + NEW_DEVICE(25) = 85 → DENY
    assert outcome.decision == "DENY"


async def test_consecutive_failures_does_not_fire_below_floor() -> None:
    user = MagicMock(failed_login_count=FAILURE_FLOOR - 1)
    db = _db([
        _result(scalar=user),
        _result(scalar=None),
        _result(scalar=None),
    ])

    evaluator = RiskEvaluator()
    outcome = await evaluator.evaluate(
        db, ctx=RiskContext(tenant_id=_TENANT, user_id=_USER, ip=None, user_agent=None)
    )

    assert "CONSECUTIVE_FAILURES" not in outcome.fired


async def test_new_device_fires_when_ua_unseen() -> None:
    user = MagicMock(failed_login_count=0)
    db = _db([
        _result(scalar=user),    # user
        _result(scalar=None),    # latest session
        _result(scalar=None),    # ua probe → not found → new device
    ])

    evaluator = RiskEvaluator()
    outcome = await evaluator.evaluate(
        db, ctx=RiskContext(tenant_id=_TENANT, user_id=_USER, ip=None, user_agent="new-ua-1")
    )

    assert "NEW_DEVICE" in outcome.fired


async def test_ip_subnet_jump_fires_on_different_prefix() -> None:
    user = MagicMock(failed_login_count=0)
    latest = MagicMock(ip="192.168.5.10", user_agent="Mozilla Chrome macOS")
    db = _db([
        _result(scalar=user),
        _result(scalar=latest),  # latest_session
        _result(scalar="found-id"),  # ua seen before → not new device
    ])

    evaluator = RiskEvaluator()
    outcome = await evaluator.evaluate(
        db,
        ctx=RiskContext(
            tenant_id=_TENANT,
            user_id=_USER,
            ip="10.0.0.5",
            user_agent="Mozilla Chrome macOS",
        ),
    )

    assert "IP_SUBNET_JUMP" in outcome.fired


async def test_ip_subnet_jump_quiet_within_same_prefix() -> None:
    user = MagicMock(failed_login_count=0)
    latest = MagicMock(ip="192.168.5.10", user_agent="ua")
    db = _db([
        _result(scalar=user),
        _result(scalar=latest),
        _result(scalar="found"),
    ])

    evaluator = RiskEvaluator()
    outcome = await evaluator.evaluate(
        db,
        ctx=RiskContext(
            tenant_id=_TENANT, user_id=_USER, ip="192.168.5.99", user_agent="ua"
        ),
    )

    assert "IP_SUBNET_JUMP" not in outcome.fired


# --------------------------------------------------------------------------- #
# Decision thresholds
# --------------------------------------------------------------------------- #
async def test_high_score_decision_is_deny() -> None:
    user = MagicMock(failed_login_count=FAILURE_FLOOR)  # 60 weight
    # Different subnet (+35) and different ua class (+15) when ctx switches.
    latest = MagicMock(ip="1.2.3.4", user_agent="X Firefox Windows")
    db = _db([
        _result(scalar=user),
        _result(scalar=latest),
        _result(scalar=None),  # new device too
    ])

    evaluator = RiskEvaluator()
    outcome = await evaluator.evaluate(
        db,
        ctx=RiskContext(
            tenant_id=_TENANT,
            user_id=_USER,
            ip="9.8.7.6",
            user_agent="X Chrome macOS",
        ),
    )

    # CONSECUTIVE(60) + IP_SUBNET_JUMP(35) + NEW_DEVICE(25) + NEW_UA(15) = 135
    assert outcome.score >= 70
    assert outcome.decision == "DENY"


async def test_zero_score_decision_is_allow() -> None:
    user = MagicMock(failed_login_count=0)
    latest = MagicMock(ip="1.2.3.4", user_agent="Mozilla Chrome macOS")
    db = _db([
        _result(scalar=user),
        _result(scalar=latest),
        _result(scalar="found"),  # ua seen
    ])

    evaluator = RiskEvaluator()
    outcome = await evaluator.evaluate(
        db,
        ctx=RiskContext(
            tenant_id=_TENANT,
            user_id=_USER,
            ip="1.2.3.99",  # same /24
            user_agent="Mozilla Chrome macOS",  # same class
        ),
    )

    assert outcome.score == 0
    assert outcome.decision == "ALLOW"
    assert outcome.fired == ()


# --------------------------------------------------------------------------- #
# Endpoint integration — DENY and STEP_UP through create_session
# --------------------------------------------------------------------------- #
def _patch_admin_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    @asynccontextmanager
    async def _scope(*, tenant_id: str = "", user_id: str = "PLATFORM"):
        fake = MagicMock()
        fake.add = MagicMock()
        fake.flush = AsyncMock()
        empty = MagicMock()
        empty.scalar_one_or_none.return_value = None
        empty.scalars.return_value.all.return_value = []
        fake.execute = AsyncMock(return_value=empty)
        yield fake

    monkeypatch.setattr(
        "foundation_identity.api.v1.sessions.admin_session_scope", _scope
    )


_LOGIN = {"method": "EMAIL_PASSWORD", "email": "u@example.com", "password": "pw-123456"}


async def test_password_login_denied_when_risk_high(
    client: AsyncClient, app, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_admin_scope(monkeypatch)

    async def _deny(*_a, **_kw):
        return RiskOutcome(score=95, decision="DENY", fired=("CONSECUTIVE_FAILURES",))

    monkeypatch.setattr(
        "foundation_identity.services.risk_evaluator.RiskEvaluator.evaluate", _deny
    )

    resp = await client.post("/api/identity/v1/sessions", json=_LOGIN)
    assert resp.status_code == 401
    assert "LOGIN_DENIED_RISK" in resp.text


async def test_password_login_step_up_returns_challenge_even_without_mfa(
    client: AsyncClient, app, mock_redis, monkeypatch: pytest.MonkeyPatch
) -> None:
    """STEP_UP must force MFA even when user.mfa_enabled is False."""
    from datetime import UTC, datetime, timedelta

    from foundation_identity.schemas.mfa import MfaChallengeResponse

    _patch_admin_scope(monkeypatch)

    # User has MFA disabled (the default _set_mfa_enabled scenario).
    async def _step_up(*_a, **_kw):
        return RiskOutcome(
            score=40, decision="STEP_UP", fired=("NEW_DEVICE", "IP_SUBNET_JUMP")
        )

    monkeypatch.setattr(
        "foundation_identity.services.risk_evaluator.RiskEvaluator.evaluate", _step_up
    )
    monkeypatch.setattr(
        "foundation_identity.services.mfa_service.MfaService.begin_challenge",
        AsyncMock(
            return_value=MfaChallengeResponse(
                challenge_id="chal_risk",
                methods=["TOTP"],
                expires_at=datetime.now(UTC) + timedelta(minutes=5),
            )
        ),
    )

    resp = await client.post("/api/identity/v1/sessions", json=_LOGIN)
    assert resp.status_code == 202, resp.text
    assert resp.json()["challenge_id"] == "chal_risk"
    # No token must leak in the 202 body.
    assert "access_token" not in resp.text


async def test_password_login_allow_when_risk_low(
    client: AsyncClient, app, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_admin_scope(monkeypatch)

    async def _allow(*_a, **_kw):
        return RiskOutcome(score=0, decision="ALLOW", fired=())

    monkeypatch.setattr(
        "foundation_identity.services.risk_evaluator.RiskEvaluator.evaluate", _allow
    )

    resp = await client.post("/api/identity/v1/sessions", json=_LOGIN)
    assert resp.status_code == 201
    assert resp.json()["access_token"] == "stub-access-token"


async def test_risk_eval_failure_fails_open_and_allows_login(
    client: AsyncClient, app, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A risk-eval crash must not block login — score=0 fail-open."""
    _patch_admin_scope(monkeypatch)

    async def _boom(*_a, **_kw):
        raise RuntimeError("simulated risk-eval crash")

    monkeypatch.setattr(
        "foundation_identity.services.risk_evaluator.RiskEvaluator.evaluate", _boom
    )

    resp = await client.post("/api/identity/v1/sessions", json=_LOGIN)
    assert resp.status_code == 201
    assert resp.json()["access_token"] == "stub-access-token"


async def test_login_denied_risk_error_code_shape() -> None:
    """The error type fits the AUTH/401 category and has a user message."""
    exc = FoundationError(LOGIN_DENIED_RISK)
    assert exc.error_code.http_status == 401
    assert exc.error_code.code.endswith(".LOGIN_DENIED_RISK")
    assert exc.user_message

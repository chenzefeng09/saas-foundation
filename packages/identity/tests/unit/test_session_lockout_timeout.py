"""P2-B + P2-C tests: session idle/absolute timeout + login lockout.

Exercises the helpers introduced in `api/v1/sessions.py`:
  * `_check_account_lockout` / `_record_login_failure` / `_record_login_success`
    — locks an account after the configured floor of failed attempts; clears
    the lock on a successful login.
  * `_touch_session_or_expire` — updates `last_seen_at` while the session is
    fresh, revokes it with `idle_timeout` / `absolute_timeout` reasons when it
    isn't, raises `TOKEN_EXPIRED` either way.
  * `_relink_session_jti` — refuses rotation when the underlying session row
    has already expired by either clock.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest

from foundation_identity.api.v1 import sessions as sess_mod
from foundation_identity.errors import (
    ACCOUNT_LOCKED,
    TOKEN_EXPIRED,
    FoundationError,
)

_TENANT = "tnt_01J5DEV00000000000000000A1"
_USER = "usr_01J5DEVUSER000000000000001"


def _result(scalar: object = None) -> MagicMock:
    r = MagicMock()
    r.scalar_one_or_none.return_value = scalar
    return r


def _patch_scope(
    monkeypatch: pytest.MonkeyPatch, session_mock: MagicMock
) -> None:
    @asynccontextmanager
    async def _scope(*, tenant_id: str = "", user_id: str = "PLATFORM"):
        yield session_mock

    monkeypatch.setattr(
        "foundation_identity.api.v1.sessions.admin_session_scope", _scope
    )


def _async_session(execute_results: list[MagicMock]) -> MagicMock:
    db = MagicMock()
    db.execute = AsyncMock(side_effect=execute_results)
    db.flush = AsyncMock()
    return db


# --------------------------------------------------------------------------- #
# Lockout
# --------------------------------------------------------------------------- #
async def test_check_lockout_passes_when_user_not_locked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = MagicMock(locked_until=None)
    _patch_scope(monkeypatch, _async_session([_result(scalar=user)]))
    await sess_mod._check_account_lockout("u@example.com")  # no raise


async def test_check_lockout_raises_when_locked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = MagicMock(locked_until=datetime.now(UTC) + timedelta(minutes=10))
    _patch_scope(monkeypatch, _async_session([_result(scalar=user)]))
    with pytest.raises(FoundationError) as exc:
        await sess_mod._check_account_lockout("u@example.com")
    assert exc.value.error_code is ACCOUNT_LOCKED


async def test_check_lockout_passes_when_lock_expired(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = MagicMock(locked_until=datetime.now(UTC) - timedelta(minutes=1))
    _patch_scope(monkeypatch, _async_session([_result(scalar=user)]))
    await sess_mod._check_account_lockout("u@example.com")  # no raise


async def test_record_login_failure_increments_and_locks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Pre-existing count = max - 1 → this attempt should push it over and lock.
    from foundation_identity.config import get_settings

    floor = get_settings().password_max_failed_attempts_floor
    user = MagicMock(failed_login_count=floor - 1, locked_until=None)
    db = _async_session([_result(scalar=user)])
    _patch_scope(monkeypatch, db)

    await sess_mod._record_login_failure("u@example.com")

    assert user.failed_login_count == floor
    assert user.locked_until is not None  # locked


async def test_record_login_success_clears_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = MagicMock(failed_login_count=3, locked_until=datetime.now(UTC))
    db = _async_session([_result(scalar=user)])
    _patch_scope(monkeypatch, db)

    await sess_mod._record_login_success(tenant_id=_TENANT, user_id=_USER)

    assert user.failed_login_count == 0
    assert user.locked_until is None


async def test_lockout_infra_failure_is_swallowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A DB hiccup must not break login — defence-in-depth only."""

    @asynccontextmanager
    async def _scope(*, tenant_id: str = "", user_id: str = "PLATFORM"):
        raise RuntimeError("simulated db outage")
        yield  # pragma: no cover

    monkeypatch.setattr(
        "foundation_identity.api.v1.sessions.admin_session_scope", _scope
    )
    await sess_mod._check_account_lockout("u@example.com")  # no raise


# --------------------------------------------------------------------------- #
# Session idle/absolute timeout
# --------------------------------------------------------------------------- #
def _session_row(
    *,
    expires_at: datetime,
    last_seen_at: datetime,
    revoked: bool = False,
) -> MagicMock:
    row = MagicMock()
    row.expires_at = expires_at
    row.last_seen_at = last_seen_at
    row.revoked_at = None if not revoked else datetime.now(UTC)
    row.revoke_reason = None
    return row


async def test_touch_updates_last_seen_when_fresh(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime.now(UTC)
    row = _session_row(
        expires_at=now + timedelta(hours=4),
        last_seen_at=now - timedelta(minutes=1),
    )
    _patch_scope(monkeypatch, _async_session([_result(scalar=row)]))

    await sess_mod._touch_session_or_expire(tenant_id=_TENANT, user_id=_USER)

    assert row.last_seen_at > now - timedelta(seconds=2)
    assert row.revoked_at is None


async def test_touch_raises_when_already_revoked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime.now(UTC)
    row = _session_row(
        expires_at=now + timedelta(hours=4),
        last_seen_at=now,
        revoked=True,
    )
    _patch_scope(monkeypatch, _async_session([_result(scalar=row)]))

    with pytest.raises(FoundationError) as exc:
        await sess_mod._touch_session_or_expire(tenant_id=_TENANT, user_id=_USER)
    assert exc.value.error_code is TOKEN_EXPIRED


async def test_touch_revokes_on_absolute_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime.now(UTC)
    row = _session_row(
        expires_at=now - timedelta(minutes=5),  # past absolute
        last_seen_at=now - timedelta(minutes=1),
    )
    _patch_scope(monkeypatch, _async_session([_result(scalar=row)]))

    with pytest.raises(FoundationError) as exc:
        await sess_mod._touch_session_or_expire(tenant_id=_TENANT, user_id=_USER)
    assert exc.value.error_code is TOKEN_EXPIRED
    assert row.revoked_at is not None
    assert row.revoke_reason == "absolute_timeout"


async def test_touch_revokes_on_idle_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from foundation_identity.config import get_settings

    idle = get_settings().session_idle_timeout_floor_seconds
    now = datetime.now(UTC)
    row = _session_row(
        expires_at=now + timedelta(hours=4),
        # Older than the idle floor.
        last_seen_at=now - timedelta(seconds=idle + 60),
    )
    _patch_scope(monkeypatch, _async_session([_result(scalar=row)]))

    with pytest.raises(FoundationError) as exc:
        await sess_mod._touch_session_or_expire(tenant_id=_TENANT, user_id=_USER)
    assert exc.value.error_code is TOKEN_EXPIRED
    assert row.revoke_reason == "idle_timeout"


async def test_touch_noop_when_no_session_row(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_scope(monkeypatch, _async_session([_result(scalar=None)]))
    await sess_mod._touch_session_or_expire(tenant_id=_TENANT, user_id=_USER)


# --------------------------------------------------------------------------- #
# Refresh-rotation timeout enforcement (_relink_session_jti)
# --------------------------------------------------------------------------- #
async def test_relink_refuses_rotation_past_absolute(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime.now(UTC)
    row = _session_row(
        expires_at=now - timedelta(minutes=1),
        last_seen_at=now - timedelta(minutes=2),
    )
    _patch_scope(monkeypatch, _async_session([_result(scalar=row)]))

    with pytest.raises(FoundationError) as exc:
        await sess_mod._relink_session_jti(
            tenant_id=_TENANT,
            user_id=_USER,
            old_jti="old",
            new_jti="new",
            last_seen_at=now,
        )
    assert exc.value.error_code is TOKEN_EXPIRED
    assert row.revoke_reason == "absolute_timeout"


async def test_relink_refuses_rotation_past_idle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from foundation_identity.config import get_settings

    idle = get_settings().session_idle_timeout_floor_seconds
    now = datetime.now(UTC)
    row = _session_row(
        expires_at=now + timedelta(hours=4),
        last_seen_at=now - timedelta(seconds=idle + 120),
    )
    _patch_scope(monkeypatch, _async_session([_result(scalar=row)]))

    with pytest.raises(FoundationError) as exc:
        await sess_mod._relink_session_jti(
            tenant_id=_TENANT,
            user_id=_USER,
            old_jti="old",
            new_jti="new",
            last_seen_at=now,
        )
    assert exc.value.error_code is TOKEN_EXPIRED
    assert row.revoke_reason == "idle_timeout"

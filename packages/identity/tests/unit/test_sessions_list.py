"""Tests for GET /sessions — list active sessions endpoint."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from foundation_identity.api.v1.sessions import _parse_device


# --------------------------------------------------------------------------- #
# Unit tests for _parse_device
# --------------------------------------------------------------------------- #


class TestParseDevice:
    def test_none_returns_unknown(self) -> None:
        assert _parse_device(None) == "Unknown device"

    def test_empty_returns_unknown(self) -> None:
        assert _parse_device("") == "Unknown device"

    def test_chrome_macos(self) -> None:
        ua = (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
        )
        result = _parse_device(ua)
        assert "Chrome" in result
        assert "macOS" in result

    def test_safari_ios(self) -> None:
        ua = (
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
        )
        result = _parse_device(ua)
        assert "Safari" in result
        assert "iOS" in result

    def test_firefox_windows(self) -> None:
        ua = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) "
            "Gecko/20100101 Firefox/120.0"
        )
        result = _parse_device(ua)
        assert "Firefox" in result
        assert "Windows" in result

    def test_android_chrome(self) -> None:
        ua = (
            "Mozilla/5.0 (Linux; Android 13; Pixel 7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36"
        )
        result = _parse_device(ua)
        assert "Chrome" in result
        assert "Android" in result

    def test_edge_browser(self) -> None:
        ua = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 Edg/120.0 Safari/537.36"
        )
        result = _parse_device(ua)
        assert "Edge" in result


# --------------------------------------------------------------------------- #
# Integration-level tests: GET /sessions endpoint
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_list_sessions_returns_empty_when_no_sessions(
    client: AsyncClient, tenant_headers: dict[str, str],
) -> None:
    """When DB returns no rows, endpoint should return empty list."""
    from foundation_identity.domain.models import Session as SessionModel

    # Patch db_session to yield a mock that returns no rows
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = []

    mock_db = AsyncMock()
    mock_db.execute.return_value = mock_result

    from foundation_identity.api import dependencies as deps

    async def _mock_db():
        yield mock_db

    from foundation_identity.main import create_app
    from foundation_identity.adapters.audit_publisher import get_audit_publisher
    from foundation_identity.adapters.keycloak_admin import get_keycloak_admin
    from foundation_identity.api.v1.sessions import _oidc_adapter

    app = create_app()
    from unittest.mock import AsyncMock as AM
    kc_mock = AM()
    audit_mock = AM()
    oidc_mock = AM()

    from foundation_identity.api.dependencies import db_session
    app.dependency_overrides[db_session] = _mock_db
    app.dependency_overrides[get_keycloak_admin] = lambda: kc_mock
    app.dependency_overrides[get_audit_publisher] = lambda: audit_mock
    app.dependency_overrides[_oidc_adapter] = lambda: oidc_mock

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as c:
        resp = await c.get(
            "/api/identity/v1/sessions",
            headers=tenant_headers,
        )

    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert data == []


@pytest.mark.asyncio
async def test_list_sessions_returns_session_rows(
    client: AsyncClient, tenant_headers: dict[str, str],
) -> None:
    """When DB has sessions, endpoint returns them with device parsed."""
    from foundation_identity.domain.models import Session as SessionModel

    now = datetime.now(UTC)
    fake_session = MagicMock(spec=SessionModel)
    fake_session.id = "sess_01J5TESTSESSION0000000001"
    fake_session.user_id = "usr_01J5DEVUSER000000000000001"
    fake_session.ip = "127.0.0.1"
    fake_session.user_agent = (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 Chrome/120.0 Safari/537.36"
    )
    fake_session.last_seen_at = now - timedelta(minutes=5)
    fake_session.issued_at = now - timedelta(hours=2)
    fake_session.revoked_at = None
    fake_session.expires_at = now + timedelta(hours=22)

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [fake_session]

    mock_db = AsyncMock()
    mock_db.execute.return_value = mock_result

    from foundation_identity.main import create_app
    from foundation_identity.adapters.audit_publisher import get_audit_publisher
    from foundation_identity.adapters.keycloak_admin import get_keycloak_admin
    from foundation_identity.api.v1.sessions import _oidc_adapter
    from foundation_identity.api.dependencies import db_session

    app = create_app()
    kc_mock = AsyncMock()
    audit_mock = AsyncMock()
    oidc_mock = AsyncMock()

    async def _mock_db():
        yield mock_db

    app.dependency_overrides[db_session] = _mock_db
    app.dependency_overrides[get_keycloak_admin] = lambda: kc_mock
    app.dependency_overrides[get_audit_publisher] = lambda: audit_mock
    app.dependency_overrides[_oidc_adapter] = lambda: oidc_mock

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as c:
        resp = await c.get(
            "/api/identity/v1/sessions",
            headers=tenant_headers,
        )

    assert resp.status_code == 200
    items = resp.json()
    assert isinstance(items, list)
    assert len(items) == 1
    item = items[0]
    assert item["id"] == "sess_01J5TESTSESSION0000000001"
    assert item["ip"] == "127.0.0.1"
    assert "Chrome" in item["device"]
    assert "macOS" in item["device"]
    assert item["current"] is True  # first (most recent) is flagged current

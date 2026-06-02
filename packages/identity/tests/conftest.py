"""Pytest fixtures shared across unit + integration tests."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from typing import Any
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from foundation_identity.adapters.audit_publisher import AuditPublisher
from foundation_identity.adapters.keycloak_admin import KeycloakAdminAdapter
from foundation_identity.api.dependencies import audit, keycloak
from foundation_identity.main import create_app


# ---------------------------------------------------------------- env defaults
@pytest.fixture(autouse=True, scope="session")
def _env_defaults(monkeypatch_session: pytest.MonkeyPatch) -> None:
    """Make tests hermetic: don't require .env / docker-compose to import settings."""
    monkeypatch_session.setenv("IDENTITY_ENV", "dev")
    monkeypatch_session.setenv("IDENTITY_LOG_FORMAT", "console")
    monkeypatch_session.setenv("IDENTITY_OTEL_ENABLED", "false")
    monkeypatch_session.setenv("IDENTITY_AUDIT_PUBLISHER_KIND", "log_only")
    monkeypatch_session.setenv("IDENTITY_REQUIRE_TENANT_CONTEXT", "false")


@pytest.fixture(scope="session")
def monkeypatch_session() -> Iterator[pytest.MonkeyPatch]:
    """Session-scoped monkeypatch (pytest only ships function-scoped)."""
    mp = pytest.MonkeyPatch()
    try:
        yield mp
    finally:
        mp.undo()


# ---------------------------------------------------------------- app + client
@pytest.fixture
def mock_keycloak() -> AsyncMock:
    mock = AsyncMock(spec=KeycloakAdminAdapter)
    mock.create_user.return_value = "kc-user-fake-uuid"
    mock.trigger_required_action.return_value = None
    mock.disable_user.return_value = None
    mock.enable_user.return_value = None
    mock.logout_all_sessions.return_value = None
    mock.update_user.return_value = None
    mock.delete_user.return_value = None
    return mock


@pytest.fixture
def mock_audit() -> AsyncMock:
    mock = AsyncMock(spec=AuditPublisher)
    mock.publish.return_value = None
    return mock


@pytest.fixture
def app(mock_keycloak: AsyncMock, mock_audit: AsyncMock) -> FastAPI:
    application = create_app()
    application.dependency_overrides[keycloak] = lambda: mock_keycloak
    application.dependency_overrides[audit] = lambda: mock_audit
    return application


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[AsyncClient]:
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as c:
        yield c


# ---------------------------------------------------------------- helper headers
@pytest.fixture
def tenant_headers() -> dict[str, str]:
    # IDs are exactly 26 base32 chars to satisfy TENANT_ID_PATTERN /
    # USER_ID_PATTERN in foundation_identity.api.middleware.  Prior version
    # used 25-char IDs which the middleware silently rejected, masking real
    # endpoint behaviour in tests.
    return {
        "X-Tenant-Id": "tnt_01J5DEV00000000000000000A1",
        "X-User-Id": "usr_01J5DEVUSER000000000000001",
        "X-Actor": "USER",
    }


# ---------------------------------------------------------------- utility
def make_invite_payload(email: str = "alice@example.com", **kw: Any) -> dict[str, Any]:
    base = {"email": email, "display_name": "Alice", "send_invite_email": False}
    base.update(kw)
    return base

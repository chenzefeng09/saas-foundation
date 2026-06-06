"""Pytest fixtures shared across unit + integration tests."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from foundation_identity.adapters.audit_publisher import AuditPublisher
from foundation_identity.adapters.keycloak_admin import KeycloakAdminAdapter
from foundation_identity.adapters.keycloak_oidc import KeycloakOIDCAdapter
from foundation_identity.api.dependencies import audit, db_session, keycloak
from foundation_identity.api.v1.sessions import _oidc_adapter
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


# Stub claims returned by the mock OIDC adapter's verify_token.
# Tests that call /sessions/me or /sessions (password grant) rely on these.
STUB_OIDC_CLAIMS: dict[str, Any] = {
    "user_id": "usr_01J5DEVUSER000000000000001",
    "tenant_id": "tnt_01J5DEV00000000000000000A1",
    "email": "stub-user@example.com",
    "preferred_username": "stub-user",
    "name": "Stub User",
    "realm_access": {"roles": ["user"]},
    "sub": "usr_01J5DEVUSER000000000000001",
    "exp": 9999999999,
}


class _ScalarResult:
    def __init__(self, rows: list[Any] | None = None) -> None:
        self._rows = rows or []

    def all(self) -> list[Any]:
        return self._rows


class FakeAsyncSession:
    """Small SQLAlchemy AsyncSession stand-in for API tests that do not need DB."""

    def __init__(self) -> None:
        self.added: list[Any] = []

    async def scalar(self, *_args: Any, **_kwargs: Any) -> Any:
        return None

    async def scalars(self, *_args: Any, **_kwargs: Any) -> _ScalarResult:
        return _ScalarResult()

    async def get(self, *_args: Any, **_kwargs: Any) -> Any:
        return None

    def add(self, obj: Any) -> None:
        self.added.append(obj)

    async def flush(self) -> None:
        now = datetime.now(UTC)
        for obj in self.added:
            if hasattr(obj, "created_at") and getattr(obj, "created_at") is None:
                setattr(obj, "created_at", now)
            if hasattr(obj, "updated_at") and getattr(obj, "updated_at") is None:
                setattr(obj, "updated_at", now)
        return None


@pytest.fixture
def mock_oidc() -> AsyncMock:
    """Stub OIDC adapter: verify_token returns STUB_OIDC_CLAIMS; grants return
    a fake token bundle with access_token='stub-access-token'."""
    mock = AsyncMock(spec=KeycloakOIDCAdapter)
    mock.verify_token.return_value = STUB_OIDC_CLAIMS
    _token_bundle: dict[str, Any] = {
        "access_token": "stub-access-token",
        "refresh_token": "stub-refresh-token",
        "expires_in": 300,
        "scope": "openid",
    }
    mock.password_grant.return_value = _token_bundle
    mock.client_credentials_grant.return_value = _token_bundle
    return mock


@pytest.fixture
def app(mock_keycloak: AsyncMock, mock_audit: AsyncMock, mock_oidc: AsyncMock) -> FastAPI:
    application = create_app()

    async def _db_override() -> AsyncIterator[FakeAsyncSession]:
        yield FakeAsyncSession()

    application.dependency_overrides[keycloak] = lambda: mock_keycloak
    application.dependency_overrides[audit] = lambda: mock_audit
    application.dependency_overrides[db_session] = _db_override
    application.dependency_overrides[_oidc_adapter] = lambda: mock_oidc
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

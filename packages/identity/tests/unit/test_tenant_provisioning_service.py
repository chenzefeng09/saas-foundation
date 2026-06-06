"""Unit tests for tenant provisioning saga orchestration."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any, ClassVar
from unittest.mock import AsyncMock

import pytest

from foundation_identity.services.tenant_provisioning_service import TenantProvisioningService


class _Result:
    def __init__(self, row: tuple[Any, ...] | None = None) -> None:
        self._row = row

    def fetchone(self) -> tuple[Any, ...] | None:
        return self._row


class _FakeSession:
    def __init__(self) -> None:
        self.executed: list[tuple[str, dict[str, Any] | None]] = []
        self.added: list[Any] = []
        self.tenant_row: tuple[str, str] | None = None
        self.user_row: tuple[str] | None = None
        self.role_row: tuple[str] | None = None
        self.binding_row: tuple[str] | None = None

    async def execute(self, stmt: Any, params: dict[str, Any] | None = None) -> _Result:
        sql = str(stmt)
        self.executed.append((sql, params))
        if "FROM tenant.tenant" in sql:
            return _Result(self.tenant_row)
        if "FROM identity.user" in sql:
            return _Result(self.user_row)
        if "FROM authz.role_binding" in sql:
            return _Result(self.binding_row)
        if "FROM authz.role " in sql:
            return _Result(self.role_row)
        return _Result()

    async def scalar(self, *_args: Any, **_kwargs: Any) -> Any:
        return None

    def add(self, obj: Any) -> None:
        self.added.append(obj)

    async def flush(self) -> None:
        now = datetime.now(UTC)
        for obj in self.added:
            if hasattr(obj, "created_at") and obj.created_at is None:
                obj.created_at = now
            if hasattr(obj, "updated_at") and obj.updated_at is None:
                obj.updated_at = now


class _Response:
    def __init__(self, status_code: int, payload: dict[str, Any] | None = None) -> None:
        self.status_code = status_code
        self._payload = payload or {}
        self.text = str(self._payload)

    def json(self) -> dict[str, Any]:
        return self._payload


class _FakeAsyncClient:
    calls: ClassVar[list[tuple[str, str, dict[str, str] | None, dict[str, Any] | None]]] = []
    org_status: int = 201
    plans_payload: ClassVar[dict[str, Any]] = {"items": [{"id": "plan_free", "tier": "FREE"}]}

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        return None

    async def __aenter__(self) -> _FakeAsyncClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        return None

    async def post(
        self,
        url: str,
        *,
        json: dict[str, Any],
        headers: dict[str, str],
    ) -> _Response:
        self.calls.append(("POST", url, headers, json))
        if url.endswith("/org-units"):
            return _Response(self.org_status, {"id": "ou_root"})
        if url.endswith("/subscriptions"):
            return _Response(201, {"id": "sub_default"})
        return _Response(404)

    async def get(self, url: str, *, headers: dict[str, str]) -> _Response:
        self.calls.append(("GET", url, headers, None))
        if url.endswith("/plans"):
            return _Response(200, self.plans_payload)
        return _Response(404)


@pytest.fixture
def fake_session(monkeypatch: pytest.MonkeyPatch) -> _FakeSession:
    session = _FakeSession()

    @asynccontextmanager
    async def _scope(*_args: Any, **_kwargs: Any) -> AsyncIterator[_FakeSession]:
        yield session

    monkeypatch.setattr(
        "foundation_identity.services.tenant_provisioning_service.admin_session_scope",
        _scope,
    )
    monkeypatch.setattr("foundation_identity.domain.db.admin_session_scope", _scope)
    return session


@pytest.fixture(autouse=True)
def fake_http(monkeypatch: pytest.MonkeyPatch) -> None:
    _FakeAsyncClient.calls = []
    _FakeAsyncClient.org_status = 201
    _FakeAsyncClient.plans_payload = {"items": [{"id": "plan_free", "tier": "FREE"}]}
    monkeypatch.setattr(
        "foundation_identity.services.tenant_provisioning_service.httpx.AsyncClient",
        _FakeAsyncClient,
    )


def _service(keycloak: AsyncMock | None = None) -> TenantProvisioningService:
    return TenantProvisioningService(
        keycloak=keycloak or AsyncMock(),
        audit=AsyncMock(),
        org_url="http://org/api/org/v1",
        billing_url="http://billing/api/billing/v1",
        authz_url="http://authz/api/authz/v1",
    )


@pytest.mark.unit
async def test_provision_creates_tenant_admin_and_downstream_resources(
    fake_session: _FakeSession,
) -> None:
    keycloak = AsyncMock()
    keycloak.create_user.return_value = "kc_admin"
    keycloak.trigger_required_action.return_value = None

    result = await _service(keycloak).provision(
        name="Acme",
        tier="FREE",
        admin_email="admin@example.com",
        admin_display_name="Admin",
        actor_user_id="usr_01J5DEVUSER000000000000001",
        tenant_id="tnt_01J5DEV00000000000000000A1",
    )

    assert result["tenant_id"] == "tnt_01J5DEV00000000000000000A1"
    assert result["admin_user_id"].startswith("usr_")
    assert result["root_ou_id"] == "ou_root"
    assert result["subscription_id"] == "sub_default"
    assert result["steps"] == [
        "tenant_row_created",
        "admin_user_created",
        "root_ou_created",
        "subscription_created",
        "authz_bootstrapped",
    ]

    called_urls = [call[1] for call in _FakeAsyncClient.calls]
    assert "http://org/api/org/v1/org-units" in called_urls
    assert "http://billing/api/billing/v1/plans" in called_urls
    assert "http://billing/api/billing/v1/subscriptions" in called_urls
    assert any("INSERT INTO tenant.tenant" in stmt for stmt, _ in fake_session.executed)
    assert any("INSERT INTO authz.role " in stmt for stmt, _ in fake_session.executed)
    assert any("INSERT INTO authz.role_binding" in stmt for stmt, _ in fake_session.executed)


@pytest.mark.unit
async def test_provision_returns_partial_result_when_admin_invite_fails(
    fake_session: _FakeSession,
) -> None:
    keycloak = AsyncMock()
    keycloak.create_user.side_effect = RuntimeError("keycloak down")

    result = await _service(keycloak).provision(
        name="Acme",
        admin_email="admin@example.com",
        actor_user_id="PLATFORM",
        tenant_id="tnt_01J5DEV00000000000000000A1",
    )

    assert result["tenant_id"] == "tnt_01J5DEV00000000000000000A1"
    assert result["admin_user_id"] is None
    assert result["root_ou_id"] is None
    assert result["subscription_id"] is None
    assert result["steps"] == ["tenant_row_created"]
    assert result["error"].startswith("admin_user_invite failed:")
    assert _FakeAsyncClient.calls == []
    assert any("INSERT INTO tenant.tenant" in stmt for stmt, _ in fake_session.executed)


@pytest.mark.unit
async def test_provision_retries_idempotent_existing_resources(
    fake_session: _FakeSession,
) -> None:
    fake_session.tenant_row = ("tnt_01J5DEV00000000000000000A1", "ACTIVE")
    fake_session.user_row = ("usr_existing_admin",)
    fake_session.role_row = ("rol_existing",)
    fake_session.binding_row = ("rbd_existing",)
    _FakeAsyncClient.org_status = 409
    _FakeAsyncClient.plans_payload = {"items": []}

    keycloak = AsyncMock()
    result = await _service(keycloak).provision(
        name="Acme",
        tier="ENTERPRISE",
        admin_email="admin@example.com",
        actor_user_id="PLATFORM",
        tenant_id="tnt_01J5DEV00000000000000000A1",
    )

    assert result["admin_user_id"] == "usr_existing_admin"
    assert result["root_ou_id"] is None
    assert result["subscription_id"] is None
    assert result["steps"] == [
        "tenant_row_exists",
        "admin_user_exists",
        "root_ou_exists",
        "subscription_skipped:no_plan",
        "authz_bootstrapped",
    ]
    keycloak.create_user.assert_not_called()
    assert not any("INSERT INTO tenant.tenant" in stmt for stmt, _ in fake_session.executed)
    assert not any("INSERT INTO authz.role_binding" in stmt for stmt, _ in fake_session.executed)

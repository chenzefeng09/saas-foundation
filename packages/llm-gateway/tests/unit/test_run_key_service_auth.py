"""Only an authenticated SERVICE caller mints or revokes run-scoped keys.

The callers are the agent-platform scheduler and BFF. They send ``X-Actor:
SERVICE`` plus the pre-shared ``X-Internal-Service-Token``; the middleware
downgrades an unproven SERVICE claim to USER, and the two routes refuse
anything but SERVICE before the body is validated or a DB session opens.

These go through the real middleware stack, router and exception handlers
(the ``create_app`` order, without its observability side effects) with the DB
session and the service replaced by fakes.
"""
from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from fastapi import FastAPI
from pydantic import SecretStr
from structlog.testing import capture_logs

from foundation_llm_gateway.api import middleware
from foundation_llm_gateway.api.dependencies import db_session, llm_gateway_service
from foundation_llm_gateway.api.exception_handlers import install_exception_handlers
from foundation_llm_gateway.api.middleware import RequestIdMiddleware, TenantContextMiddleware
from foundation_llm_gateway.api.v1 import api_v1
from foundation_llm_gateway.config import Settings
from foundation_llm_gateway.services.llm_gateway_service import LLMGatewayService

PREFIX = "/api/llm-gateway/v1"
TENANT = "tnt_01J5DEVXX00000000000000001"
TOKEN = "test-llm-gateway-service-token-0123456789"
MINT = ("/tenant-keys/ephemeral", {"run_id": "run_A", "ttl_seconds": 660})
REVOKE = ("/tenant-keys/revoke-run", {"run_id": "run_A"})
PERMISSION_DENIED = "FOUNDATION.LLM_GATEWAY.AUTH.PERMISSION_DENIED"


class _Session:
    """What the mint route asks of a session: one provider lookup."""

    def __init__(self, provider: Any) -> None:
        self.provider = provider

    async def scalar(self, stmt: Any) -> Any:
        return self.provider


class _Gateway:
    def __init__(self, *, configured_token: str = TOKEN, provider: Any = "default") -> None:
        self.sessions_opened = 0
        self.provider = (
            SimpleNamespace(id="llmp_TEST", tenant_id=TENANT) if provider == "default" else provider
        )
        self.svc = MagicMock(spec=LLMGatewayService)
        self.svc.mint_ephemeral_key = AsyncMock(return_value=SimpleNamespace(
            id="llmk_EPH", virtual_key="sk-foundation-eph-abc", provider_id="llmp_TEST",
            name="run:run_A", rate_limit_rpm=60, enabled=True, run_id="run_A", ephemeral=True,
            expires_at=datetime.now(UTC) + timedelta(seconds=660),
        ))
        self.svc.disable_ephemeral_keys_for_run = AsyncMock(return_value=1)
        self.settings = Settings(internal_service_token=SecretStr(configured_token))
        self.app = FastAPI()
        self.app.add_middleware(TenantContextMiddleware)
        self.app.add_middleware(RequestIdMiddleware)
        install_exception_handlers(self.app)
        self.app.include_router(api_v1, prefix=PREFIX)
        self.app.dependency_overrides[db_session] = self._session
        self.app.dependency_overrides[llm_gateway_service] = lambda: self.svc

    async def _session(self) -> AsyncIterator[_Session]:
        self.sessions_opened += 1
        yield _Session(self.provider)

    async def post(self, path: str, body: dict[str, Any], headers: dict[str, Any]) -> httpx.Response:
        transport = httpx.ASGITransport(app=self.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://gw") as client:
            return await client.post(f"{PREFIX}{path}", json=body, headers=headers)


@pytest.fixture
def gateway(monkeypatch: pytest.MonkeyPatch) -> _Gateway:
    gw = _Gateway()
    monkeypatch.setattr(middleware, "get_settings", lambda: gw.settings)
    return gw


def _headers(**extra: Any) -> dict[str, Any]:
    return {"X-Tenant-Id": TENANT, "Authorization": "Bearer some-jwt", **extra}


SERVICE = {"X-Actor": "SERVICE", "X-Internal-Service-Token": TOKEN}


@pytest.mark.parametrize("route", [MINT, REVOKE], ids=["mint", "revoke"])
@pytest.mark.parametrize(
    "headers",
    [
        pytest.param({}, id="no-actor"),
        pytest.param({"X-Actor": "USER"}, id="user"),
        pytest.param({"X-Actor": "USER", "X-Internal-Service-Token": TOKEN}, id="user-with-token"),
        pytest.param({"X-Actor": "SERVICE"}, id="service-without-token"),
        pytest.param({"X-Actor": "SERVICE", "X-Internal-Service-Token": TOKEN + "x"}, id="service-wrong-token"),
        pytest.param({"X-Actor": "SERVICE", "X-Internal-Service-Token": ""}, id="service-empty-token"),
        # Arrives as a non-ASCII str, on which a str compare_digest raises (a 500).
        pytest.param({"X-Actor": "SERVICE", "X-Internal-Service-Token": "tökén".encode()}, id="service-non-ascii-token"),
        pytest.param({"X-Actor": "ADMIN"}, id="admin"),
        pytest.param({"X-Actor": "ADMIN", "X-Internal-Service-Token": TOKEN}, id="admin-with-token"),
    ],
)
async def test_anyone_but_an_authenticated_service_is_refused_before_the_db(
    gateway: _Gateway, route: tuple[str, dict[str, Any]], headers: dict[str, Any],
) -> None:
    path, body = route
    resp = await gateway.post(path, body, _headers(**headers))

    assert resp.status_code == 403, resp.text
    assert resp.json()["code"] == PERMISSION_DENIED
    assert gateway.sessions_opened == 0
    gateway.svc.mint_ephemeral_key.assert_not_called()
    gateway.svc.disable_ephemeral_keys_for_run.assert_not_called()


@pytest.mark.parametrize("route", [MINT, REVOKE], ids=["mint", "revoke"])
async def test_without_a_tenant_the_request_is_unauthenticated(
    gateway: _Gateway, route: tuple[str, dict[str, Any]],
) -> None:
    path, body = route
    resp = await gateway.post(path, body, {"Authorization": "Bearer some-jwt", **SERVICE})

    assert resp.status_code == 401
    assert gateway.sessions_opened == 0


@pytest.mark.parametrize("route", [MINT, REVOKE], ids=["mint", "revoke"])
async def test_an_invalid_body_from_an_unauthenticated_caller_is_still_403(
    gateway: _Gateway, route: tuple[str, dict[str, Any]],
) -> None:
    """The actor gate runs before body validation: no schema hints for strangers."""
    path, _ = route
    resp = await gateway.post(path, {"run_id": ""}, _headers())

    assert resp.status_code == 403
    assert resp.json()["code"] == PERMISSION_DENIED


async def test_service_with_the_token_mints_a_run_key(gateway: _Gateway) -> None:
    resp = await gateway.post(*MINT, _headers(**SERVICE))

    assert resp.status_code == 201, resp.text
    assert resp.json()["virtual_key"] == "sk-foundation-eph-abc"
    kwargs = gateway.svc.mint_ephemeral_key.await_args.kwargs
    assert kwargs["tenant_id"] == TENANT and kwargs["run_id"] == "run_A"


async def test_service_with_the_token_revokes_a_runs_keys(gateway: _Gateway) -> None:
    resp = await gateway.post(*REVOKE, _headers(**SERVICE))

    assert resp.status_code == 200, resp.text
    assert resp.json() == {"run_id": "run_A", "disabled": 1}
    gateway.svc.disable_ephemeral_keys_for_run.assert_awaited_once()
    assert gateway.svc.disable_ephemeral_keys_for_run.await_args.kwargs == {
        "tenant_id": TENANT, "run_id": "run_A",
    }


async def test_an_authenticated_mint_for_a_tenant_without_a_provider_is_still_404(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The BFF and the scheduler read this 404 as "no model configured"."""
    gw = _Gateway(provider=None)
    monkeypatch.setattr(middleware, "get_settings", lambda: gw.settings)

    resp = await gw.post(*MINT, _headers(**SERVICE))

    assert resp.status_code == 404
    assert resp.json()["code"] == "FOUNDATION.LLM_GATEWAY.PROVIDER.NOT_FOUND"
    gw.svc.mint_ephemeral_key.assert_not_called()


@pytest.mark.parametrize("route", [MINT, REVOKE], ids=["mint", "revoke"])
async def test_an_unset_token_disables_service_altogether(
    monkeypatch: pytest.MonkeyPatch, route: tuple[str, dict[str, Any]],
) -> None:
    gw = _Gateway(configured_token="")
    monkeypatch.setattr(middleware, "get_settings", lambda: gw.settings)

    for token in ("", TOKEN):
        resp = await gw.post(*route, _headers(**{"X-Actor": "SERVICE", "X-Internal-Service-Token": token}))
        assert resp.status_code == 403

    assert gw.sessions_opened == 0


async def test_an_unproven_service_claim_is_logged_without_the_token(gateway: _Gateway) -> None:
    with capture_logs() as logs:
        await gateway.post(*MINT, _headers(**{"X-Actor": "SERVICE", "X-Internal-Service-Token": "guess"}))

    (entry,) = [e for e in logs if e["event"] == "service_actor.unverified"]
    assert entry["token_presented"] is True and "guess" not in repr(entry)


async def test_an_unproven_service_claim_no_longer_writes_tenant_defaults(gateway: _Gateway) -> None:
    """SERVICE is verified for every route, not only the run-key ones: the
    tenant-default and member-preference writes accepted a bare header."""
    transport = httpx.ASGITransport(app=gateway.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://gw") as client:
        resp = await client.put(
            f"{PREFIX}/tenant-defaults",
            json={"purpose": "llm", "model_id": "m", "provider_id": "llmp_TEST"},
            headers=_headers(**{"X-Actor": "SERVICE"}),
        )

    assert resp.status_code == 403
    assert resp.json()["code"] == PERMISSION_DENIED

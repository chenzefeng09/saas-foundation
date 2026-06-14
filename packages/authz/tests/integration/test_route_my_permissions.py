"""Route-layer tests for ``GET /my-permissions``.

Verifies the self-read effective-permissions endpoint:

* A user bound to a role returns that role's expanded permission set (wildcard
  tokens included), sorted for a stable payload.
* A user with no bindings returns an empty list (200, not 401).
* The endpoint carries no ``require_permission`` guard — any authenticated
  principal may read their own grants.

These exercise the full FastAPI app (``create_app``) with DB + OPA overridden,
so they live in the integration tier even though no real Postgres is involved.
Mirrors the structure of ``test_route_authz.py``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from foundation_authz.adapters.audit_publisher import AuditPublisher
from foundation_authz.adapters.opa_client import OpaClient
from foundation_authz.api.dependencies import audit, db_session, opa
from foundation_authz.main import create_app
from tests._factories import make_binding, make_role
from tests.conftest import FakeAsyncSession

pytestmark = pytest.mark.integration

TENANT = "tnt_01J5VALIDTENANT000000000T1"
USER = "usr_01J5VALIDUSER00000000000U1"
API = "/api/authz/v1"

_HEADERS = {
    "X-Tenant-Id": TENANT,
    "X-User-Id": USER,
    "X-Actor": "USER",
    "X-Request-Id": "req_01J5VALIDREQUEST00000000R1",
}


def _build(session: FakeAsyncSession) -> FastAPI:
    app = create_app()

    async def _db_override() -> AsyncIterator[FakeAsyncSession]:
        yield session

    app.dependency_overrides[db_session] = _db_override
    app.dependency_overrides[audit] = lambda: AsyncMock(spec=AuditPublisher)
    app.dependency_overrides[opa] = lambda: AsyncMock(spec=OpaClient)
    return app


async def _client(app: FastAPI) -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver")


def _stage_caller_roles(session: FakeAsyncSession, *, permissions: list[str]) -> None:
    """Stage one binding+role JOIN row for USER granting ``permissions``.

    ``_load_effective_roles`` issues the top-level binding query then one
    inheritance-expansion execute() which the Fake answers with [] (no parents).
    """
    role = make_role(tenant_id=TENANT, name="caller_role", permissions=permissions)
    binding = make_binding(tenant_id=TENANT, principal_id=USER, role_id=role.id)
    session.queue_execute([(binding, role)])
    session.queue_execute([])  # inheritance expansion → no parents


async def test_my_permissions_returns_expanded_set_sorted() -> None:
    session = FakeAsyncSession()
    _stage_caller_roles(session, permissions=["session.read", "authz.role.manage", "billing.*"])

    app = _build(session)
    async with await _client(app) as c:
        resp = await c.get(f"{API}/my-permissions", headers=_HEADERS)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    # Sorted, deterministic payload — wildcard tokens preserved verbatim.
    assert body["permissions"] == ["authz.role.manage", "billing.*", "session.read"]


async def test_my_permissions_empty_for_unbound_user() -> None:
    session = FakeAsyncSession()
    # No binding rows staged → _load_effective_roles returns []; the inheritance
    # walk short-circuits (empty roles), so no further execute() is consumed.
    session.queue_execute([])

    app = _build(session)
    async with await _client(app) as c:
        resp = await c.get(f"{API}/my-permissions", headers=_HEADERS)

    assert resp.status_code == 200, resp.text
    assert resp.json()["permissions"] == []


async def test_my_permissions_super_admin_star() -> None:
    session = FakeAsyncSession()
    _stage_caller_roles(session, permissions=["*"])

    app = _build(session)
    async with await _client(app) as c:
        resp = await c.get(f"{API}/my-permissions", headers=_HEADERS)

    assert resp.status_code == 200, resp.text
    assert resp.json()["permissions"] == ["*"]

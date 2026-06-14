"""Route-layer per-action authorization tests.

Verifies that ``require_permission`` is wired onto the write endpoints and that
it self-authorizes in-process (no HTTP self-call): a caller lacking
``authz.role.manage`` is 403'd before the handler runs, while a caller holding
it (or "*") passes.

These exercise the full FastAPI app (``create_app``) with DB + OPA overridden,
so they live in the integration tier even though no real Postgres is involved.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from foundation_authz.api.dependencies import audit, db_session, opa
from foundation_authz.domain.models import Role
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

_VALID_CREATE_BODY = {
    "name": "viewer",
    "display_name": "Viewer",
    "permissions": ["session.read"],
}


def _build(session: FakeAsyncSession) -> FastAPI:
    app = create_app()
    from unittest.mock import AsyncMock

    from foundation_authz.adapters.audit_publisher import AuditPublisher
    from foundation_authz.adapters.opa_client import OpaClient

    async def _db_override() -> AsyncIterator[FakeAsyncSession]:
        yield session

    app.dependency_overrides[db_session] = _db_override
    app.dependency_overrides[audit] = lambda: AsyncMock(spec=AuditPublisher)
    app.dependency_overrides[opa] = lambda: AsyncMock(spec=OpaClient)
    return app


async def _client(app: FastAPI) -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver")


def _stage_caller_roles(session: FakeAsyncSession, *, permissions: list[str], times: int) -> None:
    """Stage the JOIN result returned by _load_effective_roles, ``times`` times.

    The role/binding granting ``permissions`` to USER.  ``_expand_inherited_permissions``
    then issues one more execute() per call which the Fake answers with [] (no
    inheritance), so we only need to stage the top-level binding rows.
    """
    role = make_role(tenant_id=TENANT, name="caller_role", permissions=permissions)
    binding = make_binding(tenant_id=TENANT, principal_id=USER, role_id=role.id)
    for _ in range(times):
        session.queue_execute([(binding, role)])
        session.queue_execute([])  # inheritance expansion → no parents


async def test_create_role_denied_without_manage_permission() -> None:
    session = FakeAsyncSession()
    # Caller holds only session.read → require_permission("authz.role.manage") misses.
    _stage_caller_roles(session, permissions=["session.read"], times=1)

    app = _build(session)
    async with await _client(app) as c:
        resp = await c.post(f"{API}/roles", json=_VALID_CREATE_BODY, headers=_HEADERS)

    assert resp.status_code == 403
    assert resp.json()["code"] == "FOUNDATION.AUTHZ.POLICY.PERMISSION_DENIED"
    # Handler must not have created anything (dep short-circuited).
    assert session.added == []


async def test_create_role_allowed_with_manage_permission() -> None:
    session = FakeAsyncSession()
    # Caller holds the management token AND covers the requested perm (session.read).
    # effective_permissions is computed twice (dep + handler) → stage twice.
    _stage_caller_roles(
        session,
        permissions=["authz.role.manage", "session.*"],
        times=2,
    )
    session.queue_scalar(None)  # role-name uniqueness probe → no existing

    app = _build(session)
    async with await _client(app) as c:
        resp = await c.post(f"{API}/roles", json=_VALID_CREATE_BODY, headers=_HEADERS)

    assert resp.status_code == 201, resp.text
    assert resp.json()["name"] == "viewer"
    created = [r for r in session.added if isinstance(r, Role)]
    assert len(created) == 1 and created[0].permissions == ["session.read"]


async def test_create_role_allowed_for_super_admin_star() -> None:
    session = FakeAsyncSession()
    _stage_caller_roles(session, permissions=["*"], times=2)
    session.queue_scalar(None)

    app = _build(session)
    async with await _client(app) as c:
        resp = await c.post(
            f"{API}/roles",
            json={"name": "powerful", "display_name": "Powerful", "permissions": ["platform.admin"]},
            headers=_HEADERS,
        )

    # super_admin's "*" satisfies both require_permission AND the escalation guard,
    # so even granting platform.admin is allowed.
    assert resp.status_code == 201, resp.text
    created = [r for r in session.added if isinstance(r, Role)]
    assert len(created) == 1 and created[0].permissions == ["platform.admin"]

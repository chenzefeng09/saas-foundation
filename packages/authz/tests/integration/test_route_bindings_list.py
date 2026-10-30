"""GET /bindings lifecycle filtering, through the full FastAPI app.

The list is ACTIVE-only unless ``filter.status`` asks for EXPIRED and/or
REVOKED bindings, and every item carries ``status`` plus the revocation fields
so a client can tell a current grant from audit history.

DB + OPA are overridden (no real Postgres), so assertions are on the WHERE
clause the route builds and on the serialized response.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.dialects import postgresql

from foundation_authz.adapters.audit_publisher import AuditPublisher
from foundation_authz.adapters.opa_client import OpaClient
from foundation_authz.api.dependencies import audit, db_session, opa
from foundation_authz.main import create_app
from tests._factories import make_binding
from tests.conftest import FakeAsyncSession

pytestmark = pytest.mark.integration

TENANT = "tnt_01J5VALIDTENANT000000000T1"
USER = "usr_01J5VALIDUSER00000000000U1"
URL = "/api/authz/v1/bindings"

_HEADERS = {
    "X-Tenant-Id": TENANT,
    "X-User-Id": USER,
    "X-Actor": "USER",
    "X-Request-Id": "req_01J5VALIDREQUEST00000000R1",
}

ACTIVE_ONLY = "authz.role_binding.revoked_at IS NULL AND (authz.role_binding.expires_at IS NULL"
REVOKED_ONLY = "authz.role_binding.revoked_at IS NOT NULL"


def _build(session: FakeAsyncSession) -> FastAPI:
    app = create_app()

    async def _db_override() -> AsyncIterator[FakeAsyncSession]:
        yield session

    app.dependency_overrides[db_session] = _db_override
    app.dependency_overrides[audit] = lambda: AsyncMock(spec=AuditPublisher)
    app.dependency_overrides[opa] = lambda: AsyncMock(spec=OpaClient)
    return app


async def _get(session: FakeAsyncSession, params: dict[str, Any] | None = None) -> Any:
    async with AsyncClient(
        transport=ASGITransport(app=_build(session)), base_url="http://testserver"
    ) as c:
        return await c.get(URL, params=params, headers=_HEADERS)


def _where(session: FakeAsyncSession) -> str:
    stmt = session.statements[-1]
    compiled = stmt.whereclause.compile(
        dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}
    )
    return " ".join(str(compiled).split())


async def test_default_lists_active_bindings_only() -> None:
    session = FakeAsyncSession()
    active = make_binding(tenant_id=TENANT)
    session.queue_scalars([active])

    resp = await _get(session)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["next_cursor"] is None
    [item] = body["items"]
    assert item["id"] == active.id
    assert item["status"] == "ACTIVE"
    assert item["revoked_at"] is None
    assert item["revoked_by"] is None
    where = _where(session)
    assert ACTIVE_ONLY in where
    assert REVOKED_ONLY not in where


async def test_revoked_bindings_listed_only_when_requested() -> None:
    session = FakeAsyncSession()
    revoked = make_binding(tenant_id=TENANT, revoked=True, revoked_reason="API revoke")
    session.queue_scalars([revoked])

    resp = await _get(session, {"filter.status": "REVOKED"})

    assert resp.status_code == 200, resp.text
    [item] = resp.json()["items"]
    assert item["status"] == "REVOKED"
    assert item["revoked_at"] is not None
    assert item["revoked_by"] == revoked.revoked_by
    assert item["revoked_reason"] == "API revoke"
    where = _where(session)
    assert REVOKED_ONLY in where
    assert "revoked_at IS NULL" not in where


async def test_multiple_statuses_are_ored() -> None:
    session = FakeAsyncSession()

    resp = await _get(session, {"filter.status": "ACTIVE,REVOKED"})

    assert resp.status_code == 200, resp.text
    where = _where(session)
    assert ACTIVE_ONLY in where
    assert f" OR {REVOKED_ONLY}" in where
    assert "expires_at <" not in where  # EXPIRED not requested


async def test_all_statuses_disable_lifecycle_filtering() -> None:
    session = FakeAsyncSession()

    resp = await _get(session, {"filter.status": "REVOKED,EXPIRED,ACTIVE"})

    assert resp.status_code == 200, resp.text
    where = _where(session)
    assert "revoked_at" not in where
    assert "expires_at" not in where


@pytest.mark.parametrize("value", ["", "revoked", "DELETED", "ACTIVE,", "ACTIVE REVOKED"])
async def test_invalid_status_filter_is_rejected(value: str) -> None:
    session = FakeAsyncSession()

    resp = await _get(session, {"filter.status": value})

    assert resp.status_code == 422, resp.text
    assert resp.headers["content-type"].startswith("application/problem+json")
    body = resp.json()
    assert body["code"] == "FOUNDATION.AUTHZ.INPUT.VALIDATION_FAILED"
    assert body["errors"][0]["field"] == "/filter.status"
    assert session.statements == []  # rejected before touching the DB


async def test_next_cursor_is_last_returned_id() -> None:
    session = FakeAsyncSession()
    rows = [
        make_binding(binding_id=f"rbd_01J5VALIDBINDING0000000B{i}0", tenant_id=TENANT)
        for i in range(3)
    ]
    session.queue_scalars(rows)  # limit + 1 rows → more pages

    resp = await _get(session, {"limit": 2})

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert [i["id"] for i in body["items"]] == [rows[0].id, rows[1].id]
    assert body["next_cursor"] == rows[1].id

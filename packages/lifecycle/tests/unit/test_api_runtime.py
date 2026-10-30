"""HTTP-facing runtime tests for lifecycle service."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.dialects import postgresql

from foundation_lifecycle.api import dependencies
from foundation_lifecycle.api.exception_handlers import install_exception_handlers
from foundation_lifecycle.errors import RESOURCE_NOT_IN_BIN, FoundationError
from foundation_lifecycle.main import create_app

from tests._factories import make_legal_hold


def test_healthz_includes_request_id_header() -> None:
    client = TestClient(create_app())

    response = client.get("/api/lifecycle/v1/healthz")

    assert response.status_code == 200
    assert response.json()["status"] == "OK"
    assert response.headers["X-Request-Id"].startswith("req_")


def test_invalid_tenant_header_returns_problem_json() -> None:
    client = TestClient(create_app())

    response = client.get(
        "/api/lifecycle/v1/recycle-bin",
        headers={"X-Tenant-Id": "bad"},
    )

    assert response.status_code == 400
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.json()["code"] == "FOUNDATION.LIFECYCLE.INPUT.VALIDATION_FAILED"


def test_foundation_error_handler_returns_problem_json() -> None:
    app = FastAPI()
    install_exception_handlers(app)

    @app.get("/boom")
    async def boom() -> None:
        raise FoundationError(RESOURCE_NOT_IN_BIN, extra={"bin_id": "bin_missing"})

    response = TestClient(app).get("/boom")

    assert response.status_code == RESOURCE_NOT_IN_BIN.http_status
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.json()["bin_id"] == "bin_missing"


@pytest.mark.parametrize(("path", "stale_cursor"), [
    ("/api/lifecycle/v1/legal-holds", "lhd_01J0000000000000000000HLD1"),
    ("/api/lifecycle/v1/recycle-bin", "bin_01J0000000000000000000BIN1"),
])
def test_list_with_a_cursor_it_did_not_issue_is_422_not_500(path: str, stale_cursor: str) -> None:
    app = create_app()

    async def _no_db() -> AsyncIterator[None]:
        yield None  # the cursor is rejected before any query runs

    app.dependency_overrides[dependencies.db_session] = _no_db

    response = TestClient(app).get(
        path,
        params={"cursor": stale_cursor},  # a bare id: what these lists used to hand out
        headers={"X-Tenant-Id": "tnt_01J0000000000000000000TNT1"},
    )

    assert response.status_code == 422
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.json()["code"] == "FOUNDATION.LIFECYCLE.INPUT.VALIDATION_FAILED"


class _RecordingRestore:
    def __init__(self) -> None:
        self.restored_by: list[str] = []

    async def restore(self, session: Any, *, restored_by: str, **_: Any) -> None:
        self.restored_by.append(restored_by)


_CALLER, _OTHER_USER = "usr_01J0000000000000000000USR1", "usr_01J0000000000000000000USR2"


@pytest.mark.parametrize(("body", "expected"), [
    pytest.param(None, _CALLER, id="no-body"),
    pytest.param({}, _CALLER, id="empty-body"),
    pytest.param({"restored_by": None}, _CALLER, id="null-restorer"),
    pytest.param({"restored_by": _OTHER_USER}, _OTHER_USER, id="explicit-restorer"),
])
def test_restore_records_the_caller_unless_a_restorer_is_given(
    body: dict[str, Any] | None, expected: str,
) -> None:
    app = create_app()
    svc = _RecordingRestore()

    async def _no_db() -> AsyncIterator[None]:
        yield None

    app.dependency_overrides[dependencies.db_session] = _no_db
    app.dependency_overrides[dependencies.lifecycle_service] = lambda: svc

    response = TestClient(app).post(
        "/api/lifecycle/v1/recycle-bin/bin_01J0000000000000000000BIN1:restore",
        json=body,
        headers={"X-Tenant-Id": "tnt_01J0000000000000000000TNT1", "X-User-Id": _CALLER},
    )

    assert response.status_code == 200, response.text
    assert svc.restored_by == [expected]


def test_list_legal_holds_hands_the_resource_filters_to_the_query(fake_session: Any) -> None:
    app = create_app()

    async def _fake_db() -> AsyncIterator[Any]:
        yield fake_session  # the real LegalHoldService builds the query; the fake records it

    app.dependency_overrides[dependencies.db_session] = _fake_db
    fake_session.queue_scalars([
        make_legal_hold(hold_id="lhd_1", placed_at=datetime(2026, 10, 30, 12, 0, tzinfo=UTC)),
    ])

    response = TestClient(app).get(
        "/api/lifecycle/v1/legal-holds",
        params={"filter.resource_type": "user_data", "filter.resource_id": "res_123"},
        headers={"X-Tenant-Id": "tnt_01J0000000000000000000TNT1"},
    )

    assert response.status_code == 200
    assert [h["id"] for h in response.json()["items"]] == ["lhd_1"]
    (stmt,) = fake_session.statements
    sql = str(stmt.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}))
    assert "lifecycle.legal_hold.resource_type_id = 'user_data'" in sql
    assert "lifecycle.legal_hold.resource_id = 'res_123'" in sql

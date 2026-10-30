"""HTTP-facing runtime tests for lifecycle service."""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from foundation_lifecycle.api import dependencies
from foundation_lifecycle.api.exception_handlers import install_exception_handlers
from foundation_lifecycle.errors import RESOURCE_NOT_IN_BIN, FoundationError
from foundation_lifecycle.main import create_app


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

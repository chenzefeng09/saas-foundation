"""HTTP-facing runtime tests for lifecycle service."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

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

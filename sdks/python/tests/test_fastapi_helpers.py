"""Tests for foundation_sdk.fastapi shared helpers.

These pin the contract that business services rely on: a single
RequestContextMiddleware that populates the contextvars, and a
register_problem_details fallback that never leaks ``str(exc)``.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from foundation_sdk.fastapi import (
    get_request_id,
    get_tenant_id,
    get_user_id,
    install_request_context,
    register_problem_details,
)


@pytest.fixture
def app() -> FastAPI:
    application = FastAPI()
    install_request_context(
        application, service_name="test-service", service_version="9.9.9",
    )
    register_problem_details(application, internal_code="TEST.INTERNAL")

    @application.get("/echo-context")
    async def echo_context() -> dict:
        return {
            "request_id": get_request_id(),
            "tenant_id": get_tenant_id(),
            "user_id": get_user_id(),
        }

    @application.get("/boom")
    async def boom() -> None:
        raise RuntimeError("super secret SQL: SELECT * FROM users WHERE id='x'")

    @application.get("/typed-error")
    async def typed_error() -> None:
        raise HTTPException(status_code=418, detail="i am a teapot")

    return application


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    return TestClient(app, raise_server_exceptions=False)


def test_request_id_generated_when_missing(client: TestClient) -> None:
    resp = client.get("/echo-context")
    assert resp.status_code == 200
    body = resp.json()
    assert body["request_id"].startswith("req_")
    assert resp.headers["X-Request-Id"] == body["request_id"]


def test_request_id_propagated_from_header(client: TestClient) -> None:
    resp = client.get("/echo-context", headers={"X-Request-Id": "req_FROMCALLER"})
    assert resp.status_code == 200
    assert resp.json()["request_id"] == "req_FROMCALLER"
    assert resp.headers["X-Request-Id"] == "req_FROMCALLER"


def test_service_name_and_version_added(client: TestClient) -> None:
    resp = client.get("/echo-context")
    assert resp.headers["X-Service-Name"] == "test-service"
    assert resp.headers["X-Service-Version"] == "9.9.9"


def test_tenant_and_user_populated_from_headers(client: TestClient) -> None:
    resp = client.get(
        "/echo-context",
        headers={
            "X-Tenant-Id": "tnt_01J5TEST00000000000000000A",
            "X-User-Id": "usr_01J5USER000000000000000001",
        },
    )
    body = resp.json()
    assert body["tenant_id"] == "tnt_01J5TEST00000000000000000A"
    assert body["user_id"] == "usr_01J5USER000000000000000001"


def test_tenant_default_empty(client: TestClient) -> None:
    body = client.get("/echo-context").json()
    assert body["tenant_id"] == ""
    assert body["user_id"] == ""


def test_problem_details_never_leaks_exception_message(client: TestClient) -> None:
    resp = client.get("/boom")
    assert resp.status_code == 500
    body = resp.json()
    # The exception message contained "SELECT * FROM users" — it must not
    # appear in the response body or headers.
    serialised = resp.text
    assert "SELECT" not in serialised
    assert "super secret" not in serialised
    # But the request_id IS in the body so ops can correlate to logs.
    assert body["request_id"].startswith("req_")
    assert body["code"] == "TEST.INTERNAL"
    assert body["status"] == 500


def test_problem_details_passes_through_starlette_http_errors(
    client: TestClient,
) -> None:
    """HTTPException is handled by Starlette's default handler, NOT our fallback."""
    resp = client.get("/typed-error")
    assert resp.status_code == 418
    # Should be the standard FastAPI {"detail": "i am a teapot"} body,
    # NOT our Problem-Details wrapper.
    assert resp.json() == {"detail": "i am a teapot"}

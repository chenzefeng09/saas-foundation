"""Middleware: RequestId generation + tenant header validation."""

from __future__ import annotations

import re

import pytest
from httpx import AsyncClient

# docs/errors.md §3.1, as contracts/openapi/_common.yaml's Error.code pattern.
CODE_FORMAT = re.compile(r"FOUNDATION\.[A-Z_]+\.[A-Z_]+\.[A-Z_]+")


@pytest.mark.unit
async def test_request_id_generated_when_missing(client: AsyncClient) -> None:
    resp = await client.get("/api/identity/v1/healthz")
    rid = resp.headers["X-Request-Id"]
    assert rid.startswith("req_")
    assert len(rid) == 4 + 26  # "req_" + 26-char ULID


@pytest.mark.unit
async def test_request_id_echoed_when_valid(client: AsyncClient) -> None:
    sent = "req_01J5ABCDEFGHJKMNPQRSTVWXYZ"
    resp = await client.get(
        "/api/identity/v1/healthz",
        headers={"X-Request-Id": sent},
    )
    assert resp.headers["X-Request-Id"] == sent


@pytest.mark.unit
async def test_request_id_regenerated_when_malformed(client: AsyncClient) -> None:
    resp = await client.get(
        "/api/identity/v1/healthz",
        headers={"X-Request-Id": "not-a-real-id"},
    )
    assert resp.headers["X-Request-Id"] != "not-a-real-id"
    assert resp.headers["X-Request-Id"].startswith("req_")


@pytest.mark.unit
async def test_invalid_tenant_header_returns_400(client: AsyncClient) -> None:
    resp = await client.patch(
        "/api/identity/v1/users/usr_01J5VALIDUSER00000000000001",
        headers={
            "X-Tenant-Id": "not-a-tenant-id",
            "X-User-Id": "usr_01J5VALIDUSER00000000000001",
        },
        json={"display_name": "x"},
    )
    assert resp.status_code == 400
    body = resp.json()
    assert body["code"] == "FOUNDATION.IDENTITY.INPUT.INVALID_FORMAT"
    assert resp.headers["content-type"].startswith("application/problem+json")


@pytest.mark.unit
async def test_missing_tenant_header_returns_problem_json_401(client: AsyncClient) -> None:
    path = "/api/identity/v1/mfa/methods"
    resp = await client.get(path)
    assert resp.status_code == 401
    assert resp.headers["content-type"].startswith("application/problem+json")
    body = resp.json()
    assert body["code"] == "FOUNDATION.IDENTITY.AUTH.TENANT_CONTEXT_MISSING"
    assert CODE_FORMAT.fullmatch(body["code"])
    assert body["status"] == 401
    assert body["instance"] == path
    assert body["request_id"] == resp.headers["X-Request-Id"]

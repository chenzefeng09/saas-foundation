"""Smoke: /healthz returns OK shape (no DB, no auth required)."""

from __future__ import annotations

import pytest
from httpx import AsyncClient


@pytest.mark.unit
async def test_healthz_ok(client: AsyncClient) -> None:
    resp = await client.get("/api/identity/v1/healthz")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "OK"
    assert body["service"] == "identity-service"
    assert "version" in body
    assert resp.headers.get("X-Request-Id", "").startswith("req_")


@pytest.mark.unit
async def test_readyz_ok(client: AsyncClient) -> None:
    resp = await client.get("/api/identity/v1/readyz")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "OK"
    assert body["dependencies"]["postgres"]["status"] == "OK"

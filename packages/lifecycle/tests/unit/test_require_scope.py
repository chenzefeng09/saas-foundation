"""Tests for the scope-check Depends (storage-v1 §10.1)."""

from __future__ import annotations

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from foundation_lifecycle.api.dependencies import require_scope
from foundation_lifecycle.api.exception_handlers import install_exception_handlers
from foundation_lifecycle.errors import INSUFFICIENT_SCOPE, FoundationError


@pytest.fixture
def app_with_scope() -> FastAPI:
    app = FastAPI()
    install_exception_handlers(app)

    @app.get("/protected", dependencies=[Depends(require_scope("storage.quota.write"))])
    async def protected() -> dict:
        return {"ok": True}

    @app.get("/open")
    async def open_endpoint() -> dict:
        return {"ok": True}

    return app


def test_missing_header_returns_403(app_with_scope: FastAPI) -> None:
    client = TestClient(app_with_scope)
    resp = client.get("/protected")
    assert resp.status_code == 403
    assert resp.headers["content-type"].startswith("application/problem+json")
    body = resp.json()
    assert body["code"] == "FOUNDATION.LIFECYCLE.POLICY.INSUFFICIENT_SCOPE"
    assert body["required_scope"] == "storage.quota.write"
    assert "storage.quota.write" in body["detail"]


def test_header_without_scope_returns_403(app_with_scope: FastAPI) -> None:
    client = TestClient(app_with_scope)
    resp = client.get(
        "/protected", headers={"X-Foundation-Scopes": "audit.write notification.send"}
    )
    assert resp.status_code == 403


def test_header_with_scope_passes(app_with_scope: FastAPI) -> None:
    client = TestClient(app_with_scope)
    resp = client.get(
        "/protected",
        headers={"X-Foundation-Scopes": "audit.write storage.quota.write"},
    )
    assert resp.status_code == 200


def test_unprotected_endpoint_ignores_header(app_with_scope: FastAPI) -> None:
    client = TestClient(app_with_scope)
    resp = client.get("/open")
    assert resp.status_code == 200


def test_require_scope_raises_outside_request() -> None:
    """The dep should raise INSUFFICIENT_SCOPE (403) when the scope is missing."""
    from unittest.mock import MagicMock

    dep = require_scope("storage.quota.write")
    request = MagicMock()
    request.headers = {"X-Foundation-Scopes": ""}
    with pytest.raises(FoundationError) as exc:
        dep(request)
    assert exc.value.error_code is INSUFFICIENT_SCOPE
    assert exc.value.error_code.http_status == 403

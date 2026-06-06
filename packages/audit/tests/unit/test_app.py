"""Tests for FastAPI app, middleware, and exception handlers.

Uses TestClient to spin up the app without any external services.
"""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# App creation tests
# ---------------------------------------------------------------------------

class TestCreateApp:
    def test_create_app_returns_fastapi_instance(self) -> None:
        """create_app() builds a FastAPI app with expected properties."""
        from foundation_audit.main import create_app
        from fastapi import FastAPI

        app = create_app()
        assert isinstance(app, FastAPI)
        assert "Audit" in app.title

    def test_app_has_api_routes(self) -> None:
        """The app mounts audit API routes."""
        from foundation_audit.main import create_app
        app = create_app()
        paths = [route.path for route in app.routes]  # type: ignore[union-attr]
        # At least the health route should be registered
        assert any("/healthz" in p or "/readyz" in p or "health" in p for p in paths)

    def test_healthz_endpoint(self) -> None:
        """GET /healthz returns 200 without tenant context."""
        from foundation_audit.main import create_app
        app = create_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/audit/v1/healthz")
        # Health endpoint must be reachable (200 OK)
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Middleware tests
# ---------------------------------------------------------------------------

class TestMiddleware:
    def _make_client(self) -> TestClient:
        from foundation_audit.main import create_app
        return TestClient(create_app(), raise_server_exceptions=False)

    def test_request_id_header_injected(self) -> None:
        """X-Request-Id header is returned in responses."""
        client = self._make_client()
        resp = client.get("/api/audit/v1/healthz")
        assert "X-Request-Id" in resp.headers

    def test_provided_request_id_echoed(self) -> None:
        """If client sends valid X-Request-Id, it is echoed back."""
        client = self._make_client()
        rid = "req_01J00000000000000000000RID"
        resp = client.get("/api/audit/v1/healthz", headers={"X-Request-Id": rid})
        assert resp.headers.get("X-Request-Id") == rid

    def test_invalid_tenant_id_returns_400(self) -> None:
        """Invalid X-Tenant-Id format returns 400."""
        client = self._make_client()
        resp = client.post(
            "/api/audit/v1/events",
            json={"event_id": "evt_X"},
            headers={
                "X-Tenant-Id": "invalid-tenant",
                "X-User-Id": "usr_01J0000000000000000000USR1",
            },
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Exception handler tests
# ---------------------------------------------------------------------------

class TestExceptionHandlers:
    def test_validation_error_returns_422(self) -> None:
        """Pydantic validation error returns 422 with problem+json."""
        from collections.abc import AsyncIterator

        from foundation_audit.api.dependencies import db_session
        from foundation_audit.main import create_app

        async def fake_db_session() -> AsyncIterator[object]:
            yield object()

        app = create_app()
        app.dependency_overrides[db_session] = fake_db_session
        client = TestClient(app, raise_server_exceptions=False)
        # POST with invalid body triggers validation
        resp = client.post(
            "/api/audit/v1/events",
            json={"not_valid": True},
            headers={
                "X-Tenant-Id": "tnt_01J0000000000000000000TNT1",
                "X-Actor": "USER",
            },
        )
        assert resp.status_code == 422

    def test_foundation_error_format(self) -> None:
        """FoundationError is rendered as RFC 9457 problem+json."""
        from foundation_audit.api.exception_handlers import _body
        body = _body(
            code="FOUNDATION.AUDIT.TEST.CODE",
            title="Test Title",
            status=400,
            detail="test detail",
            instance="/test",
            request_id="req_01J0",
        )
        assert body["code"] == "FOUNDATION.AUDIT.TEST.CODE"
        assert body["status"] == 400
        assert "timestamp" in body
        assert "type" in body


# ---------------------------------------------------------------------------
# IngestService test coverage boost
# ---------------------------------------------------------------------------

class TestIngestServiceCoverage:
    @pytest.mark.asyncio
    async def test_ingest_one_adds_to_session(self) -> None:
        """ingest_one calls session.add and session.flush."""
        from datetime import UTC, datetime
        from foundation_audit.services.ingest_service import IngestService
        from foundation_audit.schemas.event import AuditEvent
        from unittest.mock import AsyncMock, MagicMock

        svc = IngestService()
        mock_session = MagicMock()
        mock_session.add = MagicMock()
        mock_session.flush = AsyncMock()

        event = AuditEvent(
            event_id="evt_01J00000000000000000000001",
            occurred_at=datetime.now(UTC),
            tenant_id="tnt_01J0000000000000000000TNT1",
            service="identity",
            event_type="test",
            actor_kind="USER",
        )
        await svc.ingest_one(mock_session, event)
        mock_session.add.assert_called_once()
        mock_session.flush.assert_called_once()

    @pytest.mark.asyncio
    async def test_ingest_batch_returns_count(self) -> None:
        from datetime import UTC, datetime
        from foundation_audit.services.ingest_service import IngestService
        from foundation_audit.schemas.event import AuditEvent
        from unittest.mock import AsyncMock, MagicMock

        svc = IngestService()
        mock_session = MagicMock()
        mock_session.add = MagicMock()
        mock_session.flush = AsyncMock()

        events = [
            AuditEvent(
                event_id=f"evt_01J0000000000000000000000{i}",
                occurred_at=datetime.now(UTC),
                tenant_id="tnt_01J0000000000000000000TNT1",
                service="identity",
                event_type="test",
                actor_kind="USER",
            )
            for i in range(3)
        ]
        count = await svc.ingest_batch(mock_session, events)
        assert count == 3
        assert mock_session.add.call_count == 3

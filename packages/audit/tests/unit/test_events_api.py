"""Unit tests for events API endpoints using FastAPI TestClient + mocked CH/crypto."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from foundation_audit.api.v1.events import _row_to_stored
from foundation_audit.domain.base import FoundationContext


# ---------------------------------------------------------------------------
# Minimal FastAPI app fixture for testing
# ---------------------------------------------------------------------------

def _make_context(
    tenant_id: str = "tnt_01J0000000000000000000TNT1",
) -> FoundationContext:
    return FoundationContext(
        tenant_id=tenant_id,
        user_id="usr_01J0000000000000000000USR1",
        actor="USER",
        request_id="req_01J0000000000000000000REQ1",
    )


# ---------------------------------------------------------------------------
# Tests for _row_to_stored helper (pure logic, no IO)
# ---------------------------------------------------------------------------

class TestRowToStored:
    def _make_row(self, **overrides: Any) -> dict[str, Any]:
        return {
            "event_id": "evt_01J00000000000000000000001",
            "schema_version": 1,
            "occurred_at": datetime(2026, 1, 1, 12, 0, tzinfo=None),
            "ingested_at": datetime(2026, 1, 1, 12, 1, tzinfo=None),
            "tsa_timestamp": None,
            "tenant_id": "tnt_01J0000000000000000000TNT1",
            "service": "identity",
            "service_version": "1.0.0",
            "event_type": "test.event",
            "severity": "INFO",
            "outcome": "SUCCESS",
            "actor_kind": "USER",
            "actor_user_id": "usr_01J0",
            "actor_api_key_id": None,
            "resource_type": "",
            "resource_id": None,
            "resource_path": None,
            "request_id": None,
            "trace_id": None,
            "span_id": None,
            "session_id": None,
            "parent_event_id": None,
            "ip": None,
            "user_agent": None,
            "country": None,
            "payload": json.dumps({"action": "test"}),
            "payload_size": 20,
            "payload_truncated": False,
            "compliance_modes": [],
            "retention_until": None,
            "legal_hold": False,
            "prev_hash": "0" * 64,
            "curr_hash": "a" * 64,
            "merkle_batch_id": "mrk_01J0",
            "merkle_leaf_idx": 0,
            "batch_signature": None,
            "worm_written": False,
            "worm_uri": None,
            **overrides,
        }

    def test_basic_row_conversion(self) -> None:
        row = self._make_row()
        stored = _row_to_stored(row)
        assert stored.event_id == "evt_01J00000000000000000000001"
        assert stored.tenant_id == "tnt_01J0000000000000000000TNT1"
        assert stored.service == "identity"

    def test_payload_parsed_from_json_string(self) -> None:
        row = self._make_row(payload=json.dumps({"amount": 100, "currency": "CNY"}))
        stored = _row_to_stored(row)
        assert stored.payload == {"amount": 100, "currency": "CNY"}

    def test_payload_invalid_json_defaults_to_empty(self) -> None:
        row = self._make_row(payload="not-valid-json{")
        stored = _row_to_stored(row)
        assert stored.payload == {}

    def test_occurred_at_gets_utc(self) -> None:
        """Naive datetime from CH gets UTC timezone."""
        row = self._make_row(occurred_at=datetime(2026, 3, 15, 8, 30, tzinfo=None))
        stored = _row_to_stored(row)
        from datetime import timezone
        assert stored.occurred_at.tzinfo == timezone.utc

    def test_merkle_fields_preserved(self) -> None:
        row = self._make_row(merkle_batch_id="mrk_ABC", merkle_leaf_idx=5)
        stored = _row_to_stored(row)
        assert stored.merkle_batch_id == "mrk_ABC"
        assert stored.merkle_leaf_idx == 5

    def test_worm_fields(self) -> None:
        row = self._make_row(worm_written=True, worm_uri="s3://bucket/key")
        stored = _row_to_stored(row)
        assert stored.worm_written is True
        assert stored.worm_uri == "s3://bucket/key"

    def test_empty_string_resource_type_becomes_none(self) -> None:
        row = self._make_row(resource_type="")
        stored = _row_to_stored(row)
        assert stored.resource_type is None

    def test_hash_fields(self) -> None:
        row = self._make_row(prev_hash="b" * 64, curr_hash="c" * 64)
        stored = _row_to_stored(row)
        assert stored.prev_hash == "b" * 64
        assert stored.curr_hash == "c" * 64


# ---------------------------------------------------------------------------
# Tests for verify_integrity — CROSS-TENANT check
# ---------------------------------------------------------------------------

class TestVerifyIntegrityCrossTenant:
    """Verify that cross-tenant requests are rejected."""

    def test_rejects_wrong_tenant_id(self) -> None:
        """Request with tenant_id != ctx.tenant_id must raise 403."""
        from foundation_audit.api.v1.events import verify_integrity, VerifyIntegrityRequest
        import asyncio

        ctx = _make_context(tenant_id="tnt_01J0000000000000000000TNT1")
        body = VerifyIntegrityRequest(
            tenant_id="tnt_EVIL_DIFFERENT_TENANT_0000001",  # different tenant
        )

        async def _run() -> None:
            from fastapi import HTTPException
            with pytest.raises(HTTPException) as exc_info:
                await verify_integrity(body=body, ctx=ctx)
            assert exc_info.value.status_code == 403

        asyncio.run(_run())


# ---------------------------------------------------------------------------
# Tests for queryEvents — CROSS-TENANT check + basic functionality
# ---------------------------------------------------------------------------

class TestQueryEventsCrossTenant:
    def test_rejects_wrong_tenant_id(self) -> None:
        from foundation_audit.api.v1.events import query_events
        from foundation_audit.schemas.event import AuditQuery
        import asyncio

        ctx = _make_context(tenant_id="tnt_01J0000000000000000000TNT1")
        q = AuditQuery(tenant_id="tnt_EVIL00000000000000000000001")

        async def _run() -> None:
            from fastapi import HTTPException
            with pytest.raises(HTTPException) as exc_info:
                await query_events(query=q, ctx=ctx)
            assert exc_info.value.status_code == 403

        asyncio.run(_run())

    def test_returns_empty_on_ch_no_results(self) -> None:
        from foundation_audit.api.v1.events import query_events
        from foundation_audit.schemas.event import AuditQuery
        import asyncio

        ctx = _make_context()
        q = AuditQuery(tenant_id=ctx.tenant_id, limit=10)

        async def _run() -> None:
            with patch("foundation_audit.api.v1.events.ch.query_events", new_callable=AsyncMock, return_value=[]):
                result = await query_events(query=q, ctx=ctx)
            assert result.items == []
            assert result.next_cursor is None

        asyncio.run(_run())

    def test_returns_items_and_cursor(self) -> None:
        from foundation_audit.api.v1.events import query_events
        from foundation_audit.schemas.event import AuditQuery
        import asyncio

        ctx = _make_context()
        q = AuditQuery(tenant_id=ctx.tenant_id, limit=2)

        now = datetime(2026, 1, 1, 12, 0, tzinfo=None)
        fake_rows = [
            {
                "event_id": f"evt_01J0000000000000000000000{i}",
                "schema_version": 1,
                "occurred_at": now,
                "ingested_at": now,
                "tsa_timestamp": None,
                "tenant_id": ctx.tenant_id,
                "service": "identity",
                "service_version": "",
                "event_type": "test",
                "severity": "INFO",
                "outcome": "SUCCESS",
                "actor_kind": "USER",
                "actor_user_id": None,
                "actor_api_key_id": None,
                "resource_type": "",
                "resource_id": None,
                "resource_path": None,
                "request_id": None,
                "trace_id": None,
                "span_id": None,
                "session_id": None,
                "parent_event_id": None,
                "ip": None,
                "user_agent": None,
                "country": None,
                "payload": "{}",
                "payload_size": 2,
                "payload_truncated": False,
                "compliance_modes": [],
                "retention_until": None,
                "legal_hold": False,
                "prev_hash": "0" * 64,
                "curr_hash": "a" * 64,
                "merkle_batch_id": None,
                "merkle_leaf_idx": None,
                "batch_signature": None,
                "worm_written": False,
                "worm_uri": None,
            }
            for i in range(2)
        ]

        async def _run() -> None:
            with patch("foundation_audit.api.v1.events.ch.query_events", new_callable=AsyncMock, return_value=fake_rows):
                result = await query_events(query=q, ctx=ctx)
            assert len(result.items) == 2
            # limit == len(items) → next_cursor is set
            assert result.next_cursor == result.items[-1].event_id

        asyncio.run(_run())

    def test_ch_503_on_exception(self) -> None:
        from foundation_audit.api.v1.events import query_events
        from foundation_audit.schemas.event import AuditQuery
        import asyncio

        ctx = _make_context()
        q = AuditQuery(tenant_id=ctx.tenant_id)

        async def _run() -> None:
            from fastapi import HTTPException
            with patch("foundation_audit.api.v1.events.ch.query_events",
                       side_effect=Exception("CH down")):
                with pytest.raises(HTTPException) as exc_info:
                    await query_events(query=q, ctx=ctx)
            assert exc_info.value.status_code == 503

        asyncio.run(_run())


# ---------------------------------------------------------------------------
# Tests for worm helper
# ---------------------------------------------------------------------------

class TestWormHelper:
    def test_should_worm_security(self) -> None:
        from foundation_audit.adapters.worm import _should_worm
        assert _should_worm({"severity": "SECURITY"}) is True
        assert _should_worm({"severity": "CRITICAL"}) is True
        assert _should_worm({"severity": "INFO"}) is False
        assert _should_worm({"severity": "ERROR"}) is False

    def test_object_key_format(self) -> None:
        from foundation_audit.adapters.worm import _object_key
        ev = {
            "event_id": "evt_TESTID",
            "tenant_id": "tnt_T1",
            "occurred_at": "2026-06-15T10:30:00+00:00",
        }
        key = _object_key(ev)
        assert "tenant=tnt_T1" in key
        assert "year=2026" in key
        assert "month=06" in key
        assert "day=15" in key
        assert "hour=10" in key
        assert key.endswith("evt_TESTID.json")

    def test_worm_disabled_returns_none(self) -> None:
        from foundation_audit.adapters.worm import write_worm
        import asyncio
        with patch("foundation_audit.adapters.worm.get_settings") as mock_settings:
            s = type("S", (), {"worm_enabled": False})()
            mock_settings.return_value = s
            result = asyncio.run(write_worm({"severity": "CRITICAL", "event_id": "evt_X"}))
        assert result is None


# ---------------------------------------------------------------------------
# Tests for ingest_service record_attempts
# ---------------------------------------------------------------------------

class TestIngestServiceRecordAttempts:
    @pytest.mark.asyncio
    async def test_record_attempts_increments_counter(self) -> None:
        """record_attempts executes an UPDATE without raising."""
        from foundation_audit.services.ingest_service import IngestService
        from unittest.mock import AsyncMock, MagicMock

        svc = IngestService()
        mock_session = MagicMock()
        mock_session.execute = AsyncMock()
        mock_session.flush = AsyncMock()

        # Should not raise
        await svc.record_attempts(mock_session, [1, 2, 3], error="CH refused")
        mock_session.execute.assert_called_once()
        mock_session.flush.assert_called_once()

    @pytest.mark.asyncio
    async def test_record_attempts_empty_list_is_noop(self) -> None:
        """Empty row_ids → no DB calls."""
        from foundation_audit.services.ingest_service import IngestService
        from unittest.mock import AsyncMock, MagicMock

        svc = IngestService()
        mock_session = MagicMock()
        mock_session.execute = AsyncMock()

        await svc.record_attempts(mock_session, [], error="x")
        mock_session.execute.assert_not_called()

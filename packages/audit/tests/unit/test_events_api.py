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
# Tests for exportEvents — CSV/JSON + CROSS-TENANT check
# ---------------------------------------------------------------------------

def _make_export_row(event_id: str, tenant_id: str, **overrides: Any) -> dict[str, Any]:
    row = {
        "event_id": event_id,
        "occurred_at": datetime(2026, 1, 1, 12, 0, tzinfo=None),
        "ingested_at": datetime(2026, 1, 1, 12, 1, tzinfo=None),
        "tenant_id": tenant_id,
        "service": "identity",
        "event_type": "user.login",
        "severity": "INFO",
        "outcome": "SUCCESS",
        "actor_kind": "USER",
        "actor_user_id": "usr_01J0",
        "resource_type": "user",
        "resource_id": "usr_01J0",
        "request_id": "req_01J0",
        "session_id": None,
    }
    row.update(overrides)
    return row


class TestExportEventsCrossTenant:
    def test_rejects_wrong_tenant_id(self) -> None:
        from foundation_audit.api.v1.events import export_events
        from foundation_audit.schemas.event import AuditQuery
        import asyncio

        ctx = _make_context(tenant_id="tnt_01J0000000000000000000TNT1")
        q = AuditQuery(tenant_id="tnt_EVIL00000000000000000000001")

        async def _run() -> None:
            from fastapi import HTTPException
            with pytest.raises(HTTPException) as exc_info:
                await export_events(query=q, fmt="csv", ctx=ctx)
            assert exc_info.value.status_code == 403

        asyncio.run(_run())


class TestExportEventsCsv:
    def test_csv_export_headers_and_body(self) -> None:
        from foundation_audit.api.v1.events import export_events, EXPORT_COLUMNS
        from foundation_audit.schemas.event import AuditQuery
        import asyncio

        ctx = _make_context()
        q = AuditQuery(tenant_id=ctx.tenant_id)
        rows = [_make_export_row(f"evt_01J000000000000000000000{i:02d}", ctx.tenant_id) for i in range(3)]

        async def _run() -> None:
            with patch("foundation_audit.api.v1.events.ch.query_events", new_callable=AsyncMock, return_value=rows):
                resp = await export_events(query=q, fmt="csv", ctx=ctx)
            assert resp.status_code == 200
            assert resp.media_type == "text/csv"
            cd = resp.headers["content-disposition"]
            assert cd == f'attachment; filename="audit-export-{ctx.tenant_id}.csv"'
            # All bytes are ASCII (no latin-1 crash risk).
            body = resp.body.decode("utf-8")
            body.encode("latin-1")  # would raise if non-latin-1
            lines = body.strip().splitlines()
            assert lines[0] == ",".join(EXPORT_COLUMNS)
            assert len(lines) == 1 + 3  # header + 3 rows
            assert "evt_01J00000000000000000000000" in body

        asyncio.run(_run())

    def test_csv_export_empty(self) -> None:
        from foundation_audit.api.v1.events import export_events, EXPORT_COLUMNS
        from foundation_audit.schemas.event import AuditQuery
        import asyncio

        ctx = _make_context()
        q = AuditQuery(tenant_id=ctx.tenant_id)

        async def _run() -> None:
            with patch("foundation_audit.api.v1.events.ch.query_events", new_callable=AsyncMock, return_value=[]):
                resp = await export_events(query=q, fmt="csv", ctx=ctx)
            assert resp.status_code == 200
            lines = resp.body.decode("utf-8").strip().splitlines()
            assert lines == [",".join(EXPORT_COLUMNS)]  # header only

        asyncio.run(_run())


class TestExportEventsJson:
    def test_json_export(self) -> None:
        from foundation_audit.api.v1.events import export_events
        from foundation_audit.schemas.event import AuditQuery
        import asyncio

        ctx = _make_context()
        q = AuditQuery(tenant_id=ctx.tenant_id)
        rows = [_make_export_row("evt_01J00000000000000000000001", ctx.tenant_id)]

        async def _run() -> None:
            with patch("foundation_audit.api.v1.events.ch.query_events", new_callable=AsyncMock, return_value=rows):
                resp = await export_events(query=q, fmt="json", ctx=ctx)
            assert resp.status_code == 200
            assert resp.media_type == "application/json"
            assert resp.headers["content-disposition"] == f'attachment; filename="audit-export-{ctx.tenant_id}.json"'
            data = json.loads(resp.body)
            assert isinstance(data, list)
            assert len(data) == 1
            assert data[0]["event_id"] == "evt_01J00000000000000000000001"
            assert data[0]["service"] == "identity"
            # datetimes serialized to ISO strings
            assert data[0]["occurred_at"] == "2026-01-01T12:00:00"

        asyncio.run(_run())


class TestExportEventsPagination:
    def test_cursor_loop_aggregates_pages(self) -> None:
        """When a full page is returned, the loop fetches again using the cursor."""
        from foundation_audit.api.v1.events import export_events, EXPORT_PAGE_SIZE
        from foundation_audit.schemas.event import AuditQuery
        import asyncio

        ctx = _make_context()
        q = AuditQuery(tenant_id=ctx.tenant_id)

        # First call returns a full page (EXPORT_PAGE_SIZE rows) → loop continues;
        # second call returns a short page → loop stops.
        page1 = [_make_export_row(f"evt_{i:026d}", ctx.tenant_id) for i in range(EXPORT_PAGE_SIZE)]
        page2 = [_make_export_row("evt_FINAL00000000000000000001", ctx.tenant_id)]
        mock = AsyncMock(side_effect=[page1, page2])

        async def _run() -> None:
            with patch("foundation_audit.api.v1.events.ch.query_events", mock):
                resp = await export_events(query=q, fmt="csv", ctx=ctx)
            # header + page1 + page2 rows
            lines = resp.body.decode("utf-8").strip().splitlines()
            assert len(lines) == 1 + EXPORT_PAGE_SIZE + 1
            # Second call used the cursor = last event_id of page1
            assert mock.call_count == 2
            second_kwargs = mock.call_args_list[1].kwargs
            assert second_kwargs["cursor"] == page1[-1]["event_id"]

        asyncio.run(_run())

    def test_ch_503_on_exception(self) -> None:
        from foundation_audit.api.v1.events import export_events
        from foundation_audit.schemas.event import AuditQuery
        import asyncio

        ctx = _make_context()
        q = AuditQuery(tenant_id=ctx.tenant_id)

        async def _run() -> None:
            from fastapi import HTTPException
            with patch("foundation_audit.api.v1.events.ch.query_events", side_effect=Exception("CH down")):
                with pytest.raises(HTTPException) as exc_info:
                    await export_events(query=q, fmt="csv", ctx=ctx)
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

    def test_worm_via_storage_client_path(self) -> None:
        """Flag ON → write goes through StorageClient.put_object with COMPLIANCE lock."""
        import asyncio
        from foundation_audit.adapters import worm as worm_mod

        captured: dict[str, Any] = {}

        async def fake_put_object(**kwargs: Any) -> None:
            captured.update(kwargs)

        fake_client = type("C", (), {"put_object": staticmethod(fake_put_object)})()

        fake_audit_settings = type("S", (), {
            "worm_enabled": True,
            "worm_retention_years": 7,
            "worm_bucket": "legacy-bucket",  # must not be reached
            "s3_endpoint": "http://ignored",
            "s3_access_key": "x",
            "s3_secret_key": "x",
        })()

        fake_storage_settings = type("SS", (), {"bucket_audit": "foundation-audit"})()

        with patch.object(worm_mod, "get_settings", return_value=fake_audit_settings), \
             patch.object(worm_mod, "_is_storage_client_enabled", return_value=True), \
             patch(
                 "foundation_storage.StorageClient.as_system",
                 return_value=fake_client,
             ), \
             patch(
                 "foundation_storage.get_settings",
                 return_value=fake_storage_settings,
             ):
            uri = asyncio.run(worm_mod.write_worm({
                "severity": "SECURITY",
                "event_id": "evt_NEW01",
                "tenant_id": "tnt_T2",
                "occurred_at": "2026-06-15T10:30:00+00:00",
            }))

        # URI assembled from storage settings bucket_audit + new layout key
        assert uri == (
            "s3://foundation-audit/tenants/tnt_T2/events/2026/06/15/10/evt_NEW01.json"
        )
        # put_object received the correct kwargs
        assert captured["content_type"] == "application/json"
        assert captured["object_lock_mode"] == "COMPLIANCE"
        assert captured["object_lock_retain_until"].year >= datetime.now(UTC).year + 7
        assert captured["key"].key == (
            "tenants/tnt_T2/events/2026/06/15/10/evt_NEW01.json"
        )
        assert isinstance(captured["body"], bytes)
        # body is valid JSON containing the event_id
        payload = json.loads(captured["body"])
        assert payload["event_id"] == "evt_NEW01"


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

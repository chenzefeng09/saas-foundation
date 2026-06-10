"""Unit tests for ClickHouse adapter helpers (no CH connection required)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from foundation_audit.adapters.clickhouse import (
    EVENTS_COLUMNS,
    MERKLE_BATCH_COLUMNS,
    _event_to_row,
    get_events_for_verification,
)


class TestEventToRow:
    """Test _event_to_row column alignment."""

    def _make_event(self, **overrides: Any) -> dict[str, Any]:
        return {
            "event_id": "evt_01J00000000000000000000001",
            "schema_version": 1,
            "occurred_at": datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC).isoformat(),
            "tenant_id": "tnt_01J0000000000000000000TNT1",
            "service": "identity",
            "service_version": "1.0.0",
            "event_type": "test.event",
            "severity": "INFO",
            "outcome": "SUCCESS",
            "actor_kind": "USER",
            "actor_user_id": "usr_01J0000000000000000000USR1",
            "payload": {"action": "login"},
            "prev_hash": "0" * 64,
            "curr_hash": "a" * 64,
            "merkle_batch_id": "mrk_01J0",
            "merkle_leaf_idx": 0,
            **overrides,
        }

    def test_row_length_matches_columns(self) -> None:
        """Row must have exactly len(EVENTS_COLUMNS) elements."""
        row = _event_to_row(self._make_event())
        assert len(row) == len(EVENTS_COLUMNS)

    def test_column_order_event_id_first(self) -> None:
        """event_id must be at index 0 (first column)."""
        event = self._make_event()
        row = _event_to_row(event)
        assert row[0] == "evt_01J00000000000000000000001"
        assert EVENTS_COLUMNS[0] == "event_id"

    def test_tenant_id_in_correct_position(self) -> None:
        """tenant_id column position must match."""
        event = self._make_event()
        row = _event_to_row(event)
        idx = EVENTS_COLUMNS.index("tenant_id")
        assert row[idx] == "tnt_01J0000000000000000000TNT1"

    def test_prev_hash_curr_hash_positions(self) -> None:
        """prev_hash and curr_hash must be in correct positions."""
        event = self._make_event()
        row = _event_to_row(event)
        prev_idx = EVENTS_COLUMNS.index("prev_hash")
        curr_idx = EVENTS_COLUMNS.index("curr_hash")
        assert row[prev_idx] == "0" * 64
        assert row[curr_idx] == "a" * 64

    def test_merkle_batch_id_and_leaf_idx(self) -> None:
        """merkle_batch_id and merkle_leaf_idx must be present."""
        event = self._make_event()
        row = _event_to_row(event)
        bid_idx = EVENTS_COLUMNS.index("merkle_batch_id")
        lidx_idx = EVENTS_COLUMNS.index("merkle_leaf_idx")
        assert row[bid_idx] == "mrk_01J0"
        assert row[lidx_idx] == 0

    def test_payload_serialised_as_json_string(self) -> None:
        """payload dict must be stored as JSON string."""
        event = self._make_event(payload={"key": "value", "num": 42})
        row = _event_to_row(event)
        idx = EVENTS_COLUMNS.index("payload")
        stored_payload = row[idx]
        assert isinstance(stored_payload, str)
        parsed = json.loads(stored_payload)
        assert parsed == {"key": "value", "num": 42}

    def test_payload_size_computed(self) -> None:
        """payload_size must equal len(json.dumps(payload).encode())."""
        payload = {"x": "hello"}
        event = self._make_event(payload=payload)
        row = _event_to_row(event)
        size_idx = EVENTS_COLUMNS.index("payload_size")
        expected_size = len(json.dumps(payload, ensure_ascii=False).encode())
        assert row[size_idx] == expected_size

    def test_occurred_at_naive_datetime(self) -> None:
        """occurred_at must be stored as naive datetime (CH stores UTC naive)."""
        event = self._make_event()
        row = _event_to_row(event)
        idx = EVENTS_COLUMNS.index("occurred_at")
        dt = row[idx]
        assert isinstance(dt, datetime)
        assert dt.tzinfo is None  # naive UTC

    def test_occurred_at_from_string(self) -> None:
        """occurred_at string is parsed correctly."""
        event = self._make_event(occurred_at="2026-06-01T10:30:00Z")
        row = _event_to_row(event)
        idx = EVENTS_COLUMNS.index("occurred_at")
        dt = row[idx]
        assert dt.year == 2026
        assert dt.month == 6
        assert dt.day == 1

    def test_worm_columns_default(self) -> None:
        """worm_written defaults False, worm_uri defaults None."""
        event = self._make_event()
        row = _event_to_row(event)
        worm_idx = EVENTS_COLUMNS.index("worm_written")
        uri_idx = EVENTS_COLUMNS.index("worm_uri")
        assert row[worm_idx] is False
        assert row[uri_idx] is None

    def test_nullable_fields_default_to_none(self) -> None:
        """actor_api_key_id, resource_id, trace_id etc. default to None if missing."""
        event = self._make_event()
        row = _event_to_row(event)
        for col in ("actor_api_key_id", "resource_id", "resource_path", "trace_id", "span_id"):
            idx = EVENTS_COLUMNS.index(col)
            assert row[idx] is None, f"Expected None for {col}"

    def test_compliance_modes_default_empty_list(self) -> None:
        """compliance_modes must default to an empty list."""
        event = self._make_event()
        row = _event_to_row(event)
        idx = EVENTS_COLUMNS.index("compliance_modes")
        assert row[idx] == []


class TestGetEventsForVerification:
    """Regression coverage for the column_names handling in verify-integrity.

    clickhouse-connect's QueryResult.column_names is a list of plain *strings*.
    A previous bug did ``[d.name for d in result.column_names]`` which raised
    ``'str' object has no attribute 'name'`` and got surfaced to callers as a
    bogus 503 "ClickHouse unavailable". These tests pin the correct behaviour:
    rows are zipped against the string column names directly.
    """

    @pytest.mark.asyncio
    async def test_string_column_names_do_not_raise(self) -> None:
        """column_names as plain strings must map rows to dicts (no AttributeError)."""
        col_names = [
            "event_id", "tenant_id", "service", "occurred_at", "ingested_at",
            "prev_hash", "curr_hash", "merkle_batch_id", "merkle_leaf_idx",
            "schema_version", "event_type", "severity", "outcome", "actor_kind",
            "actor_user_id", "actor_api_key_id", "resource_type", "resource_id",
            "resource_path", "request_id", "trace_id", "span_id", "session_id",
            "parent_event_id", "ip", "user_agent", "country", "payload",
            "service_version",
        ]
        row = (
            "evt_01J00000000000000000000001", "tnt_01J0000000000000000000TNT1",
            "identity", datetime(2026, 1, 1, tzinfo=UTC), datetime(2026, 1, 1, tzinfo=UTC),
            "0" * 64, "a" * 64, "mrk_01J0", 0,
            1, "test.event", "INFO", "SUCCESS", "USER",
            "usr_1", None, None, None, None, None, None, None, None, None,
            None, None, None, json.dumps({"k": "v"}), "1.0.0",
        )

        result = MagicMock()
        result.column_names = col_names  # list[str], as clickhouse-connect returns
        result.result_rows = [row]

        client = MagicMock()
        client.query = MagicMock(return_value=result)

        with patch(
            "foundation_audit.adapters.clickhouse.get_clickhouse_client",
            new=AsyncMock(return_value=client),
        ):
            out = await get_events_for_verification(
                tenant_id="tnt_01J0000000000000000000TNT1",
                limit=10,
            )

        assert len(out) == 1
        assert out[0]["event_id"] == "evt_01J00000000000000000000001"
        assert out[0]["curr_hash"] == "a" * 64
        assert out[0]["payload"] == json.dumps({"k": "v"})

    @pytest.mark.asyncio
    async def test_empty_result_returns_empty_list(self) -> None:
        """No rows → empty list, no error."""
        result = MagicMock()
        result.column_names = ["event_id", "tenant_id"]
        result.result_rows = []

        client = MagicMock()
        client.query = MagicMock(return_value=result)

        with patch(
            "foundation_audit.adapters.clickhouse.get_clickhouse_client",
            new=AsyncMock(return_value=client),
        ):
            out = await get_events_for_verification(
                tenant_id="tnt_01J0000000000000000000TNT1",
                limit=10,
            )

        assert out == []


class TestMerkleBatchColumns:
    """Verify merkle_batch column list is self-consistent."""

    def test_batch_id_first(self) -> None:
        assert MERKLE_BATCH_COLUMNS[0] == "batch_id"

    def test_merkle_root_present(self) -> None:
        assert "merkle_root" in MERKLE_BATCH_COLUMNS

    def test_signature_and_key_id(self) -> None:
        assert "signature" in MERKLE_BATCH_COLUMNS
        assert "signature_key_id" in MERKLE_BATCH_COLUMNS

    def test_tsa_fields(self) -> None:
        assert "tsa_token" in MERKLE_BATCH_COLUMNS
        assert "tsa_provider" in MERKLE_BATCH_COLUMNS
        assert "tsa_timestamp" in MERKLE_BATCH_COLUMNS

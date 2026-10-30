"""Unit tests for ClickHouse adapter helpers (no CH connection required)."""

from __future__ import annotations

import json
import struct
from collections.abc import Awaitable, Callable
from datetime import UTC, date, datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from clickhouse_connect.datatypes.registry import get_from_name
from clickhouse_connect.driver.insert import InsertContext

from foundation_audit.adapters.clickhouse import (
    EVENTS_COLUMNS,
    MERKLE_BATCH_COLUMNS,
    _event_to_row,
    _insert,
    get_events_for_verification,
    insert_events,
    insert_merkle_batches,
    query_events,
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

    def test_occurred_at_utc_datetime(self) -> None:
        """occurred_at is aware UTC: clickhouse-connect takes a naive one for local time."""
        event = self._make_event(occurred_at="2026-01-01T20:00:00+08:00")
        row = _event_to_row(event)
        idx = EVENTS_COLUMNS.index("occurred_at")
        dt = row[idx]
        assert dt == datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        assert dt.tzinfo is UTC

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


_TENANT = "tnt_01J0000000000000000000TNT1"
_EVT = "evt_01JC0000000000000000000001"
# Everything after the tenant filter of a page that resumes after a cursor: the
# keyset follows the ORDER BY (same columns, same direction).
_KEYSET_TAIL = (
    "AND occurred_at >= {after_ts:DateTime64(3, 'UTC')} "
    "AND (occurred_at, event_id) > ({after_ts:DateTime64(3, 'UTC')}, {after_id:String}) "
    "ORDER BY tenant_id, occurred_at, event_id LIMIT {limit:UInt32}"
)


async def _sent_query(**kwargs: Any) -> tuple[str, dict[str, Any]]:
    """The SQL and parameters that query_events hands clickhouse-connect."""
    result = MagicMock()
    result.result_rows = []
    client = MagicMock()
    client.query = MagicMock(return_value=result)
    with patch(
        "foundation_audit.adapters.clickhouse.get_clickhouse_client",
        new=AsyncMock(return_value=client),
    ):
        await query_events(tenant_id=_TENANT, **kwargs)
    (sql,), call_kwargs = client.query.call_args
    return sql, call_kwargs["parameters"]


@pytest.mark.usefixtures("local_time_not_utc")
class TestQueryEventsKeyset:
    """query_events resumes after the full sort key (occurred_at, event_id)."""

    @pytest.mark.asyncio
    async def test_resumes_after_the_full_sort_key(self) -> None:
        stored = datetime(2026, 10, 30, 12, 0, 0, 250000)  # naive UTC, as CH hands it back

        sql, params = await _sent_query(after=(stored, _EVT), limit=3)

        assert sql.endswith("WHERE tenant_id = {tenant_id:String} " + _KEYSET_TAIL)
        # Bound as text: clickhouse-connect would drop the milliseconds of a datetime.
        assert params["after_ts"] == "2026-10-30 12:00:00.250"
        assert params["after_id"] == _EVT
        assert params["limit"] == 3

    @pytest.mark.asyncio
    async def test_keyset_bound_is_the_utc_instant(self) -> None:
        ts = datetime(2026, 10, 30, 20, 0, 0, 250000, tzinfo=timezone(timedelta(hours=8)))

        _, params = await _sent_query(after=(ts, _EVT))

        assert params["after_ts"] == "2026-10-30 12:00:00.250"

    @pytest.mark.asyncio
    async def test_first_page_has_no_keyset_bound(self) -> None:
        sql, params = await _sent_query(limit=3)

        assert sql.endswith(
            "WHERE tenant_id = {tenant_id:String} "
            "ORDER BY tenant_id, occurred_at, event_id LIMIT {limit:UInt32}"
        )
        assert "after_ts" not in params


_UTC8 = timezone(timedelta(hours=8))
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
# One instant, 2026-10-30 12:00:00.250 UTC, spelled the ways it reaches the adapter.
_INSTANT = datetime(2026, 10, 30, 12, 0, 0, 250000, tzinfo=UTC)
_SPELLINGS: list[datetime | str] = [
    "2026-10-30T12:00:00.250Z",
    "2026-10-30T20:00:00.250+08:00",
    "2026-10-30T07:00:00.250-05:00",
    "2026-10-30T12:00:00.250",  # no offset: UTC
    datetime(2026, 10, 30, 20, 0, 0, 250000, tzinfo=_UTC8),
    datetime(2026, 10, 30, 12, 0, 0, 250000),  # naive: UTC, as CH hands it back
]


@pytest.mark.usefixtures("local_time_not_utc")
class TestQueryEventsTimeBounds:
    """occurred_from / occurred_to are bound as the UTC instant, to the millisecond."""

    @pytest.mark.parametrize(
        "bound",
        [
            datetime(2026, 10, 30, 12, 0, 0, 250000, tzinfo=UTC),
            datetime(2026, 10, 30, 20, 0, 0, 250999, tzinfo=_UTC8),  # cut to the ms, as stored
            datetime(2026, 10, 30, 12, 0, 0, 250000),  # naive: UTC
        ],
    )
    @pytest.mark.asyncio
    async def test_bounds_are_the_utc_instant(self, bound: datetime) -> None:
        sql, params = await _sent_query(occurred_from=bound, occurred_to=bound)

        assert "AND occurred_at >= {occurred_from:DateTime64(3, 'UTC')} " in sql
        assert "AND occurred_at <= {occurred_to:DateTime64(3, 'UTC')} " in sql
        # Text: clickhouse-connect binds a datetime in whole seconds, a naive one as local time.
        assert params["occurred_from"] == "2026-10-30 12:00:00.250"
        assert params["occurred_to"] == "2026-10-30 12:00:00.250"


def _stored_ms(value: datetime) -> int:
    """Epoch ms that clickhouse-connect sends for ``value`` in a DateTime64(3, 'UTC') column."""
    ch_type = get_from_name("DateTime64(3, 'UTC')")
    dest = bytearray()
    ch_type.write_column([value], dest, InsertContext("t", ["c"], [ch_type]))
    (ms,) = struct.unpack("<q", dest)
    return int(ms)


def _epoch_ms(ts: datetime) -> int:
    return (ts - _EPOCH) // timedelta(milliseconds=1)


async def _inserted(insert: Callable[[], Awaitable[None]]) -> list[dict[str, Any]]:
    """The rows ``insert`` hands clickhouse-connect, as {column: value}."""
    client = MagicMock()
    with patch(
        "foundation_audit.adapters.clickhouse.get_clickhouse_client",
        new=AsyncMock(return_value=client),
    ):
        await insert()
    (_table, data), call_kwargs = client.insert.call_args
    return [dict(zip(call_kwargs["column_names"], row, strict=True)) for row in data]


def _event(**overrides: Any) -> dict[str, Any]:
    return {"event_id": _EVT, "tenant_id": _TENANT, "service": "identity", **overrides}


@pytest.mark.usefixtures("local_time_not_utc")
class TestInsertedInstants:
    """Every datetime is stored as the UTC instant it names, to the millisecond.

    ClickHouse keeps a DateTime64 as ticks since the epoch.  ``_stored_ms`` runs
    clickhouse-connect's own serialiser, which reads a naive datetime as host local
    time, so these pass only if no naive datetime reaches it.
    """

    @pytest.mark.parametrize("value", _SPELLINGS)
    @pytest.mark.asyncio
    async def test_event_times(self, value: datetime | str) -> None:
        (row,) = await _inserted(
            lambda: insert_events([_event(occurred_at=value, ingested_at=value)]),
        )

        assert _stored_ms(row["occurred_at"]) == _epoch_ms(_INSTANT)
        assert _stored_ms(row["ingested_at"]) == _epoch_ms(_INSTANT)

    @pytest.mark.asyncio
    async def test_missing_event_times_are_now(self) -> None:
        (row,) = await _inserted(lambda: insert_events([_event()]))

        now = _epoch_ms(datetime.now(UTC))
        assert abs(_stored_ms(row["occurred_at"]) - now) < 60_000
        assert abs(_stored_ms(row["ingested_at"]) - now) < 60_000

    @pytest.mark.asyncio
    async def test_retention_date_is_the_utc_day(self) -> None:
        (row,) = await _inserted(
            lambda: insert_events([_event(occurred_at="2026-10-31T03:00:00+08:00")]),
        )

        assert row["retention_until"] == date(2026, 10, 30)

    @pytest.mark.parametrize("value", _SPELLINGS)
    @pytest.mark.asyncio
    async def test_merkle_batch_times(self, value: datetime | str) -> None:
        times = {"created_at": value, "sealed_at": value, "tsa_timestamp": value}

        (row,) = await _inserted(lambda: insert_merkle_batches([{"batch_id": "mrk_1", **times}]))

        assert _stored_ms(row["created_at"]) == _epoch_ms(_INSTANT)
        assert _stored_ms(row["sealed_at"]) == _epoch_ms(_INSTANT)
        assert _stored_ms(row["tsa_timestamp"]) == _epoch_ms(_INSTANT)

    @pytest.mark.asyncio
    async def test_merkle_batch_without_tsa(self) -> None:
        (row,) = await _inserted(lambda: insert_merkle_batches([{"batch_id": "mrk_1"}]))

        assert row["tsa_timestamp"] is None
        now = _epoch_ms(datetime.now(UTC))
        assert abs(_stored_ms(row["created_at"]) - now) < 60_000
        assert abs(_stored_ms(row["sealed_at"]) - now) < 60_000

    @pytest.mark.asyncio
    async def test_any_naive_datetime_is_stored_as_utc(self) -> None:
        """_insert itself holds for a column the row builders do not know yet."""
        naive = datetime(2026, 10, 30, 12, 0, 0, 250000)

        (row,) = await _inserted(lambda: _insert("audit.events", [[naive]], ["occurred_at"]))

        assert _stored_ms(row["occurred_at"]) == _epoch_ms(_INSTANT)


class TestInsertMerkleBatches:
    @pytest.mark.asyncio
    async def test_a_run_s_batches_go_in_one_insert(self) -> None:
        """One insert is one part for ClickHouse to merge, however many chains a run seals."""
        client = MagicMock()
        with patch(
            "foundation_audit.adapters.clickhouse.get_clickhouse_client",
            new=AsyncMock(return_value=client),
        ):
            await insert_merkle_batches([{"batch_id": "mrk_1"}, {"batch_id": "mrk_2"}])

        client.insert.assert_called_once()
        (table, data), _ = client.insert.call_args
        assert table == "audit.merkle_batch"
        assert [row[MERKLE_BATCH_COLUMNS.index("batch_id")] for row in data] == ["mrk_1", "mrk_2"]

    @pytest.mark.asyncio
    async def test_no_batches_insert_nothing(self) -> None:
        client = MagicMock()
        with patch(
            "foundation_audit.adapters.clickhouse.get_clickhouse_client",
            new=AsyncMock(return_value=client),
        ):
            await insert_merkle_batches([])

        client.insert.assert_not_called()


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

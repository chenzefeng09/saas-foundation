"""verify-integrity over chains the worker built, read back as ClickHouse hands them out.

Events take the real path: AuditEvent → IngestService's outbox JSON (through JSON
text, as Postgres JSONB keeps it) → BatchProcessor (hash chain, Merkle batch) →
the adapter's inserts → clickhouse-connect's own codec for each column's type in
audit-schema.sql → the adapter's verification queries → verify_integrity.  Only
Postgres, the ClickHouse server, crypto-service and the worker's clock are stand-ins.
"""

from __future__ import annotations

import itertools
import json
import operator
import re
from collections import Counter
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta, tzinfo
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from clickhouse_connect.datatypes.registry import get_from_name
from clickhouse_connect.driver import ctypes as ch_ctypes
from clickhouse_connect.driver.exceptions import OperationalError
from clickhouse_connect.driver.insert import InsertContext
from clickhouse_connect.driver.query import QueryContext

from foundation_audit.api.v1.events import (
    VerifyIntegrityRequest,
    VerifyIntegrityResponse,
    verify_integrity,
)
from foundation_audit.config import Settings
from foundation_audit.domain.base import FoundationContext
from foundation_audit.errors import EVENT_NOT_FOUND, VALIDATION_FAILED, FoundationError
from foundation_audit.schemas.event import AuditEvent
from foundation_audit.services.ingest_service import IngestService
from foundation_audit.services.pagination import encode_chain_cursor, encode_cursor
from foundation_audit.worker.batch_processor import BatchProcessor

_SCHEMA_SQL = (
    Path(__file__).resolve().parents[4]
    / "deploy/docker-compose/config/clickhouse/audit-schema.sql"
)
_TENANT = "tnt_01J0000000000000000000TNT1"
_NOON = datetime(2026, 10, 30, 12, tzinfo=UTC)
_SETTINGS = Settings(tsa_enabled=False, worm_enabled=False)

# clickhouse-connect 0.7.19 reads DateTime64 columns with datetime.utcfromtimestamp.
pytestmark = pytest.mark.filterwarnings("ignore:datetime.datetime.utcfromtimestamp")


# ---------------------------------------------------------------------------
# ClickHouse stand-in
# ---------------------------------------------------------------------------

def _column_types(table: str) -> dict[str, str]:
    """Column → type of ``table``, as audit-schema.sql creates it."""
    ddl = _SCHEMA_SQL.read_text(encoding="utf-8")
    body = re.search(rf"CREATE TABLE IF NOT EXISTS {re.escape(table)}\s*\((.*?)\n\)", ddl, re.S)
    assert body is not None, table
    types: dict[str, str] = {}
    for line in body.group(1).splitlines():
        column = line.split("--")[0].strip().rstrip(",")
        if column:
            name, column_type = column.split(None, 1)
            types[name] = column_type.split(" DEFAULT ")[0].strip()
    return types


class _Body:
    """A response body as clickhouse-connect's buffer reads it: one chunk."""

    def __init__(self, data: bytes) -> None:
        self.gen = iter([data])

    def close(self) -> None:
        pass


def _stored(column_type: str, values: list[Any]) -> list[Any]:
    """``values`` written to a ``column_type`` column and read back by clickhouse-connect.

    The column is followed by a byte, as in a server's response more follows it:
    clickhouse-connect 0.7.19's C reader crashes on a lone '' that ends its input.
    """
    ch_type = get_from_name(column_type)
    native = bytearray()
    ch_type.write_column(values, native, InsertContext("t", ["c"], [ch_type]))
    buffer = ch_ctypes.RespBuffCls(_Body(bytes(native) + b"\0"))
    return list(ch_type.read_column(buffer, len(values), QueryContext()))


def _chained_at(row: dict[str, Any]) -> tuple[datetime, str, int]:
    """Where the worker chained the event of ``row``."""
    return row["ingested_at"], row["merkle_batch_id"], row["merkle_leaf_idx"]


def _bound_position(p: dict[str, Any]) -> tuple[datetime, str, int]:
    """The chain position bound in the parameters, as the server reads it.

    The adapter binds a datetime as DateTime64(3, 'UTC') text, which the server
    compares with the naive UTC values its column holds.
    """
    return datetime.fromisoformat(p["at_ingested_at"]), p["at_batch_id"], p["at_leaf_idx"]


_CHAIN_ORDER = "(ingested_at, merkle_batch_id, merkle_leaf_idx)"
_AT = "({at_ingested_at:DateTime64(3, 'UTC')}, {at_batch_id:String}, {at_leaf_idx:UInt32})"

# The WHERE conditions of the adapter's verification queries, as the server applies them.
_CONDITIONS: dict[str, Callable[[dict[str, Any], dict[str, Any]], bool]] = {
    "tenant_id = {tenant_id:String}": lambda row, p: row["tenant_id"] == p["tenant_id"],
    "service = {service:String}": lambda row, p: row["service"] == p["service"],
    "service IN {services:Array(String)}": lambda row, p: row["service"] in p["services"],
    "event_id = {event_id:String}": lambda row, p: row["event_id"] == p["event_id"],
    "curr_hash IN {curr_hashes:Array(String)}": lambda row, p: row["curr_hash"] in p["curr_hashes"],
    "merkle_batch_id IN {batch_ids:Array(String)}": (
        lambda row, p: row["merkle_batch_id"] in p["batch_ids"]
    ),
    "batch_id IN {batch_ids:Array(String)}": lambda row, p: row["batch_id"] in p["batch_ids"],
    f"{_CHAIN_ORDER} > {_AT}": lambda row, p: _chained_at(row) > _bound_position(p),
    f"{_CHAIN_ORDER} >= {_AT}": lambda row, p: _chained_at(row) >= _bound_position(p),
    f"{_CHAIN_ORDER} < {_AT}": lambda row, p: _chained_at(row) < _bound_position(p),
    f"{_CHAIN_ORDER} <= {_AT}": lambda row, p: _chained_at(row) <= _bound_position(p),
}
_SELECT = re.compile(
    r"SELECT (?P<columns>.+) FROM (?P<table>\S+) WHERE (?P<where>.+?)(?: ORDER BY (?P<order>.+?))?"
    r"(?: LIMIT (?P<limit>\d+|\{limit:UInt32\})(?: BY (?P<by>\w+))?)?"
)


class _ClickHouse:
    """audit.events and audit.merkle_batch, answering the adapter as the server would.

    insert() keeps every value as clickhouse-connect's codec hands it back for its
    column's type: naive UTC datetimes to the millisecond, '' where a String column
    got '', and None in a column that is not Nullable fails as it does there.
    query() reads the SELECT list, WHERE conditions, [ORDER BY] and [LIMIT [BY]] of the SQL.
    Either fails, storing or reading nothing, while ``refuse`` lists it.
    """

    def __init__(self) -> None:
        self.types = {t: _column_types(t) for t in ("audit.events", "audit.merkle_batch")}
        self.rows: dict[str, list[dict[str, Any]]] = {t: [] for t in self.types}
        # ("insert" or "query", table): refused once each, as by a server out of reach
        self.refuse: list[tuple[str, str]] = []

    def _answer(self, statement: str, table: str) -> None:
        if (statement, table) in self.refuse:
            self.refuse.remove((statement, table))
            raise OperationalError(f"{statement} {table}: connection refused")

    def insert(self, table: str, data: list[list[Any]], column_names: list[str]) -> None:
        self._answer("insert", table)
        assert sorted(column_names) == sorted(self.types[table])  # nothing left to a DEFAULT
        columns = [
            _stored(self.types[table][name], [row[i] for row in data])
            for i, name in enumerate(column_names)
        ]
        self.rows[table] += [
            dict(zip(column_names, row, strict=True)) for row in zip(*columns, strict=True)
        ]

    def query(self, sql: str, parameters: dict[str, Any]) -> SimpleNamespace:
        select = _SELECT.fullmatch(sql)
        assert select is not None, sql
        self._answer("query", select["table"])
        conditions = select["where"].split(" AND ")
        rows = [
            row
            for row in self.rows[select["table"]]
            if all(_CONDITIONS[c](row, parameters) for c in conditions)
        ]
        for key in reversed(select["order"].split(", ") if select["order"] else []):
            column, _, direction = key.partition(" ")
            rows.sort(key=operator.itemgetter(column), reverse=direction == "DESC")
        if select["limit"] is not None:
            limit = parameters["limit"] if select["limit"].startswith("{") else int(select["limit"])
            if select["by"] is None:
                rows = rows[:limit]
            else:  # LIMIT n BY column: the first n rows of each value of column
                taken: Counter[Any] = Counter()
                kept = []
                for row in rows:
                    taken[row[select["by"]]] += 1
                    if taken[row[select["by"]]] <= limit:
                        kept.append(row)
                rows = kept
        columns = select["columns"].split(", ")
        return SimpleNamespace(
            column_names=tuple(columns),
            result_rows=[tuple(row[c] for c in columns) for row in rows],
        )

    def event(self, event_id: str) -> dict[str, Any]:
        """The stored row of ``event_id``, to tamper with."""
        (row,) = (r for r in self.rows["audit.events"] if r["event_id"] == event_id)
        return row


def _serving(clickhouse: _ClickHouse) -> Any:
    return patch(
        "foundation_audit.adapters.clickhouse.get_clickhouse_client",
        new=AsyncMock(return_value=clickhouse),
    )


# ---------------------------------------------------------------------------
# The real path, Postgres and crypto-service aside
# ---------------------------------------------------------------------------

async def _sign(root_hex: str, *, tenant_id: str) -> tuple[str, str]:
    """crypto-service's signature: one that verifies for this root and tenant only."""
    return f"sig({tenant_id}:{root_hex})", "kek_audit_1"


async def _signature_valid(
    root_hex: str, signature_b64: str, kek_id: str, *, tenant_id: str,
) -> bool:
    return (signature_b64, kek_id) == await _sign(root_hex, tenant_id=tenant_id)


@asynccontextmanager
async def _no_database() -> AsyncIterator[MagicMock]:
    yield MagicMock()


class _WorkerClock(datetime):
    """The worker host's clock: now() is a second on at every reading.

    A chain's batches follow each other in ingested_at, to the millisecond.  A real
    worker spends round trips to Postgres, ClickHouse and crypto-service on every
    batch; the stand-ins here can seal two in one millisecond.
    """

    _seconds = itertools.count(1)

    @classmethod
    def now(cls, tz: tzinfo | None = None) -> datetime:  # type: ignore[override]
        start = datetime(2026, 10, 30, 12, 1, tzinfo=UTC)
        return (start + timedelta(seconds=next(cls._seconds))).astimezone(tz)


async def _outbox(events: list[AuditEvent]) -> list[tuple[int, dict[str, Any]]]:
    """``events`` as IngestService writes them to the outbox: (id, event_json)."""
    session = MagicMock(flush=AsyncMock())
    await IngestService().ingest_batch(session, events)
    rows = [add.args[0] for add in session.add.call_args_list]
    return [(row_id, row.event_json) for row_id, row in enumerate(rows, start=1)]


def _worker() -> BatchProcessor:
    with patch("foundation_audit.worker.batch_processor.get_settings", return_value=_SETTINGS):
        return BatchProcessor()


async def _deliver(
    worker: BatchProcessor, pending: list[tuple[int, dict[str, Any]]], clickhouse: _ClickHouse,
) -> int:
    """One pass of ``worker`` over the outbox rows ``pending``.

    Each pass reads event_json afresh through JSON text, as Postgres hands out JSONB.
    """
    fetched = [(row_id, json.loads(json.dumps(event_json))) for row_id, event_json in pending]
    with (
        patch("foundation_audit.worker.batch_processor.system_session_scope", _no_database),
        patch("foundation_audit.worker.batch_processor.datetime", _WorkerClock),
        patch.object(worker._ingest, "fetch_pending", AsyncMock(return_value=fetched)),
        patch.object(worker._ingest, "mark_delivered", AsyncMock()),
        patch.object(worker._ingest, "record_attempts", AsyncMock()),
        patch("foundation_audit.worker.batch_processor.crypto_client.sign_merkle_root", _sign),
        _serving(clickhouse),
    ):
        return await worker.run_once()


async def _verify(clickhouse: _ClickHouse, **request: Any) -> VerifyIntegrityResponse:
    """One verify-integrity call for the tenant; ``request`` holds the other body fields."""
    ctx = FoundationContext(
        tenant_id=_TENANT, user_id=None, actor="ADMIN", request_id="req_01J0000000000000000000REQ1",
    )
    with (
        patch("foundation_audit.config.get_settings", return_value=_SETTINGS),
        patch("foundation_audit.api.v1.events.crypto_client.verify_signature", _signature_valid),
        _serving(clickhouse),
    ):
        return await verify_integrity(VerifyIntegrityRequest(tenant_id=_TENANT, **request), ctx=ctx)


async def _verify_all(clickhouse: _ClickHouse, **request: Any) -> list[VerifyIntegrityResponse]:
    """The windows of a run of calls, each resuming at the next_cursor of the one before."""
    windows = [await _verify(clickhouse, **request)]
    while windows[-1].next_cursor is not None:
        assert len(windows) < 100, "the cursor does not move on"
        windows.append(await _verify(clickhouse, cursor=windows[-1].next_cursor, **request))
    return windows


def _evt(n: int) -> str:
    return f"evt_01JC{n:022d}"


def _emitted() -> list[AuditEvent]:
    """Events of two services, as the ingest API accepts them.

    Times come in every spelling, to the microsecond; optional fields are missing
    or sent empty; payloads hold what JSON can; one event lists sensitive_fields.
    """
    return [
        AuditEvent(
            event_id=_evt(1), occurred_at="2026-10-30T12:00:00.250999Z", tenant_id=_TENANT,
            service="identity", event_type="user.login", actor_kind="USER",
            actor_user_id="usr_1", payload={"ip": "203.0.113.7", "mfa": True},
        ),
        AuditEvent(
            event_id=_evt(2), occurred_at="2026-10-30T20:00:00.5+08:00", tenant_id=_TENANT,
            service="lifecycle", service_version="", event_type="report.run",
            actor_kind="SYSTEM", payload={},
        ),
        AuditEvent(
            event_id=_evt(3), occurred_at=datetime(2026, 10, 30, 12, 0, 1), tenant_id=_TENANT,
            service="identity", service_version="2.3.1", event_type="user.update",
            actor_kind="ADMIN", actor_user_id="", resource_type="user", resource_id="usr_1",
            request_id="req_01J0000000000000000000REQ1", ip="",
            payload={"changes": {"name": ["Zoë", "Zoé"]}, "ratio": 0.1},
            sensitive_fields=["changes"],
        ),
        AuditEvent(
            event_id=_evt(4), occurred_at="2026-10-30T07:00:01.999-05:00", tenant_id=_TENANT,
            service="identity", event_type="user.logout", severity="SECURITY",
            outcome="DENIED", actor_kind="API_KEY", actor_api_key_id="key_1",
            payload={"reason": "token expired", "rows": 12345678901234567890},
        ),
        AuditEvent(
            event_id=_evt(5), occurred_at="2026-10-30T12:00:02Z", tenant_id=_TENANT,
            service="lifecycle", event_type="report.done", actor_kind="SERVICE_ACCOUNT",
            trace_id="0af7651916cd43dd8448eb211c80319c", payload={"rows": 3},
        ),
    ]


def _logins(*ns: int) -> list[AuditEvent]:
    """identity events with ids _evt(n), emitted a second apart in the order given."""
    return [
        AuditEvent(
            event_id=_evt(n), occurred_at=datetime(2026, 10, 30, 12, 0, i), tenant_id=_TENANT,
            service="identity", event_type="user.login", actor_kind="USER", payload={"n": n},
        )
        for i, n in enumerate(ns)
    ]


async def _sealed() -> _ClickHouse:
    """The tables once a worker delivered _emitted() in two batches (3 and 2 events)."""
    clickhouse, worker = _ClickHouse(), _worker()
    outbox = await _outbox(_emitted())
    assert await _deliver(worker, outbox[:3], clickhouse) == 3
    assert await _deliver(worker, outbox[3:], clickhouse) == 2
    return clickhouse


async def _three_batches() -> _ClickHouse:
    """_emitted() delivered as evt1-2, evt3-4 and evt5.

    identity's chain is evt1 → evt3 → evt4, lifecycle's evt2 → evt5.
    """
    clickhouse, worker = _ClickHouse(), _worker()
    outbox = await _outbox(_emitted())
    for batch in (outbox[:2], outbox[2:4], outbox[4:]):
        assert await _deliver(worker, batch, clickhouse) == len(batch)
    return clickhouse


def _flip(hex_text: str) -> str:
    return hex_text[:-1] + ("1" if hex_text[-1] == "0" else "0")


def _chain(service: str, start: str, first: int, last: int, *, events: int) -> dict[str, Any]:
    """A VerifiedChain as model_dump() gives it: _evt(first) to _evt(last) of ``service``."""
    return {
        "service": service,
        "start": start,
        "first_event_id": _evt(first),
        "last_event_id": _evt(last),
        "events_checked": events,
    }


def _result(
    events: int, chains: list[dict[str, Any]], *, signatures: int,
) -> dict[str, Any]:
    """An untampered window's result as model_dump() gives it, next_cursor aside."""
    return {
        "valid": True,
        "events_checked": events,
        "first_break_event_id": None,
        "signatures_verified": signatures,
        "signatures_failed": 0,
        "tsa_present": 0,
        "message": "OK",
        "chains": chains,
    }


def _remove_batch(clickhouse: _ClickHouse, batch_id: str) -> None:
    """Drop a batch's events from audit.events, as the TTL does once they expire."""
    events = clickhouse.rows["audit.events"]
    events[:] = [row for row in events if row["merkle_batch_id"] != batch_id]


def _batch_of(clickhouse: _ClickHouse, n: int) -> str:
    return clickhouse.event(_evt(n))["merkle_batch_id"]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.usefixtures("local_time_not_utc")
class TestVerifyIntegrity:
    @pytest.mark.asyncio
    async def test_an_untampered_chain_verifies(self) -> None:
        clickhouse = await _sealed()

        result = await _verify(clickhouse)

        assert result.model_dump() == {
            "valid": True,
            "events_checked": 5,
            "first_break_event_id": None,
            "signatures_verified": 2,
            "signatures_failed": 0,
            "tsa_present": 0,
            "message": "OK",
            "next_cursor": None,
            "chains": [
                _chain("identity", "genesis", 1, 4, events=3),
                _chain("lifecycle", "genesis", 2, 5, events=2),
            ],
        }

    @pytest.mark.asyncio
    async def test_a_chain_verifies_in_the_order_it_was_chained(self) -> None:
        """Event ids need not follow the order events reach the outbox in."""
        clickhouse = _ClickHouse()
        assert await _deliver(_worker(), await _outbox(_logins(9, 7, 8)), clickhouse) == 3

        result = await _verify(clickhouse)

        assert (result.valid, result.first_break_event_id) == (True, None)

    @pytest.mark.asyncio
    async def test_a_restarted_worker_carries_the_chain_on_from_its_last_event(self) -> None:
        """A new worker process reads the chain's head back from ClickHouse."""
        clickhouse, worker = _ClickHouse(), _worker()
        outbox = await _outbox(_logins(6, 2, 9, 7, 8, 1))
        assert await _deliver(worker, outbox[:2], clickhouse) == 2
        assert await _deliver(worker, outbox[2:4], clickhouse) == 2
        assert await _deliver(_worker(), outbox[4:], clickhouse) == 2

        result = await _verify(clickhouse)

        assert (result.valid, result.first_break_event_id) == (True, None)

    @pytest.mark.asyncio
    async def test_a_batch_clickhouse_refused_is_chained_again_when_retried(self) -> None:
        """None of a refused batch is stored: its retry carries each chain on from ClickHouse."""
        clickhouse, worker = _ClickHouse(), _worker()
        outbox = await _outbox(_emitted())
        for batch in (outbox[:3], outbox[3:]):  # the chains' first batch, then a later one
            clickhouse.refuse.append(("insert", "audit.events"))
            assert await _deliver(worker, batch, clickhouse) == 0  # left in the outbox
            assert await _deliver(worker, batch, clickhouse) == len(batch)  # the next run

        result = await _verify(clickhouse)

        assert (result.valid, result.first_break_event_id) == (True, None)

    @pytest.mark.asyncio
    async def test_a_chain_head_clickhouse_did_not_read_is_not_taken_for_genesis(self) -> None:
        clickhouse = _ClickHouse()
        outbox = await _outbox(_emitted())
        assert await _deliver(_worker(), outbox[:3], clickhouse) == 3
        worker = _worker()  # restarted: it reads each chain's head from ClickHouse
        clickhouse.refuse.append(("query", "audit.events"))
        with pytest.raises(OperationalError):
            await _deliver(worker, outbox[3:], clickhouse)  # left in the outbox
        assert await _deliver(worker, outbox[3:], clickhouse) == 2  # the next run

        result = await _verify(clickhouse)

        assert (result.valid, result.first_break_event_id) == (True, None)

    @pytest.mark.asyncio
    async def test_rows_come_back_unlike_the_outbox_json(self) -> None:
        """What the test above verifies over is not what the worker hashed from."""
        clickhouse = await _sealed()

        lifecycle = clickhouse.event(_evt(2))
        assert lifecycle["occurred_at"] == datetime(2026, 10, 30, 12, 0, 0, 500000)  # naive UTC
        assert (lifecycle["service_version"], lifecycle["resource_type"]) == ("", "")
        assert (lifecycle["request_id"], lifecycle["actor_user_id"]) == ("", None)
        assert lifecycle["payload"] == "{}"
        login = clickhouse.event(_evt(1))
        assert login["occurred_at"] == datetime(2026, 10, 30, 12, 0, 0, 250000)  # µs cut off
        assert "sensitive_fields" not in login

    @pytest.mark.parametrize(
        ("event_id", "tamper"),
        [
            pytest.param(_evt(3), {"curr_hash": "f" * 64}, id="curr_hash"),
            pytest.param(_evt(5), {"prev_hash": "0" * 64}, id="prev_hash"),
            pytest.param(
                _evt(1), {"payload": json.dumps({"ip": "198.51.100.9", "mfa": True})}, id="payload",
            ),
            pytest.param(_evt(2), {"payload": "not json"}, id="payload_was_empty_object"),
            pytest.param(_evt(4), {"outcome": "SUCCESS"}, id="outcome"),
            pytest.param(_evt(5), {"resource_type": "report"}, id="empty_field_filled"),
            pytest.param(_evt(3), {"service_version": ""}, id="field_emptied"),
            pytest.param(_evt(1), {"actor_user_id": None}, id="field_nulled"),
        ],
    )
    @pytest.mark.asyncio
    async def test_a_tampered_event_breaks_the_chain_there(
        self, event_id: str, tamper: dict[str, Any],
    ) -> None:
        clickhouse = await _sealed()
        clickhouse.event(event_id).update(tamper)

        result = await _verify(clickhouse)

        assert not result.valid
        assert result.first_break_event_id == event_id

    @pytest.mark.asyncio
    async def test_a_moved_occurred_at_breaks_the_chain_there(self) -> None:
        clickhouse = await _sealed()
        clickhouse.event(_evt(4))["occurred_at"] += timedelta(milliseconds=1)

        result = await _verify(clickhouse)

        assert not result.valid
        assert result.first_break_event_id == _evt(4)

    @pytest.mark.asyncio
    async def test_events_swapped_within_their_batch_break_the_chain(self) -> None:
        clickhouse = await _sealed()
        first, third = clickhouse.event(_evt(1)), clickhouse.event(_evt(3))
        first["merkle_leaf_idx"], third["merkle_leaf_idx"] = (
            third["merkle_leaf_idx"], first["merkle_leaf_idx"],
        )

        result = await _verify(clickhouse)

        assert not result.valid
        assert result.first_break_event_id == _evt(3)  # now first in its chain

    @pytest.mark.asyncio
    async def test_a_deleted_event_breaks_the_chain_at_the_next_one(self) -> None:
        clickhouse = await _sealed()
        clickhouse.rows["audit.events"].remove(clickhouse.event(_evt(3)))

        result = await _verify(clickhouse)

        assert not result.valid
        assert result.first_break_event_id == _evt(4)  # the next identity event

    @pytest.mark.asyncio
    async def test_a_changed_merkle_root_fails_its_batch(self) -> None:
        clickhouse = await _sealed()
        batch = clickhouse.rows["audit.merkle_batch"][0]
        batch["merkle_root"] = _flip(batch["merkle_root"])

        result = await _verify(clickhouse)

        assert not result.valid
        assert result.first_break_event_id == _evt(1)  # the batch's first event
        assert (result.signatures_verified, result.signatures_failed) == (1, 1)

    @pytest.mark.asyncio
    async def test_a_signature_that_does_not_verify_fails_its_batch(self) -> None:
        clickhouse = await _sealed()
        clickhouse.rows["audit.merkle_batch"][1]["signature"] = "sig(forged)"

        result = await _verify(clickhouse)

        assert not result.valid
        assert result.first_break_event_id is None  # the chain itself holds
        assert (result.signatures_verified, result.signatures_failed) == (1, 1)


@pytest.mark.usefixtures("local_time_not_utc")
class TestVerifyIntegrityWindows:
    """A window: ``limit`` events in chain order, from a cursor or from_event_id."""

    @pytest.mark.asyncio
    async def test_a_window_resumes_right_after_the_last_one(self) -> None:
        clickhouse = await _sealed()  # chain order evt1 … evt5, batches evt1-3 and evt4-5

        windows = await _verify_all(clickhouse, limit=2)

        assert [w.model_dump(exclude={"next_cursor"}) for w in windows] == [
            _result(2, [
                _chain("identity", "genesis", 1, 1, events=1),
                _chain("lifecycle", "genesis", 2, 2, events=1),
            ], signatures=1),  # the first batch, evt3 out of the window
            _result(2, [_chain("identity", "previous_event", 3, 4, events=2)], signatures=2),
            _result(1, [_chain("lifecycle", "previous_event", 5, 5, events=1)], signatures=1),
        ]
        assert windows[-1].next_cursor is None

    @pytest.mark.parametrize("n", range(1, 6))
    @pytest.mark.parametrize("limit", range(1, 7))
    @pytest.mark.asyncio
    async def test_windows_of_any_size_check_every_event_once(self, limit: int, n: int) -> None:
        """A tampered event shows in the one window that holds it, at that event."""
        clickhouse = await _sealed()
        clickhouse.event(_evt(n))["payload"] = json.dumps({"tampered": True})

        windows = await _verify_all(clickhouse, limit=limit)

        assert len(windows) == -(-5 // limit)
        assert sum(w.events_checked for w in windows) == 5
        assert [w.first_break_event_id for w in windows if not w.valid] == [_evt(n)]
        assert all(w.signatures_failed == 0 for w in windows)  # cut batches too

    @pytest.mark.parametrize(
        "tamper",
        [
            pytest.param({"payload": json.dumps({"changes": {}})}, id="payload"),
            pytest.param({"prev_hash": "0" * 64}, id="prev_hash_genesis"),
            pytest.param({"prev_hash": "not a hash"}, id="prev_hash_not_hex"),
            pytest.param({"curr_hash": "f" * 64}, id="curr_hash"),
            pytest.param({"curr_hash": "not a hash"}, id="curr_hash_not_hex"),
        ],
    )
    @pytest.mark.asyncio
    async def test_a_resumed_window_catches_tampering_at_its_first_event(
        self, tamper: dict[str, Any],
    ) -> None:
        clickhouse = await _sealed()
        first = (await _verify(clickhouse, limit=2)).next_cursor  # after evt2
        clickhouse.event(_evt(3)).update(tamper)  # the next window's first event

        result = await _verify(clickhouse, cursor=first, limit=2)

        assert not result.valid
        assert result.first_break_event_id == _evt(3)

    @pytest.mark.asyncio
    async def test_an_event_deleted_just_before_the_window_is_caught_at_its_first_event(
        self,
    ) -> None:
        """evt1 gone, evt3 seems to start the chain; evt1's batch no longer adds up."""
        clickhouse = await _sealed()
        first = (await _verify(clickhouse, limit=2)).next_cursor
        clickhouse.rows["audit.events"].remove(clickhouse.event(_evt(1)))

        result = await _verify(clickhouse, cursor=first, limit=2)

        assert not result.valid
        assert result.first_break_event_id == _evt(3)
        assert (result.signatures_verified, result.signatures_failed) == (1, 1)

    @pytest.mark.asyncio
    async def test_a_window_of_one_service_checks_whole_batches(self) -> None:
        """Both batches hold lifecycle events too: their roots need those leaves."""
        clickhouse = await _sealed()

        windows = await _verify_all(clickhouse, service="identity", limit=2)

        assert [w.model_dump(exclude={"next_cursor"}) for w in windows] == [
            _result(2, [_chain("identity", "genesis", 1, 3, events=2)], signatures=1),
            _result(1, [_chain("identity", "previous_event", 4, 4, events=1)], signatures=1),
        ]

    @pytest.mark.asyncio
    async def test_a_window_from_an_event_follows_the_chain_before_it(self) -> None:
        """from_event_id starts the window there in chain order, not at ids from it on."""
        clickhouse = _ClickHouse()
        assert await _deliver(_worker(), await _outbox(_logins(9, 7, 8)), clickhouse) == 3

        from_7 = await _verify(clickhouse, from_event_id=_evt(7))
        from_8 = await _verify(clickhouse, from_event_id=_evt(8))  # not evt9, chained first

        assert from_7.model_dump(exclude={"next_cursor"}) == _result(
            2, [_chain("identity", "previous_event", 7, 8, events=2)], signatures=1,
        )
        assert from_8.model_dump(exclude={"next_cursor"}) == _result(
            1, [_chain("identity", "previous_event", 8, 8, events=1)], signatures=1,
        )
        assert from_7.next_cursor is None

    @pytest.mark.asyncio
    async def test_from_event_id_must_be_a_stored_event(self) -> None:
        clickhouse = await _sealed()

        with pytest.raises(FoundationError) as exc:
            await _verify(clickhouse, from_event_id=_evt(6))

        assert exc.value.error_code is EVENT_NOT_FOUND

    @pytest.mark.parametrize(
        "request_fields",
        [
            pytest.param({"cursor": encode_cursor(_NOON, _evt(1))}, id="query_cursor"),
            pytest.param({"cursor": _evt(1)}, id="event_id"),
            pytest.param(
                {"cursor": encode_chain_cursor(_NOON, "mrk_1", 0), "from_event_id": _evt(1)},
                id="cursor_and_from_event_id",
            ),
        ],
    )
    @pytest.mark.asyncio
    async def test_a_start_verify_cannot_place_is_refused_before_clickhouse(
        self, request_fields: dict[str, Any],
    ) -> None:
        clickhouse = await _sealed()
        clickhouse.refuse.append(("query", "audit.events"))  # reached, it would be a 503

        with pytest.raises(FoundationError) as exc:
            await _verify(clickhouse, **request_fields)

        assert exc.value.error_code is VALIDATION_FAILED

    @pytest.mark.asyncio
    async def test_a_chain_whose_oldest_events_are_gone_verifies_from_the_oldest_kept(
        self,
    ) -> None:
        clickhouse = await _three_batches()
        _remove_batch(clickhouse, _batch_of(clickhouse, 1))  # evt1 and evt2

        result = await _verify(clickhouse)

        assert result.model_dump() == _result(3, [
            _chain("identity", "predecessor_not_retained", 3, 4, events=2),
            _chain("lifecycle", "predecessor_not_retained", 5, 5, events=1),
        ], signatures=2) | {"next_cursor": None}

    @pytest.mark.parametrize(
        "tamper",
        [
            pytest.param({"payload": json.dumps({"changes": {}})}, id="payload"),
            pytest.param({"prev_hash": "f" * 64}, id="prev_hash"),
            pytest.param({"prev_hash": "0" * 64}, id="prev_hash_genesis"),
        ],
    )
    @pytest.mark.asyncio
    async def test_the_oldest_kept_event_is_checked_against_its_own_prev_hash(
        self, tamper: dict[str, Any],
    ) -> None:
        clickhouse = await _three_batches()
        _remove_batch(clickhouse, _batch_of(clickhouse, 1))
        clickhouse.event(_evt(3)).update(tamper)

        result = await _verify(clickhouse)

        assert not result.valid
        assert result.first_break_event_id == _evt(3)

    @pytest.mark.asyncio
    async def test_a_gap_after_the_oldest_kept_event_still_breaks_the_chain(self) -> None:
        clickhouse, worker = _ClickHouse(), _worker()
        outbox = await _outbox(_logins(1, 2, 3, 4, 5, 6))
        for batch in (outbox[:2], outbox[2:4], outbox[4:]):
            assert await _deliver(worker, batch, clickhouse) == 2
        _remove_batch(clickhouse, _batch_of(clickhouse, 1))
        clickhouse.rows["audit.events"].remove(clickhouse.event(_evt(4)))

        result = await _verify(clickhouse)

        assert not result.valid
        assert result.first_break_event_id == _evt(5)  # the event after the gap

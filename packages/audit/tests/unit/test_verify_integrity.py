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
import uuid
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
from foundation_audit.services.hash_chain import compute_merkle_root
from foundation_audit.services.ingest_service import IngestService
from foundation_audit.services.pagination import encode_chain_cursor, encode_cursor
from foundation_audit.worker.batch_processor import BatchProcessor

_SCHEMA_SQL = (
    Path(__file__).resolve().parents[4]
    / "deploy/docker-compose/config/clickhouse/audit-schema.sql"
)
_TENANT = "tnt_01J0000000000000000000TNT1"
_OTHER_TENANT = "tnt_01J0000000000000000000TNT2"
_NOON = datetime(2026, 10, 30, 12, tzinfo=UTC)
# verify's clock, unless a test sets it: a day after the worker delivered, when no
# event is near expiry
_VERIFIED_AT = _NOON + timedelta(days=1)
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
    "created_at >= {created_from:DateTime64(3, 'UTC')}": (
        lambda row, p: row["created_at"] >= datetime.fromisoformat(p["created_from"])
    ),
    "created_at <= {created_to:DateTime64(3, 'UTC')}": (
        lambda row, p: row["created_at"] <= datetime.fromisoformat(p["created_to"])
    ),
    f"{_CHAIN_ORDER} > {_AT}": lambda row, p: _chained_at(row) > _bound_position(p),
    f"{_CHAIN_ORDER} >= {_AT}": lambda row, p: _chained_at(row) >= _bound_position(p),
    f"{_CHAIN_ORDER} < {_AT}": lambda row, p: _chained_at(row) < _bound_position(p),
    f"{_CHAIN_ORDER} <= {_AT}": lambda row, p: _chained_at(row) <= _bound_position(p),
    "ingested_at >= {retained_from:DateTime64(3, 'UTC')}": (
        lambda row, p: row["ingested_at"] >= datetime.fromisoformat(p["retained_from"])
    ),
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


class _BatchIds:
    """The worker's uuid module, its uuid4() counting up.

    A run's batches share an ingested_at, so verify reads them in batch id order:
    here, the order in which the run reached their chains.
    """

    _numbers = itertools.count(1)

    @classmethod
    def uuid4(cls) -> uuid.UUID:
        return uuid.UUID(int=next(cls._numbers) << 96)  # in the hex digits a batch id keeps


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
        patch("foundation_audit.worker.batch_processor.uuid", _BatchIds),
        patch.object(worker._ingest, "fetch_pending", AsyncMock(return_value=fetched)),
        patch.object(worker._ingest, "mark_delivered", AsyncMock()),
        patch.object(worker._ingest, "record_attempts", AsyncMock()),
        patch("foundation_audit.worker.batch_processor.crypto_client.sign_merkle_root", _sign),
        _serving(clickhouse),
    ):
        return await worker.run_once()


def _clock(now: datetime) -> type[datetime]:
    """A host clock standing at ``now``."""

    class _Clock(datetime):
        @classmethod
        def now(cls, tz: tzinfo | None = None) -> datetime:  # type: ignore[override]
            return now.astimezone(tz)

    return _Clock


async def _verify(
    clickhouse: _ClickHouse,
    *,
    tenant_id: str = _TENANT,
    now: datetime = _VERIFIED_AT,
    settings: Settings = _SETTINGS,
    **request: Any,
) -> VerifyIntegrityResponse:
    """verify-integrity as ``tenant_id`` asks it at ``now``, with the rest of its ``request``."""
    ctx = FoundationContext(
        tenant_id=tenant_id, user_id=None, actor="ADMIN",
        request_id="req_01J0000000000000000000REQ1",
    )
    with (
        patch("foundation_audit.config.get_settings", return_value=settings),
        patch("foundation_audit.api.v1.events.datetime", _clock(now)),
        patch("foundation_audit.api.v1.events.crypto_client.verify_signature", _signature_valid),
        _serving(clickhouse),
    ):
        body = VerifyIntegrityRequest(tenant_id=tenant_id, **request)
        return await verify_integrity(body, ctx=ctx)


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


def _logins(*ns: int, tenant_id: str = _TENANT) -> list[AuditEvent]:
    """identity events with ids _evt(n), emitted a second apart in the order given."""
    return [
        AuditEvent(
            event_id=_evt(n), occurred_at=datetime(2026, 10, 30, 12, 0, i), tenant_id=tenant_id,
            service="identity", event_type="user.login", actor_kind="USER", payload={"n": n},
        )
        for i, n in enumerate(ns)
    ]


def _interleaved(*runs: list[AuditEvent]) -> list[AuditEvent]:
    """The events of ``runs`` taken in turn, as emitters reach the outbox side by side."""
    return [event for turn in itertools.zip_longest(*runs) for event in turn if event]


async def _sealed() -> _ClickHouse:
    """The tables once a worker delivered _emitted() in two runs (3 and 2 events).

    Each run seals a batch per service: identity [1, 3] and lifecycle [2], then
    identity [4] and lifecycle [5].  Chain order is evt1, evt3, evt2, evt4, evt5.
    """
    clickhouse, worker = _ClickHouse(), _worker()
    outbox = await _outbox(_emitted())
    assert await _deliver(worker, outbox[:3], clickhouse) == 3
    assert await _deliver(worker, outbox[3:], clickhouse) == 2
    return clickhouse


async def _two_tenants_in_one_run() -> _ClickHouse:
    """The tables once a worker delivered _emitted() and another tenant's logins in one run.

    The run seals identity [1, 3, 4] and lifecycle [2, 5], and the other tenant's
    identity [11, 12, 13].
    """
    clickhouse = _ClickHouse()
    theirs = _logins(11, 12, 13, tenant_id=_OTHER_TENANT)
    outbox = await _outbox(_interleaved(_emitted(), theirs))
    assert await _deliver(_worker(), outbox, clickhouse) == 8
    return clickhouse


async def _as_one_batch_per_run(clickhouse: _ClickHouse) -> None:
    """Re-seal the one run in ``clickhouse`` as the worker did before a batch per chain.

    One batch over the whole run, leaves in outbox order, its root signed under the
    first event's tenant, its row filed under that event's tenant and service.  The
    chains stay as they are.
    """
    events = clickhouse.rows["audit.events"]  # as the run inserted them
    batches = clickhouse.rows["audit.merkle_batch"]
    assert {event["ingested_at"] for event in events} == {batch["created_at"] for batch in batches}
    for leaf_idx, event in enumerate(events):
        event["merkle_batch_id"], event["merkle_leaf_idx"] = "mrk_RUN", leaf_idx
    root = compute_merkle_root([event["curr_hash"] for event in events])
    signature, key_id = await _sign(root, tenant_id=events[0]["tenant_id"])
    batches[:] = [{
        **batches[0],
        "batch_id": "mrk_RUN",
        "tenant_id": events[0]["tenant_id"],
        "service": events[0]["service"],
        "event_count": len(events),
        "first_event_id": events[0]["event_id"],
        "last_event_id": events[-1]["event_id"],
        "merkle_root": root,
        "signature": signature,
        "signature_key_id": key_id,
    }]


async def _three_runs() -> _ClickHouse:
    """_emitted() delivered in three runs: evt1-2, evt3-4 and evt5.

    identity's chain is evt1 → evt3 → evt4, lifecycle's evt2 → evt5.  The runs seal
    identity [1] and lifecycle [2], identity [3, 4], then lifecycle [5].
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
        "signatures_unverifiable": 0,
        "tsa_present": 0,
        "message": "OK",
        "chains": chains,
    }


def _expire_run(clickhouse: _ClickHouse, n: int) -> None:
    """Drop _evt(n)'s run from audit.events, as the TTL does once it expires.

    A run's events go together: one insert, one ingested_at, which the TTL counts from.
    """
    events = clickhouse.rows["audit.events"]
    ingested_at = clickhouse.event(_evt(n))["ingested_at"]
    events[:] = [row for row in events if row["ingested_at"] != ingested_at]


def _ingested(clickhouse: _ClickHouse, n: int) -> datetime:
    """When the worker stamped _evt(n)'s batch."""
    return clickhouse.event(_evt(n))["ingested_at"].replace(tzinfo=UTC)


async def _six_logins() -> _ClickHouse:
    """identity's chain evt1 → … → evt6, delivered as evt1-2, evt3-4 and evt5-6."""
    clickhouse, worker = _ClickHouse(), _worker()
    outbox = await _outbox(_logins(1, 2, 3, 4, 5, 6))
    for batch in (outbox[:2], outbox[2:4], outbox[4:]):
        assert await _deliver(worker, batch, clickhouse) == 2
    return clickhouse


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
            "signatures_verified": 4,
            "signatures_failed": 0,
            "signatures_unverifiable": 0,
            "tsa_present": 0,
            "message": "OK",
            "next_cursor": None,
            "chains": [
                _chain("identity", "genesis", 1, 4, events=3),
                _chain("lifecycle", "genesis", 2, 5, events=2),
            ],
        }

    @pytest.mark.asyncio
    async def test_tenants_delivered_in_one_run_each_verify(self) -> None:
        """A run seals each tenant's chains apart, so each tenant verifies its own."""
        clickhouse = await _two_tenants_in_one_run()

        for tenant_id, events, chains in ((_TENANT, 5, 2), (_OTHER_TENANT, 3, 1)):
            result = await _verify(clickhouse, tenant_id=tenant_id)

            assert (result.valid, result.first_break_event_id) == (True, None), tenant_id
            assert result.events_checked == events
            assert (result.signatures_verified, result.signatures_failed) == (chains, 0)

    @pytest.mark.asyncio
    async def test_a_tenant_s_tampered_batch_fails_that_tenant_only(self) -> None:
        clickhouse = await _two_tenants_in_one_run()
        batches = clickhouse.rows["audit.merkle_batch"]
        (theirs,) = (batch for batch in batches if batch["tenant_id"] == _OTHER_TENANT)
        theirs["merkle_root"] = _flip(theirs["merkle_root"])

        mine, others = await _verify(clickhouse), await _verify(clickhouse, tenant_id=_OTHER_TENANT)

        assert (mine.valid, mine.signatures_verified, mine.signatures_failed) == (True, 2, 0)
        assert (others.valid, others.signatures_verified, others.signatures_failed) == (False, 0, 1)
        assert others.first_break_event_id == _evt(11)

    @pytest.mark.asyncio
    async def test_a_service_filter_verifies_that_service_s_chain(self) -> None:
        clickhouse = await _sealed()

        result = await _verify(clickhouse, service="identity")

        assert (result.valid, result.first_break_event_id) == (True, None)
        assert result.events_checked == 3  # 1, 3 and 4
        assert (result.signatures_verified, result.signatures_failed) == (2, 0)

    @pytest.mark.asyncio
    async def test_a_batch_the_limit_cuts_verifies_whole(self) -> None:
        clickhouse, worker = _ClickHouse(), _worker()
        outbox = await _outbox(_logins(1, 2, 3, 4, 5))
        assert await _deliver(worker, outbox[:3], clickhouse) == 3
        assert await _deliver(worker, outbox[3:], clickhouse) == 2

        result = await _verify(clickhouse, limit=4)  # [1, 2, 3], and 4 of [4, 5]

        assert (result.valid, result.events_checked) == (True, 4)
        assert (result.signatures_verified, result.signatures_unverifiable) == (2, 0)

    @pytest.mark.asyncio
    async def test_a_service_filter_and_limit_verify_the_batch_they_cut(self) -> None:
        clickhouse = await _sealed()

        result = await _verify(clickhouse, service="identity", limit=1)  # 1 of [1, 3]

        assert (result.valid, result.events_checked) == (True, 1)
        assert (result.signatures_verified, result.signatures_unverifiable) == (1, 0)

    @pytest.mark.asyncio
    async def test_a_batch_from_event_id_cuts_verifies_whole(self) -> None:
        clickhouse = _ClickHouse()
        assert await _deliver(_worker(), await _outbox(_logins(1, 2, 3)), clickhouse) == 3

        result = await _verify(clickhouse, from_event_id=_evt(2))  # 2 and 3 of [1, 2, 3]

        # The chain check still takes 2 for the first of its chain, a matter of its own.
        assert (result.signatures_verified, result.signatures_unverifiable) == (1, 0)

    @pytest.mark.asyncio
    async def test_a_leaf_the_limit_leaves_out_is_still_checked(self) -> None:
        """A cut batch is recomputed from the leaves stored, not passed on what the window holds."""
        clickhouse = _ClickHouse()
        assert await _deliver(_worker(), await _outbox(_logins(1, 2, 3)), clickhouse) == 3
        clickhouse.event(_evt(3))["curr_hash"] = "f" * 64

        result = await _verify(clickhouse, limit=2)

        assert not result.valid
        assert result.first_break_event_id == _evt(1)  # the batch's first event
        assert (result.signatures_verified, result.signatures_failed) == (0, 1)

    @pytest.mark.asyncio
    async def test_a_batch_sealed_over_two_tenants_is_unverifiable_for_either(self) -> None:
        """What the worker stored before it sealed a batch per chain: neither holds it whole."""
        clickhouse = await _two_tenants_in_one_run()
        await _as_one_batch_per_run(clickhouse)  # its row is the first tenant's

        for tenant_id in (_TENANT, _OTHER_TENANT):
            result = await _verify(clickhouse, tenant_id=tenant_id)

            assert result.model_dump() == {
                **result.model_dump(),
                "valid": False,
                "first_break_event_id": None,  # the chains hold
                "signatures_verified": 0,
                "signatures_failed": 0,
                "signatures_unverifiable": 1,
                "message": "Integrity not proven: 1 Merkle batch(es) could not be verified",
            }, tenant_id

    @pytest.mark.parametrize("service", [None, "identity"])
    @pytest.mark.asyncio
    async def test_a_batch_sealed_over_one_tenant_s_services_verifies(
        self, service: str | None,
    ) -> None:
        """What the worker stored before, for a run of one tenant: the tenant holds it whole.

        Its row is under the service of the run's first event, identity.
        """
        clickhouse = _ClickHouse()
        assert await _deliver(_worker(), await _outbox(_emitted()), clickhouse) == 5
        await _as_one_batch_per_run(clickhouse)

        result = await _verify(clickhouse, service=service)

        assert (result.valid, result.first_break_event_id) == (True, None)
        assert (result.signatures_verified, result.signatures_unverifiable) == (1, 0)

    @pytest.mark.asyncio
    async def test_such_a_batch_is_unverifiable_under_another_service_s_filter(self) -> None:
        """A service filter reads the rows under its service only; this one is identity's."""
        clickhouse = _ClickHouse()
        assert await _deliver(_worker(), await _outbox(_emitted()), clickhouse) == 5
        await _as_one_batch_per_run(clickhouse)

        result = await _verify(clickhouse, service="lifecycle")

        assert (result.valid, result.first_break_event_id) == (False, None)
        assert (result.signatures_verified, result.signatures_unverifiable) == (0, 1)

    @pytest.mark.asyncio
    async def test_a_batch_that_lost_its_last_event_is_not_valid(self) -> None:
        """No later event shows the chain's last one gone; its batch shows it unproven."""
        clickhouse = _ClickHouse()
        assert await _deliver(_worker(), await _outbox(_logins(1, 2, 3)), clickhouse) == 3
        clickhouse.rows["audit.events"].remove(clickhouse.event(_evt(3)))

        result = await _verify(clickhouse)

        assert (result.valid, result.first_break_event_id) == (False, None)
        assert (result.signatures_failed, result.signatures_unverifiable) == (0, 1)

    @pytest.mark.asyncio
    async def test_batches_whose_rows_clickhouse_refused_are_not_valid(self) -> None:
        clickhouse = _ClickHouse()
        clickhouse.refuse.append(("insert", "audit.merkle_batch"))
        assert await _deliver(_worker(), await _outbox(_emitted()), clickhouse) == 5

        result = await _verify(clickhouse)

        assert (result.valid, result.first_break_event_id) == (False, None)
        assert (result.signatures_failed, result.signatures_unverifiable) == (0, 2)

    @pytest.mark.asyncio
    async def test_batches_clickhouse_did_not_read_are_not_valid(self) -> None:
        clickhouse = await _sealed()
        clickhouse.refuse.append(("query", "audit.merkle_batch"))

        result = await _verify(clickhouse)

        assert (result.valid, result.first_break_event_id) == (False, None)
        assert (result.signatures_failed, result.signatures_unverifiable) == (0, 4)

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
        assert result.signatures_unverifiable == 1  # identity [1, 3] lost 3

    @pytest.mark.asyncio
    async def test_a_changed_merkle_root_fails_its_batch(self) -> None:
        clickhouse = await _sealed()
        batch = clickhouse.rows["audit.merkle_batch"][0]  # identity [1, 3]
        batch["merkle_root"] = _flip(batch["merkle_root"])

        result = await _verify(clickhouse)

        assert not result.valid
        assert result.first_break_event_id == _evt(1)  # the batch's first event
        assert (result.signatures_verified, result.signatures_failed) == (3, 1)

    @pytest.mark.asyncio
    async def test_a_signature_that_does_not_verify_fails_its_batch(self) -> None:
        clickhouse = await _sealed()
        clickhouse.rows["audit.merkle_batch"][1]["signature"] = "sig(forged)"  # lifecycle [2]

        result = await _verify(clickhouse)

        assert not result.valid
        assert result.first_break_event_id is None  # the chain itself holds
        assert (result.signatures_verified, result.signatures_failed) == (3, 1)

    @pytest.mark.asyncio
    async def test_a_signature_by_another_tenant_s_key_fails_its_batch(self) -> None:
        clickhouse = await _sealed()
        batch = clickhouse.rows["audit.merkle_batch"][2]  # identity [4]
        batch["signature"], _ = await _sign(batch["merkle_root"], tenant_id=_OTHER_TENANT)

        result = await _verify(clickhouse)

        assert not result.valid
        assert (result.signatures_verified, result.signatures_failed) == (3, 1)


@pytest.mark.usefixtures("local_time_not_utc")
class TestVerifyIntegrityWindows:
    """A window: ``limit`` events in chain order, from a cursor or from_event_id."""

    @pytest.mark.asyncio
    async def test_a_window_resumes_right_after_the_last_one(self) -> None:
        clickhouse = await _sealed()  # chain order evt1, evt3, evt2, evt4, evt5

        windows = await _verify_all(clickhouse, limit=2)

        assert [w.model_dump(exclude={"next_cursor"}) for w in windows] == [
            _result(2, [_chain("identity", "genesis", 1, 3, events=2)], signatures=1),
            _result(2, [
                _chain("lifecycle", "genesis", 2, 2, events=1),
                _chain("identity", "previous_event", 4, 4, events=1),
            ], signatures=2),
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
        assert all(  # cut batches too
            (w.signatures_failed, w.signatures_unverifiable) == (0, 0) for w in windows
        )

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
        first = (await _verify(clickhouse, limit=1)).next_cursor  # after evt1
        clickhouse.event(_evt(3)).update(tamper)  # the next window's first event

        result = await _verify(clickhouse, cursor=first, limit=1)

        assert not result.valid
        assert result.first_break_event_id == _evt(3)

    @pytest.mark.asyncio
    async def test_an_event_deleted_just_before_the_window_is_caught_by_its_batch(
        self,
    ) -> None:
        """evt1 gone, evt3 seems to start the chain: only evt1's batch, not whole now, shows it."""
        clickhouse = await _sealed()
        first = (await _verify(clickhouse, limit=1)).next_cursor  # after evt1
        clickhouse.rows["audit.events"].remove(clickhouse.event(_evt(1)))

        result = await _verify(clickhouse, cursor=first, limit=2)  # evt3 and evt2

        assert (result.valid, result.first_break_event_id) == (False, None)
        assert (
            result.signatures_verified, result.signatures_failed, result.signatures_unverifiable,
        ) == (1, 0, 1)

    @pytest.mark.asyncio
    async def test_a_window_of_one_service_checks_whole_batches(self) -> None:
        """identity's batches hold its events only: the filter leaves none of their leaves out."""
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
        clickhouse = await _three_runs()
        _expire_run(clickhouse, 1)  # evt1 and evt2

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
        clickhouse = await _three_runs()
        _expire_run(clickhouse, 1)
        clickhouse.event(_evt(3)).update(tamper)

        result = await _verify(clickhouse)

        assert not result.valid
        assert result.first_break_event_id == _evt(3)

    @pytest.mark.asyncio
    async def test_a_gap_after_the_oldest_kept_event_still_breaks_the_chain(self) -> None:
        clickhouse = await _six_logins()
        _expire_run(clickhouse, 1)
        clickhouse.rows["audit.events"].remove(clickhouse.event(_evt(4)))

        result = await _verify(clickhouse)

        assert not result.valid
        assert result.first_break_event_id == _evt(5)  # the event after the gap


@pytest.mark.usefixtures("local_time_not_utc")
class TestVerifyIntegrityExpiry:
    """Rows expire events_ttl_days after ingested_at; verify leaves out the last day.

    The TTL removes expired rows part by part, as it merges each part, so at any
    time a chain's expired events may be gone, all there, or some of each.
    """

    @pytest.mark.parametrize("ttl_days", [2, 90])
    @pytest.mark.asyncio
    async def test_events_a_day_from_expiry_are_left_out_though_still_stored(
        self, ttl_days: int,
    ) -> None:
        clickhouse = await _three_runs()  # evt1-2, evt3-4, evt5
        settings = _SETTINGS.model_copy(update={"events_ttl_days": ttl_days})
        # evt3-4 expire in a day, evt1-2 a second or so before them
        now = _ingested(clickhouse, 3) + timedelta(days=ttl_days - 1)

        result = await _verify(clickhouse, now=now, settings=settings)
        a_moment_later = await _verify(
            clickhouse, now=now + timedelta(milliseconds=1), settings=settings,
        )

        assert result.model_dump() == _result(3, [
            _chain("identity", "predecessor_not_retained", 3, 4, events=2),
            _chain("lifecycle", "predecessor_not_retained", 5, 5, events=1),
        ], signatures=2) | {"next_cursor": None}
        assert a_moment_later.model_dump() == _result(1, [
            _chain("lifecycle", "predecessor_not_retained", 5, 5, events=1),
        ], signatures=1) | {"next_cursor": None}

    @pytest.mark.asyncio
    async def test_expired_events_the_ttl_has_not_reached_are_not_taken_for_the_chain(
        self,
    ) -> None:
        """The TTL took evt3-4's part, and not yet evt1-2's."""
        clickhouse = await _six_logins()
        _expire_run(clickhouse, 3)

        result = await _verify(clickhouse, now=_ingested(clickhouse, 5) + timedelta(days=89))

        assert result.model_dump() == _result(
            2, [_chain("identity", "predecessor_not_retained", 5, 6, events=2)], signatures=1,
        ) | {"next_cursor": None}

    @pytest.mark.asyncio
    async def test_a_window_resumes_once_the_events_before_it_expired(self) -> None:
        """The run's first window ended at evt2; evt1-4 expired before the next call."""
        clickhouse = await _six_logins()
        first = await _verify(clickhouse, limit=2)
        _expire_run(clickhouse, 3)

        result = await _verify(
            clickhouse, cursor=first.next_cursor, limit=2,
            now=_ingested(clickhouse, 5) + timedelta(days=89),
        )

        assert result.model_dump() == _result(
            2, [_chain("identity", "predecessor_not_retained", 5, 6, events=2)], signatures=1,
        ) | {"next_cursor": None}

    @pytest.mark.asyncio
    async def test_an_event_removed_before_it_expires_breaks_the_chain(self) -> None:
        clickhouse = await _six_logins()
        clickhouse.rows["audit.events"].remove(clickhouse.event(_evt(4)))  # a day from expiry

        result = await _verify(clickhouse, now=_ingested(clickhouse, 3) + timedelta(days=89))

        assert not result.valid
        assert result.first_break_event_id == _evt(5)
        assert (
            result.signatures_verified, result.signatures_failed, result.signatures_unverifiable,
        ) == (1, 0, 1)  # evt3-4's batch lost evt4

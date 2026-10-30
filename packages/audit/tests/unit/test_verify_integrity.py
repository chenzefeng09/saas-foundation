"""verify-integrity over chains the worker built, read back as ClickHouse hands them out.

Events take the real path: AuditEvent → IngestService's outbox JSON (through JSON
text, as Postgres JSONB keeps it) → BatchProcessor (hash chain, Merkle batch) →
the adapter's inserts → clickhouse-connect's own codec for each column's type in
audit-schema.sql → the adapter's verification queries → verify_integrity.  Only
Postgres, the ClickHouse server and crypto-service are stand-ins.
"""

from __future__ import annotations

import json
import operator
import re
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from clickhouse_connect.datatypes.registry import get_from_name
from clickhouse_connect.driver import ctypes as ch_ctypes
from clickhouse_connect.driver.insert import InsertContext
from clickhouse_connect.driver.query import QueryContext

from foundation_audit.api.v1.events import (
    VerifyIntegrityRequest,
    VerifyIntegrityResponse,
    verify_integrity,
)
from foundation_audit.config import Settings
from foundation_audit.domain.base import FoundationContext
from foundation_audit.schemas.event import AuditEvent
from foundation_audit.services.ingest_service import IngestService
from foundation_audit.worker.batch_processor import BatchProcessor

_SCHEMA_SQL = (
    Path(__file__).resolve().parents[4]
    / "deploy/docker-compose/config/clickhouse/audit-schema.sql"
)
_TENANT = "tnt_01J0000000000000000000TNT1"
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
    """``values`` written to a ``column_type`` column and read back by clickhouse-connect."""
    ch_type = get_from_name(column_type)
    native = bytearray()
    ch_type.write_column(values, native, InsertContext("t", ["c"], [ch_type]))
    buffer = ch_ctypes.RespBuffCls(_Body(bytes(native)))
    return list(ch_type.read_column(buffer, len(values), QueryContext()))


# The WHERE conditions of the adapter's verification queries, as the server applies them.
_CONDITIONS: dict[str, Callable[[dict[str, Any], dict[str, Any]], bool]] = {
    "tenant_id = {tenant_id:String}": lambda row, p: row["tenant_id"] == p["tenant_id"],
    "service = {service:String}": lambda row, p: row["service"] == p["service"],
    "event_id >= {from_event_id:String}": lambda row, p: row["event_id"] >= p["from_event_id"],
}
_SELECT = re.compile(
    r"SELECT (?P<columns>.+) FROM (?P<table>\S+) WHERE (?P<where>.+) "
    r"ORDER BY (?P<order>.+) LIMIT (?P<limit>\d+|\{limit:UInt32\})"
)


class _ClickHouse:
    """audit.events and audit.merkle_batch, answering the adapter as the server would.

    insert() keeps every value as clickhouse-connect's codec hands it back for its
    column's type: naive UTC datetimes to the millisecond, '' where a String column
    got '', and None in a column that is not Nullable fails as it does there.
    query() reads the SELECT list, WHERE conditions, ORDER BY and LIMIT of the SQL.
    """

    def __init__(self) -> None:
        self.types = {t: _column_types(t) for t in ("audit.events", "audit.merkle_batch")}
        self.rows: dict[str, list[dict[str, Any]]] = {t: [] for t in self.types}

    def insert(self, table: str, data: list[list[Any]], column_names: list[str]) -> None:
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
        conditions = select["where"].split(" AND ")
        rows = [
            row
            for row in self.rows[select["table"]]
            if all(_CONDITIONS[c](row, parameters) for c in conditions)
        ]
        for key in reversed(select["order"].split(", ")):
            column, _, direction = key.partition(" ")
            rows.sort(key=operator.itemgetter(column), reverse=direction == "DESC")
        limit = parameters["limit"] if select["limit"].startswith("{") else int(select["limit"])
        columns = select["columns"].split(", ")
        return SimpleNamespace(
            column_names=tuple(columns),
            result_rows=[tuple(row[c] for c in columns) for row in rows[:limit]],
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
        patch.object(worker._ingest, "fetch_pending", AsyncMock(return_value=fetched)),
        patch.object(worker._ingest, "mark_delivered", AsyncMock()),
        patch.object(worker._ingest, "record_attempts", AsyncMock()),
        patch("foundation_audit.worker.batch_processor.crypto_client.sign_merkle_root", _sign),
        _serving(clickhouse),
    ):
        return await worker.run_once()


async def _verify(clickhouse: _ClickHouse) -> VerifyIntegrityResponse:
    ctx = FoundationContext(
        tenant_id=_TENANT, user_id=None, actor="ADMIN", request_id="req_01J0000000000000000000REQ1",
    )
    with (
        patch("foundation_audit.config.get_settings", return_value=_SETTINGS),
        patch("foundation_audit.api.v1.events.crypto_client.verify_signature", _signature_valid),
        _serving(clickhouse),
    ):
        return await verify_integrity(VerifyIntegrityRequest(tenant_id=_TENANT), ctx=ctx)


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


async def _sealed() -> _ClickHouse:
    """The tables once a worker delivered _emitted() in two batches (3 and 2 events)."""
    clickhouse, worker = _ClickHouse(), _worker()
    outbox = await _outbox(_emitted())
    assert await _deliver(worker, outbox[:3], clickhouse) == 3
    assert await _deliver(worker, outbox[3:], clickhouse) == 2
    return clickhouse


def _flip(hex_text: str) -> str:
    return hex_text[:-1] + ("1" if hex_text[-1] == "0" else "0")


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
        }

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
        assert (result.signatures_verified, result.signatures_failed) == (1, 1)

    @pytest.mark.asyncio
    async def test_a_signature_that_does_not_verify_fails_its_batch(self) -> None:
        clickhouse = await _sealed()
        clickhouse.rows["audit.merkle_batch"][1]["signature"] = "sig(forged)"

        result = await _verify(clickhouse)

        assert not result.valid
        assert result.first_break_event_id is None  # the chain itself holds
        assert (result.signatures_verified, result.signatures_failed) == (1, 1)

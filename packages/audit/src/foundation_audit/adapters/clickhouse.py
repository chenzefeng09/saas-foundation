"""ClickHouse async adapter — wraps clickhouse-connect for audit writes & reads.

Usage:
    client = get_clickhouse_client()
    await client.insert_events(rows)
    head = await client.get_chain_head(tenant_id, service)
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

import clickhouse_connect

from foundation_audit.config import get_settings
from foundation_audit.observability import get_logger

log = get_logger(__name__)

# clickhouse-connect's sync client is thread-safe; we run blocking calls
# in the default executor (thread pool) to stay async-friendly.
_client: clickhouse_connect.driver.Client | None = None
_client_lock = asyncio.Lock()


def _make_client() -> clickhouse_connect.driver.Client:
    s = get_settings()
    return clickhouse_connect.get_client(
        host=s.clickhouse_host,
        port=s.clickhouse_port,
        username=s.clickhouse_user,
        password=s.clickhouse_password,
        database=s.clickhouse_database,
        connect_timeout=s.clickhouse_connect_timeout,
        send_receive_timeout=30,
        compress=True,
    )


async def get_clickhouse_client() -> clickhouse_connect.driver.Client:
    """Return (lazily-created) module-level ClickHouse client."""
    global _client
    async with _client_lock:
        if _client is None:
            loop = asyncio.get_running_loop()
            _client = await loop.run_in_executor(None, _make_client)
    return _client


# ---------------------------------------------------------------------------
# Datetimes reach clickhouse-connect only through _insert and _query, each one
# as the exact UTC instant it names.  Left to itself, clickhouse-connect inserts
# a naive datetime as host local time (datetime.timestamp()) and binds a
# datetime parameter in whole seconds, again reading a naive one as local time.
# ---------------------------------------------------------------------------
def _utc(value: datetime | str) -> datetime:
    """``value`` (a datetime or ISO 8601 text) as an aware UTC datetime.

    A naive value is UTC: that is how ClickHouse hands back ``DateTime64(3, 'UTC')``.
    """
    ts = datetime.fromisoformat(value) if isinstance(value, str) else value
    return ts.astimezone(UTC) if ts.tzinfo else ts.replace(tzinfo=UTC)


def _ch_datetime64(ts: datetime) -> str:
    """``ts`` as the text of a ``DateTime64(3, 'UTC')`` query parameter.

    Milliseconds are kept and the rest cut off, as an insert stores them, so a
    bound compares with stored values exactly.
    """
    utc = _utc(ts)
    return utc.strftime("%Y-%m-%d %H:%M:%S.") + f"{utc.microsecond // 1000:03d}"


async def _insert(table: str, rows: list[list[Any]], column_names: list[str]) -> None:
    """Insert ``rows`` into ``table``, every datetime in them as a UTC instant."""
    client = await get_clickhouse_client()
    data = [[_utc(v) if isinstance(v, datetime) else v for v in row] for row in rows]
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(
        None,
        lambda: client.insert(table, data, column_names=column_names),
    )


async def _query(sql: str, params: dict[str, Any]) -> Any:
    """Run ``sql``; a datetime parameter is bound as ``_ch_datetime64`` text.

    That text is UTC, so ``sql`` declares such a parameter ``DateTime64(3, 'UTC')``.
    """
    client = await get_clickhouse_client()
    bound = {k: _ch_datetime64(v) if isinstance(v, datetime) else v for k, v in params.items()}
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None,
        lambda: client.query(sql, parameters=bound),
    )


# ---------------------------------------------------------------------------
# Column order for audit.events INSERT
# Must stay aligned with audit-schema.sql DDL.
# ---------------------------------------------------------------------------
EVENTS_COLUMNS = [
    "event_id",
    "schema_version",
    "occurred_at",
    "ingested_at",
    "tsa_timestamp",
    "tenant_id",
    "service",
    "service_version",
    "event_type",
    "severity",
    "outcome",
    "actor_kind",
    "actor_user_id",
    "actor_api_key_id",
    "resource_type",
    "resource_id",
    "resource_path",
    "request_id",
    "trace_id",
    "span_id",
    "session_id",
    "parent_event_id",
    "ip",
    "user_agent",
    "country",
    "payload",
    "payload_size",
    "payload_truncated",
    "compliance_modes",
    "retention_until",
    "legal_hold",
    "prev_hash",
    "curr_hash",
    "merkle_batch_id",
    "merkle_leaf_idx",
    "batch_signature",
    "worm_written",
    "worm_uri",
]

MERKLE_BATCH_COLUMNS = [
    "batch_id",
    "tenant_id",
    "service",
    "created_at",
    "sealed_at",
    "event_count",
    "first_event_id",
    "last_event_id",
    "merkle_root",
    "signature",
    "signature_key_id",
    "tsa_token",
    "tsa_provider",
    "tsa_timestamp",
    "external_anchor",
]


def _event_to_row(ev: dict[str, Any]) -> list[Any]:
    """Convert event dict → list aligned with EVENTS_COLUMNS."""
    import json

    payload = ev.get("payload", {})
    payload_str = json.dumps(payload, ensure_ascii=False) if isinstance(payload, dict) else str(payload)
    payload_size = len(payload_str.encode())

    occurred_at = _utc(ev.get("occurred_at") or datetime.now(UTC))
    ingested_at = _utc(ev.get("ingested_at") or datetime.now(UTC))

    return [
        ev.get("event_id", ""),
        int(ev.get("schema_version", 1)),
        occurred_at,
        ingested_at,
        None,                                    # tsa_timestamp (filled by TSA adapter)
        ev.get("tenant_id", ""),
        ev.get("service", ""),
        ev.get("service_version") or "",
        ev.get("event_type", ""),
        ev.get("severity", "INFO"),
        ev.get("outcome", "SUCCESS"),
        ev.get("actor_kind", "SYSTEM"),
        ev.get("actor_user_id"),
        ev.get("actor_api_key_id"),
        ev.get("resource_type") or "",
        ev.get("resource_id"),
        ev.get("resource_path"),
        ev.get("request_id") or "",
        ev.get("trace_id"),
        ev.get("span_id"),
        ev.get("session_id"),
        ev.get("parent_event_id"),
        ev.get("ip"),
        ev.get("user_agent"),
        ev.get("country"),
        payload_str,
        payload_size,
        False,                                   # payload_truncated
        [],                                      # compliance_modes
        occurred_at.date(),                      # retention_until: CH default is +1 year; provide date to avoid NULL
        False,                                   # legal_hold
        ev.get("prev_hash", "0" * 64),
        ev.get("curr_hash", "0" * 64),
        ev.get("merkle_batch_id"),
        ev.get("merkle_leaf_idx"),
        ev.get("batch_signature"),
        ev.get("worm_written", False),
        ev.get("worm_uri"),
    ]


async def insert_events(events: list[dict[str, Any]]) -> None:
    """Insert a batch of event dicts into audit.events."""
    if not events:
        return
    rows = [_event_to_row(ev) for ev in events]
    await _insert("audit.events", rows, EVENTS_COLUMNS)
    log.debug("clickhouse.events.inserted", count=len(rows))


def _merkle_batch_to_row(batch: dict[str, Any]) -> list[Any]:
    """Convert merkle_batch dict → list aligned with MERKLE_BATCH_COLUMNS."""
    tsa_ts = batch.get("tsa_timestamp")
    return [
        batch.get("batch_id", ""),
        batch.get("tenant_id", ""),
        batch.get("service") or "",
        _utc(batch.get("created_at") or datetime.now(UTC)),
        _utc(batch.get("sealed_at") or datetime.now(UTC)),
        int(batch.get("event_count", 0)),
        batch.get("first_event_id", ""),
        batch.get("last_event_id", ""),
        batch.get("merkle_root", "0" * 64),
        batch.get("signature", ""),
        batch.get("signature_key_id", ""),
        batch.get("tsa_token"),
        batch.get("tsa_provider") or "",
        _utc(tsa_ts) if tsa_ts else None,
        batch.get("external_anchor"),
    ]


async def insert_merkle_batches(batches: list[dict[str, Any]]) -> None:
    """Insert merkle_batch rows, all in one insert.

    That is one part for ClickHouse to merge, however many chains a run seals.
    """
    if not batches:
        return
    rows = [_merkle_batch_to_row(batch) for batch in batches]
    await _insert("audit.merkle_batch", rows, MERKLE_BATCH_COLUMNS)
    log.debug("clickhouse.merkle_batch.inserted", count=len(rows))


async def get_chain_head(tenant_id: str, service: str) -> str | None:
    """Return the curr_hash of the last event chained for (tenant, service).

    That is the last leaf of its latest batch, in the order of
    get_events_for_verification.  Returns None if no events exist yet (genesis).
    """
    query = (
        "SELECT curr_hash FROM audit.events "
        "WHERE tenant_id = {tenant_id:String} AND service = {service:String} "
        "ORDER BY ingested_at DESC, merkle_batch_id DESC, merkle_leaf_idx DESC LIMIT 1"
    )
    result = await _query(query, {"tenant_id": tenant_id, "service": service})
    rows = result.result_rows
    if not rows:
        return None
    val = rows[0][0]
    return str(val) if val else None


async def query_events(
    *,
    tenant_id: str,
    service: str | None = None,
    event_type: str | None = None,
    event_types: list[str] | None = None,
    severity: str | None = None,
    outcome: str | None = None,
    actor_user_id: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    session_id: str | None = None,
    request_id: str | None = None,
    occurred_from: datetime | None = None,
    occurred_to: datetime | None = None,
    after: tuple[datetime, str] | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Query events from ClickHouse with mandatory tenant_id filter.

    Rows come oldest first, in the table's sort order ``(occurred_at, event_id)``.
    ``after`` is the ``(occurred_at, event_id)`` of the last row of the previous
    page; the page resumes right after it in that order (services.pagination).
    ``occurred_from`` and ``occurred_to`` are inclusive, to the stored millisecond.
    """
    # Build WHERE clauses — tenant_id is ALWAYS injected (no RLS in CH)
    conditions: list[str] = ["tenant_id = {tenant_id:String}"]
    params: dict[str, Any] = {"tenant_id": tenant_id}

    if service:
        conditions.append("service = {service:String}")
        params["service"] = service
    if event_type:
        conditions.append("event_type = {event_type:String}")
        params["event_type"] = event_type
    if event_types:
        conditions.append("event_type IN {event_types:Array(String)}")
        params["event_types"] = event_types
    if severity:
        conditions.append("severity = {severity:String}")
        params["severity"] = severity
    if outcome:
        conditions.append("outcome = {outcome:String}")
        params["outcome"] = outcome
    if actor_user_id:
        conditions.append("actor_user_id = {actor_user_id:String}")
        params["actor_user_id"] = actor_user_id
    if resource_type:
        conditions.append("resource_type = {resource_type:String}")
        params["resource_type"] = resource_type
    if resource_id:
        conditions.append("resource_id = {resource_id:String}")
        params["resource_id"] = resource_id
    if session_id:
        conditions.append("session_id = {session_id:String}")
        params["session_id"] = session_id
    if request_id:
        conditions.append("request_id = {request_id:String}")
        params["request_id"] = request_id
    if occurred_from:
        conditions.append("occurred_at >= {occurred_from:DateTime64(3, 'UTC')}")
        params["occurred_from"] = occurred_from
    if occurred_to:
        conditions.append("occurred_at <= {occurred_to:DateTime64(3, 'UTC')}")
        params["occurred_to"] = occurred_to
    if after is not None:
        after_ts, after_id = after
        # The row comparison is the keyset.  The bare bound on occurred_at follows
        # from it; it is there because ClickHouse skips parts and granules with the
        # sort key for it but not for a tuple comparison.
        conditions.append("occurred_at >= {after_ts:DateTime64(3, 'UTC')}")
        conditions.append(
            "(occurred_at, event_id) > ({after_ts:DateTime64(3, 'UTC')}, {after_id:String})"
        )
        params["after_ts"] = after_ts
        params["after_id"] = after_id

    where = " AND ".join(conditions)
    sql = (
        f"SELECT {', '.join(EVENTS_COLUMNS)} FROM audit.events "
        f"WHERE {where} "
        f"ORDER BY tenant_id, occurred_at, event_id "
        f"LIMIT {{limit:UInt32}}"
    )
    params["limit"] = limit

    result = await _query(sql, params)

    out: list[dict[str, Any]] = []
    for row in result.result_rows:
        out.append(dict(zip(EVENTS_COLUMNS, row, strict=False)))
    return out


async def get_events_for_verification(
    *,
    tenant_id: str,
    service: str | None = None,
    from_event_id: str | None = None,
    limit: int = 1000,
) -> list[dict[str, Any]]:
    """Fetch events for hash-chain verification, in the order the worker chained them.

    The worker chains a batch's events in leaf order and stamps them all with the
    batch's ingested_at, so that order is ingested_at, then merkle_leaf_idx;
    event_id need not follow it.  It holds while ingested_at moves on from batch
    to batch, as it does for one worker on a clock that does not step back.
    """
    conditions = ["tenant_id = {tenant_id:String}"]
    params: dict[str, Any] = {"tenant_id": tenant_id}
    if service:
        conditions.append("service = {service:String}")
        params["service"] = service
    if from_event_id:
        conditions.append("event_id >= {from_event_id:String}")
        params["from_event_id"] = from_event_id

    where = " AND ".join(conditions)
    cols = "event_id, tenant_id, service, occurred_at, ingested_at, prev_hash, curr_hash, merkle_batch_id, merkle_leaf_idx"
    # Also select canonical fields needed to recompute curr_hash
    extra_cols = (
        ", schema_version, event_type, severity, outcome, actor_kind, actor_user_id, "
        "actor_api_key_id, resource_type, resource_id, resource_path, request_id, "
        "trace_id, span_id, session_id, parent_event_id, ip, user_agent, country, "
        "payload, service_version"
    )
    sql = (
        f"SELECT {cols}{extra_cols} FROM audit.events "
        f"WHERE {where} "
        f"ORDER BY tenant_id, ingested_at, merkle_batch_id, merkle_leaf_idx "
        f"LIMIT {{limit:UInt32}}"
    )
    params["limit"] = limit

    result = await _query(sql, params)
    # clickhouse-connect returns column_names as a list of plain strings
    col_names_list = list(result.column_names)
    out: list[dict[str, Any]] = []
    for row in result.result_rows:
        out.append(dict(zip(col_names_list, row, strict=False)))
    return out


async def get_merkle_batches(
    *,
    tenant_id: str,
    service: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Fetch merkle_batch rows for integrity verification."""
    conditions = ["tenant_id = {tenant_id:String}"]
    params: dict[str, Any] = {"tenant_id": tenant_id}
    if service:
        conditions.append("service = {service:String}")
        params["service"] = service

    where = " AND ".join(conditions)
    sql = (
        f"SELECT {', '.join(MERKLE_BATCH_COLUMNS)} FROM audit.merkle_batch "
        f"WHERE {where} "
        f"ORDER BY created_at "
        f"LIMIT {{limit:UInt32}}"
    )
    params["limit"] = limit

    result = await _query(sql, params)
    out: list[dict[str, Any]] = []
    for row in result.result_rows:
        out.append(dict(zip(MERKLE_BATCH_COLUMNS, row, strict=False)))
    return out

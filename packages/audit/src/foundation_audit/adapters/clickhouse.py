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

    occurred_raw = ev.get("occurred_at")
    if isinstance(occurred_raw, str):
        occurred_at = datetime.fromisoformat(occurred_raw.replace("Z", "+00:00"))
    elif isinstance(occurred_raw, datetime):
        occurred_at = occurred_raw
    else:
        occurred_at = datetime.now(UTC)
    if occurred_at.tzinfo is not None:
        occurred_at = occurred_at.replace(tzinfo=None)  # CH stores as UTC naive

    ingested_raw = ev.get("ingested_at", datetime.now(UTC).isoformat())
    if isinstance(ingested_raw, str):
        ingested_at = datetime.fromisoformat(ingested_raw.replace("Z", "+00:00")).replace(tzinfo=None)
    elif isinstance(ingested_raw, datetime):
        ingested_at = ingested_raw.replace(tzinfo=None)
    else:
        ingested_at = datetime.utcnow()  # noqa: DTZ003

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
    client = await get_clickhouse_client()
    rows = [_event_to_row(ev) for ev in events]
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(
        None,
        lambda: client.insert("audit.events", rows, column_names=EVENTS_COLUMNS),
    )
    log.debug("clickhouse.events.inserted", count=len(rows))


async def insert_merkle_batch(batch: dict[str, Any]) -> None:
    """Insert a single merkle_batch row."""
    client = await get_clickhouse_client()

    sealed_raw = batch.get("sealed_at", datetime.now(UTC).isoformat())
    if isinstance(sealed_raw, str):
        sealed_at = datetime.fromisoformat(sealed_raw.replace("Z", "+00:00")).replace(tzinfo=None)
    elif isinstance(sealed_raw, datetime):
        sealed_at = sealed_raw.replace(tzinfo=None)
    else:
        sealed_at = datetime.utcnow()  # noqa: DTZ003

    created_raw = batch.get("created_at", datetime.now(UTC).isoformat())
    if isinstance(created_raw, str):
        created_at = datetime.fromisoformat(created_raw.replace("Z", "+00:00")).replace(tzinfo=None)
    elif isinstance(created_raw, datetime):
        created_at = created_raw.replace(tzinfo=None)
    else:
        created_at = datetime.utcnow()  # noqa: DTZ003

    tsa_ts = batch.get("tsa_timestamp")
    if isinstance(tsa_ts, str):
        tsa_ts = datetime.fromisoformat(tsa_ts.replace("Z", "+00:00")).replace(tzinfo=None)
    elif isinstance(tsa_ts, datetime):
        tsa_ts = tsa_ts.replace(tzinfo=None)

    row = [
        batch.get("batch_id", ""),
        batch.get("tenant_id", ""),
        batch.get("service") or "",
        created_at,
        sealed_at,
        int(batch.get("event_count", 0)),
        batch.get("first_event_id", ""),
        batch.get("last_event_id", ""),
        batch.get("merkle_root", "0" * 64),
        batch.get("signature", ""),
        batch.get("signature_key_id", ""),
        batch.get("tsa_token"),
        batch.get("tsa_provider") or "",
        tsa_ts,
        batch.get("external_anchor"),
    ]
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(
        None,
        lambda: client.insert("audit.merkle_batch", [row], column_names=MERKLE_BATCH_COLUMNS),
    )
    log.debug("clickhouse.merkle_batch.inserted", batch_id=batch.get("batch_id"))


async def get_chain_head(tenant_id: str, service: str) -> str | None:
    """Return the curr_hash of the most-recently ingested event for (tenant, service).

    Returns None if no events exist yet (genesis).
    """
    client = await get_clickhouse_client()
    query = (
        "SELECT curr_hash FROM audit.events "
        "WHERE tenant_id = {tenant_id:String} AND service = {service:String} "
        "ORDER BY ingested_at DESC, event_id DESC LIMIT 1"
    )
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None,
        lambda: client.query(query, parameters={"tenant_id": tenant_id, "service": service}),
    )
    rows = result.result_rows
    if not rows:
        return None
    val = rows[0][0]
    return str(val) if val else None


def _ch_datetime64(ts: datetime) -> str:
    """``ts`` as the text of a ``DateTime64(3, 'UTC')`` query parameter.

    clickhouse-connect binds a ``datetime`` parameter in whole seconds and reads
    a naive one as local time; a keyset bound must be the stored value exactly.
    """
    utc = ts.astimezone(UTC) if ts.tzinfo else ts.replace(tzinfo=UTC)
    return utc.strftime("%Y-%m-%d %H:%M:%S.") + f"{utc.microsecond // 1000:03d}"


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
    """
    client = await get_clickhouse_client()

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
        conditions.append("occurred_at >= {occurred_from:DateTime64(3)}")
        params["occurred_from"] = occurred_from.replace(tzinfo=None) if occurred_from.tzinfo else occurred_from
    if occurred_to:
        conditions.append("occurred_at <= {occurred_to:DateTime64(3)}")
        params["occurred_to"] = occurred_to.replace(tzinfo=None) if occurred_to.tzinfo else occurred_to
    if after is not None:
        after_ts, after_id = after
        # The row comparison is the keyset.  The bare bound on occurred_at follows
        # from it; it is there because ClickHouse skips parts and granules with the
        # sort key for it but not for a tuple comparison.
        conditions.append("occurred_at >= {after_ts:DateTime64(3, 'UTC')}")
        conditions.append(
            "(occurred_at, event_id) > ({after_ts:DateTime64(3, 'UTC')}, {after_id:String})"
        )
        params["after_ts"] = _ch_datetime64(after_ts)
        params["after_id"] = after_id

    where = " AND ".join(conditions)
    sql = (
        f"SELECT {', '.join(EVENTS_COLUMNS)} FROM audit.events "
        f"WHERE {where} "
        f"ORDER BY tenant_id, occurred_at, event_id "
        f"LIMIT {{limit:UInt32}}"
    )
    params["limit"] = limit

    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None,
        lambda: client.query(sql, parameters=params),
    )

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
    """Fetch events ordered by ingested_at for hash-chain verification."""
    client = await get_clickhouse_client()

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
        f"ORDER BY tenant_id, ingested_at, event_id "
        f"LIMIT {{limit:UInt32}}"
    )
    params["limit"] = limit

    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None,
        lambda: client.query(sql, parameters=params),
    )
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
    client = await get_clickhouse_client()

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

    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None,
        lambda: client.query(sql, parameters=params),
    )
    out: list[dict[str, Any]] = []
    for row in result.result_rows:
        out.append(dict(zip(MERKLE_BATCH_COLUMNS, row, strict=False)))
    return out

"""Audit API endpoints — ingest + query + integrity verification."""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_audit.adapters import clickhouse as ch
from foundation_audit.adapters import crypto_client
from foundation_audit.api.dependencies import current_context, current_request_id, db_session, ingest_service
from foundation_audit.domain.base import FoundationContext
from foundation_audit.errors import EVENT_NOT_FOUND, VALIDATION_FAILED, FoundationError
from foundation_audit.schemas.event import AuditEvent, AuditQuery, AuditQueryResult, AuditEventStored
from foundation_audit.services.hash_chain import (
    GENESIS_HASH,
    canonical_event,
    compute_chain_hash,
    compute_merkle_root,
)
from foundation_audit.services.ingest_service import IngestService
from foundation_audit.services.pagination import (
    decode_chain_cursor,
    decode_cursor,
    encode_chain_cursor,
    encode_cursor,
)

router = APIRouter()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _row_to_stored(row: dict[str, Any]) -> AuditEventStored:
    """Convert a ClickHouse row dict → AuditEventStored Pydantic model."""
    payload_raw = row.get("payload", "{}")
    if isinstance(payload_raw, str):
        try:
            payload = json.loads(payload_raw)
        except (json.JSONDecodeError, ValueError):
            payload = {}
    else:
        payload = payload_raw or {}

    # Coerce datetimes: CH returns naive UTC datetimes
    def _dt(v: Any) -> datetime | None:
        if v is None:
            return None
        if isinstance(v, datetime):
            from datetime import timezone
            return v.replace(tzinfo=timezone.utc) if v.tzinfo is None else v
        return None

    return AuditEventStored(
        event_id=row["event_id"],
        schema_version=int(row.get("schema_version", 1)),
        occurred_at=_dt(row.get("occurred_at")) or datetime.utcnow(),  # noqa: DTZ003
        ingested_at=_dt(row.get("ingested_at")) or datetime.utcnow(),  # noqa: DTZ003
        tsa_timestamp=_dt(row.get("tsa_timestamp")),
        tenant_id=row.get("tenant_id", ""),
        service=row.get("service", ""),
        service_version=row.get("service_version") or None,
        event_type=row.get("event_type", ""),
        severity=row.get("severity", "INFO"),
        outcome=row.get("outcome", "SUCCESS"),
        actor_kind=row.get("actor_kind", "SYSTEM"),
        actor_user_id=row.get("actor_user_id") or None,
        actor_api_key_id=row.get("actor_api_key_id") or None,
        resource_type=row.get("resource_type") or None,
        resource_id=row.get("resource_id") or None,
        resource_path=row.get("resource_path") or None,
        request_id=row.get("request_id") or None,
        trace_id=row.get("trace_id") or None,
        span_id=row.get("span_id") or None,
        session_id=row.get("session_id") or None,
        parent_event_id=row.get("parent_event_id") or None,
        ip=row.get("ip") or None,
        user_agent=row.get("user_agent") or None,
        country=row.get("country") or None,
        payload=payload,
        sensitive_fields=[],
        prev_hash=row.get("prev_hash") or None,
        curr_hash=row.get("curr_hash") or None,
        merkle_batch_id=row.get("merkle_batch_id") or None,
        merkle_leaf_idx=row.get("merkle_leaf_idx"),
        batch_signature=row.get("batch_signature") or None,
        worm_written=bool(row.get("worm_written", False)),
        worm_uri=row.get("worm_uri") or None,
    )


# ---------------------------------------------------------------------------
# Ingest
# ---------------------------------------------------------------------------

@router.post("/events", status_code=202, operation_id="ingestEvent")
async def ingest_event(
    event: AuditEvent,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: IngestService = Depends(ingest_service),
) -> dict:
    await svc.ingest_one(session, event)
    return {"accepted": True, "event_id": event.event_id}


@router.post("/events/batch", status_code=202, operation_id="ingestEventBatch")
async def ingest_events_batch(
    events: list[AuditEvent],
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: IngestService = Depends(ingest_service),
) -> dict:
    count = await svc.ingest_batch(session, events)
    return {"accepted": True, "count": count}


# ---------------------------------------------------------------------------
# Query
# ---------------------------------------------------------------------------

@router.post("/events:query", operation_id="queryEvents")
async def query_events(
    query: AuditQuery,
    ctx: FoundationContext = Depends(current_context),
) -> AuditQueryResult:
    """Query audit events from ClickHouse.

    tenant_id is ALWAYS enforced from the authenticated context — the query
    body tenant_id must match the context tenant_id to prevent cross-tenant reads.
    ClickHouse has no RLS; all filtering is done via SQL WHERE clauses.

    Events come oldest first; ``next_cursor`` resumes right after the last event
    returned, keyset-paged on ``(occurred_at, event_id)`` (services.pagination).
    """
    # Security: enforce tenant from context, not just from body
    if query.tenant_id != ctx.tenant_id:
        raise HTTPException(
            status_code=403,
            detail="query.tenant_id must match authenticated tenant context",
        )

    # A cursor this query did not hand out is a 422 before ClickHouse is asked.
    after = decode_cursor(query.cursor) if query.cursor else None
    try:
        rows = await ch.query_events(
            tenant_id=ctx.tenant_id,
            service=query.service,
            event_type=query.event_type,
            event_types=query.event_types,
            severity=query.severity,
            outcome=query.outcome,
            actor_user_id=query.actor_user_id,
            resource_type=query.resource_type,
            resource_id=query.resource_id,
            session_id=query.session_id,
            request_id=query.request_id,
            occurred_from=query.occurred_from,
            occurred_to=query.occurred_to,
            after=after,
            limit=query.limit + 1,  # one row more than the page: is there a next page?
        )
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"ClickHouse unavailable: {exc}") from exc

    page = rows[: query.limit]
    # The cursor is the sort key of the last event *returned*, as ClickHouse stored it.
    next_cursor = (
        encode_cursor(page[-1]["occurred_at"], page[-1]["event_id"])
        if len(rows) > query.limit
        else None
    )
    return AuditQueryResult(
        items=[_row_to_stored(r) for r in page],
        next_cursor=next_cursor,
        total_estimate=None,  # CH count(*) is expensive; skip for now
    )


# ---------------------------------------------------------------------------
# Export (synchronous)
# ---------------------------------------------------------------------------

# Columns emitted in CSV / per-row JSON exports, in order.
EXPORT_COLUMNS: list[str] = [
    "event_id",
    "occurred_at",
    "ingested_at",
    "tenant_id",
    "service",
    "event_type",
    "severity",
    "outcome",
    "actor_kind",
    "actor_user_id",
    "resource_type",
    "resource_id",
    "request_id",
    "session_id",
]

EXPORT_MAX_ROWS = 10000
EXPORT_PAGE_SIZE = 1000


def _export_value(row: dict[str, Any], col: str) -> str:
    """Stringify a ClickHouse row value for export (datetimes → ISO, None → '')."""
    val = row.get(col)
    if val is None:
        return ""
    if isinstance(val, datetime):
        return val.isoformat()
    return str(val)


@router.post("/events:export", operation_id="exportEvents")
async def export_events(
    query: AuditQuery,
    fmt: Literal["csv", "json"] = Query("csv", alias="format"),
    ctx: FoundationContext = Depends(current_context),
) -> Response:
    """Synchronously export audit events as CSV or JSON.

    Reuses the same filters as ``/events:query`` (the ``cursor`` field in the
    body is ignored — pagination is driven internally). tenant_id is ALWAYS
    enforced from the authenticated context; a mismatched body tenant_id is
    rejected with 403. Total export is capped at ``EXPORT_MAX_ROWS`` rows.
    """
    # Security: enforce tenant from context, not just from body
    if query.tenant_id != ctx.tenant_id:
        raise HTTPException(
            status_code=403,
            detail="query.tenant_id must match authenticated tenant context",
        )

    # Keyset-loop fetch up to EXPORT_MAX_ROWS rows, each page resuming right
    # after the last event of the one before.
    rows: list[dict[str, Any]] = []
    after: tuple[datetime, str] | None = None
    try:
        while len(rows) < EXPORT_MAX_ROWS:
            page_limit = min(EXPORT_PAGE_SIZE, EXPORT_MAX_ROWS - len(rows))
            page = await ch.query_events(
                tenant_id=ctx.tenant_id,
                service=query.service,
                event_type=query.event_type,
                event_types=query.event_types,
                severity=query.severity,
                outcome=query.outcome,
                actor_user_id=query.actor_user_id,
                resource_type=query.resource_type,
                resource_id=query.resource_id,
                session_id=query.session_id,
                request_id=query.request_id,
                occurred_from=query.occurred_from,
                occurred_to=query.occurred_to,
                after=after,
                limit=page_limit,
            )
            if not page:
                break
            rows.extend(page)
            if len(page) < page_limit:
                break
            after = (page[-1]["occurred_at"], page[-1]["event_id"])
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"ClickHouse unavailable: {exc}") from exc

    # Pure-ASCII filename to avoid latin-1 Content-Disposition crashes.
    safe_tenant = "".join(
        c if c.isascii() and (c.isalnum() or c in "-_") else "_" for c in ctx.tenant_id
    )
    filename = f"audit-export-{safe_tenant}.{fmt}"
    disposition = f'attachment; filename="{filename}"'

    if fmt == "json":
        items = [{col: _export_value(r, col) for col in EXPORT_COLUMNS} for r in rows]
        return Response(
            content=json.dumps(items, ensure_ascii=False),
            media_type="application/json",
            headers={"Content-Disposition": disposition},
        )

    # CSV
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(EXPORT_COLUMNS)
    for r in rows:
        writer.writerow([_export_value(r, col) for col in EXPORT_COLUMNS])
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": disposition},
    )


# ---------------------------------------------------------------------------
# Integrity verification
# ---------------------------------------------------------------------------

class VerifyIntegrityRequest(BaseModel):
    tenant_id: str
    service: str | None = None
    # The next_cursor of the previous call: the window resumes right after it.
    cursor: str | None = None
    # Deprecated, for old clients: the window starts at this event, in chain order.
    from_event_id: str | None = None
    limit: int = Field(default=1000, ge=1, le=10000)


ChainStart = Literal["genesis", "previous_event", "predecessor_not_retained"]


class VerifiedChain(BaseModel):
    """A (tenant, service) chain's events in the window, and what the first one follows.

    ``start`` is
    - ``previous_event``: first_event_id must follow the chain's last event before
      the window, and was checked against it;
    - ``genesis``: no event of the chain is stored before first_event_id, which
      must be the chain's first event;
    - ``predecessor_not_retained``: no event of the chain is stored before
      first_event_id, nor the one it follows (the chain's earlier events expired,
      or were removed), so first_event_id is checked against its own prev_hash.
    Events a day or less from expiry count as not stored.
    """

    service: str
    start: ChainStart
    first_event_id: str
    last_event_id: str
    events_checked: int


class VerifyIntegrityResponse(BaseModel):
    valid: bool
    events_checked: int
    first_break_event_id: str | None = None
    signatures_verified: int
    signatures_failed: int
    tsa_present: int
    message: str
    # Send as cursor to check the events after this window; None once none are left.
    next_cursor: str | None = None
    chains: list[VerifiedChain] = Field(default_factory=list)


async def _window_start(
    body: VerifyIntegrityRequest, tenant_id: str,
) -> tuple[ch.ChainPosition | None, bool]:
    """Where the window starts, and whether the event there is in it.

    A cursor verify did not hand out is a 422, and an unknown from_event_id a 404,
    before the window is read.
    """
    if body.cursor and body.from_event_id:
        raise FoundationError(VALIDATION_FAILED, detail="send cursor or from_event_id, not both")
    if body.cursor:
        return decode_chain_cursor(body.cursor), False
    if not body.from_event_id:
        return None, False
    try:
        position = await ch.get_chain_position(tenant_id=tenant_id, event_id=body.from_event_id)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"ClickHouse unavailable: {exc}") from exc
    if position is None:
        raise FoundationError(
            EVENT_NOT_FOUND, detail="from_event_id is not a stored event of this tenant",
        )
    return position, True


def _chain_hashes(
    prev_hash: str, event: dict[str, Any], hash_algorithm: str,
) -> tuple[str, str] | None:
    """The (prev_hash, curr_hash) the worker stores for ``event`` after ``prev_hash``.

    None when ``prev_hash`` (a stored value) is not hex: no stored pair can match.
    """
    try:
        return compute_chain_hash(
            prev_hash=prev_hash, event_data=canonical_event(event), hash_algorithm=hash_algorithm,
        )
    except ValueError:
        return None


@router.post("/events:verify-integrity", operation_id="verifyIntegrity")
async def verify_integrity(
    body: VerifyIntegrityRequest,
    ctx: FoundationContext = Depends(current_context),
) -> VerifyIntegrityResponse:
    """Verify hash chain integrity and Merkle batch signatures for a tenant.

    A call checks a window of up to ``limit`` events of the tenant's chains (one
    per service) in the order the worker chained them; ``next_cursor`` resumes
    right after it, so a run of calls checks every event once.

    Steps:
    1. Fetch the window from ClickHouse in chain order (ingested_at, then Merkle
       leaf; ch.get_events_for_verification), and the last event before it of
       each chain in it (ch.get_chain_heads_before).
    2. Recompute prev_hash / curr_hash for each event from the canonical form the
       worker hashed (hash_chain.canonical_event); compare with stored values.  A
       chain's first event in the window must follow that last event; with none
       stored, it is the chain's first event or its earlier events are gone
       (``chains`` says which).
    3. For each merkle_batch the window touches: recompute Merkle root from all
       of the batch's leaf curr_hashes, in the window or not, call crypto-service
       /verify to check Ed25519 signature.
    4. Report first break event_id, signatures_verified/failed counts.

    Note: Cross-tenant verification is blocked (must match ctx.tenant_id).
    Events hashed before canonical_event existed cannot be rebuilt from their
    rows, so they show as a break.  The chain alone cannot tell events that
    expired from events removed: a chain stored from some event on verifies from
    there, as ``predecessor_not_retained``.  Events a day or less from expiry
    (``events_ttl_days`` after ingested_at) are left out: the TTL removes expired
    events part by part, so some of them may be gone while others are still there.
    """
    if body.tenant_id != ctx.tenant_id:
        raise HTTPException(
            status_code=403,
            detail="verify tenant_id must match authenticated tenant context",
        )

    start, include_start = await _window_start(body, ctx.tenant_id)

    from foundation_audit.config import get_settings
    settings = get_settings()
    # Events ingested from retained_from on are a day or more from expiry: no TTL
    # has touched them.
    retained_from = datetime.now(UTC) - timedelta(days=settings.events_ttl_days - 1)

    # --- Fetch events ---
    try:
        rows = await ch.get_events_for_verification(
            tenant_id=ctx.tenant_id,
            service=body.service,
            start=start,
            include_start=include_start,
            retained_from=retained_from,
            limit=body.limit + 1,  # one row more than the window: is there a next one?
        )
        events = rows[: body.limit]
        # service → its chain's first event in the window
        first_events: dict[str, dict[str, Any]] = {}
        for ev in events:
            first_events.setdefault(ev.get("service", ""), ev)
        # The event each chain's first event in the window must follow.  A window
        # from the start has nothing before it.
        heads_before = (
            await ch.get_chain_heads_before(
                tenant_id=ctx.tenant_id,
                services=sorted(first_events),
                start=start,
                include_start=include_start,
                retained_from=retained_from,
            )
            if start is not None and first_events
            else {}
        )
        # A first event that follows nothing stored before it, yet not genesis:
        # is the event it names stored at all (out of place, then)?
        claimed = sorted({
            ev.get("prev_hash", "")
            for service, ev in first_events.items()
            if service not in heads_before and ev.get("prev_hash", "") != GENESIS_HASH
        })
        claims_stored = (
            await ch.get_stored_curr_hashes(
                tenant_id=ctx.tenant_id, curr_hashes=claimed, retained_from=retained_from,
            )
            if claimed
            else set()
        )
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"ClickHouse unavailable: {exc}") from exc

    if not events:
        return VerifyIntegrityResponse(
            valid=True,
            events_checked=0,
            signatures_verified=0,
            signatures_failed=0,
            tsa_present=0,
            message="No events found for verification.",
        )

    # --- Phase 1: Recompute hash chain ---
    first_break_event_id: str | None = None
    chains: dict[str, VerifiedChain] = {}  # service → its events in the window
    prev_hashes: dict[str, str] = {}  # service → last curr_hash

    for ev in events:
        service = ev.get("service", "")
        stored_curr = ev.get("curr_hash", "")
        stored_prev = ev.get("prev_hash", "")

        chain = chains.get(service)
        if chain is None:
            # The chain's first event in the window
            chain_start: ChainStart
            if service in heads_before:
                chain_start, prev_hash = "previous_event", heads_before[service]
            elif stored_prev != GENESIS_HASH and (service, stored_prev) not in claims_stored:
                # Its predecessor is gone: its own prev_hash is all there is to check
                chain_start, prev_hash = "predecessor_not_retained", stored_prev
            else:
                chain_start, prev_hash = "genesis", GENESIS_HASH
            chain = chains[service] = VerifiedChain(
                service=service,
                start=chain_start,
                first_event_id=ev.get("event_id", ""),
                last_event_id=ev.get("event_id", ""),
                events_checked=0,
            )
        else:
            prev_hash = prev_hashes[service]
        chain.last_event_id = ev.get("event_id", "")
        chain.events_checked += 1

        # Recompute over the event as the worker hashed it, rebuilt from its row
        expected = _chain_hashes(prev_hash, ev, settings.hash_algorithm)
        if expected != (stored_prev, stored_curr):
            if first_break_event_id is None:
                first_break_event_id = ev.get("event_id")

        # Advance chain (use STORED curr_hash so downstream errors don't cascade)
        prev_hashes[service] = stored_curr

    # --- Phase 2: Verify Merkle batch signatures ---
    # The batches the window touches, each with its first event in the window (a
    # batch's events come in leaf order).  A limit, a cursor or a service filter
    # can leave some of a batch's leaves out of the window, so its root is
    # recomputed from all of them.
    batch_first_event: dict[str, str] = {}
    for ev in events:
        bid = ev.get("merkle_batch_id")
        if bid:
            batch_first_event.setdefault(bid, ev.get("event_id", ""))
    batch_ids = list(batch_first_event)

    # Fetch every leaf and the merkle_batch metadata for signature verification
    try:
        batch_leaves = await ch.get_batch_leaves(tenant_id=ctx.tenant_id, batch_ids=batch_ids)
        batches = await ch.get_merkle_batches(tenant_id=ctx.tenant_id, batch_ids=batch_ids)
    except Exception as exc:
        batch_leaves, batches = {}, []
        # Non-fatal for hash chain check; just can't verify signatures
        _ = exc

    batch_meta = {b["batch_id"]: b for b in batches}
    sigs_verified = 0
    sigs_failed = 0
    tsa_count = 0

    for bid, first_event_id in batch_first_event.items():
        meta = batch_meta.get(bid)
        if meta is None:
            sigs_failed += 1
            continue

        recomputed_root: str | None
        try:
            recomputed_root = compute_merkle_root(
                batch_leaves.get(bid, []), hash_algorithm=settings.hash_algorithm,
            )
        except ValueError:  # a leaf that is not hex: no root to match
            recomputed_root = None
        stored_root = meta.get("merkle_root", "")
        sig_b64 = meta.get("signature", "")
        key_id = meta.get("signature_key_id", "")

        if recomputed_root is None or stored_root != recomputed_root:
            # Merkle root mismatch — tampered
            sigs_failed += 1
            if first_break_event_id is None:
                first_break_event_id = first_event_id  # the batch's first event in the window
            continue

        if not sig_b64 or not key_id:
            # Unsigned batch (crypto-service was unavailable during sealing)
            sigs_failed += 1
            continue

        # Verify signature
        valid = await crypto_client.verify_signature(
            recomputed_root,
            sig_b64,
            key_id,
            tenant_id=ctx.tenant_id,
        )
        if valid:
            sigs_verified += 1
        else:
            sigs_failed += 1

        if meta.get("tsa_token"):
            tsa_count += 1

    chain_valid = first_break_event_id is None
    all_sigs_ok = sigs_failed == 0
    last = events[-1]

    return VerifyIntegrityResponse(
        valid=chain_valid and all_sigs_ok,
        events_checked=len(events),
        first_break_event_id=first_break_event_id,
        signatures_verified=sigs_verified,
        signatures_failed=sigs_failed,
        tsa_present=tsa_count,
        message="OK" if (chain_valid and all_sigs_ok) else "Integrity violation detected",
        next_cursor=(
            encode_chain_cursor(
                last["ingested_at"], last["merkle_batch_id"], last["merkle_leaf_idx"],
            )
            if len(rows) > body.limit
            else None
        ),
        chains=list(chains.values()),
    )

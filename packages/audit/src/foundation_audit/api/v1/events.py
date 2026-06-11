"""Audit API endpoints — ingest + query + integrity verification."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_audit.adapters import clickhouse as ch
from foundation_audit.adapters import crypto_client
from foundation_audit.api.dependencies import current_context, current_request_id, db_session, ingest_service
from foundation_audit.domain.base import FoundationContext
from foundation_audit.schemas.event import AuditEvent, AuditQuery, AuditQueryResult, AuditEventStored
from foundation_audit.services.hash_chain import compute_chain_hash, compute_merkle_root
from foundation_audit.services.ingest_service import IngestService

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
    """
    # Security: enforce tenant from context, not just from body
    if query.tenant_id != ctx.tenant_id:
        raise HTTPException(
            status_code=403,
            detail="query.tenant_id must match authenticated tenant context",
        )

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
            cursor=query.cursor,
            limit=query.limit,
        )
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"ClickHouse unavailable: {exc}") from exc

    items = [_row_to_stored(r) for r in rows]
    next_cursor = items[-1].event_id if len(items) == query.limit else None
    return AuditQueryResult(
        items=items,
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

    # Cursor-loop fetch up to EXPORT_MAX_ROWS rows.
    rows: list[dict[str, Any]] = []
    cursor: str | None = None
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
                cursor=cursor,
                limit=page_limit,
            )
            if not page:
                break
            rows.extend(page)
            if len(page) < page_limit:
                break
            cursor = page[-1]["event_id"]
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
    from_event_id: str | None = None
    limit: int = Field(default=1000, ge=1, le=10000)


class VerifyIntegrityResponse(BaseModel):
    valid: bool
    events_checked: int
    first_break_event_id: str | None = None
    signatures_verified: int
    signatures_failed: int
    tsa_present: int
    message: str


@router.post("/events:verify-integrity", operation_id="verifyIntegrity")
async def verify_integrity(
    body: VerifyIntegrityRequest,
    ctx: FoundationContext = Depends(current_context),
) -> VerifyIntegrityResponse:
    """Verify hash chain integrity and Merkle batch signatures for a tenant.

    Steps:
    1. Fetch events from ClickHouse ordered by ingested_at (same order worker used).
    2. Recompute prev_hash / curr_hash for each event; compare with stored values.
    3. For each merkle_batch: recompute Merkle root from stored leaf curr_hashes,
       call crypto-service /verify to check Ed25519 signature.
    4. Report first break event_id, signatures_verified/failed counts.

    Note: Cross-tenant verification is blocked (must match ctx.tenant_id).
    """
    if body.tenant_id != ctx.tenant_id:
        raise HTTPException(
            status_code=403,
            detail="verify tenant_id must match authenticated tenant context",
        )

    # --- Fetch events ---
    try:
        events = await ch.get_events_for_verification(
            tenant_id=ctx.tenant_id,
            service=body.service,
            from_event_id=body.from_event_id,
            limit=body.limit,
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
    prev_hashes: dict[tuple[str, str], str] = {}  # (tenant, service) → last curr_hash

    from foundation_audit.config import get_settings
    settings = get_settings()

    for ev in events:
        key = (ev.get("tenant_id", ""), ev.get("service", ""))
        prev = prev_hashes.get(key)

        # Build the event dict as the worker would have seen it (strip server-added fields)
        event_data: dict[str, Any] = {}
        _skip = frozenset({
            "prev_hash", "curr_hash", "merkle_batch_id", "merkle_leaf_idx",
            "batch_signature", "ingested_at", "tsa_timestamp",
            "worm_written", "worm_uri",
        })
        for k, v in ev.items():
            if k in _skip or v is None:
                continue
            # CH returns datetimes as datetime objects; canonical JSON needs strings
            if isinstance(v, datetime):
                event_data[k] = v.isoformat()
            else:
                event_data[k] = v

        # payload comes back as string from CH; convert for canonical hashing
        if "payload" in event_data and isinstance(event_data["payload"], str):
            try:
                event_data["payload"] = json.loads(event_data["payload"])
            except (json.JSONDecodeError, ValueError):
                event_data["payload"] = {}

        # Recompute
        expected_prev, expected_curr = compute_chain_hash(
            prev_hash=prev,
            event_data=event_data,
            hash_algorithm=settings.hash_algorithm,
        )

        stored_curr = ev.get("curr_hash", "")
        stored_prev = ev.get("prev_hash", "")

        if stored_curr != expected_curr or stored_prev != expected_prev:
            if first_break_event_id is None:
                first_break_event_id = ev.get("event_id")

        # Advance chain (use STORED curr_hash so downstream errors don't cascade)
        prev_hashes[key] = stored_curr

    # --- Phase 2: Verify Merkle batch signatures ---
    # Group events by batch_id to recompute Merkle root per batch
    from collections import defaultdict
    batch_leaves: dict[str, list[tuple[int, str]]] = defaultdict(list)
    for ev in events:
        bid = ev.get("merkle_batch_id")
        leaf_idx = ev.get("merkle_leaf_idx")
        curr_hash = ev.get("curr_hash", "")
        if bid and leaf_idx is not None and curr_hash:
            batch_leaves[bid].append((leaf_idx, curr_hash))

    # Fetch merkle_batch metadata for signature verification
    try:
        batches = await ch.get_merkle_batches(
            tenant_id=ctx.tenant_id,
            service=body.service,
            limit=body.limit,
        )
    except Exception as exc:
        batches = []
        # Non-fatal for hash chain check; just can't verify signatures
        _ = exc

    batch_meta = {b["batch_id"]: b for b in batches}
    sigs_verified = 0
    sigs_failed = 0
    tsa_count = 0

    for bid, leaf_list in batch_leaves.items():
        # Sort by leaf index, then build ordered hash list
        leaf_list.sort(key=lambda x: x[0])
        leaf_hashes = [h for _, h in leaf_list]
        recomputed_root = compute_merkle_root(leaf_hashes, hash_algorithm=settings.hash_algorithm)

        meta = batch_meta.get(bid)
        if meta is None:
            sigs_failed += 1
            continue

        stored_root = meta.get("merkle_root", "")
        sig_b64 = meta.get("signature", "")
        key_id = meta.get("signature_key_id", "")

        if stored_root != recomputed_root:
            # Merkle root mismatch — tampered
            sigs_failed += 1
            if first_break_event_id is None and leaf_list:
                first_break_event_id = leaf_list[0][1]  # leaf hash as marker
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

    return VerifyIntegrityResponse(
        valid=chain_valid and all_sigs_ok,
        events_checked=len(events),
        first_break_event_id=first_break_event_id,
        signatures_verified=sigs_verified,
        signatures_failed=sigs_failed,
        tsa_present=tsa_count,
        message="OK" if (chain_valid and all_sigs_ok) else "Integrity violation detected",
    )

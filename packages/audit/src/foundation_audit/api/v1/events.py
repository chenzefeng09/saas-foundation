"""Audit API endpoints — ingest + query."""

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_audit.api.dependencies import current_context, current_request_id, db_session, ingest_service
from foundation_audit.domain.base import FoundationContext
from foundation_audit.schemas.event import AuditEvent, AuditQuery, AuditQueryResult
from foundation_audit.services.ingest_service import IngestService

router = APIRouter()


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
    """Query audit events. Requires ClickHouse.

    TODO(M2): Implement ClickHouse query via clickhouse-connect.
    For now, returns empty result.
    """
    return AuditQueryResult(items=[], next_cursor=None, total_estimate=0)


# ---------------------------------------------------------------------------
# Integrity verification
# ---------------------------------------------------------------------------

class VerifyIntegrityRequest(BaseModel):
    tenant_id: str
    service: str | None = None
    from_event_id: str | None = None
    limit: int = Field(default=1000, ge=1, le=10000)


@router.post("/events:verify-integrity", operation_id="verifyIntegrity")
async def verify_integrity(
    body: VerifyIntegrityRequest,
) -> dict:
    """Verify hash chain integrity for a tenant's events.

    Reads events from ClickHouse, recomputes the hash chain,
    and reports any breaks.
    """
    return {
        "status": "NOT_IMPLEMENTED",
        "message": "Hash chain verification requires ClickHouse. Coming in M2.",
    }

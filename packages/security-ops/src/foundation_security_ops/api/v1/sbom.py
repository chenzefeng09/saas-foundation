"""SBOM endpoints — generate, verify, watch."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Response
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_security_ops.api.dependencies import (
    current_request_id,
    db_session,
    security_ops_service,
)
from foundation_security_ops.services.security_ops_service import SecurityOpsService

router = APIRouter()


def _watch_out(w: Any) -> dict[str, Any]:
    return {
        "image_ref": w.image_ref,
        "registered_at": w.registered_at.isoformat() if w.registered_at else None,
        "last_scanned_at": w.last_scanned_at.isoformat() if w.last_scanned_at else None,
        "notify": w.notify or [],
        "new_cves_count": w.new_cves_count,
    }


@router.get("/sbom/images/{image_ref:path}", tags=["sbom"])
async def get_sbom_for_image(
    image_ref: str,
    session: AsyncSession = Depends(db_session),
    svc: SecurityOpsService = Depends(security_ops_service),
    request_id: str = Depends(current_request_id),
) -> Response:
    """Generate or retrieve SBOM for an image reference (CycloneDX JSON)."""
    raw, _record = await svc.generate_sbom(
        session, image_ref, fmt="cyclonedx-json", request_id=request_id
    )
    return Response(
        content=raw,
        media_type="application/vnd.cyclonedx+json",
    )


@router.get("/sbom/watch", tags=["sbom"])
async def list_sbom_watches(
    session: AsyncSession = Depends(db_session),
    svc: SecurityOpsService = Depends(security_ops_service),
) -> list[dict[str, Any]]:
    watches = await svc.list_sbom_watches(session)
    return [_watch_out(w) for w in watches]


class RegisterSbomWatchRequest(BaseModel):
    image_ref: str
    notify: list[str] = []


@router.post("/sbom/watch", status_code=201, tags=["sbom"])
async def register_sbom_watch(
    body: RegisterSbomWatchRequest,
    session: AsyncSession = Depends(db_session),
    svc: SecurityOpsService = Depends(security_ops_service),
    request_id: str = Depends(current_request_id),
) -> dict[str, Any]:
    watch = await svc.register_sbom_watch(
        session,
        body.image_ref,
        notify=body.notify,
        request_id=request_id,
    )
    return _watch_out(watch)

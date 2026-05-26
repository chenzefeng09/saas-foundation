"""Health endpoints."""

from datetime import UTC, datetime

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from foundation_audit import __version__

router = APIRouter()
_START_TIME = datetime.now(UTC)


@router.get("/healthz", operation_id="getHealthz")
async def healthz() -> dict:
    return {"status": "OK", "service": "audit-service", "version": __version__,
            "uptime_seconds": int((datetime.now(UTC) - _START_TIME).total_seconds())}


@router.get("/readyz", operation_id="getReadyz")
async def readyz() -> JSONResponse:
    return JSONResponse({"status": "OK", "service": "audit-service", "version": __version__})

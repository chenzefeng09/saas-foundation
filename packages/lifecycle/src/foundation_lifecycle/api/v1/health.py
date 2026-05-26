"""Health endpoints."""

from datetime import UTC, datetime
from fastapi import APIRouter
from foundation_lifecycle import __version__
router = APIRouter(); _START = datetime.now(UTC)

@router.get("/healthz")
async def healthz() -> dict:
    return {"status": "OK", "service": "lifecycle-service", "version": __version__, "uptime_seconds": int((datetime.now(UTC) - _START).total_seconds())}

from datetime import UTC, datetime

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from foundation_security_ops import __version__
from foundation_security_ops.config import get_settings

router = APIRouter()
_START_TIME = datetime.now(UTC)
_service_name = get_settings().service_name


@router.get("/healthz")
async def healthz() -> JSONResponse:
    return JSONResponse(
        {
            "status": "OK",
            "service": _service_name,
            "version": __version__,
            "uptime_seconds": int((datetime.now(UTC) - _START_TIME).total_seconds()),
        }
    )


@router.get("/readyz")
async def readyz() -> JSONResponse:
    return JSONResponse(
        {
            "status": "OK",
            "service": _service_name,
            "version": __version__,
            "dependencies": {},
        }
    )

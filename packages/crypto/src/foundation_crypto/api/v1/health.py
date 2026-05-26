"""Health endpoints."""

from datetime import UTC, datetime

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from foundation_crypto import __version__
from foundation_crypto.config import get_settings
from foundation_crypto.schemas.common import HealthStatus

router = APIRouter()

_START_TIME = datetime.now(UTC)
_service_name = get_settings().service_name


@router.get("/healthz", operation_id="getHealthz")
async def healthz() -> HealthStatus:
    return HealthStatus(
        status="OK",
        service=_service_name,
        version=__version__,
        uptime_seconds=int((datetime.now(UTC) - _START_TIME).total_seconds()),
    )


@router.get("/readyz", operation_id="getReadyz")
async def readyz() -> JSONResponse:
    """K8s readiness probe — also reports Vault connectivity."""
    settings = get_settings()
    deps: dict[str, dict[str, str | int]] = {}

    # Quick Vault connectivity check
    try:
        from foundation_crypto.adapters.vault_provider import VaultKeyProvider
        _ = VaultKeyProvider()  # instantiates and authenticates
        deps["vault"] = {"status": "OK"}
    except Exception as exc:
        deps["vault"] = {"status": "UNHEALTHY", "detail": str(exc)[:200]}
        return JSONResponse(
            status_code=503,
            content={
                "status": "DEGRADED",
                "service": _service_name,
                "version": __version__,
                "dependencies": deps,
            },
        )

    return JSONResponse(
        content={
            "status": "OK",
            "service": _service_name,
            "version": __version__,
            "dependencies": deps,
        },
    )

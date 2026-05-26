"""Health endpoints — no auth, no tenant context."""

from __future__ import annotations

import time

from fastapi import APIRouter

from foundation_identity import __version__
from foundation_identity.schemas.common import HealthStatus

router = APIRouter(tags=["health"])

_BOOT_TS = time.time()


@router.get("/healthz", response_model=HealthStatus, operation_id="getHealthz")
async def healthz() -> HealthStatus:
    return HealthStatus(
        status="OK",
        service="identity-service",
        version=__version__,
        uptime_seconds=int(time.time() - _BOOT_TS),
    )


@router.get("/readyz", response_model=HealthStatus, operation_id="getReadyz")
async def readyz() -> HealthStatus:
    # M1 skeleton: trust the engine pool's pre-ping. M2 will probe Keycloak / Redis.
    return HealthStatus(
        status="OK",
        service="identity-service",
        version=__version__,
        uptime_seconds=int(time.time() - _BOOT_TS),
        dependencies={
            "postgres": {"status": "OK", "latency_ms": 0},
            "keycloak": {"status": "OK", "latency_ms": 0},
        },
    )

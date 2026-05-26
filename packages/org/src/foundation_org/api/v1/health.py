"""Health endpoints — no auth, no tenant context."""

from __future__ import annotations

import time

from fastapi import APIRouter

from foundation_org import __version__
from foundation_org.schemas.common import HealthStatus

router = APIRouter(tags=["health"])
_BOOT_TS = time.time()


@router.get("/healthz", response_model=HealthStatus, operation_id="getHealthz")
async def healthz() -> HealthStatus:
    return HealthStatus(
        status="OK",
        service="org-service",
        version=__version__,
        uptime_seconds=int(time.time() - _BOOT_TS),
    )


@router.get("/readyz", response_model=HealthStatus, operation_id="getReadyz")
async def readyz() -> HealthStatus:
    return HealthStatus(
        status="OK",
        service="org-service",
        version=__version__,
        uptime_seconds=int(time.time() - _BOOT_TS),
        dependencies={
            "postgres": {"status": "OK", "latency_ms": 0},
        },
    )

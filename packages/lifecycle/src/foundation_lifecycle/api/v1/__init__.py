"""Lifecycle API v1 router."""
from fastapi import APIRouter

from foundation_lifecycle.api.v1 import (
    health,
    large_attachment as la,
    lifecycle as lc,
    storage_quotas as sq,
    storage_reports as sr,
)

api_v1 = APIRouter()
api_v1.include_router(health.router, tags=["health"])
api_v1.include_router(lc.router, tags=["lifecycle"])
api_v1.include_router(sq.router, tags=["storage-quotas"])
api_v1.include_router(sr.router, tags=["storage-reports"])
api_v1.include_router(la.router, tags=["large-attachment"])

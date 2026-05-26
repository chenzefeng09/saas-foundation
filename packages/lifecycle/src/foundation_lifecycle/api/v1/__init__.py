"""Lifecycle API v1 router."""
from fastapi import APIRouter
from foundation_lifecycle.api.v1 import health, lifecycle as lc
api_v1 = APIRouter()
api_v1.include_router(health.router, tags=["health"])
api_v1.include_router(lc.router, tags=["lifecycle"])

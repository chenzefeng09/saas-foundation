"""Audit API v1 router."""

from fastapi import APIRouter

from foundation_audit.api.v1 import events, health

api_v1 = APIRouter()
api_v1.include_router(health.router, tags=["health"])
api_v1.include_router(events.router, tags=["events"])

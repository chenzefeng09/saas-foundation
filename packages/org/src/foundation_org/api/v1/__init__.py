"""API v1 routers."""

from fastapi import APIRouter

from foundation_org.api.v1 import health, memberships, org_units, teams

api_v1 = APIRouter()
api_v1.include_router(health.router)
api_v1.include_router(org_units.router)
api_v1.include_router(teams.router)
api_v1.include_router(memberships.router)

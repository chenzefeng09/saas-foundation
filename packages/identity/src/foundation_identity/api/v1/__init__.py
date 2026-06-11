"""API v1 routers."""

from fastapi import APIRouter

from foundation_identity.api.v1 import (
    health,
    internal,
    mfa,
    platform_admin,
    platform_sso,
    policies,
    sessions,
    sso,
    users,
)

api_v1 = APIRouter()
api_v1.include_router(health.router)
api_v1.include_router(sessions.router)
api_v1.include_router(users.router)
api_v1.include_router(policies.router)
api_v1.include_router(mfa.router)
api_v1.include_router(sso.router)
api_v1.include_router(platform_admin.router)
api_v1.include_router(platform_sso.router)
api_v1.include_router(internal.router)

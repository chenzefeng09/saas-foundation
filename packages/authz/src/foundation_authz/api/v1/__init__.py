"""API v1 routers."""

from fastapi import APIRouter

from foundation_authz.api.v1 import bindings, check, health, permissions, roles

api_v1 = APIRouter()
api_v1.include_router(health.router)
api_v1.include_router(check.router)
api_v1.include_router(roles.router)
api_v1.include_router(bindings.router)
api_v1.include_router(permissions.router)

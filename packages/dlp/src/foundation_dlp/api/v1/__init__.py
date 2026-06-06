from fastapi import APIRouter

from foundation_dlp.api.v1 import dlp, dlp_sdk, health

api_v1 = APIRouter()
api_v1.include_router(health.router, tags=["health"])
api_v1.include_router(dlp.router, prefix="/core", tags=["dlp-core"])
api_v1.include_router(dlp_sdk.router)

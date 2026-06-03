from fastapi import APIRouter
from foundation_api_platform.api.v1 import api_platform, health

api_v1 = APIRouter()
api_v1.include_router(health.router, tags=["health"])
api_v1.include_router(api_platform.router)

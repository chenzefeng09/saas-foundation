from fastapi import APIRouter
from foundation_compliance.api.v1 import compliance, health

api_v1 = APIRouter()
api_v1.include_router(health.router, tags=["health"])
api_v1.include_router(compliance.router)

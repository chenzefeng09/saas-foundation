from fastapi import APIRouter
from foundation_data_protection.api.v1 import data_protection, health

api_v1 = APIRouter()
api_v1.include_router(health.router, tags=["health"])
api_v1.include_router(data_protection.router)

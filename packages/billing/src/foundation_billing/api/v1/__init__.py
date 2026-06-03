from fastapi import APIRouter
from foundation_billing.api.v1 import billing, health

api_v1 = APIRouter()
api_v1.include_router(health.router, tags=["health"])
api_v1.include_router(billing.router)

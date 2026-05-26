from fastapi import APIRouter
from foundation_llm_gateway.api.v1 import health
api_v1 = APIRouter()
api_v1.include_router(health.router, tags=["health"])

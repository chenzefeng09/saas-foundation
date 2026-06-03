from fastapi import APIRouter
from foundation_llm_gateway.api.v1 import health, llm_gateway

api_v1 = APIRouter()
api_v1.include_router(health.router, tags=["health"])
api_v1.include_router(llm_gateway.router)

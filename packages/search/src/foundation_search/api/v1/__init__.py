from fastapi import APIRouter
from foundation_search.api.v1 import health, search

api_v1 = APIRouter()
api_v1.include_router(health.router, tags=["health"])
api_v1.include_router(search.router)

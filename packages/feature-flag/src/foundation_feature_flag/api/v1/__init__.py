from fastapi import APIRouter

from foundation_feature_flag.api.v1 import evaluate, flags, health, user_overrides

api_v1 = APIRouter()
api_v1.include_router(health.router, tags=["health"])
api_v1.include_router(evaluate.router, tags=["evaluation"])
api_v1.include_router(flags.router, tags=["flags"])
api_v1.include_router(user_overrides.router, tags=["user-overrides"])

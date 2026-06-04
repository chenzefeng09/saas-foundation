from fastapi import APIRouter
from foundation_notification.api.v1 import health, notification

api_v1 = APIRouter()
api_v1.include_router(health.router, tags=["health"])
api_v1.include_router(notification.router)

"""Crypto API v1 router aggregation."""

from fastapi import APIRouter

from foundation_crypto.api.v1 import algorithms, envelope, health, keks, password, sign

api_v1 = APIRouter()
api_v1.include_router(health.router, tags=["health"])
api_v1.include_router(keks.router, prefix="/keks", tags=["keys"])
api_v1.include_router(envelope.router, tags=["data"])
api_v1.include_router(sign.router, tags=["signing"])
api_v1.include_router(password.router, tags=["password"])
api_v1.include_router(algorithms.router, tags=["algorithms"])

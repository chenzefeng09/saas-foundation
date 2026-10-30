from fastapi import APIRouter

from foundation_security_ops.api.v1 import drills, health, incidents, sbom, scans, vulnerabilities

api_v1 = APIRouter()
api_v1.include_router(health.router, tags=["health"])
api_v1.include_router(scans.router)
api_v1.include_router(vulnerabilities.router)
api_v1.include_router(sbom.router)
api_v1.include_router(incidents.router)
api_v1.include_router(drills.router)

"""Data Protection API endpoints — masking, destruction, cross-border."""
from __future__ import annotations
from typing import Any
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from foundation_data_protection.api.dependencies import (
    current_context, current_request_id, data_protection_service, db_session, masking_engine,
)
from foundation_data_protection.domain.base import FoundationContext
from foundation_data_protection.services.data_protection_service import DataProtectionService
from foundation_data_protection.services.masking_engine import MaskingEngine

router = APIRouter()


# ---------- Masking ----------

class MaskRequest(BaseModel):
    data: dict[str, Any]
    rules: list[dict[str, str]]


class MaskFieldRequest(BaseModel):
    field_name: str
    value: str
    mask_type: str = "default"


@router.post("/mask", tags=["data-protection"])
async def mask(
    body: MaskRequest,
    ctx: FoundationContext = Depends(current_context),
    engine: MaskingEngine = Depends(masking_engine),
) -> dict[str, Any]:
    rules_dict = {r["field"]: {"method": r.get("method", "mask"), **{k: v for k, v in r.items() if k not in ("field", "method")}} for r in body.rules if "field" in r}
    result = engine.mask_record(body.data, rules_dict)
    return {"masked_data": result}


@router.post("/mask-field", tags=["data-protection"])
async def mask_field(
    body: MaskFieldRequest,
    ctx: FoundationContext = Depends(current_context),
    engine: MaskingEngine = Depends(masking_engine),
) -> dict[str, Any]:
    from foundation_data_protection.services.masking_engine import PRESETS
    method_params = PRESETS.get(body.mask_type, {"method": "mask"})
    method = method_params.pop("method", "mask") if isinstance(method_params, dict) else "mask"
    params = {k: v for k, v in method_params.items()} if isinstance(method_params, dict) else {}
    masked = engine.mask(body.value, method, **params)
    return {"field_name": body.field_name, "masked_value": masked, "mask_type": body.mask_type}


@router.get("/masking-rules", tags=["data-protection"])
async def get_masking_rules(
    ctx: FoundationContext = Depends(current_context),
) -> dict[str, Any]:
    from foundation_data_protection.services.masking_engine import PRESETS
    return {"rules": [{"name": k, "method": v.get("method", "mask")} for k, v in PRESETS.items()]}


# ---------- Destruction ----------

class RequestDestructionRequest(BaseModel):
    resource_ids: list[str]
    method: str = "crypto_shred"


@router.post("/destruction", status_code=201, tags=["data-protection"])
async def request_destruction(
    body: RequestDestructionRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: DataProtectionService = Depends(data_protection_service),
    request_id: str = Depends(current_request_id),
) -> dict[str, Any]:
    req = await svc.request_destruction(
        session, tenant_id=ctx.tenant_id,
        resource_type="generic",
        resource_ids=body.resource_ids,
        destruction_method=body.method,
        reason="API request",
        requested_by=ctx.user_id or "",
        witness_user_id=None,
        request_id=request_id,
    )
    return {"id": req.id, "status": req.status, "resource_ids": req.resource_ids, "destruction_method": req.destruction_method}


@router.get("/destruction/{request_id}", tags=["data-protection"])
async def get_destruction_status(
    request_id: str,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
) -> dict[str, Any]:
    from foundation_data_protection.domain.models import DataDestructionRequest
    req = await session.get(DataDestructionRequest, request_id)
    if req is None or req.tenant_id != ctx.tenant_id:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Destruction request not found")
    return {"id": req.id, "status": req.status, "resource_ids": req.resource_ids}


# ---------- Cross-Border ----------

class CrossBorderCheckRequest(BaseModel):
    destination_country: str
    data_categories: list[str]


@router.post("/cross-border/check", tags=["data-protection"])
async def check_cross_border(
    body: CrossBorderCheckRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: DataProtectionService = Depends(data_protection_service),
    request_id: str = Depends(current_request_id),
) -> dict[str, Any]:
    return await svc.check_cross_border(
        session, tenant_id=ctx.tenant_id,
        data_country="CN",
        destination_country=body.destination_country,
        data_type=", ".join(body.data_categories),
        data_size_bytes=0,
        has_standard_contract=False,
        has_safety_assessment=False,
        request_id=request_id,
    )


@router.get("/data-residency", tags=["data-protection"])
async def get_data_residency(
    ctx: FoundationContext = Depends(current_context),
) -> dict[str, Any]:
    from foundation_data_protection.services.data_protection_service import RESTRICTED_DESTINATIONS
    return {
        "tenant_id": ctx.tenant_id,
        "primary_region": "CN",
        "restricted_destinations": list(RESTRICTED_DESTINATIONS),
        "policy": "PIPL compliant — standard contract required for overseas transfer",
    }

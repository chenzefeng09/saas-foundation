"""DLP + Classification API endpoints (dlp-classification-v1 §3)."""

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_dlp.api.dependencies import current_context, current_request_id, db_session, dlp_service
from foundation_dlp.domain.base import FoundationContext
from foundation_dlp.services.dlp_service import DLPService

router = APIRouter()


class TagResourceRequest(BaseModel):
    resource_type: str; resource_id: str
    sensitivity: str = Field(pattern=r"^L[1-5]$")
    tags: list[str] | None = None; reason: str | None = None

class CheckAccessRequest(BaseModel):
    user_id: str; user_clearance: str = Field(pattern=r"^L[1-5]$")
    resource_type: str; resource_id: str

class CheckDownloadRequest(BaseModel):
    user_id: str; user_clearance: str = Field(pattern=r"^L[1-5]$")
    resource_type: str; resource_id: str
    destination: str = "laptop"

class ScanContentRequest(BaseModel):
    content: str; resource_type: str; resource_id: str


# -- Classification --
@router.post("/classification:tag", status_code=201, operation_id="tagResource")
async def tag_resource(
    body: TagResourceRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: DLPService = Depends(dlp_service),
    request_id: str = Depends(current_request_id),
) -> dict:
    cls = await svc.tag_resource(session, tenant_id=ctx.tenant_id,
        resource_type=body.resource_type, resource_id=body.resource_id,
        sensitivity=body.sensitivity, tags=body.tags, reason=body.reason,
        tagged_by=ctx.user_id or "", request_id=request_id)
    return {"id": cls.id, "sensitivity": cls.sensitivity, "tagged": True}

@router.get("/classification:get", operation_id="getClassification")
async def get_classification(
    resource_type: str = Query(...), resource_id: str = Query(...),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: DLPService = Depends(dlp_service),
) -> dict:
    cls = await svc.get_sensitivity(session, tenant_id=ctx.tenant_id,
        resource_type=resource_type, resource_id=resource_id)
    return {"sensitivity": cls.sensitivity, "tags": cls.tags, "downgradable": cls.downgradable}

# -- Access Checks --
@router.post("/check:read", operation_id="checkRead")
async def check_read(
    body: CheckAccessRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: DLPService = Depends(dlp_service),
    request_id: str = Depends(current_request_id),
) -> dict:
    return await svc.check_read(session, tenant_id=ctx.tenant_id, user_id=body.user_id,
        user_clearance=body.user_clearance, resource_type=body.resource_type,
        resource_id=body.resource_id, request_id=request_id)

@router.post("/check:download", operation_id="checkDownload")
async def check_download(
    body: CheckDownloadRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: DLPService = Depends(dlp_service),
    request_id: str = Depends(current_request_id),
) -> dict:
    return await svc.check_download(session, tenant_id=ctx.tenant_id, user_id=body.user_id,
        user_clearance=body.user_clearance, resource_type=body.resource_type,
        resource_id=body.resource_id, destination=body.destination, request_id=request_id)

@router.post("/scan", operation_id="scanContent")
async def scan_content(
    body: ScanContentRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: DLPService = Depends(dlp_service),
    request_id: str = Depends(current_request_id),
) -> dict:
    return await svc.scan_content(session, tenant_id=ctx.tenant_id, content=body.content,
        resource_type=body.resource_type, resource_id=body.resource_id, request_id=request_id)

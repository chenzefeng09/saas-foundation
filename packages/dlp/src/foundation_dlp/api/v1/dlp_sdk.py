"""DLP SDK-compatible endpoints matching foundation_sdk.resources.dlp paths."""
from __future__ import annotations
from typing import Any
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from foundation_dlp.api.dependencies import (
    current_context, current_request_id, db_session, dlp_service,
)
from foundation_dlp.domain.base import FoundationContext
from foundation_dlp.services.dlp_service import DLPService

router = APIRouter()


class CheckDownloadRequest(BaseModel):
    file_id: str
    sensitivity: str


class ScanContentRequest(BaseModel):
    content: str
    content_type: str = "text"
    sensitivity_threshold: str = "L4"


class ClassifyFileRequest(BaseModel):
    file_id: str
    sensitivity: str
    reason: str = ""


class AddSensitiveWordRequest(BaseModel):
    word: str
    category: str


@router.post("/check-download", tags=["dlp"])
async def check_download(
    body: CheckDownloadRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: DLPService = Depends(dlp_service),
    request_id: str = Depends(current_request_id),
) -> dict[str, Any]:
    return await svc.check_download(
        session, tenant_id=ctx.tenant_id,
        user_id=ctx.user_id or "",
        user_clearance=body.sensitivity,  # treat file sensitivity as clearance threshold
        resource_type="file",
        resource_id=body.file_id,
        destination="laptop",
        request_id=request_id,
    )


@router.post("/scan", tags=["dlp"])
async def scan_content(
    body: ScanContentRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: DLPService = Depends(dlp_service),
    request_id: str = Depends(current_request_id),
) -> dict[str, Any]:
    return await svc.scan_content(
        session, tenant_id=ctx.tenant_id,
        content=body.content,
        resource_type=body.content_type,
        resource_id="scan_request",
        request_id=request_id,
    )


@router.post("/classify", status_code=201, tags=["dlp"])
async def classify_file(
    body: ClassifyFileRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: DLPService = Depends(dlp_service),
    request_id: str = Depends(current_request_id),
) -> dict[str, Any]:
    cls = await svc.tag_resource(
        session, tenant_id=ctx.tenant_id,
        resource_type="file",
        resource_id=body.file_id,
        sensitivity=body.sensitivity,  # type: ignore[arg-type]
        tags=None,
        reason=body.reason or None,
        tagged_by=ctx.user_id or "",
        request_id=request_id,
    )
    return {"id": cls.id, "file_id": body.file_id, "sensitivity": cls.sensitivity, "classified": True}


@router.get("/sensitive-words", tags=["dlp"])
async def get_sensitive_words(
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
) -> dict[str, Any]:
    from sqlalchemy import select
    from foundation_dlp.domain.models import DLPRule
    rows = list((await session.scalars(
        select(DLPRule).where(
            ((DLPRule.tenant_id == ctx.tenant_id) | DLPRule.tenant_id.is_(None)),
            DLPRule.rule_type == "KEYWORD",
            DLPRule.enabled.is_(True),
        )
    )).all())
    return {"items": [{"id": r.id, "name": r.name, "pattern": r.pattern, "sensitivity": r.min_sensitivity} for r in rows]}


@router.post("/sensitive-words", status_code=201, tags=["dlp"])
async def add_sensitive_word(
    body: AddSensitiveWordRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    request_id: str = Depends(current_request_id),
) -> dict[str, Any]:
    import ulid, json
    from foundation_dlp.domain.models import DLPRule
    rule = DLPRule(
        id=f"rule_{ulid.new()!s}",
        tenant_id=ctx.tenant_id,
        name=body.word,
        rule_type="KEYWORD",
        pattern=json.dumps([body.word]),
        min_sensitivity="L3",
        enabled=True,
    )
    session.add(rule)
    await session.flush()
    return {"id": rule.id, "word": body.word, "category": body.category, "created": True}

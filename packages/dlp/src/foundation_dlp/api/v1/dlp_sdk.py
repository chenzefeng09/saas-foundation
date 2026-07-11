"""DLP SDK-compatible endpoints matching foundation_sdk.resources.dlp paths."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_dlp.api.dependencies import (
    TrustedUserClearance,
    current_context,
    current_request_id,
    db_session,
    dlp_service,
    require_management_actor,
    trusted_user_clearance,
)
from foundation_dlp.domain.base import FoundationContext
from foundation_dlp.domain.models import SensitivityLevel
from foundation_dlp.services.dlp_service import DLPService

router = APIRouter()


class CheckDownloadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    file_id: str
    destination: str = "laptop"


class ScanContentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    content: str
    content_type: str = "text"
    sensitivity_threshold: SensitivityLevel = "L4"


class ClassifyFileRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    file_id: str
    sensitivity: SensitivityLevel
    reason: str = ""


class AddSensitiveWordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    word: str
    category: str


@router.post("/check-download", tags=["dlp"])
async def check_download(
    body: CheckDownloadRequest,
    ctx: FoundationContext = Depends(current_context),
    trusted_user: TrustedUserClearance = Depends(trusted_user_clearance),
    session: AsyncSession = Depends(db_session),
    svc: DLPService = Depends(dlp_service),
    request_id: str = Depends(current_request_id),
) -> dict[str, Any]:
    return await svc.check_download(
        session,
        tenant_id=ctx.tenant_id,
        user_id=trusted_user.user_id,
        user_clearance=trusted_user.clearance,
        resource_type="file",
        resource_id=body.file_id,
        destination=body.destination,
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
        session,
        tenant_id=ctx.tenant_id,
        content=body.content,
        resource_type=body.content_type,
        resource_id=None,
        request_id=request_id,
        persist_classification=False,
    )


@router.post("/classify", status_code=201, tags=["dlp"])
async def classify_file(
    body: ClassifyFileRequest,
    ctx: FoundationContext = Depends(require_management_actor),
    session: AsyncSession = Depends(db_session),
    svc: DLPService = Depends(dlp_service),
    request_id: str = Depends(current_request_id),
) -> dict[str, Any]:
    cls = await svc.tag_resource(
        session,
        tenant_id=ctx.tenant_id,
        resource_type="file",
        resource_id=body.file_id,
        sensitivity=body.sensitivity,
        tags=None,
        reason=body.reason or None,
        tagged_by=ctx.user_id or "",
        request_id=request_id,
    )
    return {
        "id": cls.id,
        "file_id": body.file_id,
        "sensitivity": cls.sensitivity,
        "classified": True,
    }


@router.get("/sensitive-words", tags=["dlp"])
async def get_sensitive_words(
    ctx: FoundationContext = Depends(require_management_actor),
    session: AsyncSession = Depends(db_session),
) -> dict[str, Any]:
    from sqlalchemy import select

    from foundation_dlp.domain.models import DLPRule

    rows = list(
        (
            await session.scalars(
                select(DLPRule).where(
                    ((DLPRule.tenant_id == ctx.tenant_id) | DLPRule.tenant_id.is_(None)),
                    DLPRule.rule_type == "KEYWORD",
                    DLPRule.enabled.is_(True),
                )
            )
        ).all()
    )
    return {
        "items": [
            {"id": r.id, "name": r.name, "pattern": r.pattern, "sensitivity": r.min_sensitivity}
            for r in rows
        ]
    }


@router.post("/sensitive-words", status_code=201, tags=["dlp"])
async def add_sensitive_word(
    body: AddSensitiveWordRequest,
    ctx: FoundationContext = Depends(require_management_actor),
    session: AsyncSession = Depends(db_session),
    request_id: str = Depends(current_request_id),
) -> dict[str, Any]:
    import json

    import ulid

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

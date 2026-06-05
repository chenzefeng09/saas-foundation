"""Search API endpoints — query, index, deindex."""
from __future__ import annotations
from typing import Any
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from foundation_search.api.dependencies import (
    current_context, current_request_id, db_session, search_service,
)
from foundation_search.domain.base import FoundationContext
from foundation_search.services.search_service import SearchService

router = APIRouter()


class QueryRequest(BaseModel):
    q: str
    resource_types: list[str] | None = None
    tags: list[str] | None = None
    cursor: str | None = None
    limit: int = 20


class IndexRequest(BaseModel):
    resource_type: str
    resource_id: str
    title: str
    content: str
    tags: list[str] = []
    acl_user_ids: list[str] = []
    # M2: ACL expansion fields
    acl_team_ids: list[str] = []
    owner_id: str | None = None
    visibility: str | None = None  # "PUBLIC_IN_TENANT" | "PRIVATE" | etc.
    metadata: dict[str, Any] = {}


@router.post("/query", tags=["search"])
async def query(
    body: QueryRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: SearchService = Depends(search_service),
) -> dict[str, Any]:
    return await svc.query(
        session, tenant_id=ctx.tenant_id,
        q=body.q,
        resource_types=body.resource_types,
        tags=body.tags,
        user_id=ctx.user_id,
        cursor=body.cursor,
        limit=body.limit,
    )


@router.post("/index", status_code=201, tags=["search"])
async def index(
    body: IndexRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: SearchService = Depends(search_service),
    request_id: str = Depends(current_request_id),
) -> dict[str, Any]:
    idx = await svc.index_resource(
        session, tenant_id=ctx.tenant_id,
        resource_type=body.resource_type,
        resource_id=body.resource_id,
        title=body.title,
        content=body.content,
        tags=body.tags,
        acl_user_ids=body.acl_user_ids,
        acl_team_ids=body.acl_team_ids,
        owner_id=body.owner_id,
        visibility=body.visibility,
        metadata=body.metadata,
        request_id=request_id,
    )
    return {"id": idx.id, "resource_type": idx.resource_type, "resource_id": idx.resource_id, "indexed": True}


@router.delete("/index/{resource_id}", tags=["search"])
async def deindex(
    resource_id: str,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: SearchService = Depends(search_service),
    request_id: str = Depends(current_request_id),
) -> dict[str, Any]:
    count = await svc.deindex(
        session, tenant_id=ctx.tenant_id,
        resource_id=resource_id,
        request_id=request_id,
    )
    return {"resource_id": resource_id, "deindexed": count}

"""API Platform endpoints — API keys, OAuth apps, webhooks."""
from __future__ import annotations
from typing import Any
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from foundation_api_platform.api.dependencies import (
    api_platform_service, current_context, current_request_id, db_session,
)
from foundation_api_platform.domain.base import FoundationContext
from foundation_api_platform.services.api_platform_service import APIPlatformService

router = APIRouter()


# ---------- API Keys ----------

class CreateApiKeyRequest(BaseModel):
    name: str
    scopes: list[str]
    ip_whitelist: list[str] | None = None
    rate_limit_rpm: int = 60
    expires_in_days: int | None = None


class ValidateApiKeyRequest(BaseModel):
    key_hash: str
    required_scope: str | None = None


@router.post("/keys", status_code=201, tags=["api-platform"])
async def create_api_key(
    body: CreateApiKeyRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: APIPlatformService = Depends(api_platform_service),
    request_id: str = Depends(current_request_id),
) -> dict[str, Any]:
    return await svc.create_api_key(
        session, tenant_id=ctx.tenant_id,
        name=body.name, scopes=body.scopes,
        ip_whitelist=body.ip_whitelist,
        rate_limit_rpm=body.rate_limit_rpm,
        expires_in_days=body.expires_in_days,
        created_by=ctx.user_id or "",
        request_id=request_id,
    )


@router.get("/keys", tags=["api-platform"])
async def list_api_keys(
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
) -> dict[str, Any]:
    from sqlalchemy import select
    from foundation_api_platform.domain.models import APIKey
    rows = list((await session.scalars(
        select(APIKey).where(
            APIKey.tenant_id == ctx.tenant_id,
            APIKey.is_active.is_(True),
        )
    )).all())
    return {"items": [{"id": r.id, "name": r.name, "scopes": r.scopes, "rate_limit_rpm": r.rate_limit_rpm} for r in rows]}


@router.post("/keys/{key_id}/revoke", tags=["api-platform"])
async def revoke_api_key(
    key_id: str,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: APIPlatformService = Depends(api_platform_service),
) -> dict[str, Any]:
    await svc.revoke_api_key(session, tenant_id=ctx.tenant_id, key_id=key_id)
    return {"key_id": key_id, "revoked": True}


@router.post("/keys/validate", tags=["api-platform"])
async def validate_api_key(
    body: ValidateApiKeyRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: APIPlatformService = Depends(api_platform_service),
) -> dict[str, Any]:
    key = await svc.validate_api_key(
        session, key_hash=body.key_hash, required_scope=body.required_scope,
    )
    if key is None:
        return {"valid": False}
    return {"valid": True, "key_id": key.id, "scopes": key.scopes}


# ---------- OAuth Apps ----------

class RegisterOAuthAppRequest(BaseModel):
    name: str
    redirect_uris: list[str]
    scopes: list[str]


@router.post("/oauth-apps", status_code=201, tags=["api-platform"])
async def register_oauth_app(
    body: RegisterOAuthAppRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: APIPlatformService = Depends(api_platform_service),
    request_id: str = Depends(current_request_id),
) -> dict[str, Any]:
    app = await svc.register_oauth_app(
        session, tenant_id=ctx.tenant_id,
        name=body.name, redirect_uris=body.redirect_uris,
        scopes=body.scopes,
        created_by=ctx.user_id or "",
        request_id=request_id,
    )
    return {"id": app.id, "name": app.name, "client_id": app.client_id, "redirect_uris": app.redirect_uris}


@router.get("/oauth-apps", tags=["api-platform"])
async def list_oauth_apps(
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
) -> dict[str, Any]:
    from sqlalchemy import select
    from foundation_api_platform.domain.models import OAuthApp
    rows = list((await session.scalars(
        select(OAuthApp).where(OAuthApp.tenant_id == ctx.tenant_id)
    )).all())
    return {"items": [{"id": r.id, "name": r.name, "client_id": r.client_id, "scopes": r.scopes} for r in rows]}


# ---------- Webhooks ----------

class SubscribeWebhookRequest(BaseModel):
    url: str
    event_types: list[str]
    secret: str | None = None


@router.post("/webhooks", status_code=201, tags=["api-platform"])
async def subscribe_webhook(
    body: SubscribeWebhookRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: APIPlatformService = Depends(api_platform_service),
    request_id: str = Depends(current_request_id),
) -> dict[str, Any]:
    sub = await svc.subscribe_webhook(
        session, tenant_id=ctx.tenant_id,
        url=body.url, event_types=body.event_types,
        secret=body.secret,
        request_id=request_id,
    )
    return {"id": sub.id, "url": sub.url, "event_types": sub.event_types, "enabled": sub.enabled}


@router.get("/webhooks", tags=["api-platform"])
async def list_webhooks(
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
) -> dict[str, Any]:
    from sqlalchemy import select
    from foundation_api_platform.domain.models import WebhookSubscription
    rows = list((await session.scalars(
        select(WebhookSubscription).where(
            WebhookSubscription.tenant_id == ctx.tenant_id,
            WebhookSubscription.enabled.is_(True),
        )
    )).all())
    return {"items": [{"id": r.id, "url": r.url, "event_types": r.event_types} for r in rows]}


@router.delete("/webhooks/{webhook_id}", tags=["api-platform"])
async def delete_webhook(
    webhook_id: str,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
) -> dict[str, Any]:
    from foundation_api_platform.domain.models import WebhookSubscription
    sub = await session.get(WebhookSubscription, webhook_id)
    if sub and sub.tenant_id == ctx.tenant_id:
        sub.enabled = False
    return {"webhook_id": webhook_id, "deleted": True}

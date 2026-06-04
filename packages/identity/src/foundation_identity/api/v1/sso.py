"""SSO provider management endpoints (per-tenant enterprise IdP + social IdPs)."""

from __future__ import annotations

from fastapi import APIRouter, Body, Depends, Path, status
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_identity.api.dependencies import current_context, db_session, sso_service
from foundation_identity.domain.base import FoundationContext
from foundation_identity.schemas.sso import (
    CreateSsoProviderRequest,
    SocialProviderRead,
    SsoProviderRead,
)
from foundation_identity.services.sso_service import SsoService

router = APIRouter(prefix="/sso", tags=["sso"])


@router.get(
    "/providers",
    response_model=list[SsoProviderRead],
    operation_id="listSsoProviders",
)
async def list_sso_providers(
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: SsoService = Depends(sso_service),
) -> list[SsoProviderRead]:
    """List all enterprise SSO providers configured for this tenant."""
    return await svc.list_providers(session, tenant_id=ctx.tenant_id)


@router.post(
    "/providers",
    response_model=SsoProviderRead,
    status_code=status.HTTP_201_CREATED,
    operation_id="createSsoProvider",
)
async def create_sso_provider(
    body: CreateSsoProviderRequest = Body(...),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: SsoService = Depends(sso_service),
) -> SsoProviderRead:
    """Configure a new enterprise SSO provider (OIDC / SAML / AD / LDAP / etc.)."""
    return await svc.create_provider(
        session,
        tenant_id=ctx.tenant_id,
        request_id=ctx.request_id,
        body=body,
    )


@router.post(
    "/providers/{provider_id}/enable",
    response_model=SsoProviderRead,
    operation_id="enableSsoProvider",
)
async def enable_sso_provider(
    provider_id: str = Path(...),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: SsoService = Depends(sso_service),
) -> SsoProviderRead:
    """Enable an SSO provider."""
    return await svc.set_provider_enabled(
        session,
        tenant_id=ctx.tenant_id,
        request_id=ctx.request_id,
        provider_id=provider_id,
        enabled=True,
    )


@router.post(
    "/providers/{provider_id}/disable",
    response_model=SsoProviderRead,
    operation_id="disableSsoProvider",
)
async def disable_sso_provider(
    provider_id: str = Path(...),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: SsoService = Depends(sso_service),
) -> SsoProviderRead:
    """Disable an SSO provider (does not delete it)."""
    return await svc.set_provider_enabled(
        session,
        tenant_id=ctx.tenant_id,
        request_id=ctx.request_id,
        provider_id=provider_id,
        enabled=False,
    )


@router.delete(
    "/providers/{provider_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    operation_id="deleteSsoProvider",
    response_class=Response,
)
async def delete_sso_provider(
    provider_id: str = Path(...),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: SsoService = Depends(sso_service),
) -> Response:
    """Permanently delete an SSO provider from this tenant and Keycloak."""
    await svc.delete_provider(
        session,
        tenant_id=ctx.tenant_id,
        request_id=ctx.request_id,
        provider_id=provider_id,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/social",
    response_model=list[SocialProviderRead],
    operation_id="listSocialProviders",
)
async def list_social_providers(
    ctx: FoundationContext = Depends(current_context),
    svc: SsoService = Depends(sso_service),
) -> list[SocialProviderRead]:
    """List available social login providers (Google, GitHub, WeChat, etc.)."""
    return await svc.list_social_providers(tenant_id=ctx.tenant_id)

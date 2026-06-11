"""SSO provider management endpoints (per-tenant enterprise IdP + social IdPs).

Most endpoints here are tenant-scoped (require ``X-Tenant-Id`` → ``current_context``).
Two endpoints are intentionally PUBLIC (no auth, no tenant header) — they back the
unauthenticated browser login page:

* ``GET /sso/login-options`` — list enabled PLATFORM providers (id/name/kind only)
* ``GET /sso/providers/{provider_id}/authorize-url`` — build the Keycloak authorize URL

Both are registered in ``api.middleware.PUBLIC_PATHS`` (login-options exactly;
authorize-url via the ``/authorize-url`` suffix) so the tenant-context middleware
skips them.  They query the DB through ``admin_session_scope`` because there is no
tenant context at login time.
"""

from __future__ import annotations

from fastapi import APIRouter, Body, Depends, Path, Query, status
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_identity.adapters.audit_publisher import get_audit_publisher
from foundation_identity.adapters.keycloak_admin import get_keycloak_admin
from foundation_identity.api.dependencies import current_context, db_session, sso_service
from foundation_identity.domain.base import FoundationContext
from foundation_identity.domain.db import admin_session_scope
from foundation_identity.schemas.sso import (
    CreateSsoProviderRequest,
    SocialProviderRead,
    SsoAuthorizeUrlRead,
    SsoLoginOptionRead,
    SsoProviderRead,
)
from foundation_identity.services.sso_service import SsoService

router = APIRouter(prefix="/sso", tags=["sso"])


def _public_sso_service() -> SsoService:
    """SsoService for PUBLIC endpoints (no DI tenant context required)."""
    return SsoService(keycloak=get_keycloak_admin(), audit=get_audit_publisher())


# --------------------------------------------------------------------------- #
# PUBLIC — browser login flow (no auth, no tenant header)
# --------------------------------------------------------------------------- #


@router.get(
    "/login-options",
    response_model=list[SsoLoginOptionRead],
    operation_id="listSsoLoginOptions",
    summary="List enabled platform SSO providers for the public login page",
)
async def list_sso_login_options(
    svc: SsoService = Depends(_public_sso_service),
) -> list[SsoLoginOptionRead]:
    """PUBLIC: enabled ``scope='PLATFORM'`` providers (id/name/kind only).

    No config is ever returned.  Queried cross-tenant via ``admin_session_scope``
    because the caller is unauthenticated and carries no tenant context.
    """
    async with admin_session_scope(tenant_id="", user_id="PLATFORM") as session:
        return await svc.list_platform_login_options(session)


@router.get(
    "/providers/{provider_id}/authorize-url",
    response_model=SsoAuthorizeUrlRead,
    operation_id="getSsoAuthorizeUrl",
    summary="Build the browser-facing Keycloak authorize URL for a provider",
)
async def get_sso_authorize_url(
    provider_id: str = Path(...),
    redirect_uri: str = Query(..., min_length=1),
    state: str = Query(..., min_length=1),
    svc: SsoService = Depends(_public_sso_service),
) -> SsoAuthorizeUrlRead:
    """PUBLIC: construct the Keycloak ``.../auth`` URL the browser redirects to.

    Validates the provider exists, is enabled, and has a ``keycloak_idp_alias``
    (else 404).  ``redirect_uri`` and ``state`` are URL-encoded into the query.
    """
    async with admin_session_scope(tenant_id="", user_id="PLATFORM") as session:
        url = await svc.build_authorize_url(
            session,
            provider_id=provider_id,
            redirect_uri=redirect_uri,
            state=state,
        )
    return SsoAuthorizeUrlRead(authorize_url=url)


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

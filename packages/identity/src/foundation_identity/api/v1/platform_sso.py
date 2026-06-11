"""Platform-level SSO endpoints — cross-tenant provider + routing management.

Prefix: /platform/sso

Same two-layer guard as :mod:`platform_admin`:
  1. ``require_super_admin`` — fail-closed authz /check for action=platform.admin.
  2. ``admin_session_scope`` — app_admin connection with ``SET LOCAL app.actor='ADMIN'``
     so admin_all RLS policies activate (cross-tenant / platform-row access).

Platform SSO providers carry ``tenant_id IS NULL`` and are readable by any
tenant session (for login) but only mutable through this admin path.
"""

from __future__ import annotations

from fastapi import APIRouter, Body, Depends, status
from fastapi.responses import Response

from foundation_identity.adapters.audit_publisher import get_audit_publisher
from foundation_identity.adapters.keycloak_admin import get_keycloak_admin
from foundation_identity.api.v1.platform_admin import require_super_admin
from foundation_identity.domain.base import foundation_context
from foundation_identity.domain.db import admin_session_scope
from foundation_identity.observability import get_logger
from foundation_identity.schemas.sso import (
    CreatePlatformSsoProviderRequest,
    CreateSsoRoutingRuleRequest,
    SsoProviderRead,
    SsoRoutingRuleRead,
    UpdateSsoRoutingRuleRequest,
)
from foundation_identity.services.sso_service import SsoService

log = get_logger(__name__)

router = APIRouter(prefix="/platform/sso", tags=["platform-sso"])


def _svc() -> SsoService:
    return SsoService(keycloak=get_keycloak_admin(), audit=get_audit_publisher())


def _request_id() -> str:
    ctx = foundation_context.get()
    return (ctx.request_id if ctx else None) or ""


# ─────────────────────────────────────────────────────────────────────────────
# Providers
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/providers", operation_id="listPlatformSsoProviders")
async def list_platform_sso_providers(
    actor_user_id: str = Depends(require_super_admin),
) -> dict[str, list[SsoProviderRead]]:
    """List all SSO providers across every tenant and the platform scope."""
    svc = _svc()
    async with admin_session_scope(tenant_id="", user_id=actor_user_id) as session:
        items = await svc.list_providers_platform(session)
    return {"items": items}


@router.post(
    "/providers",
    status_code=status.HTTP_201_CREATED,
    response_model=SsoProviderRead,
    operation_id="createPlatformSsoProvider",
)
async def create_platform_sso_provider(
    body: CreatePlatformSsoProviderRequest = Body(...),
    actor_user_id: str = Depends(require_super_admin),
) -> SsoProviderRead:
    """Create a PLATFORM- or TENANT-scoped SSO provider."""
    svc = _svc()
    async with admin_session_scope(tenant_id="", user_id=actor_user_id) as session:
        return await svc.create_provider_platform(
            session,
            request_id=_request_id(),
            body=body,
        )


@router.post(
    "/providers/{provider_id}/enable",
    response_model=SsoProviderRead,
    operation_id="enablePlatformSsoProvider",
)
async def enable_platform_sso_provider(
    provider_id: str,
    actor_user_id: str = Depends(require_super_admin),
) -> SsoProviderRead:
    """Enable any SSO provider (cross-tenant / platform)."""
    svc = _svc()
    async with admin_session_scope(tenant_id="", user_id=actor_user_id) as session:
        return await svc.set_provider_enabled(
            session,
            tenant_id=None,
            request_id=_request_id(),
            provider_id=provider_id,
            enabled=True,
        )


@router.post(
    "/providers/{provider_id}/disable",
    response_model=SsoProviderRead,
    operation_id="disablePlatformSsoProvider",
)
async def disable_platform_sso_provider(
    provider_id: str,
    actor_user_id: str = Depends(require_super_admin),
) -> SsoProviderRead:
    """Disable any SSO provider (cross-tenant / platform)."""
    svc = _svc()
    async with admin_session_scope(tenant_id="", user_id=actor_user_id) as session:
        return await svc.set_provider_enabled(
            session,
            tenant_id=None,
            request_id=_request_id(),
            provider_id=provider_id,
            enabled=False,
        )


@router.delete(
    "/providers/{provider_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    operation_id="deletePlatformSsoProvider",
)
async def delete_platform_sso_provider(
    provider_id: str,
    actor_user_id: str = Depends(require_super_admin),
) -> Response:
    """Permanently delete any SSO provider (cross-tenant / platform)."""
    svc = _svc()
    async with admin_session_scope(tenant_id="", user_id=actor_user_id) as session:
        await svc.delete_provider(
            session,
            tenant_id=None,
            request_id=_request_id(),
            provider_id=provider_id,
        )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ─────────────────────────────────────────────────────────────────────────────
# Routing rules
# ─────────────────────────────────────────────────────────────────────────────


@router.get(
    "/providers/{provider_id}/routing-rules",
    operation_id="listPlatformSsoRoutingRules",
)
async def list_routing_rules(
    provider_id: str,
    actor_user_id: str = Depends(require_super_admin),
) -> dict[str, list[SsoRoutingRuleRead]]:
    """List routing rules for a provider (priority order)."""
    svc = _svc()
    async with admin_session_scope(tenant_id="", user_id=actor_user_id) as session:
        items = await svc.list_rules(session, provider_id)
    return {"items": items}


@router.post(
    "/providers/{provider_id}/routing-rules",
    status_code=status.HTTP_201_CREATED,
    response_model=SsoRoutingRuleRead,
    operation_id="createPlatformSsoRoutingRule",
)
async def create_routing_rule(
    provider_id: str,
    body: CreateSsoRoutingRuleRequest = Body(...),
    actor_user_id: str = Depends(require_super_admin),
) -> SsoRoutingRuleRead:
    """Create a routing rule for a provider."""
    svc = _svc()
    async with admin_session_scope(tenant_id="", user_id=actor_user_id) as session:
        return await svc.create_rule(
            session,
            request_id=_request_id(),
            provider_id=provider_id,
            body=body,
        )


@router.patch(
    "/providers/{provider_id}/routing-rules/{rule_id}",
    response_model=SsoRoutingRuleRead,
    operation_id="updatePlatformSsoRoutingRule",
)
async def update_routing_rule(
    provider_id: str,
    rule_id: str,
    body: UpdateSsoRoutingRuleRequest = Body(...),
    actor_user_id: str = Depends(require_super_admin),
) -> SsoRoutingRuleRead:
    """Update a routing rule (partial)."""
    svc = _svc()
    async with admin_session_scope(tenant_id="", user_id=actor_user_id) as session:
        return await svc.update_rule(
            session,
            request_id=_request_id(),
            provider_id=provider_id,
            rule_id=rule_id,
            body=body,
        )


@router.delete(
    "/providers/{provider_id}/routing-rules/{rule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    operation_id="deletePlatformSsoRoutingRule",
)
async def delete_routing_rule(
    provider_id: str,
    rule_id: str,
    actor_user_id: str = Depends(require_super_admin),
) -> Response:
    """Delete a routing rule."""
    svc = _svc()
    async with admin_session_scope(tenant_id="", user_id=actor_user_id) as session:
        await svc.delete_rule(
            session,
            request_id=_request_id(),
            provider_id=provider_id,
            rule_id=rule_id,
        )
    return Response(status_code=status.HTTP_204_NO_CONTENT)

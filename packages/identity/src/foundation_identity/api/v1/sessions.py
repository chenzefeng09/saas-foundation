"""Session (login / logout / service-account / me) endpoints — skeleton.

Full implementation delegates to Keycloak's token endpoint; this v1 skeleton
covers the wire shape so contract tests pass. M2 adds the actual login flow.

In addition to login/logout the module also hosts two endpoints required by
the business layer (agent-platform B-M1 review feedback):

* ``POST /sessions/service-account-token`` — Identity mints a short-lived,
  scope-limited, tenant-bound JWT that a backend service (e.g. agent-platform
  scheduler) can hand to a workload it spawns (e.g. an OpenHands container).
  Replaces the previous anti-pattern where the scheduler forwarded its own
  global API token into every sandbox.
* ``GET /sessions/me`` — Resolves the caller's identity from the bearer
  token; BFFs use this on every page-load to rehydrate the user profile
  *without* trusting any client-side identity store.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import ulid
from fastapi import APIRouter, Depends, Path, status
from fastapi.responses import Response

from foundation_identity.api.dependencies import current_context
from foundation_identity.domain.base import FoundationContext
from foundation_identity.errors import (
    SCOPE_NOT_ALLOWED,
    SESSION_NOT_FOUND,
    TTL_OUT_OF_RANGE,
    FoundationError,
)
from foundation_identity.schemas.session import (
    CreateSessionRequest,
    MeResponse,
    ServiceAccountTokenRequest,
    ServiceAccountTokenResponse,
    SessionRead,
)

router = APIRouter(prefix="/sessions", tags=["sessions"])

# --------------------------------------------------------------------------- #
# Service-account scope catalogue — keep in sync with docs/CONVENTIONS.md §4
# and the equivalent registry in foundation_authz.
# --------------------------------------------------------------------------- #
_ALLOWED_SCOPES: frozenset[str] = frozenset(
    {
        "audit.write",
        "llm-gateway.invoke",
        "lifecycle.write",
        "notification.send",
        "search.read",
        "search.write",
        "billing.usage.write",
        # Add new scopes here AND in CONVENTIONS.md to keep them in lockstep.
    }
)

_MIN_TTL = 60
_MAX_TTL = 86_400


@router.post(
    "",
    response_model=SessionRead,
    status_code=status.HTTP_201_CREATED,
    operation_id="createSession",
)
async def create_session(body: CreateSessionRequest) -> SessionRead:
    """SKELETON — returns a fabricated session.

    Real implementation:
      * EMAIL_PASSWORD → POST keycloak /token (password grant)
      * OIDC           → exchange code at keycloak /broker/<provider>/endpoint
      * SAML           → POST ACS endpoint
    """
    now = datetime.now(UTC)
    return SessionRead(
        id=f"sess_{ulid.new()!s}",
        user_id=f"usr_{ulid.new()!s}",
        tenant_id="tnt_01J5SKELETON00000000000000",
        access_token="<keycloak-jwt-placeholder>",
        refresh_token="<keycloak-refresh-placeholder>",
        expires_at=now + timedelta(hours=1),
        issued_at=now,
        scopes=[],
    )


@router.get("/current", response_model=SessionRead, operation_id="getCurrentSession")
async def get_current_session(
    ctx: FoundationContext = Depends(current_context),
) -> SessionRead:
    """SKELETON — returns whatever the gateway told us.

    Real implementation reads from identity.session table.
    """
    now = datetime.now(UTC)
    return SessionRead(
        id=f"sess_{ulid.new()!s}",
        user_id=ctx.user_id or f"usr_{ulid.new()!s}",
        tenant_id=ctx.tenant_id,
        access_token="<from-current-request-jwt>",
        refresh_token="",
        expires_at=now + timedelta(hours=1),
        issued_at=now,
        scopes=[],
    )


@router.delete(
    "/current",
    status_code=status.HTTP_204_NO_CONTENT,
    operation_id="revokeCurrentSession",
    response_class=Response,
)
async def revoke_current_session(
    ctx: FoundationContext = Depends(current_context),  # noqa: ARG001 — used in M2
) -> Response:
    """SKELETON — would revoke keycloak session + mark session.revoked_at."""
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete(
    "/{session_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    operation_id="revokeSession",
    response_class=Response,
)
async def revoke_session(
    session_id: str = Path(pattern=r"^sess_[0-9A-Z]{26}$"),
) -> Response:
    """SKELETON — admin kills another session."""
    if not session_id.startswith("sess_"):
        raise FoundationError(SESSION_NOT_FOUND)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --------------------------------------------------------------------------- #
# /sessions/me — resolve caller identity from bearer token
# --------------------------------------------------------------------------- #


@router.get(
    "/me",
    response_model=MeResponse,
    operation_id="getMe",
    summary="Resolve caller identity from bearer token",
)
async def get_me(
    ctx: FoundationContext = Depends(current_context),
) -> MeResponse:
    """SKELETON — would join keycloak user record + tenant settings.

    Real implementation:
      1. middleware already verified the bearer JWT signature + audience
      2. read user from identity.user table by ctx.user_id
      3. join tenant.user_role for roles
      4. read mfa_enabled / locale from user profile
    """
    return MeResponse(
        user_id=ctx.user_id or f"usr_{ulid.new()!s}",
        tenant_id=ctx.tenant_id,
        email="placeholder@example.com",
        display_name="placeholder",
        roles=[],
        mfa_enabled=False,
        # locale will be sourced from the user record once M2 wires the DB
        # lookup; placeholder default is fine for the skeleton.
        locale="zh-CN",
    )


# --------------------------------------------------------------------------- #
# /sessions/service-account-token — mint short-lived workload tokens
# --------------------------------------------------------------------------- #


@router.post(
    "/service-account-token",
    response_model=ServiceAccountTokenResponse,
    status_code=status.HTTP_201_CREATED,
    operation_id="issueServiceAccountToken",
    summary="Mint a short-lived, scope-limited, tenant-bound token",
)
async def issue_service_account_token(
    body: ServiceAccountTokenRequest,
    ctx: FoundationContext = Depends(current_context),
) -> ServiceAccountTokenResponse:
    """Issue a short-lived service-account token.

    Authorisation rules:
      * Caller MUST be authenticated as a *service principal* (e.g.
        ``svc_agent-scheduler``).  End-user tokens are rejected.  This skeleton
        leaves the principal-type check to M2 once the JWT validator is in.
      * ``body.tenant_id`` MUST equal ``ctx.tenant_id``.  A service token for
        tenant A cannot mint a token for tenant B.  Cross-tenant minting needs
        a dedicated admin endpoint (out of scope).
      * Every scope in ``body.scopes`` MUST appear in :data:`_ALLOWED_SCOPES`.

    The skeleton fabricates the token; M2 plugs in Keycloak token-exchange
    (RFC 8693) so the JWT is signed by the realm key downstream services
    already trust.
    """
    if body.tenant_id != ctx.tenant_id:
        raise FoundationError(
            SCOPE_NOT_ALLOWED,
            detail=f"tenant_id {body.tenant_id} does not match caller tenant {ctx.tenant_id}",
        )

    unknown = sorted(set(body.scopes) - _ALLOWED_SCOPES)
    if unknown:
        raise FoundationError(
            SCOPE_NOT_ALLOWED,
            detail=f"scopes not in foundation catalogue: {unknown}",
        )

    if not (_MIN_TTL <= body.ttl_seconds <= _MAX_TTL):
        # Belt + braces; pydantic Field already enforces this.
        raise FoundationError(TTL_OUT_OF_RANGE)

    issued_at = datetime.now(UTC)
    return ServiceAccountTokenResponse(
        access_token="<keycloak-token-exchange-jwt-placeholder>",
        token_type="BEARER",
        issued_at=issued_at,
        expires_at=issued_at + timedelta(seconds=body.ttl_seconds),
        tenant_id=body.tenant_id,
        subject=body.subject,
        scopes=list(body.scopes),
        audience=body.audience,
        jti=f"jti_{ulid.new()!s}",
    )

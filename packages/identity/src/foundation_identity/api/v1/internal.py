"""Internal endpoints — called by the ingress, not by end users.

* ``GET /internal/authz`` is the target of ``nginx.ingress.kubernetes.io/auth-url``
  (and Envoy's external_authz filter).  The ingress sends every incoming request
  here first; we JWKS-verify the bearer token, extract the canonical foundation
  ids, and reply ``200`` with response headers the ingress is configured to
  forward to the upstream service (``auth-response-headers``).  A non-2xx
  reply aborts the request at the ingress — the upstream never sees it.

This is *defence in depth* on top of each service's own middleware, not a
replacement for it: downstream still does its own RLS / tenancy / scope checks
on whatever headers (or token) actually reach it.  The ingress merely refuses
anonymous traffic and decorates authenticated traffic with verified ids.

Enable from the ingress side with::

    nginx.ingress.kubernetes.io/auth-url:
      "http://foundation-identity.svc/api/identity/v1/internal/authz"
    nginx.ingress.kubernetes.io/auth-response-headers:
      "X-Foundation-User-Id, X-Foundation-Tenant-Id"
    nginx.ingress.kubernetes.io/auth-method: "GET"

See ``deploy/helm/foundation/templates/ingress.yaml`` for the
infrastructure-side template.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Header, Response, status

from foundation_identity.adapters.keycloak_oidc import KeycloakOIDCAdapter
from foundation_identity.api.v1.sessions import (
    _extract_tenant_id,
    _extract_user_id,
    _oidc_adapter,
    _parse_bearer,
)

router = APIRouter(prefix="/internal", tags=["internal"])


@router.get(
    "/authz",
    status_code=status.HTTP_200_OK,
    operation_id="internalAuthz",
    summary="Ingress external authz — verify bearer and emit canonical headers",
)
async def internal_authz(
    response: Response,
    authorization: str | None = Header(default=None, alias="Authorization"),
    oidc: KeycloakOIDCAdapter = Depends(_oidc_adapter),
) -> dict[str, str]:
    """Verify the bearer token and emit canonical user/tenant headers.

    Behaviour:
      * Missing / malformed token → ``401 TOKEN_INVALID`` (ingress denies).
      * JWKS verification failure → ``401`` (ingress denies).
      * Success → ``200`` with the two response headers set; body is opaque.

    The response headers MUST match the ``auth-response-headers`` annotation
    on the ingress so they are forwarded to the upstream service.  The body
    is opaque — the ingress discards it before proxying to the upstream.
    """
    token = _parse_bearer(authorization)
    claims = await oidc.verify_token(token)

    user_id = _extract_user_id(claims)
    tenant_id = _extract_tenant_id(claims)

    # Canonical names are consumed by every service middleware.  Keep the
    # X-Foundation-* aliases during the ingress migration window, but configure
    # the gateway to forward/replace the canonical names so client-supplied
    # identity headers can never become policy inputs.
    response.headers["X-User-Id"] = user_id
    response.headers["X-Tenant-Id"] = tenant_id
    response.headers["X-Foundation-User-Id"] = user_id
    response.headers["X-Foundation-Tenant-Id"] = tenant_id
    # An optional ``actor`` claim lets the ingress propagate the privilege
    # tier; default to ``USER`` so downstream middleware can rely on the header
    # always being present.
    actor = claims.get("actor")
    canonical_actor = actor if isinstance(actor, str) and actor else "USER"
    response.headers["X-Actor"] = canonical_actor
    response.headers["X-Foundation-Actor"] = canonical_actor

    return {"status": "ok"}


@router.get(
    "/authz/health",
    status_code=status.HTTP_200_OK,
    operation_id="internalAuthzHealth",
    include_in_schema=False,
)
async def internal_authz_health() -> dict[str, str]:
    """Cheap liveness probe for ingress controllers to call independently."""
    return {"status": "ok"}

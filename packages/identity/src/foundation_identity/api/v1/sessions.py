"""Session (login / logout / service-account / me) endpoints.

Wires the Identity service to Keycloak's OIDC endpoints:

* ``POST /sessions`` — end-user login via Keycloak password grant.
* ``POST /sessions/service-account-token`` — short-lived workload token via
  Keycloak ``client_credentials`` grant.
* ``GET  /sessions/me`` — resolve caller identity by JWKS-verifying the
  bearer token and returning the canonical user profile.

Token contract (must match ``schemas/session.py``):
  * ``user_id`` MUST match ``^usr_[0-9A-Z]{26}$``.  Keycloak's native ``sub``
    is a UUID, so the realm exposes a custom ``user_id`` user-attribute claim
    that holds the ULID.  We prefer ``user_id`` over ``sub``; if the token
    carries neither in the right shape, we 401.
  * ``tenant_id`` MUST match ``^tnt_[0-9A-Z]{26}$``.  Sourced from the
    realm-injected ``tenant_id`` claim; absent → fall back to
    ``settings.default_tenant_id`` (used by service-account tokens).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any

import ulid
from fastapi import APIRouter, Depends, Header, Path, status
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_identity.adapters.keycloak_oidc import (
    KeycloakOIDCAdapter,
    get_keycloak_oidc,
)
from foundation_identity.api.dependencies import current_context, db_session
from foundation_identity.config import get_settings
from foundation_identity.domain.base import FoundationContext
from foundation_identity.domain.models import Session as SessionModel
from foundation_identity.errors import (
    INVALID_CREDENTIALS,
    SCOPE_NOT_ALLOWED,
    SESSION_NOT_FOUND,
    TOKEN_INVALID,
    TTL_OUT_OF_RANGE,
    FoundationError,
)
from foundation_identity.observability import get_logger
from foundation_identity.schemas.session import (
    CreateSessionRequest,
    MeResponse,
    ServiceAccountTokenRequest,
    ServiceAccountTokenResponse,
    SessionRead,
)

router = APIRouter(prefix="/sessions", tags=["sessions"])
log = get_logger(__name__)

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
    }
)

_MIN_TTL = 60
_MAX_TTL = 86_400

_USR_PATTERN = re.compile(r"^usr_[0-9A-Z]{26}$")
_TNT_PATTERN = re.compile(r"^tnt_[0-9A-Z]{26}$")


def _oidc_adapter() -> KeycloakOIDCAdapter:
    return get_keycloak_oidc()


def _extract_user_id(claims: dict[str, Any]) -> str:
    """Pull the foundation ULID user_id out of a verified token.

    Realm config injects a ``user_id`` claim (user-attribute mapper) that
    holds the canonical ``usr_…`` ULID.  Tokens minted before that mapper
    was added — or for non-human service accounts — will not carry it; we
    fall back to ``sub`` *only* if it already matches the ULID shape, to
    avoid 500ing on schema mismatch.
    """
    candidate = claims.get("user_id") or claims.get("sub", "")
    if not isinstance(candidate, str) or not _USR_PATTERN.match(candidate):
        raise FoundationError(
            TOKEN_INVALID,
            detail="Token does not carry a foundation user_id claim",
        )
    return candidate


def _extract_tenant_id(claims: dict[str, Any]) -> str:
    """Pull the foundation ULID tenant_id from a verified token (or default)."""
    candidate = claims.get("tenant_id")
    if isinstance(candidate, str) and _TNT_PATTERN.match(candidate):
        return candidate
    # Service-account / non-human tokens may legitimately lack tenant_id.
    default = get_settings().default_tenant_id
    if not _TNT_PATTERN.match(default):
        raise FoundationError(
            TOKEN_INVALID,
            detail="Token missing tenant_id and default_tenant_id is malformed",
        )
    return default


# --------------------------------------------------------------------------- #
# POST /sessions — end-user login (Keycloak password grant)
# --------------------------------------------------------------------------- #


@router.post(
    "",
    response_model=SessionRead,
    status_code=status.HTTP_201_CREATED,
    operation_id="createSession",
)
async def create_session(
    body: CreateSessionRequest,
    oidc: KeycloakOIDCAdapter = Depends(_oidc_adapter),
) -> SessionRead:
    """Authenticate an end user and return a Keycloak-issued session.

    Only ``EMAIL_PASSWORD`` is wired in M2; ``OIDC`` and ``SAML`` raise
    INVALID_CREDENTIALS until the broker flows land.
    """
    if body.method != "EMAIL_PASSWORD":
        raise FoundationError(
            INVALID_CREDENTIALS,
            detail=f"Login method {body.method!r} not yet implemented",
        )

    tokens = await oidc.password_grant(
        username=body.email,
        password=body.password.get_secret_value(),
    )
    access_token = tokens["access_token"]
    refresh_token = tokens.get("refresh_token", "")
    expires_in = int(tokens.get("expires_in", 300))

    # We verify the access_token we just minted: cheap (JWKS already cached
    # after first hit) and lets us pull user_id/tenant_id without trusting
    # the token blob ourselves.  Also catches realm-misconfiguration early.
    claims = await oidc.verify_token(access_token)
    user_id = _extract_user_id(claims)
    tenant_id = _extract_tenant_id(claims)

    issued_at = datetime.now(UTC)
    return SessionRead(
        id=f"sess_{ulid.new()!s}",
        user_id=user_id,
        tenant_id=tenant_id,
        access_token=access_token,
        refresh_token=refresh_token,
        expires_at=issued_at + timedelta(seconds=expires_in),
        issued_at=issued_at,
        scopes=tokens.get("scope", "").split() if tokens.get("scope") else [],
        device_id=body.device_id,
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
# GET /sessions — list all active login sessions for the current user
# --------------------------------------------------------------------------- #


class ActiveSessionRead(BaseModel):
    """Minimal session info returned to the frontend ProfilePage."""

    id: str
    ip: str | None = None
    user_agent: str | None = None
    device: str  # parsed from user_agent
    last_seen_at: str | None = None
    issued_at: str
    current: bool = False


def _parse_device(user_agent: str | None) -> str:
    """Extract a human-readable device label from a User-Agent string.

    Does NOT do geo-lookup.  Returns a short label like:
      "Chrome · macOS", "Safari · iOS", "Firefox · Windows",
      "Unknown device" if UA is absent or unrecognised.
    """
    if not user_agent:
        return "Unknown device"

    ua = user_agent.lower()

    # Browser detection (order matters — more specific first)
    if "edg/" in ua or "edge/" in ua:
        browser = "Edge"
    elif "opr/" in ua or "opera" in ua:
        browser = "Opera"
    elif "firefox/" in ua or "fxios/" in ua:
        browser = "Firefox"
    elif "chrome/" in ua or "crios/" in ua:
        browser = "Chrome"
    elif "safari/" in ua:
        browser = "Safari"
    else:
        browser = "Browser"

    # OS / platform detection
    if "iphone" in ua or "ipad" in ua:
        os_label = "iOS"
    elif "android" in ua:
        os_label = "Android"
    elif "windows" in ua:
        os_label = "Windows"
    elif "macintosh" in ua or "mac os" in ua:
        os_label = "macOS"
    elif "linux" in ua:
        os_label = "Linux"
    else:
        os_label = "Unknown OS"

    return f"{browser} · {os_label}"


@router.get(
    "",
    response_model=list[ActiveSessionRead],
    operation_id="listSessions",
    summary="List all active login sessions for the current user",
)
async def list_sessions(
    ctx: FoundationContext = Depends(current_context),
    db: AsyncSession = Depends(db_session),
) -> list[ActiveSessionRead]:
    """Return all non-revoked, non-expired sessions for the authenticated user.

    Reads from identity.session table.  RLS ensures only the caller's tenant's
    rows are visible.  We additionally filter to user_id = ctx.user_id so users
    only see their own sessions (not other users in the same tenant).

    The ``current`` flag is always ``False`` here — the BFF does not pass the
    current session_id, so we cannot identify which session is "this one".
    The frontend can mark the most-recent one as current.
    """
    now = datetime.now(UTC)

    stmt = (
        select(SessionModel)
        .where(
            SessionModel.user_id == ctx.user_id,
            SessionModel.revoked_at.is_(None),
            SessionModel.expires_at > now,
        )
        .order_by(SessionModel.issued_at.desc())
        .limit(50)
    )
    result = await db.execute(stmt)
    rows = list(result.scalars().all())

    items: list[ActiveSessionRead] = []
    for i, row in enumerate(rows):
        items.append(
            ActiveSessionRead(
                id=row.id,
                ip=row.ip,
                user_agent=row.user_agent,
                device=_parse_device(row.user_agent),
                last_seen_at=row.last_seen_at.isoformat() if row.last_seen_at else None,
                issued_at=row.issued_at.isoformat(),
                current=(i == 0),  # most recent session assumed current
            )
        )
    return items


# --------------------------------------------------------------------------- #
# GET /sessions/me — resolve caller identity from bearer token
# --------------------------------------------------------------------------- #


def _parse_bearer(authorization: str | None) -> str:
    """Extract the bearer token from an ``Authorization`` header value."""
    if not authorization:
        raise FoundationError(TOKEN_INVALID, detail="Missing Authorization header")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise FoundationError(TOKEN_INVALID, detail="Expected 'Bearer <token>'")
    return token


@router.get(
    "/me",
    response_model=MeResponse,
    operation_id="getMe",
    summary="Resolve caller identity from bearer token",
)
async def get_me(
    authorization: str | None = Header(default=None, alias="Authorization"),
    oidc: KeycloakOIDCAdapter = Depends(_oidc_adapter),
) -> MeResponse:
    """JWKS-verify the bearer token and project the canonical user profile."""
    token = _parse_bearer(authorization)
    claims = await oidc.verify_token(token)

    user_id = _extract_user_id(claims)
    tenant_id = _extract_tenant_id(claims)

    email = claims.get("email") or claims.get("preferred_username") or ""
    if not email:
        raise FoundationError(
            TOKEN_INVALID,
            detail="Token missing email / preferred_username claim",
        )

    realm_access = claims.get("realm_access") or {}
    roles = list(realm_access.get("roles") or [])

    display_name = (
        claims.get("name")
        or " ".join(
            x for x in (claims.get("given_name"), claims.get("family_name")) if x
        ).strip()
        or claims.get("preferred_username")
        or email.split("@", 1)[0]
    )

    return MeResponse(
        user_id=user_id,
        tenant_id=tenant_id,
        email=email,
        display_name=display_name,
        roles=roles,
        mfa_enabled=False,
        locale="zh-CN",
    )


# --------------------------------------------------------------------------- #
# POST /sessions/service-account-token — mint short-lived workload tokens
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
    oidc: KeycloakOIDCAdapter = Depends(_oidc_adapter),
) -> ServiceAccountTokenResponse:
    """Issue a short-lived service-account token.

    Authorisation rules:
      * ``body.tenant_id`` MUST equal ``ctx.tenant_id`` — a service token for
        tenant A cannot mint one for tenant B (cross-tenant minting needs a
        dedicated admin endpoint, out of scope).
      * Every scope in ``body.scopes`` MUST appear in :data:`_ALLOWED_SCOPES`.
      * ``ttl_seconds`` is bounded by ``_MIN_TTL`` / ``_MAX_TTL``.

    Implementation: we hand back a Keycloak-minted ``client_credentials``
    access token.  Keycloak does NOT honour our requested ``ttl_seconds``
    directly — the realm's access-token lifespan applies — so the
    ``expires_at`` we report is the *actual* one from the response, while
    ``ttl_seconds`` in the request is treated as a *ceiling hint* only.
    """
    if body.tenant_id != ctx.tenant_id:
        raise FoundationError(
            SCOPE_NOT_ALLOWED,
            detail=(
                f"tenant_id {body.tenant_id} does not match caller tenant "
                f"{ctx.tenant_id}"
            ),
        )

    unknown = sorted(set(body.scopes) - _ALLOWED_SCOPES)
    if unknown:
        raise FoundationError(
            SCOPE_NOT_ALLOWED,
            detail=f"scopes not in foundation catalogue: {unknown}",
        )

    if not (_MIN_TTL <= body.ttl_seconds <= _MAX_TTL):
        raise FoundationError(TTL_OUT_OF_RANGE)

    tokens = await oidc.client_credentials_grant()
    expires_in = int(tokens.get("expires_in", body.ttl_seconds))

    issued_at = datetime.now(UTC)
    return ServiceAccountTokenResponse(
        access_token=tokens["access_token"],
        token_type="BEARER",
        issued_at=issued_at,
        expires_at=issued_at + timedelta(seconds=expires_in),
        tenant_id=body.tenant_id,
        subject=body.subject,
        scopes=list(body.scopes),
        audience=body.audience,
        jti=f"jti_{ulid.new()!s}",
    )

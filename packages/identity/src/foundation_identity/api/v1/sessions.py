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

import json
import re
from datetime import UTC, datetime, timedelta
from typing import Any

import ulid
from fastapi import APIRouter, Body, Depends, Header, Path, Request, status
from fastapi.responses import JSONResponse, Response
from jose import jwt
from jose.exceptions import JWTError
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_identity.adapters.audit_publisher import get_audit_publisher
from foundation_identity.adapters.keycloak_admin import get_keycloak_admin
from foundation_identity.adapters.keycloak_oidc import (
    KeycloakOIDCAdapter,
    get_keycloak_oidc,
)
from foundation_identity.adapters.redis_cache import RedisCacheAdapter
from foundation_identity.api.dependencies import (
    current_context,
    db_session,
    mfa_service,
    redis_cache,
    risk_evaluator,
)
from foundation_identity.config import get_settings
from foundation_identity.domain.base import FoundationContext
from foundation_identity.domain.db import admin_session_scope
from foundation_identity.domain.models import Session as SessionModel
from foundation_identity.domain.models import SsoProvider, User
from foundation_identity.errors import (
    ACCOUNT_LOCKED,
    INVALID_CREDENTIALS,
    LOGIN_DENIED_RISK,
    MFA_CODE_INVALID,
    PERMISSION_DENIED,
    REFRESH_TOKEN_REUSED,
    SCOPE_NOT_ALLOWED,
    SESSION_NOT_FOUND,
    TOKEN_EXPIRED,
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
from foundation_identity.services.mfa_service import MfaService
from foundation_identity.services.risk_evaluator import (
    RiskContext,
    RiskEvaluator,
    RiskOutcome,
)
from foundation_identity.services.sso_service import SsoService

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
        "storage.quota.write",
        # Phase 7: cross-tenant storage quota + orphan-report admin endpoints.
        "storage.admin",
    }
)

_MIN_TTL = 60
_MAX_TTL = 86_400

_USR_PATTERN = re.compile(r"^usr_[0-9A-Z]{26}$")
_TNT_PATTERN = re.compile(r"^tnt_[0-9A-Z]{26}$")


def _oidc_adapter() -> KeycloakOIDCAdapter:
    return get_keycloak_oidc()


# --------------------------------------------------------------------------- #
# Refresh-token rotation / reuse-detection helpers
# --------------------------------------------------------------------------- #

_REUSED_RT_KEY = "refresh_token:used:{jti}"

# Pending-login token bundle stashed between password-verify and mfa-verify.
# Holds the Keycloak token bundle so the client receives NO usable token until
# the second factor clears.  TTL matches the MFA challenge window.
_MFA_LOGIN_KEY = "mfa:login:{challenge_id}"
_MFA_LOGIN_TTL_SECONDS = 300


def _refresh_token_jti(refresh_token: str) -> str | None:
    """Best-effort extract of the ``jti`` from a refresh token.

    Refresh tokens are Keycloak-issued JWTs; we only need the ``jti`` to key
    the reuse-blacklist.  We do NOT verify the signature here — Keycloak
    re-validates it on the rotation grant — so a malformed token simply yields
    ``None`` and rotation tracking is skipped (the grant itself will then
    reject a bad token).
    """
    try:
        claims = jwt.get_unverified_claims(refresh_token)
    except JWTError:
        return None
    jti = claims.get("jti")
    return jti if isinstance(jti, str) and jti else None


async def _revoke_all_user_sessions(
    *, tenant_id: str, user_id: str, reason: str
) -> None:
    """Mark every active DB session for a user as revoked (breach response).

    Used when refresh-token reuse is detected: the rotated token may have been
    exfiltrated, so we invalidate the whole session family rather than just the
    presented one.  Keycloak-side session termination is handled separately via
    the admin ``logout_all_sessions`` call.
    """
    now = datetime.now(UTC)
    async with admin_session_scope(tenant_id=tenant_id, user_id="PLATFORM") as session:
        result = await session.execute(
            select(SessionModel).where(
                SessionModel.user_id == user_id,
                SessionModel.revoked_at.is_(None),
            )
        )
        for row in result.scalars().all():
            row.revoked_at = now
            row.revoke_reason = reason
        await session.flush()


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
    request: Request,
    oidc: KeycloakOIDCAdapter = Depends(_oidc_adapter),
    db: AsyncSession = Depends(db_session),
    mfa: MfaService = Depends(mfa_service),
    cache: RedisCacheAdapter = Depends(redis_cache),
    risk: RiskEvaluator = Depends(risk_evaluator),
) -> SessionRead | JSONResponse:
    """Authenticate an end user and return a Keycloak-issued session.

    ``EMAIL_PASSWORD`` uses the Keycloak password grant.  If the user has MFA
    enabled, the token bundle is stashed server-side and a ``202`` MFA challenge
    is returned instead of a session — the client receives NO usable token until
    it clears the second factor via ``POST /sessions/{challenge_id}/mfa-verify``.
    ``SSO_TOKEN`` exchanges an already-obtained OIDC access token (broker flow
    completed out-of-band by the BFF) for a foundation session, resolving the
    tenant via routing rules and JIT-provisioning the user.  ``SSO_CODE`` redeems
    an OIDC authorization code (browser SSO login) at the realm token endpoint,
    then follows the same verify → resolve → JIT path as ``SSO_TOKEN`` (returning
    refresh_token too).

    SAML enterprise IdPs are accommodated via Keycloak's SAML identity broker:
    clients still POST ``SSO_CODE`` here after Keycloak completes the SAML POST
    binding and redirects back with an OIDC ``code``.  There is no separate
    ``SAML`` method on this endpoint.
    """
    if body.method == "SSO_TOKEN":
        return await _create_session_sso_token(body, oidc)

    if body.method == "SSO_CODE":
        return await _create_session_sso_code(body, oidc)

    # Schema union enforces method ∈ {EMAIL_PASSWORD, SSO_TOKEN, SSO_CODE}, so
    # this guard is defence-in-depth against a future schema-vs-handler skew.
    if body.method != "EMAIL_PASSWORD":
        raise FoundationError(
            INVALID_CREDENTIALS,
            detail=f"Login method {body.method!r} is not supported",
        )

    # P2-C: refuse before hitting Keycloak when this account is locked out.
    await _check_account_lockout(body.email)

    try:
        tokens = await oidc.password_grant(
            username=body.email,
            password=body.password.get_secret_value(),
        )
    except FoundationError as exc:
        if exc.error_code is INVALID_CREDENTIALS:
            await _record_login_failure(body.email)
        raise

    access_token = tokens["access_token"]
    refresh_token = tokens.get("refresh_token", "")
    expires_in = int(tokens.get("expires_in", 300))

    # We verify the access_token we just minted: cheap (JWKS already cached
    # after first hit) and lets us pull user_id/tenant_id without trusting
    # the token blob ourselves.  Also catches realm-misconfiguration early.
    claims = await oidc.verify_token(access_token)
    user_id = _extract_user_id(claims)
    tenant_id = _extract_tenant_id(claims)

    # P3-G: evaluate this login attempt against the anomaly rules.  A DENY
    # outcome refuses the login outright; STEP_UP forces MFA even if the user
    # has none enabled.  ALLOW falls through to the normal MFA-vs-direct path.
    ip = _client_ip(request)
    ua = request.headers.get("user-agent")
    outcome = await _evaluate_risk(
        risk,
        tenant_id=tenant_id,
        user_id=user_id,
        ip=ip,
        user_agent=ua,
    )
    if outcome.decision == "DENY":
        raise FoundationError(
            LOGIN_DENIED_RISK,
            detail=f"score={outcome.score} fired={','.join(outcome.fired)}",
        )

    # P2-C: clean login → wipe lockout state.
    await _record_login_success(tenant_id=tenant_id, user_id=user_id)

    # MFA gate: an enabled second factor OR a STEP_UP-class risk outcome means
    # the bare password is NOT enough.  Stash the (already-minted) token bundle
    # behind a challenge and hand back 202 — the client receives no usable
    # token until mfa-verify clears the second factor.
    if outcome.decision == "STEP_UP" or await _user_requires_mfa(
        db, tenant_id=tenant_id, user_id=user_id
    ):
        return await _begin_mfa_login(
            mfa,
            cache,
            db=db,
            tenant_id=tenant_id,
            user_id=user_id,
            tokens=tokens,
            device_id=body.device_id,
            ip=ip,
            user_agent=ua,
            risk_score=outcome.score,
        )

    issued_at = datetime.now(UTC)
    expires_at = issued_at + timedelta(seconds=expires_in)
    scopes = tokens.get("scope", "").split() if tokens.get("scope") else []
    session_id = f"sess_{ulid.new()!s}"

    await _persist_session(
        session_id=session_id,
        tenant_id=tenant_id,
        user_id=user_id,
        issued_at=issued_at,
        expires_at=expires_at,
        refresh_token_jti=_refresh_token_jti(refresh_token) if refresh_token else None,
        device_id=body.device_id,
        scopes=scopes,
        ip=ip,
        user_agent=ua,
        risk_score=outcome.score,
    )

    return SessionRead(
        id=session_id,
        user_id=user_id,
        tenant_id=tenant_id,
        access_token=access_token,
        refresh_token=refresh_token,
        expires_at=expires_at,
        issued_at=issued_at,
        scopes=scopes,
        device_id=body.device_id,
    )


def _client_ip(request: Request) -> str | None:
    """Best-effort caller IP — trusts ``X-Forwarded-For`` first, then peer."""
    xff = request.headers.get("x-forwarded-for")
    if xff:
        # First hop in XFF is the original client per RFC 7239 conventions.
        return xff.split(",", 1)[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return None


async def _evaluate_risk(
    risk: RiskEvaluator,
    *,
    tenant_id: str,
    user_id: str,
    ip: str | None,
    user_agent: str | None,
) -> RiskOutcome:
    """Run risk evaluation in its own admin scope (independent transaction).

    The login itself does not own a DB session, so we open a dedicated one for
    persisting signals + scoring.  Errors are swallowed at this boundary: a
    failed risk-eval must not block login — score=0 fail-open keeps the gate
    aligned with the rest of the defence-in-depth helpers in this file.
    """
    try:
        async with admin_session_scope(
            tenant_id=tenant_id, user_id="PLATFORM"
        ) as session:
            return await risk.evaluate(
                session,
                ctx=RiskContext(
                    tenant_id=tenant_id,
                    user_id=user_id,
                    ip=ip,
                    user_agent=user_agent,
                ),
            )
    except Exception as exc:  # noqa: BLE001
        log.warning("auth.risk_eval.infra_error", error=str(exc))
        return RiskOutcome(score=0, decision="ALLOW", fired=())


async def _user_requires_mfa(
    db: AsyncSession, *, tenant_id: str, user_id: str
) -> bool:
    """Whether this user has an enabled MFA factor that login must satisfy."""
    result = await db.execute(
        select(User.mfa_enabled).where(
            User.tenant_id == tenant_id,
            User.id == user_id,
            User.deleted_at.is_(None),
        )
    )
    return bool(result.scalar_one_or_none())


async def _begin_mfa_login(
    mfa: MfaService,
    cache: RedisCacheAdapter,
    *,
    db: AsyncSession,
    tenant_id: str,
    user_id: str,
    tokens: dict[str, Any],
    device_id: str | None,
    ip: str | None = None,
    user_agent: str | None = None,
    risk_score: int = 0,
) -> JSONResponse:
    """Stash the token bundle, open an MFA challenge, return 202.

    The challenge_id links the Redis-stashed token bundle to the pending login.
    Fail-secure: a cache write failure raises (REDIS_UNAVAILABLE) and the login
    is refused rather than completing without the second factor.

    Risk-context (``ip``, ``user_agent``, ``risk_score``) flows through the
    stash so the eventual session row written by ``verify_mfa_login`` reflects
    the original attempt — not the MFA-verify request, which may come from a
    different network path than the password leg.
    """
    challenge = await mfa.begin_challenge(db, tenant_id=tenant_id, user_id=user_id)
    await cache.set(
        _MFA_LOGIN_KEY.format(challenge_id=challenge.challenge_id),
        json.dumps(
            {
                "tenant_id": tenant_id,
                "user_id": user_id,
                "tokens": tokens,
                "device_id": device_id,
                "ip": ip,
                "user_agent": user_agent,
                "risk_score": risk_score,
            }
        ),
        ttl_seconds=_MFA_LOGIN_TTL_SECONDS,
    )
    return JSONResponse(
        status_code=status.HTTP_202_ACCEPTED,
        content=challenge.model_dump(mode="json"),
    )


def _email_from_claims(claims: dict[str, Any]) -> str | None:
    """Resolve a login email from token claims.

    Prefer ``email``; fall back to ``preferred_username`` only if it looks like
    an email address (some realms set preferred_username = email).
    """
    email = claims.get("email")
    if isinstance(email, str) and "@" in email:
        return email.lower()
    pun = claims.get("preferred_username")
    if isinstance(pun, str) and _LOGIN_EMAIL_RE.match(pun):
        return pun.lower()
    return None


_LOGIN_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _new_user_id() -> str:
    return f"usr_{ulid.new()!s}"


async def _persist_session(
    *,
    session_id: str,
    tenant_id: str,
    user_id: str,
    issued_at: datetime,
    expires_at: datetime,
    refresh_token_jti: str | None,
    device_id: str | None,
    scopes: list[str],
    ip: str | None = None,
    user_agent: str | None = None,
    risk_score: int = 0,
) -> None:
    """Write a row into identity.session for a freshly-minted login.

    Makes logout / admin-kick / list-sessions operate on real data.  Runs under
    the tenant's admin scope because login happens before a normal tenant
    request context is established.  Best-effort: a write failure must not block
    the login itself, so callers wrap this defensively.
    """
    async with admin_session_scope(tenant_id=tenant_id, user_id="PLATFORM") as session:
        session.add(
            SessionModel(
                id=session_id,
                tenant_id=tenant_id,
                user_id=user_id,
                refresh_token_jti=refresh_token_jti,
                issued_at=issued_at,
                expires_at=expires_at,
                last_seen_at=issued_at,
                scopes=scopes or None,
                device_id=device_id,
                ip=ip,
                user_agent=user_agent,
                risk_score=risk_score,
            )
        )
        await session.flush()


# --------------------------------------------------------------------------- #
# Account-lockout helpers (P2-C)
# --------------------------------------------------------------------------- #


async def _check_account_lockout(email: str) -> None:
    """If the user with this email is currently locked, raise ACCOUNT_LOCKED.

    Looked up across tenants under admin scope — a brute-force attempt against
    a known email should fail without hitting Keycloak (and therefore without
    incrementing the realm-side counter twice).  Infrastructure errors are
    logged and swallowed: the gate is defence-in-depth on top of Keycloak's own
    failed-attempt tracking, so a DB hiccup must not break login.
    """
    now = datetime.now(UTC)
    try:
        async with admin_session_scope(tenant_id="", user_id="PLATFORM") as session:
            result = await session.execute(
                select(User).where(
                    User.email == email.lower(),
                    User.deleted_at.is_(None),
                )
            )
            user = result.scalar_one_or_none()
            if user is None:
                return
            if user.locked_until is not None and user.locked_until > now:
                raise FoundationError(
                    ACCOUNT_LOCKED,
                    detail=f"Account locked until {user.locked_until.isoformat()}",
                )
    except FoundationError:
        raise
    except Exception as exc:
        log.warning("auth.lockout_check.infra_error", error=str(exc))


async def _record_login_failure(email: str) -> None:
    """Increment failed_login_count; lock the account when the floor is hit.

    Best-effort: an unknown email is a no-op (we do NOT leak existence by
    behaving differently for unknown vs known emails — both incur the same
    Keycloak round-trip in the caller).  Infrastructure errors are swallowed.
    """
    settings = get_settings()
    max_attempts = settings.password_max_failed_attempts_floor
    lockout_minutes = settings.password_lockout_minutes_floor
    try:
        async with admin_session_scope(tenant_id="", user_id="PLATFORM") as session:
            result = await session.execute(
                select(User).where(
                    User.email == email.lower(),
                    User.deleted_at.is_(None),
                )
            )
            user = result.scalar_one_or_none()
            if user is None:
                return
            user.failed_login_count = (user.failed_login_count or 0) + 1
            if user.failed_login_count >= max_attempts:
                user.locked_until = datetime.now(UTC) + timedelta(
                    minutes=lockout_minutes
                )
                log.warning(
                    "auth.account_locked",
                    user_id=user.id,
                    failed_count=user.failed_login_count,
                )
            await session.flush()
    except Exception as exc:
        log.warning("auth.lockout_record_failure.infra_error", error=str(exc))


async def _record_login_success(*, tenant_id: str, user_id: str) -> None:
    """Reset failed_login_count + clear any standing lock after a clean login."""
    try:
        async with admin_session_scope(
            tenant_id=tenant_id, user_id="PLATFORM"
        ) as session:
            result = await session.execute(
                select(User).where(User.tenant_id == tenant_id, User.id == user_id)
            )
            user = result.scalar_one_or_none()
            if user is None:
                return
            if user.failed_login_count or user.locked_until:
                user.failed_login_count = 0
                user.locked_until = None
                await session.flush()
    except Exception as exc:
        log.warning("auth.lockout_record_success.infra_error", error=str(exc))


# --------------------------------------------------------------------------- #
# Session timeout helpers (P2-B)
# --------------------------------------------------------------------------- #


async def _touch_session_or_expire(
    *, tenant_id: str, user_id: str
) -> None:
    """Update the user's latest active session ``last_seen_at`` or revoke it.

    Enforces both idle and absolute timeouts using the global floors from
    settings.  Called on every authenticated request that should keep a session
    alive (``/sessions/me``, ``/sessions/current/refresh``).  Side effects:

    * No matching session row → no-op (e.g. service-account tokens, or sessions
      created before the table-write path landed).
    * ``revoked_at`` already set → raise ``TOKEN_EXPIRED``.
    * ``now > expires_at`` (absolute) → stamp ``revoked_at`` + raise.
    * ``now - last_seen_at > idle_timeout`` → stamp ``revoked_at`` + raise.
    * Otherwise → update ``last_seen_at = now``.

    Infrastructure errors (DB unreachable) are logged and swallowed: this is a
    *defence-in-depth* layer on top of the Keycloak access token's own ``exp``,
    so failing it open is preferable to 500-ing every authenticated request
    when the DB hiccups.
    """
    settings = get_settings()
    idle = timedelta(seconds=settings.session_idle_timeout_floor_seconds)
    now = datetime.now(UTC)
    try:
        async with admin_session_scope(
            tenant_id=tenant_id, user_id="PLATFORM"
        ) as session:
            result = await session.execute(
                select(SessionModel)
                .where(
                    SessionModel.tenant_id == tenant_id,
                    SessionModel.user_id == user_id,
                )
                .order_by(SessionModel.issued_at.desc())
                .limit(1)
            )
            row = result.scalar_one_or_none()
            if row is None:
                return
            if row.revoked_at is not None:
                raise FoundationError(TOKEN_EXPIRED, detail="Session revoked")
            if row.expires_at <= now:
                row.revoked_at = now
                row.revoke_reason = "absolute_timeout"
                await session.flush()
                raise FoundationError(
                    TOKEN_EXPIRED, detail="Absolute session timeout"
                )
            if row.last_seen_at is not None and (now - row.last_seen_at) > idle:
                row.revoked_at = now
                row.revoke_reason = "idle_timeout"
                await session.flush()
                raise FoundationError(
                    TOKEN_EXPIRED, detail="Idle session timeout"
                )
            row.last_seen_at = now
            await session.flush()
    except FoundationError:
        raise
    except Exception as exc:
        log.warning("session.touch.infra_error", error=str(exc))


async def _create_session_sso_token(
    body: CreateSessionRequest,
    oidc: KeycloakOIDCAdapter,
) -> SessionRead:
    """Handle method=SSO_TOKEN: verify token → resolve tenant → JIT provision.

    The BFF completed the OIDC/broker code exchange out-of-band and presents the
    resulting ``access_token`` + foundation ``provider_id``.  No refresh_token is
    available on this path, so the returned session carries an empty one.
    """
    access_token = getattr(body, "access_token", None)
    provider_id = getattr(body, "provider_id", None)
    if not access_token or not provider_id:
        raise FoundationError(
            INVALID_CREDENTIALS,
            detail="SSO_TOKEN login requires access_token and provider_id",
        )

    return await _complete_sso_session(
        oidc,
        access_token=access_token,
        provider_id=provider_id,
        refresh_token="",
        scopes=[],
        device_id=getattr(body, "device_id", None),
    )


async def _create_session_sso_code(
    body: CreateSessionRequest,
    oidc: KeycloakOIDCAdapter,
) -> SessionRead:
    """Handle method=SSO_CODE: redeem code → verify → resolve tenant → JIT.

    Server-side leg of the browser SSO login: exchange the OIDC authorization
    ``code`` for a full token bundle (access + refresh), then run the same
    verify → resolve → JIT-provision path as ``SSO_TOKEN``.  Unlike SSO_TOKEN
    this path returns the Keycloak-issued ``refresh_token`` (matching the
    password-grant response shape).

    Never logs ``code`` or tokens.
    """
    code = getattr(body, "code", None)
    redirect_uri = getattr(body, "redirect_uri", None)
    provider_id = getattr(body, "provider_id", None)
    if not code or not redirect_uri or not provider_id:
        raise FoundationError(
            INVALID_CREDENTIALS,
            detail="SSO_CODE login requires code, redirect_uri and provider_id",
        )

    tokens = await oidc.authorization_code_grant(code=code, redirect_uri=redirect_uri)
    access_token = tokens["access_token"]
    refresh_token = tokens.get("refresh_token", "")
    scopes = tokens.get("scope", "").split() if tokens.get("scope") else []

    return await _complete_sso_session(
        oidc,
        access_token=access_token,
        provider_id=provider_id,
        refresh_token=refresh_token,
        scopes=scopes,
        device_id=getattr(body, "device_id", None),
    )


async def _complete_sso_session(
    oidc: KeycloakOIDCAdapter,
    *,
    access_token: str,
    provider_id: str,
    refresh_token: str,
    scopes: list[str],
    device_id: str | None,
) -> SessionRead:
    """Shared SSO finish path: verify token → resolve tenant → JIT → SessionRead.

    Steps:
      1. Verify the access token (JWKS) → claims.
      2. Load the provider by id (admin scope; no tenant context at login yet).
      3. Resolve the target tenant + default role via routing rules.
      4. JIT-provision the user in that tenant if absent.
      5. Build the SessionRead (token expiry derived from the access token's
         ``exp`` claim; refresh_token/scopes passed through by the caller).
    """
    claims = await oidc.verify_token(access_token)
    email = _email_from_claims(claims)
    attributes = claims
    sub = claims.get("sub")

    svc = SsoService(keycloak=get_keycloak_admin(), audit=get_audit_publisher())

    # Provider lookup needs cross-tenant read (no tenant context at login).
    async with admin_session_scope(tenant_id="", user_id="PLATFORM") as session:
        result = await session.execute(
            select(SsoProvider).where(SsoProvider.id == provider_id)
        )
        provider = result.scalar_one_or_none()
        if provider is None or not provider.enabled:
            raise FoundationError(
                INVALID_CREDENTIALS, detail="SSO provider not found or disabled"
            )
        tenant_id, default_role = await svc.resolve_tenant_for_login(
            session,
            provider=provider,
            attributes=attributes,
            email=email,
        )

    if not _TNT_PATTERN.match(tenant_id):
        raise FoundationError(
            INVALID_CREDENTIALS,
            detail="Resolved tenant_id is not a valid foundation tenant",
        )

    display_name = (
        claims.get("name")
        or claims.get("preferred_username")
        or (email.split("@", 1)[0] if email else None)
    )

    # JIT provision inside the resolved tenant's admin scope.
    async with admin_session_scope(tenant_id=tenant_id, user_id="PLATFORM") as session:
        existing = None
        if email:
            res = await session.execute(
                select(User).where(
                    User.tenant_id == tenant_id,
                    User.email == email,
                    User.deleted_at.is_(None),
                )
            )
            existing = res.scalar_one_or_none()

        if existing is not None:
            user_id = existing.id
            # Self-heal: rows JIT-created before the realm exposed a ``sub``
            # claim have keycloak_user_id NULL — backfill so /sessions/me can
            # resolve this user by subject.
            if isinstance(sub, str) and existing.keycloak_user_id != sub:
                existing.keycloak_user_id = sub
                await session.flush()
        else:
            if not email:
                raise FoundationError(
                    TOKEN_INVALID,
                    detail="Token missing email; cannot JIT-provision user",
                )
            user = User(
                id=_new_user_id(),
                tenant_id=tenant_id,
                email=email,
                display_name=display_name,
                status="ACTIVE",
                keycloak_user_id=sub if isinstance(sub, str) else None,
                roles=[default_role] if default_role else None,
                mfa_enabled=False,
            )
            session.add(user)
            await session.flush()
            user_id = user.id

            await get_audit_publisher().publish(
                session,
                event_type="foundation.identity.sso.jit_provisioned",
                tenant_id=tenant_id,
                aggregate_id=user_id,
                payload={
                    "user_id": user_id,
                    "provider_id": provider_id,
                    "email": email,
                    "default_role": default_role,
                },
                request_id="",
            )
            log.info(
                "sso.jit_provisioned",
                tenant_id=tenant_id,
                user_id=user_id,
                provider_id=provider_id,
            )

            # Stamp the foundation ids onto the federated Keycloak user so
            # FUTURE tokens carry user_id / tenant_id claims like seeded
            # users (the realm's user-attribute mappers pick these up).
            # Best-effort: the current session works via the /me DB fallback.
            if isinstance(sub, str):
                try:
                    kc = get_keycloak_admin()
                    kc_user = await kc.get_user(sub)
                    attrs = dict(kc_user.get("attributes") or {})
                    attrs["user_id"] = [user_id]
                    attrs["tenant_id"] = [tenant_id]
                    await kc.update_user(sub, {"attributes": attrs})
                except FoundationError:
                    log.warning(
                        "sso.jit_kc_attr_sync_failed",
                        tenant_id=tenant_id,
                        user_id=user_id,
                    )

    issued_at = datetime.now(UTC)
    expires_in = 300
    exp = claims.get("exp")
    if isinstance(exp, int | float):
        delta = int(exp) - int(issued_at.timestamp())
        if delta > 0:
            expires_in = delta

    expires_at = issued_at + timedelta(seconds=expires_in)
    session_id = f"sess_{ulid.new()!s}"

    await _persist_session(
        session_id=session_id,
        tenant_id=tenant_id,
        user_id=user_id,
        issued_at=issued_at,
        expires_at=expires_at,
        refresh_token_jti=_refresh_token_jti(refresh_token) if refresh_token else None,
        device_id=device_id,
        scopes=scopes,
    )

    return SessionRead(
        id=session_id,
        user_id=user_id,
        tenant_id=tenant_id,
        access_token=access_token,
        refresh_token=refresh_token,
        expires_at=expires_at,
        issued_at=issued_at,
        scopes=scopes,
        device_id=device_id,
    )


class MfaLoginVerifyRequest(BaseModel):
    """Body for POST /sessions/{challenge_id}/mfa-verify."""

    model_config = ConfigDict(extra="forbid")

    code: str
    method: str = "TOTP"


@router.post(
    "/{challenge_id}/mfa-verify",
    response_model=SessionRead,
    status_code=status.HTTP_201_CREATED,
    operation_id="verifyMfa",
    summary="Complete a password-then-MFA login",
)
async def verify_mfa_login(
    body: MfaLoginVerifyRequest,
    challenge_id: str = Path(...),
    mfa: MfaService = Depends(mfa_service),
    cache: RedisCacheAdapter = Depends(redis_cache),
) -> SessionRead:
    """Second leg of a password-then-MFA login.

    Verifies the MFA ``code`` against the challenge opened at password-time, then
    retrieves the stashed token bundle and issues the session (mfa_satisfied).
    ``method`` may be ``TOTP`` (default) or ``RECOVERY`` to redeem a one-time
    recovery code instead.  The stash is single-use: it is deleted on success.
    A bad code leaves the stash in place so the user can retry until the
    challenge TTL lapses.
    """
    raw = await cache.get(_MFA_LOGIN_KEY.format(challenge_id=challenge_id))
    if raw is None:
        raise FoundationError(SESSION_NOT_FOUND, detail="MFA login challenge expired")

    stash = json.loads(raw)
    tenant_id = stash["tenant_id"]
    user_id = stash["user_id"]
    tokens = stash["tokens"]
    device_id = stash.get("device_id")
    # P3-G: risk context captured at the password leg, carried through.
    ip = stash.get("ip")
    user_agent = stash.get("user_agent")
    risk_score = int(stash.get("risk_score") or 0)

    if body.method == "RECOVERY":
        async with admin_session_scope(
            tenant_id=tenant_id, user_id="PLATFORM"
        ) as db:
            ok = await mfa.verify_recovery_code(
                db, tenant_id=tenant_id, user_id=user_id, code=body.code
            )
        if not ok:
            raise FoundationError(MFA_CODE_INVALID)
    else:
        # verify_challenge raises MFA_CODE_INVALID on a bad/expired code.
        await mfa.verify_challenge(challenge_id=challenge_id, code=body.code)

    access_token = tokens["access_token"]
    refresh_token = tokens.get("refresh_token", "")
    expires_in = int(tokens.get("expires_in", 300))
    scopes = tokens.get("scope", "").split() if tokens.get("scope") else []

    issued_at = datetime.now(UTC)
    expires_at = issued_at + timedelta(seconds=expires_in)
    session_id = f"sess_{ulid.new()!s}"

    await _persist_session(
        session_id=session_id,
        tenant_id=tenant_id,
        user_id=user_id,
        issued_at=issued_at,
        expires_at=expires_at,
        refresh_token_jti=_refresh_token_jti(refresh_token) if refresh_token else None,
        device_id=device_id,
        scopes=scopes,
        ip=ip,
        user_agent=user_agent,
        risk_score=risk_score,
    )
    # Stash consumed — prevent replay.
    await cache.delete(_MFA_LOGIN_KEY.format(challenge_id=challenge_id))

    return SessionRead(
        id=session_id,
        user_id=user_id,
        tenant_id=tenant_id,
        access_token=access_token,
        refresh_token=refresh_token,
        expires_at=expires_at,
        issued_at=issued_at,
        scopes=scopes,
        device_id=device_id,
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


class RefreshSessionRequest(BaseModel):
    """Body for POST /sessions/current/refresh."""

    model_config = ConfigDict(extra="forbid")

    refresh_token: str


@router.post(
    "/current/refresh",
    response_model=SessionRead,
    operation_id="refreshSession",
    summary="Rotate a refresh token for a fresh session bundle",
)
async def refresh_session(
    body: RefreshSessionRequest,
    oidc: KeycloakOIDCAdapter = Depends(_oidc_adapter),
    cache: RedisCacheAdapter = Depends(redis_cache),
) -> SessionRead:
    """Exchange a refresh token for a new access/refresh bundle, with rotation.

    Single-use rotation: the presented refresh token is marked used in the
    reuse-blacklist *before* it is redeemed.  If it was already marked used,
    that is a replay of a rotated token — a breach signal — so we revoke ALL of
    the user's sessions and refuse with ``REFRESH_TOKEN_REUSED``.

    Fail-secure: if the cache is unreachable the blacklist write raises
    ``REDIS_UNAVAILABLE`` and the refresh is refused rather than allowing a
    potentially-replayed token through.
    """
    settings = get_settings()
    old_jti = _refresh_token_jti(body.refresh_token)

    if (
        settings.refresh_reuse_detection_enabled
        and settings.refresh_token_rotation_enabled
        and old_jti is not None
    ):
        # SET NX: first use wins; a False return means we have seen this jti.
        first_use = await cache.set_if_absent(
            _REUSED_RT_KEY.format(jti=old_jti),
            "1",
            settings.refresh_token_lifespan_seconds,
        )
        if not first_use:
            await _handle_refresh_reuse(body.refresh_token, old_jti)
            raise FoundationError(REFRESH_TOKEN_REUSED)

    tokens = await oidc.refresh_token_grant(refresh_token=body.refresh_token)
    access_token = tokens["access_token"]
    new_refresh_token = tokens.get("refresh_token", "")
    expires_in = int(tokens.get("expires_in", 300))
    scopes = tokens.get("scope", "").split() if tokens.get("scope") else []

    claims = await oidc.verify_token(access_token)
    user_id = _extract_user_id(claims)
    tenant_id = _extract_tenant_id(claims)

    issued_at = datetime.now(UTC)
    expires_at = issued_at + timedelta(seconds=expires_in)
    new_jti = _refresh_token_jti(new_refresh_token) if new_refresh_token else None

    # Relink the live session row (if any) to the rotated refresh token so a
    # subsequent logout blacklists the *current* token.  Keyed by the OLD jti.
    if old_jti is not None:
        await _relink_session_jti(
            tenant_id=tenant_id,
            user_id=user_id,
            old_jti=old_jti,
            new_jti=new_jti,
            last_seen_at=issued_at,
        )

    return SessionRead(
        id=f"sess_{ulid.new()!s}",
        user_id=user_id,
        tenant_id=tenant_id,
        access_token=access_token,
        refresh_token=new_refresh_token,
        expires_at=expires_at,
        issued_at=issued_at,
        scopes=scopes,
    )


async def _handle_refresh_reuse(refresh_token: str, jti: str) -> None:
    """Breach response to a replayed refresh token.

    Resolve the owning user from the token, revoke all their DB sessions, end
    their Keycloak sessions, and emit a SECURITY audit event.  Best-effort
    throughout: the caller still raises REFRESH_TOKEN_REUSED regardless.
    """
    claims: dict[str, Any] = {}
    try:
        claims = jwt.get_unverified_claims(refresh_token)
    except JWTError:
        pass
    sub = claims.get("sub")
    log.warning("session.refresh_reuse_detected", jti=jti, sub=sub)

    # Resolve foundation user by keycloak subject.
    if not isinstance(sub, str) or not sub:
        return
    async with admin_session_scope(tenant_id="", user_id="PLATFORM") as session:
        res = await session.execute(
            select(User).where(
                User.keycloak_user_id == sub,
                User.deleted_at.is_(None),
            )
        )
        user = res.scalar_one_or_none()
    if user is None:
        return

    await _revoke_all_user_sessions(
        tenant_id=user.tenant_id,
        user_id=user.id,
        reason="refresh_token_reuse",
    )

    # End Keycloak-side sessions + emit security event (best-effort).
    try:
        await get_keycloak_admin().logout_all_sessions(sub)
    except FoundationError:
        log.warning("session.refresh_reuse.kc_logout_failed", sub=sub)

    try:
        async with admin_session_scope(
            tenant_id=user.tenant_id, user_id="PLATFORM"
        ) as session:
            await get_audit_publisher().publish(
                session,
                event_type="foundation.identity.session.refresh_reuse_detected",
                tenant_id=user.tenant_id,
                aggregate_id=user.id,
                payload={"user_id": user.id, "jti": jti, "severity": "SECURITY"},
                request_id="",
            )
    except FoundationError:
        log.warning("session.refresh_reuse.audit_failed", user_id=user.id)


async def _relink_session_jti(
    *,
    tenant_id: str,
    user_id: str,
    old_jti: str,
    new_jti: str | None,
    last_seen_at: datetime,
) -> None:
    """Point the session row tracked by ``old_jti`` at the rotated token.

    Also enforces idle / absolute session timeouts (P2-B): if the matched row
    has already expired by either clock, it is revoked and ``TOKEN_EXPIRED`` is
    raised so the rotation is refused.
    """
    settings = get_settings()
    idle = timedelta(seconds=settings.session_idle_timeout_floor_seconds)
    async with admin_session_scope(tenant_id=tenant_id, user_id="PLATFORM") as session:
        result = await session.execute(
            select(SessionModel).where(
                SessionModel.user_id == user_id,
                SessionModel.refresh_token_jti == old_jti,
                SessionModel.revoked_at.is_(None),
            )
        )
        row = result.scalar_one_or_none()
        if row is None:
            return
        if row.expires_at <= last_seen_at:
            row.revoked_at = last_seen_at
            row.revoke_reason = "absolute_timeout"
            await session.flush()
            raise FoundationError(TOKEN_EXPIRED, detail="Absolute session timeout")
        if row.last_seen_at is not None and (last_seen_at - row.last_seen_at) > idle:
            row.revoked_at = last_seen_at
            row.revoke_reason = "idle_timeout"
            await session.flush()
            raise FoundationError(TOKEN_EXPIRED, detail="Idle session timeout")
        row.refresh_token_jti = new_jti
        row.last_seen_at = last_seen_at
        await session.flush()


@router.delete(
    "/current",
    status_code=status.HTTP_204_NO_CONTENT,
    operation_id="revokeCurrentSession",
    response_class=Response,
)
async def revoke_current_session(
    refresh_token: str = Body(default="", embed=True),
    ctx: FoundationContext = Depends(current_context),
    oidc: KeycloakOIDCAdapter = Depends(_oidc_adapter),
    cache: RedisCacheAdapter = Depends(redis_cache),
) -> Response:
    """Log out the current session: end the Keycloak session + revoke locally.

    Given the session's refresh token, this terminates the Keycloak SSO session,
    blacklists the token's jti (so it can't be used to rotate), and marks the
    matching DB session row revoked.  All steps are best-effort — the end state
    is "session gone" — and the endpoint always returns 204.
    """
    if refresh_token:
        jti = _refresh_token_jti(refresh_token)
        try:
            await oidc.logout_session(refresh_token=refresh_token)
        except FoundationError:
            log.warning("session.logout.kc_failed")
        if jti is not None:
            try:
                await cache.set_if_absent(
                    _REUSED_RT_KEY.format(jti=jti),
                    "1",
                    get_settings().refresh_token_lifespan_seconds,
                )
            except FoundationError:
                log.warning("session.logout.blacklist_failed")
            await _mark_session_revoked_by_jti(
                tenant_id=ctx.tenant_id,
                user_id=ctx.user_id,
                jti=jti,
                reason="user_logout",
            )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


async def _mark_session_revoked_by_jti(
    *, tenant_id: str, user_id: str | None, jti: str, reason: str
) -> None:
    """Mark the DB session row carrying ``jti`` as revoked (best-effort)."""
    now = datetime.now(UTC)
    async with admin_session_scope(tenant_id=tenant_id, user_id="PLATFORM") as session:
        stmt = select(SessionModel).where(
            SessionModel.refresh_token_jti == jti,
            SessionModel.revoked_at.is_(None),
        )
        if user_id:
            stmt = stmt.where(SessionModel.user_id == user_id)
        result = await session.execute(stmt)
        row = result.scalar_one_or_none()
        if row is not None:
            row.revoked_at = now
            row.revoke_reason = reason
            await session.flush()


@router.delete(
    "/{session_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    operation_id="revokeSession",
    response_class=Response,
)
async def revoke_session(
    session_id: str = Path(pattern=r"^sess_[0-9A-Z]{26}$"),
    ctx: FoundationContext = Depends(current_context),
) -> Response:
    """Revoke another of the caller's sessions (kick a device).

    Looks up the session row, enforces that it belongs to the caller (a user
    may only kill their OWN sessions; cross-user admin kick is a separate
    privileged path), ends the Keycloak session if linked, and marks the row
    revoked.  404 if the session does not exist or is already gone.
    """
    async with admin_session_scope(
        tenant_id=ctx.tenant_id, user_id="PLATFORM"
    ) as session:
        result = await session.execute(
            select(SessionModel).where(SessionModel.id == session_id)
        )
        row = result.scalar_one_or_none()
        if row is None or row.revoked_at is not None:
            raise FoundationError(SESSION_NOT_FOUND)
        # A user may only revoke their own sessions.
        if ctx.user_id and row.user_id != ctx.user_id:
            raise FoundationError(PERMISSION_DENIED)
        row.revoked_at = datetime.now(UTC)
        row.revoke_reason = "user_revoked"
        await session.flush()

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
    """JWKS-verify the bearer token and project the canonical user profile.

    Two resolution paths:
      * Seeded / invited users carry ``user_id`` + ``tenant_id`` claims
        (user-attribute mappers) — profile comes straight from the token.
      * SSO-federated users JIT-provisioned at first broker login have no
        foundation claims yet — fall back to the ``identity.user`` row keyed
        by ``keycloak_user_id = sub``.
    """
    token = _parse_bearer(authorization)
    claims = await oidc.verify_token(token)

    email = claims.get("email") or claims.get("preferred_username") or ""
    if not email:
        raise FoundationError(
            TOKEN_INVALID,
            detail="Token missing email / preferred_username claim",
        )

    claim_user_id = claims.get("user_id")
    if isinstance(claim_user_id, str) and _USR_PATTERN.match(claim_user_id):
        user_id = claim_user_id
        tenant_id = _extract_tenant_id(claims)
        realm_access = claims.get("realm_access") or {}
        roles = list(realm_access.get("roles") or [])
        db_display_name = None
    else:
        # SSO-federated subject — resolve via the provisioned user row.
        sub = claims.get("sub")
        if not isinstance(sub, str) or not sub:
            raise FoundationError(TOKEN_INVALID, detail="Token missing sub claim")
        async with admin_session_scope(tenant_id="", user_id="PLATFORM") as session:
            res = await session.execute(
                select(User).where(
                    User.keycloak_user_id == sub,
                    User.deleted_at.is_(None),
                )
            )
            row = res.scalar_one_or_none()
        if row is None:
            raise FoundationError(
                TOKEN_INVALID,
                detail="Token subject is not a provisioned user",
            )
        user_id = row.id
        tenant_id = row.tenant_id
        roles = list(row.roles or [])
        db_display_name = row.display_name

    # P2-B: keep the session alive (idle clock) or revoke it (idle/absolute timeout).
    await _touch_session_or_expire(tenant_id=tenant_id, user_id=user_id)

    display_name = (
        db_display_name
        or claims.get("name")
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

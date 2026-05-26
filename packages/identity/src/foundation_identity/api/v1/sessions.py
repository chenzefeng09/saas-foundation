"""Session (login / logout) endpoints — skeleton.

Full implementation delegates to Keycloak's token endpoint; this v1 skeleton
covers the wire shape so contract tests pass. M2 adds the actual login flow.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import ulid
from fastapi import APIRouter, Depends, Path, status
from fastapi.responses import Response

from foundation_identity.api.dependencies import current_context
from foundation_identity.domain.base import FoundationContext
from foundation_identity.errors import SESSION_NOT_FOUND, FoundationError
from foundation_identity.schemas.session import CreateSessionRequest, SessionRead

router = APIRouter(prefix="/sessions", tags=["sessions"])


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

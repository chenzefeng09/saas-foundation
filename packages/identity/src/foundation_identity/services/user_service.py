"""User lifecycle service.

Responsibilities:
  * invite → activate → freeze/unfreeze → deactivate → hard-delete
  * keep Keycloak + identity.user table in sync
  * emit `foundation.identity.user.*` events via outbox

Out of scope (separate services):
  * MFA flows               → mfa_service.py
  * SSO provider config     → sso_service.py
  * SCIM reconciliation     → scim adapter (scim-dingtalk-v1)
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import ulid
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_identity.adapters.audit_publisher import AuditPublisher
from foundation_identity.adapters.keycloak_admin import KeycloakAdminAdapter
from foundation_identity.adapters.keycloak_oidc import KeycloakOIDCAdapter
from foundation_identity.config import get_settings
from foundation_identity.domain.models import User
from foundation_identity.errors import (
    CURRENT_PASSWORD_INCORRECT,
    INVALID_CREDENTIALS,
    PASSWORD_CHANGE_NOT_ALLOWED,
    PASSWORD_TOO_WEAK,
    USER_ALREADY_EXISTS,
    USER_NOT_FOUND,
    FoundationError,
)
from foundation_identity.observability import get_logger

log = get_logger(__name__)


def _new_user_id() -> str:
    return f"usr_{ulid.new()!s}"


class UserService:
    def __init__(
        self,
        keycloak: KeycloakAdminAdapter,
        audit: AuditPublisher,
    ) -> None:
        self._kc = keycloak
        self._audit = audit

    # ------------------------------------------------------------------ read
    async def list_users(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        cursor: str | None = None,
        limit: int = 50,
        status_filter: str | None = None,
        email_filter: str | None = None,
    ) -> tuple[list[User], str | None]:
        stmt = select(User).where(User.tenant_id == tenant_id, User.deleted_at.is_(None))
        if status_filter:
            stmt = stmt.where(User.status == status_filter)
        if email_filter:
            stmt = stmt.where(User.email == email_filter)
        if cursor:
            stmt = stmt.where(User.id > cursor)
        stmt = stmt.order_by(User.id).limit(limit + 1)

        rows = (await session.scalars(stmt)).all()
        next_cursor = rows[-1].id if len(rows) > limit else None
        return list(rows[:limit]), next_cursor

    async def get_user(self, session: AsyncSession, *, tenant_id: str, user_id: str) -> User:
        user = await session.get(User, user_id)
        if user is None or user.tenant_id != tenant_id or user.deleted_at is not None:
            raise FoundationError(USER_NOT_FOUND, extra={"user_id": user_id})
        return user

    # ------------------------------------------------------------------ invite
    async def invite(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        request_id: str,
        actor_id: str | None,
        email: str,
        display_name: str | None = None,
        roles: list[str] | None = None,
        send_invite_email: bool = True,
    ) -> User:
        # Uniqueness pre-check (RLS ensures we only see same-tenant rows)
        existing = await session.scalar(
            select(User).where(User.tenant_id == tenant_id, User.email == email)
        )
        if existing is not None:
            raise FoundationError(USER_ALREADY_EXISTS, extra={"email": email})

        kc_user_id = await self._kc.create_user(
            email=email,
            attributes={"tenant_id": [tenant_id]},
            enabled=True,
        )

        user = User(
            id=_new_user_id(),
            tenant_id=tenant_id,
            email=email,
            display_name=display_name,
            status="INVITED",
            keycloak_user_id=kc_user_id,
            roles=roles or [],
            mfa_enabled=False,
        )
        session.add(user)

        if send_invite_email:
            # Triggers Keycloak's password-set + verify-email flow
            await self._kc.trigger_required_action(kc_user_id, action="UPDATE_PASSWORD")

        await self._emit(
            session,
            event_type="foundation.identity.user.invited",
            tenant_id=tenant_id,
            request_id=request_id,
            payload={
                "user_id": user.id,
                "email": email,
                "invited_by": actor_id,
            },
        )

        await session.flush()
        return user

    # ------------------------------------------------------------------ update
    async def update(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        request_id: str,
        actor_id: str | None,
        user_id: str,
        patch: dict[str, Any],
    ) -> User:
        user = await self.get_user(session, tenant_id=tenant_id, user_id=user_id)

        for field in ("display_name", "status", "roles"):
            if field in patch and patch[field] is not None:
                setattr(user, field, patch[field])

        # Propagate display_name & email to Keycloak when applicable
        kc_patch: dict[str, Any] = {}
        if "display_name" in patch and patch["display_name"] is not None:
            kc_patch["firstName"] = patch["display_name"]
        if kc_patch and user.keycloak_user_id:
            await self._kc.update_user(user.keycloak_user_id, kc_patch)

        await self._emit(
            session,
            event_type="foundation.identity.user.updated",
            tenant_id=tenant_id,
            request_id=request_id,
            payload={
                "user_id": user.id,
                "changed_fields": sorted(patch.keys()),
                "updated_by": actor_id,
            },
        )
        await session.flush()
        return user

    # ------------------------------------------------------------------ freeze
    async def freeze(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        request_id: str,
        actor_id: str,
        user_id: str,
        reason: str,
    ) -> User:
        user = await self.get_user(session, tenant_id=tenant_id, user_id=user_id)
        user.status = "FROZEN"

        if user.keycloak_user_id:
            await self._kc.disable_user(user.keycloak_user_id)
            await self._kc.logout_all_sessions(user.keycloak_user_id)

        await self._emit(
            session,
            event_type="foundation.identity.user.frozen",
            tenant_id=tenant_id,
            request_id=request_id,
            payload={"user_id": user.id, "reason": reason, "frozen_by": actor_id},
        )
        await session.flush()
        return user

    async def unfreeze(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        request_id: str,
        actor_id: str,
        user_id: str,
    ) -> User:
        user = await self.get_user(session, tenant_id=tenant_id, user_id=user_id)
        if user.status != "FROZEN":
            return user
        user.status = "ACTIVE"
        if user.keycloak_user_id:
            await self._kc.enable_user(user.keycloak_user_id)
        await self._emit(
            session,
            event_type="foundation.identity.user.unfrozen",
            tenant_id=tenant_id,
            request_id=request_id,
            payload={"user_id": user.id, "unfrozen_by": actor_id},
        )
        await session.flush()
        return user

    # ------------------------------------------------------------------ deactivate (soft-delete)
    async def deactivate(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        request_id: str,
        actor_id: str | None,
        user_id: str,
    ) -> None:
        user = await self.get_user(session, tenant_id=tenant_id, user_id=user_id)
        user.status = "DEACTIVATED"
        user.deleted_at = datetime.now(UTC)
        if user.keycloak_user_id:
            await self._kc.disable_user(user.keycloak_user_id)
            await self._kc.logout_all_sessions(user.keycloak_user_id)
        await self._emit(
            session,
            event_type="foundation.identity.user.deactivated",
            tenant_id=tenant_id,
            request_id=request_id,
            payload={"user_id": user.id, "deactivated_by": actor_id},
        )
        await session.flush()

    # ------------------------------------------------------------------ password reset
    async def force_password_reset(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        request_id: str,
        actor_id: str,
        user_id: str,
    ) -> None:
        user = await self.get_user(session, tenant_id=tenant_id, user_id=user_id)
        if not user.keycloak_user_id:
            log.warning("user.no_kc_id", user_id=user_id)
            return
        await self._kc.trigger_required_action(user.keycloak_user_id, action="UPDATE_PASSWORD")
        await self._emit(
            session,
            event_type="foundation.identity.password.changed",
            tenant_id=tenant_id,
            request_id=request_id,
            payload={"user_id": user.id, "triggered_by": actor_id, "source": "admin_reset"},
        )

    # ------------------------------------------------------------------ self-service password change
    async def change_own_password(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        request_id: str,
        user_id: str,
        email: str,
        current_password: str,
        new_password: str,
        oidc: KeycloakOIDCAdapter,
    ) -> None:
        """Self-service password change for the authenticated caller.

        Flow (the caller is ALWAYS resolved from the bearer token by the route;
        ``user_id`` is never a path param):

          1. Load the caller's row → resolve ``keycloak_user_id``.
          2. Reject SSO/federated/passwordless accounts (no local password to
             change) with ``PASSWORD_CHANGE_NOT_ALLOWED`` (409).  Detected via a
             non-empty ``federationLink`` on the KC user record OR the absence of
             a local ``password`` credential.
          3. Validate the new password against the hard length floor →
             ``PASSWORD_TOO_WEAK`` (422).
          4. Verify the *current* password via the OIDC password grant.  A bad
             password raises ``INVALID_CREDENTIALS`` from the adapter, which we
             remap to ``CURRENT_PASSWORD_INCORRECT`` (400) so the SPA can show a
             precise message (and the BFF does not mask it as a 401 session
             expiry).
          5. Set the new password directly via the Admin reset-password call
             (``temporary=False`` → immediately usable, no forced re-reset).
          6. Emit ``foundation.identity.password.changed``.

        Neither ``current_password`` nor ``new_password`` is ever logged.
        """
        user = await self.get_user(session, tenant_id=tenant_id, user_id=user_id)
        kc_user_id = user.keycloak_user_id
        if not kc_user_id:
            # No backing Keycloak identity → nothing to change (treat like an
            # SSO/federated account: not a local-password user).
            raise FoundationError(
                PASSWORD_CHANGE_NOT_ALLOWED,
                detail="User has no local Keycloak credential to change",
            )

        # --- (2) federated / passwordless detection -------------------------
        kc_user = await self._kc.get_user(kc_user_id)
        if kc_user.get("federationLink"):
            raise FoundationError(
                PASSWORD_CHANGE_NOT_ALLOWED,
                detail="Account is linked to a federated identity provider",
            )
        if not await self._kc.has_local_password(kc_user_id):
            raise FoundationError(
                PASSWORD_CHANGE_NOT_ALLOWED,
                detail="Account has no local password credential",
            )

        # --- (3) new-password policy (hard length floor) --------------------
        min_len = get_settings().password_min_length_floor
        if not new_password or len(new_password) < min_len:
            raise FoundationError(
                PASSWORD_TOO_WEAK,
                detail=f"New password must be at least {min_len} characters",
            )

        # --- (4) verify the CURRENT password --------------------------------
        try:
            await oidc.password_grant(username=email, password=current_password)
        except FoundationError as exc:
            if exc.error_code is INVALID_CREDENTIALS:
                raise FoundationError(
                    CURRENT_PASSWORD_INCORRECT,
                    detail="Current password is incorrect",
                ) from exc
            raise

        # --- (5) set the NEW password ---------------------------------------
        await self._kc.reset_password(kc_user_id, new_password, temporary=False)

        # --- (6) audit ------------------------------------------------------
        await self._emit(
            session,
            event_type="foundation.identity.password.changed",
            tenant_id=tenant_id,
            request_id=request_id,
            payload={
                "user_id": user.id,
                "triggered_by": user.id,
                "source": "self_service",
            },
        )
        await session.flush()

    # ------------------------------------------------------------------ helpers
    async def _emit(
        self,
        session: AsyncSession,
        *,
        event_type: str,
        tenant_id: str,
        request_id: str,
        payload: dict[str, Any],
    ) -> None:
        await self._audit.publish(
            session,
            event_type=event_type,
            tenant_id=tenant_id,
            aggregate_id=payload.get("user_id"),
            payload=payload,
            request_id=request_id,
        )

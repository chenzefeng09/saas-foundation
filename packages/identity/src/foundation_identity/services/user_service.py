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
from foundation_identity.domain.models import User
from foundation_identity.errors import (
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

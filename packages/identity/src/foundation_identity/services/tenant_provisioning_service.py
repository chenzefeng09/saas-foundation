"""Tenant provisioning service — idempotent saga orchestration.

Creates a new tenant end-to-end:
  1. Generate tenant_id = tnt_{ULID}
  2. INSERT tenant.tenant row (anchor — idempotent by name or existing id)
  3. Invite first admin user via UserService.invite (KC user + DB user)
  4. Call org POST /org-units to create root org unit
  5. Call billing POST /subscriptions to bind default plan
  6. Call authz bootstrap (create super_admin / tenant_admin / member roles
     + bind admin user to super_admin)

No distributed transactions.  The tenant.tenant row acts as the saga anchor:
  - If a step after step 2 fails, the caller can retry; all downstream steps
    are idempotent or handle duplicate errors gracefully.
  - We do NOT roll back the tenant row on downstream failure — ops can re-run
    provisioning with the same tenant_id to complete the saga.

Idempotency key: tenant_id.  If provision() is called with an existing
tenant_id the tenant row INSERT is skipped (ON CONFLICT DO NOTHING) and all
subsequent steps are re-attempted to heal partial failures.
"""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime
from typing import Any

import httpx
import ulid

from foundation_identity.adapters.audit_publisher import AuditPublisher
from foundation_identity.adapters.keycloak_admin import KeycloakAdminAdapter
from foundation_identity.domain.db import admin_session_scope
from foundation_identity.observability import get_logger
from foundation_identity.services.user_service import UserService

log = get_logger(__name__)

_HTTP_TIMEOUT = 10.0  # seconds


@dataclasses.dataclass(frozen=True, slots=True)
class ProvisionResult:
    tenant_id: str
    admin_user_id: str
    root_ou_id: str | None
    subscription_id: str | None
    steps: list[str]  # names of completed steps


class TenantProvisioningService:
    """Orchestrate multi-service tenant creation."""

    def __init__(
        self,
        *,
        keycloak: KeycloakAdminAdapter,
        audit: AuditPublisher,
        org_url: str,
        billing_url: str,
        authz_url: str,
    ) -> None:
        self._kc = keycloak
        self._audit = audit
        self._org_url = org_url.rstrip("/")
        self._billing_url = billing_url.rstrip("/")
        self._authz_url = authz_url.rstrip("/")

    async def provision(
        self,
        *,
        name: str,
        tier: str = "FREE",
        admin_email: str,
        admin_display_name: str | None = None,
        actor_user_id: str = "PLATFORM",
        tenant_id: str | None = None,
    ) -> dict[str, Any]:
        """Run the full provisioning saga.

        Returns a dict suitable for JSON serialisation with the result of
        each step.
        """
        steps: list[str] = []

        # ── Step 1: generate tenant_id ──────────────────────────────────────
        tid = tenant_id or f"tnt_{ulid.new()!s}"
        log.info("provisioning.start", tenant_id=tid, name=name, tier=tier)

        # ── Step 2: INSERT tenant.tenant (idempotent) ───────────────────────
        async with admin_session_scope(tenant_id="", user_id=actor_user_id) as session:
            from sqlalchemy import text
            # Check if tenant already exists
            existing = (
                await session.execute(
                    text("SELECT id, status FROM tenant.tenant WHERE id = :id"),
                    {"id": tid},
                )
            ).fetchone()

            if existing is None:
                await session.execute(
                    text(
                        "INSERT INTO tenant.tenant "
                        "(id, name, tier, status, created_at, updated_at) "
                        "VALUES (:id, :name, :tier, 'ACTIVE', now(), now()) "
                        "ON CONFLICT (id) DO NOTHING"
                    ),
                    {"id": tid, "name": name, "tier": tier},
                )
                log.info("provisioning.tenant_row_created", tenant_id=tid)
                steps.append("tenant_row_created")
            else:
                log.info("provisioning.tenant_row_exists", tenant_id=tid, status=existing[1])
                steps.append("tenant_row_exists")

        # ── Step 3: create admin user (KC + DB) ─────────────────────────────
        user_service = UserService(keycloak=self._kc, audit=self._audit)
        admin_user_id: str | None = None

        async with admin_session_scope(tenant_id=tid, user_id=actor_user_id) as session:
            from sqlalchemy import select, text as sqla_text
            from foundation_identity.domain.models import User

            # Idempotent: check if admin user already exists for this tenant
            existing_user = (
                await session.execute(
                    sqla_text(
                        "SELECT id FROM identity.user WHERE tenant_id = :tid "
                        "AND email = :email AND deleted_at IS NULL LIMIT 1"
                    ),
                    {"tid": tid, "email": admin_email},
                )
            ).fetchone()

            if existing_user:
                admin_user_id = existing_user[0]
                log.info("provisioning.admin_user_exists", user_id=admin_user_id)
                steps.append("admin_user_exists")
            else:
                try:
                    user = await user_service.invite(
                        session,
                        tenant_id=tid,
                        request_id=f"req_{ulid.new()!s}",
                        actor_id=actor_user_id if actor_user_id.startswith("usr_") else None,
                        email=admin_email,
                        display_name=admin_display_name or admin_email.split("@")[0],
                        roles=["admin"],
                        send_invite_email=True,
                    )
                    admin_user_id = user.id
                    log.info("provisioning.admin_user_created", user_id=admin_user_id)
                    steps.append("admin_user_created")
                except Exception as exc:
                    log.error("provisioning.admin_user_failed", exc=str(exc))
                    # Non-fatal — return partial result so caller can retry
                    return {
                        "tenant_id": tid,
                        "admin_user_id": None,
                        "root_ou_id": None,
                        "subscription_id": None,
                        "steps": steps,
                        "error": f"admin_user_invite failed: {exc}",
                    }

        # ── Step 4: create root org unit ─────────────────────────────────────
        root_ou_id: str | None = None
        try:
            async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
                resp = await client.post(
                    f"{self._org_url}/org-units",
                    json={"name": name, "code": tid.replace("_", ""), "kind": "COMPANY"},
                    headers={
                        "X-Tenant-Id": tid,
                        "X-User-Id": admin_user_id or "PLATFORM",
                    },
                )
            if resp.status_code in (200, 201):
                root_ou_id = resp.json().get("id")
                steps.append("root_ou_created")
                log.info("provisioning.root_ou_created", ou_id=root_ou_id)
            elif resp.status_code == 409:
                # Already exists — extract id from error or re-list
                steps.append("root_ou_exists")
                log.info("provisioning.root_ou_exists")
            else:
                log.warning("provisioning.root_ou_failed", status=resp.status_code, body=resp.text)
                steps.append(f"root_ou_failed:{resp.status_code}")
        except httpx.HTTPError as exc:
            log.warning("provisioning.root_ou_http_error", exc=str(exc))
            steps.append("root_ou_skipped:http_error")

        # ── Step 5: billing subscribe ─────────────────────────────────────────
        subscription_id: str | None = None
        try:
            # Fetch default plan for the tier
            async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
                plans_resp = await client.get(
                    f"{self._billing_url}/plans",
                    headers={"X-Tenant-Id": tid, "X-User-Id": admin_user_id or "PLATFORM"},
                )
            plan_id: str | None = None
            if plans_resp.status_code == 200:
                plans = plans_resp.json().get("items", [])
                # Pick plan matching the tier, or first available
                for p in plans:
                    if p.get("tier", "").upper() == tier.upper():
                        plan_id = p["id"]
                        break
                if not plan_id and plans:
                    plan_id = plans[0]["id"]

            if plan_id:
                async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
                    sub_resp = await client.post(
                        f"{self._billing_url}/subscriptions",
                        json={"plan_id": plan_id, "mode": "private"},
                        headers={"X-Tenant-Id": tid, "X-User-Id": admin_user_id or "PLATFORM"},
                    )
                if sub_resp.status_code in (200, 201):
                    subscription_id = sub_resp.json().get("id")
                    steps.append("subscription_created")
                    log.info("provisioning.subscription_created", sub_id=subscription_id)
                elif sub_resp.status_code == 409:
                    steps.append("subscription_exists")
                else:
                    log.warning(
                        "provisioning.subscription_failed",
                        status=sub_resp.status_code,
                    )
                    steps.append(f"subscription_failed:{sub_resp.status_code}")
            else:
                log.warning("provisioning.no_plan_found", tier=tier)
                steps.append("subscription_skipped:no_plan")
        except httpx.HTTPError as exc:
            log.warning("provisioning.billing_http_error", exc=str(exc))
            steps.append("subscription_skipped:http_error")

        # ── Step 6: authz bootstrap (roles + super_admin binding) ─────────────
        try:
            await self._bootstrap_authz(
                tenant_id=tid,
                admin_user_id=admin_user_id,
                actor_user_id=actor_user_id,
            )
            steps.append("authz_bootstrapped")
        except Exception as exc:
            log.warning("provisioning.authz_bootstrap_failed", exc=str(exc))
            steps.append(f"authz_bootstrap_failed:{exc}")

        log.info("provisioning.done", tenant_id=tid, steps=steps)
        return {
            "tenant_id": tid,
            "admin_user_id": admin_user_id,
            "root_ou_id": root_ou_id,
            "subscription_id": subscription_id,
            "steps": steps,
        }

    async def _bootstrap_authz(
        self,
        *,
        tenant_id: str,
        admin_user_id: str | None,
        actor_user_id: str,
    ) -> None:
        """Create super_admin / tenant_admin / member roles and bind the admin.

        Reuses the same logic as bootstrap_tenant_roles.py but via the DB
        (admin_session_scope) so it is transactional and idempotent.
        """
        from sqlalchemy import text
        from foundation_identity.domain.db import admin_session_scope

        _ROLES = [
            {
                "name": "super_admin",
                "display_name": "Super Admin",
                "description": "Full access to all resources and actions.",
                "permissions": ["*"],
            },
            {
                "name": "tenant_admin",
                "display_name": "Tenant Admin",
                "description": "Manages all platform resources for the tenant.",
                "permissions": [
                    "session.*", "run.*", "sandbox.*", "skill.*",
                    "document.*", "mcp_server.*",
                ],
            },
            {
                "name": "member",
                "display_name": "Member",
                "description": "Standard tenant member with read and run access.",
                "permissions": [
                    "session.read", "session.create", "session.update",
                    "session.message.read", "session.message.create",
                    "session.attachment.read", "session.attachment.create",
                    "run.create", "run.read", "run.cancel",
                    "skill.read", "document.read", "document.search", "mcp_server.read",
                ],
            },
        ]

        def _new_role_id() -> str:
            return f"rol_{ulid.new()!s}"

        def _new_binding_id() -> str:
            return f"rbd_{ulid.new()!s}"

        async with admin_session_scope(tenant_id=tenant_id, user_id=actor_user_id) as session:
            role_ids: dict[str, str] = {}

            for role_def in _ROLES:
                name = role_def["name"]
                existing = (
                    await session.execute(
                        text(
                            "SELECT id FROM authz.role "
                            "WHERE tenant_id = :tid AND name = :name AND deleted_at IS NULL"
                        ),
                        {"tid": tenant_id, "name": name},
                    )
                ).fetchone()

                if existing:
                    role_ids[name] = existing[0]
                    continue

                role_id = _new_role_id()
                role_ids[name] = role_id
                perms = role_def["permissions"]
                perms_literal = "{" + ",".join(perms) + "}"
                await session.execute(
                    text(
                        "INSERT INTO authz.role "
                        "(id, tenant_id, name, display_name, description, "
                        " is_system, immutable, permissions, created_at, updated_at, created_by) "
                        "VALUES "
                        "(:id, :tenant_id, :name, :display_name, :description, "
                        " TRUE, TRUE, :permissions, now(), now(), 'BOOTSTRAP')"
                    ),
                    {
                        "id": role_id,
                        "tenant_id": tenant_id,
                        "name": name,
                        "display_name": role_def["display_name"],
                        "description": role_def["description"],
                        "permissions": perms_literal,
                    },
                )

            # Bind admin_user_id → super_admin (idempotent)
            if admin_user_id:
                super_admin_id = role_ids.get("super_admin")
                if super_admin_id:
                    exists = (
                        await session.execute(
                            text(
                                "SELECT id FROM authz.role_binding "
                                "WHERE tenant_id = :tid AND principal_kind = 'USER' "
                                "  AND principal_id = :uid AND role_id = :rid "
                                "  AND revoked_at IS NULL"
                            ),
                            {"tid": tenant_id, "uid": admin_user_id, "rid": super_admin_id},
                        )
                    ).fetchone()
                    if not exists:
                        await session.execute(
                            text(
                                "INSERT INTO authz.role_binding "
                                "(id, tenant_id, principal_kind, principal_id, role_id, "
                                " scope_kind, scope_id, granted_at, granted_by) "
                                "VALUES "
                                "(:id, :tenant_id, 'USER', :principal_id, :role_id, "
                                " 'TENANT', :scope_id, now(), 'BOOTSTRAP')"
                            ),
                            {
                                "id": _new_binding_id(),
                                "tenant_id": tenant_id,
                                "principal_id": admin_user_id,
                                "role_id": super_admin_id,
                                "scope_id": tenant_id,
                            },
                        )

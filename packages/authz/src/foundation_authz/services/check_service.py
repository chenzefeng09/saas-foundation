"""Core authorization decision service.

Decision algorithm (authz-v1 §4.3):
    1.  Look up permission_definition for `action`.
        - Unknown permission → PERMISSION_UNKNOWN (422) — strict by design.
    2.  Kill switch on permission? → KILL_SWITCH_DENY.
    3.  RBAC: any active binding (not revoked, not expired) granting that
        permission to user, scoped to the resource? If yes AND no policy_required
        flag → RBAC_HIT allow.
    4.  ABAC: if the permission has any of {requires_mfa, requires_4eyes,
        requires_pam_jit, requires_business_hours} → call OPA with full input.
    5.  Otherwise → DEFAULT_DENY.

Performance: RBAC step targets <2ms (Postgres partial index + Redis lookahead).
OPA call adds ~5ms in same-pod sidecar. Total budget: P99 < 15ms.
"""

from __future__ import annotations

import time
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_authz.adapters.opa_client import OpaClient
from foundation_authz.domain.models import (
    PermissionDefinition,
    Role,
    RoleBinding,
    RoleInherit,
)
from foundation_authz.errors import PERMISSION_UNKNOWN, FoundationError
from foundation_authz.observability import get_logger
from foundation_authz.schemas.check import CheckResponse, ListAccessibleIdsResponse

log = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class _EffectiveRole:
    role_id: str
    role_name: str
    scope_kind: str
    scope_id: str | None
    permissions: tuple[str, ...]


class CheckService:
    def __init__(self, opa: OpaClient) -> None:
        self._opa = opa

    # ------------------------------------------------------------------ public
    async def check(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        user_id: str,
        action: str,
        resource_type: str,
        resource_id: str | None,
        context: dict[str, Any],
    ) -> CheckResponse:
        started = time.perf_counter()

        # 1. permission definition
        perm = await session.get(PermissionDefinition, action)
        if perm is None:
            raise FoundationError(PERMISSION_UNKNOWN, extra={"action": action})

        # 2. RBAC step
        roles = await self._load_effective_roles(
            session, tenant_id=tenant_id, principal_id=user_id, principal_kind="USER"
        )
        matched = self._rbac_match(
            roles, action=action, resource_type=resource_type, resource_id=resource_id
        )

        # 3. If policy_required → ABAC (OPA) regardless of RBAC result
        if _policy_required(perm):
            opa_input = {
                "user": {"id": user_id, "tenant_id": tenant_id},
                "action": action,
                "resource": {
                    "type": resource_type,
                    "id": resource_id,
                },
                "permission_definition": {
                    "requires_mfa": perm.requires_mfa,
                    "requires_4eyes": perm.requires_4eyes,
                    "requires_pam_jit": perm.requires_pam_jit,
                    "requires_business_hours": perm.requires_business_hours,
                    "risk_level": perm.risk_level,
                },
                "request": context,
                "user_roles": [r.role_name for r in roles],
            }
            decision = await self._opa.evaluate(opa_input)
            latency = (time.perf_counter() - started) * 1000
            return CheckResponse(
                allowed=decision.allow and matched is not None,
                decision_path="OPA_HIT",
                matched_role=matched.role_name if matched else None,
                matched_policy=decision.matched_policy,
                deny_reason=(
                    None
                    if (decision.allow and matched)
                    else (decision.deny_reason or "rbac_or_opa")
                ),
                latency_ms=round(latency, 2),
            )

        # 4. RBAC alone is authoritative
        latency = (time.perf_counter() - started) * 1000
        if matched is not None:
            return CheckResponse(
                allowed=True,
                decision_path="RBAC_HIT",
                matched_role=matched.role_name,
                latency_ms=round(latency, 2),
            )
        return CheckResponse(
            allowed=False,
            decision_path="DEFAULT_DENY",
            deny_reason="no_matching_binding",
            latency_ms=round(latency, 2),
        )

    # ------------------------------------------------------------------ public (list)
    async def list_accessible_ids(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        user_id: str,
        resource_type: str,
        action: str,
        max: int,
    ) -> ListAccessibleIdsResponse:
        """Return the set of scope_ids the user can perform *action* on.

        Algorithm (pure RBAC, no OPA):
          1. Load all effective bindings for the user in this tenant.
          2. For each binding whose permissions include *action* (exact or wildcard):
             - TENANT / GLOBAL_SYSTEM scope → user has access to ALL resources;
               return immediately with all_in_tenant=True, ids=[], complete=True.
             - TEAM / ORG_UNIT / RESOURCE scope → collect scope_id into the result set.
          3. Truncate to *max* entries; if truncated set complete=False.

        Note: resource_type is accepted for forward-compatibility (future: scope walk
        by resource type).  The current RBAC model does not index bindings by
        resource_type, so we return all matching scope_ids regardless of resource_type
        and let the caller apply additional filtering if needed.
        """
        roles = await self._load_effective_roles(
            session, tenant_id=tenant_id, principal_id=user_id, principal_kind="USER"
        )

        scope_ids: set[str] = set()

        for r in roles:
            # Permission check: exact or wildcard
            if action not in r.permissions and not _wildcard_match(r.permissions, action):
                continue

            # Wide scopes → tenant-level access, no need to enumerate IDs
            if r.scope_kind in ("TENANT", "GLOBAL_SYSTEM"):
                return ListAccessibleIdsResponse(
                    ids=[],
                    complete=True,
                    all_in_tenant=True,
                )

            # Narrow scopes → collect specific scope_id
            if r.scope_id is not None:
                scope_ids.add(r.scope_id)

        # Truncate if we exceed the requested max
        ids_list = list(scope_ids)
        if len(ids_list) > max:
            return ListAccessibleIdsResponse(
                ids=ids_list[:max],
                complete=False,
                all_in_tenant=False,
            )

        return ListAccessibleIdsResponse(
            ids=ids_list,
            complete=True,
            all_in_tenant=False,
        )

    # ------------------------------------------------------------------ helpers
    async def _load_effective_roles(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        principal_id: str,
        principal_kind: str,
    ) -> list[_EffectiveRole]:
        # Active bindings (not revoked, not expired)
        stmt = (
            select(RoleBinding, Role)
            .join(Role, RoleBinding.role_id == Role.id)
            .where(
                RoleBinding.tenant_id == tenant_id,
                RoleBinding.principal_kind == principal_kind,
                RoleBinding.principal_id == principal_id,
                RoleBinding.revoked_at.is_(None),
                Role.deleted_at.is_(None),
            )
        )
        rows = (await session.execute(stmt)).all()
        out: list[_EffectiveRole] = []
        now_ts = time.time()
        for b, r in rows:
            if b.expires_at is not None and b.expires_at.timestamp() < now_ts:
                continue
            out.append(
                _EffectiveRole(
                    role_id=r.id,
                    role_name=r.name,
                    scope_kind=b.scope_kind,
                    scope_id=b.scope_id,
                    permissions=tuple(r.permissions or ()),
                )
            )
        return await self._expand_inherited_permissions(
            session,
            tenant_id=tenant_id,
            roles=out,
        )

    async def _expand_inherited_permissions(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        roles: list[_EffectiveRole],
    ) -> list[_EffectiveRole]:
        if not roles:
            return roles

        permissions_by_role = {
            role.role_id: set(role.permissions)
            for role in roles
        }
        pending_by_origin = {
            role.role_id: {role.role_id}
            for role in roles
        }
        visited_by_origin = {
            role.role_id: {role.role_id}
            for role in roles
        }

        while True:
            child_role_ids = {
                child_role_id
                for pending in pending_by_origin.values()
                for child_role_id in pending
            }
            if not child_role_ids:
                break

            stmt = (
                select(RoleInherit.child_role_id, Role)
                .join(Role, RoleInherit.parent_role_id == Role.id)
                .where(
                    RoleInherit.tenant_id == tenant_id,
                    RoleInherit.child_role_id.in_(child_role_ids),
                    Role.tenant_id == tenant_id,
                    Role.deleted_at.is_(None),
                )
            )
            rows = (await session.execute(stmt)).all()
            if not rows:
                break

            next_pending: dict[str, set[str]] = {
                origin_role_id: set()
                for origin_role_id in pending_by_origin
            }

            for child_role_id, parent_role in rows:
                for origin_role_id, pending in pending_by_origin.items():
                    if child_role_id not in pending:
                        continue
                    if parent_role.id in visited_by_origin[origin_role_id]:
                        continue

                    permissions_by_role[origin_role_id].update(
                        parent_role.permissions or ()
                    )
                    visited_by_origin[origin_role_id].add(parent_role.id)
                    next_pending[origin_role_id].add(parent_role.id)

            pending_by_origin = next_pending

        return [
            _EffectiveRole(
                role_id=role.role_id,
                role_name=role.role_name,
                scope_kind=role.scope_kind,
                scope_id=role.scope_id,
                permissions=tuple(permissions_by_role[role.role_id]),
            )
            for role in roles
        ]

    # ------------------------------------------------------------------ public (grant)
    async def effective_permissions(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        user_id: str,
    ) -> set[str]:
        """Flatten a principal's effective permission tokens (inheritance expanded).

        Reuses the same binding-load + inheritance-expansion path as ``check()`` so
        the permission set used for grant/escalation decisions never drifts from the
        set used for the live authorization decision.  Returns the union of every
        permission token across all of the user's active, in-tenant role bindings.
        """
        roles = await self._load_effective_roles(
            session, tenant_id=tenant_id, principal_id=user_id, principal_kind="USER"
        )
        perms: set[str] = set()
        for r in roles:
            perms.update(r.permissions)
        return perms

    async def role_permission_closure(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        role: Role,
    ) -> set[str]:
        """All permission tokens a *role* effectively grants (inheritance expanded).

        Used by BindingService to decide whether the actor is entitled to bind a
        principal to ``role``: binding a user to a role grants that user the role's
        full permission closure, so the grant must clear the same anti-escalation
        bar as creating a role with those permissions.  Reuses the inheritance
        walk (``_expand_inherited_permissions``) so role-closure and live-decision
        semantics never drift.
        """
        synthetic = _EffectiveRole(
            role_id=role.id,
            role_name=role.name,
            scope_kind="TENANT",
            scope_id=None,
            permissions=tuple(role.permissions or ()),
        )
        expanded = await self._expand_inherited_permissions(
            session, tenant_id=tenant_id, roles=[synthetic]
        )
        perms: set[str] = set()
        for r in expanded:
            perms.update(r.permissions)
        return perms

    @staticmethod
    def _rbac_match(
        roles: Iterable[_EffectiveRole],
        *,
        action: str,
        resource_type: str,
        resource_id: str | None,
    ) -> _EffectiveRole | None:
        for r in roles:
            # Permission grant check
            if action not in r.permissions and not _wildcard_match(r.permissions, action):
                continue
            # Scope check (RESOURCE-scoped binding must match resource_id)
            if r.scope_kind == "RESOURCE" and r.scope_id != resource_id:
                continue
            return r
        return None


def _policy_required(perm: PermissionDefinition) -> bool:
    return any(
        (
            perm.requires_mfa,
            perm.requires_4eyes,
            perm.requires_pam_jit,
            perm.requires_business_hours,
        )
    )


def _wildcard_match(permissions: Iterable[str], action: str) -> bool:
    """Wildcard support: `billing.invoice.*` matches `billing.invoice.read`.
    `billing.*` matches `billing.invoice.read`. `*` matches all.
    """
    parts = action.split(".")
    for p in permissions:
        if p == "*":
            return True
        if not p.endswith(".*"):
            continue
        # A bare single-segment action (no ".") is not a leaf of any dotted
        # namespace, so a holder like ``session.*`` must NOT match a request for
        # ``session``.  Without this guard ``session.*`` would match ``session``
        # (parts == ["session"] == prefix), drifting from ``covers`` semantics.
        if "." not in action:
            continue
        prefix = p[:-2].split(".")
        if parts[: len(prefix)] == prefix:
            return True
    return False


# ---------------------------------------------------------------------------
# Grant semantics (anti-escalation)
#
# These mirror the dot-segment semantics of ``_wildcard_match`` so that the rule
# "can I *grant* permission X?" never drifts from "does holding X *satisfy* a
# check?".  Used by RoleService / BindingService to reject privilege escalation.
# ---------------------------------------------------------------------------

def covers(holder: str, requested: str) -> bool:
    """True if a principal holding ``holder`` is entitled to grant ``requested``.

    Mirrors ``_wildcard_match`` dot-segment semantics:
      * ``*``               covers everything.
      * exact equality      covers itself.
      * ``foo.*`` covers any token whose leading segments equal ``[foo]`` — and,
        critically, a *requested* token that itself ends in ``.*`` is reduced to
        its core (``foo.bar.*`` → ``foo.bar``) before comparison so that a holder
        of ``foo.*`` may delegate ``foo.bar.*`` but NOT the broader ``foo.*``
        unless they hold exactly that (handled by the equality branch above).
    """
    if holder == "*":
        return True
    if holder == requested:
        return True
    if holder.endswith(".*"):
        prefix = holder[:-2].split(".")
        req_core = requested[:-2] if requested.endswith(".*") else requested
        # A bare single-segment token (no ".", e.g. "session") is not a child of
        # any dotted namespace, so a holder of ``session.*`` must NOT be treated
        # as covering the standalone token ``session``.  (Exact equality and the
        # ``*`` holder are handled above, so this only rejects the genuine
        # single-segment-leaf case.)  Mirrors the ``_wildcard_match`` guard so
        # grant- and check-side semantics never drift.
        if "." not in req_core:
            return False
        return req_core.split(".")[: len(prefix)] == prefix
    return False


def is_grantable(requested: str, actor_perms: set[str]) -> bool:
    """True if ``actor_perms`` is allowed to grant the single token ``requested``.

    Two rules:
      1. Management non-delegation: ``authz.*`` permissions can only be granted by
         a holder of the unrestricted ``*`` wildcard.  Nobody else — not even a
         tenant_admin holding ``authz.role.manage`` — may grant any ``authz.``
         token.  This stops an admin from minting roles/bindings that expand the
         pool of principals who can themselves manage RBAC.
      2. Otherwise the actor must hold some permission that ``covers`` the request
         (fail-closed: empty ``actor_perms`` grants nothing).
    """
    if requested.lower().startswith("authz.") and "*" not in actor_perms:
        return False
    return any(covers(h, requested) for h in actor_perms)

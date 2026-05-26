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
)
from foundation_authz.errors import PERMISSION_UNKNOWN, FoundationError
from foundation_authz.observability import get_logger
from foundation_authz.schemas.check import CheckResponse

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
                deny_reason=None if (decision.allow and matched) else (decision.deny_reason or "rbac_or_opa"),
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
        # TODO(M2): walk role_inherit DAG to expand permissions.
        return out

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
        prefix = p[:-2].split(".")
        if parts[: len(prefix)] == prefix:
            return True
    return False

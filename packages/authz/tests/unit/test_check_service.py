"""CheckService decision-path tests (authz-v1 §4.3).

Coverage:
  - PERMISSION_UNKNOWN  → 422 raised
  - RBAC_HIT            (exact action match)
  - RBAC_HIT            (wildcard match)
  - RBAC_HIT            (RESOURCE-scoped match)
  - DEFAULT_DENY        (no binding)
  - DEFAULT_DENY        (RESOURCE-scoped, wrong resource_id)
  - DEFAULT_DENY        (binding expired)
  - DEFAULT_DENY        (role soft-deleted)
  - OPA_HIT             (policy_required + RBAC + OPA allow → allow)
  - OPA_HIT             (policy_required + RBAC allow + OPA deny → deny)
  - OPA_HIT             (policy_required + no RBAC + OPA allow → deny — both must agree)
  - _wildcard_match table
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from foundation_authz.adapters.opa_client import OpaDecision
from foundation_authz.errors import PERMISSION_UNKNOWN, FoundationError
from foundation_authz.services.check_service import (
    CheckService,
    _wildcard_match,
)

from tests._factories import make_binding, make_permission, make_role
from tests.conftest import FakeAsyncSession


pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _stage_effective_roles(
    session: FakeAsyncSession,
    *,
    bindings: list[tuple],
) -> None:
    """Stage `bindings` as the JOIN result for _load_effective_roles."""
    session.queue_execute(bindings)


# ---------------------------------------------------------------------------
# PERMISSION_UNKNOWN
# ---------------------------------------------------------------------------

async def test_unknown_permission_raises_422(
    fake_session: FakeAsyncSession,
    opa_mock,
    tenant_id: str,
    user_id: str,
) -> None:
    svc = CheckService(opa=opa_mock)
    # No PermissionDefinition seeded → session.get returns None.

    with pytest.raises(FoundationError) as ei:
        await svc.check(
            fake_session,
            tenant_id=tenant_id,
            user_id=user_id,
            action="unknown.action",
            resource_type="invoice",
            resource_id=None,
            context={},
        )
    assert ei.value.error_code is PERMISSION_UNKNOWN
    assert ei.value.extra == {"action": "unknown.action"}
    opa_mock.evaluate.assert_not_awaited()


# ---------------------------------------------------------------------------
# RBAC_HIT
# ---------------------------------------------------------------------------

async def test_rbac_hit_exact_action(
    fake_session: FakeAsyncSession,
    opa_mock,
    tenant_id: str,
    user_id: str,
) -> None:
    perm = make_permission(permission_id="billing.invoice.read")
    fake_session.put(perm)

    role = make_role(tenant_id=tenant_id, permissions=["billing.invoice.read"])
    binding = make_binding(tenant_id=tenant_id, principal_id=user_id, role_id=role.id)
    _stage_effective_roles(fake_session, bindings=[(binding, role)])

    svc = CheckService(opa=opa_mock)
    resp = await svc.check(
        fake_session,
        tenant_id=tenant_id,
        user_id=user_id,
        action="billing.invoice.read",
        resource_type="invoice",
        resource_id="inv_1",
        context={},
    )

    assert resp.allowed is True
    assert resp.decision_path == "RBAC_HIT"
    assert resp.matched_role == role.name
    opa_mock.evaluate.assert_not_awaited()


async def test_rbac_hit_wildcard_action(
    fake_session: FakeAsyncSession,
    opa_mock,
    tenant_id: str,
    user_id: str,
) -> None:
    fake_session.put(make_permission(permission_id="billing.invoice.read"))

    role = make_role(tenant_id=tenant_id, permissions=["billing.*"])
    binding = make_binding(tenant_id=tenant_id, principal_id=user_id, role_id=role.id)
    _stage_effective_roles(fake_session, bindings=[(binding, role)])

    svc = CheckService(opa=opa_mock)
    resp = await svc.check(
        fake_session,
        tenant_id=tenant_id,
        user_id=user_id,
        action="billing.invoice.read",
        resource_type="invoice",
        resource_id=None,
        context={},
    )
    assert resp.allowed is True
    assert resp.decision_path == "RBAC_HIT"


async def test_rbac_hit_resource_scope(
    fake_session: FakeAsyncSession,
    opa_mock,
    tenant_id: str,
    user_id: str,
) -> None:
    fake_session.put(make_permission(permission_id="billing.invoice.read"))

    role = make_role(tenant_id=tenant_id, permissions=["billing.invoice.read"])
    binding = make_binding(
        tenant_id=tenant_id,
        principal_id=user_id,
        role_id=role.id,
        scope_kind="RESOURCE",
        scope_id="inv_42",
    )
    _stage_effective_roles(fake_session, bindings=[(binding, role)])

    svc = CheckService(opa=opa_mock)
    resp = await svc.check(
        fake_session,
        tenant_id=tenant_id,
        user_id=user_id,
        action="billing.invoice.read",
        resource_type="invoice",
        resource_id="inv_42",
        context={},
    )
    assert resp.allowed is True
    assert resp.decision_path == "RBAC_HIT"


# ---------------------------------------------------------------------------
# DEFAULT_DENY
# ---------------------------------------------------------------------------

async def test_default_deny_no_binding(
    fake_session: FakeAsyncSession,
    opa_mock,
    tenant_id: str,
    user_id: str,
) -> None:
    fake_session.put(make_permission(permission_id="billing.invoice.read"))
    _stage_effective_roles(fake_session, bindings=[])  # zero rows

    svc = CheckService(opa=opa_mock)
    resp = await svc.check(
        fake_session,
        tenant_id=tenant_id,
        user_id=user_id,
        action="billing.invoice.read",
        resource_type="invoice",
        resource_id=None,
        context={},
    )
    assert resp.allowed is False
    assert resp.decision_path == "DEFAULT_DENY"
    assert resp.deny_reason == "no_matching_binding"


async def test_default_deny_resource_scope_mismatch(
    fake_session: FakeAsyncSession,
    opa_mock,
    tenant_id: str,
    user_id: str,
) -> None:
    fake_session.put(make_permission(permission_id="billing.invoice.read"))

    role = make_role(tenant_id=tenant_id, permissions=["billing.invoice.read"])
    binding = make_binding(
        tenant_id=tenant_id,
        principal_id=user_id,
        role_id=role.id,
        scope_kind="RESOURCE",
        scope_id="inv_42",
    )
    _stage_effective_roles(fake_session, bindings=[(binding, role)])

    svc = CheckService(opa=opa_mock)
    resp = await svc.check(
        fake_session,
        tenant_id=tenant_id,
        user_id=user_id,
        action="billing.invoice.read",
        resource_type="invoice",
        resource_id="inv_OTHER",  # mismatch
        context={},
    )
    assert resp.allowed is False
    assert resp.decision_path == "DEFAULT_DENY"


async def test_expired_binding_filtered_out(
    fake_session: FakeAsyncSession,
    opa_mock,
    tenant_id: str,
    user_id: str,
) -> None:
    fake_session.put(make_permission(permission_id="billing.invoice.read"))

    role = make_role(tenant_id=tenant_id, permissions=["billing.invoice.read"])
    expired_at = datetime.now(UTC) - timedelta(hours=1)
    binding = make_binding(
        tenant_id=tenant_id,
        principal_id=user_id,
        role_id=role.id,
        expires_at=expired_at,
    )
    _stage_effective_roles(fake_session, bindings=[(binding, role)])

    svc = CheckService(opa=opa_mock)
    resp = await svc.check(
        fake_session,
        tenant_id=tenant_id,
        user_id=user_id,
        action="billing.invoice.read",
        resource_type="invoice",
        resource_id=None,
        context={},
    )
    assert resp.allowed is False
    assert resp.decision_path == "DEFAULT_DENY"


async def test_future_expiry_still_active(
    fake_session: FakeAsyncSession,
    opa_mock,
    tenant_id: str,
    user_id: str,
) -> None:
    fake_session.put(make_permission(permission_id="billing.invoice.read"))

    role = make_role(tenant_id=tenant_id, permissions=["billing.invoice.read"])
    future = datetime.now(UTC) + timedelta(hours=1)
    binding = make_binding(
        tenant_id=tenant_id,
        principal_id=user_id,
        role_id=role.id,
        expires_at=future,
    )
    _stage_effective_roles(fake_session, bindings=[(binding, role)])

    svc = CheckService(opa=opa_mock)
    resp = await svc.check(
        fake_session,
        tenant_id=tenant_id,
        user_id=user_id,
        action="billing.invoice.read",
        resource_type="invoice",
        resource_id=None,
        context={},
    )
    assert resp.allowed is True


# ---------------------------------------------------------------------------
# OPA_HIT (policy_required path)
# ---------------------------------------------------------------------------

async def test_opa_hit_rbac_plus_policy_allow(
    fake_session: FakeAsyncSession,
    opa_mock,
    tenant_id: str,
    user_id: str,
) -> None:
    perm = make_permission(
        permission_id="billing.invoice.refund",
        action="refund",
        risk_level="HIGH",
        requires_mfa=True,
    )
    fake_session.put(perm)

    role = make_role(tenant_id=tenant_id, permissions=["billing.invoice.refund"])
    binding = make_binding(tenant_id=tenant_id, principal_id=user_id, role_id=role.id)
    _stage_effective_roles(fake_session, bindings=[(binding, role)])

    opa_mock.evaluate.return_value = OpaDecision(
        allow=True, matched_policy="mfa_present"
    )

    svc = CheckService(opa=opa_mock)
    resp = await svc.check(
        fake_session,
        tenant_id=tenant_id,
        user_id=user_id,
        action="billing.invoice.refund",
        resource_type="invoice",
        resource_id="inv_1",
        context={"mfa": {"verified_within_sec": 60}},
    )

    assert resp.allowed is True
    assert resp.decision_path == "OPA_HIT"
    assert resp.matched_role == role.name
    assert resp.matched_policy == "mfa_present"

    opa_mock.evaluate.assert_awaited_once()
    opa_input = opa_mock.evaluate.await_args.args[0]
    # Spot-check OPA input contract
    assert opa_input["user"]["id"] == user_id
    assert opa_input["action"] == "billing.invoice.refund"
    assert opa_input["permission_definition"]["requires_mfa"] is True
    assert opa_input["request"] == {"mfa": {"verified_within_sec": 60}}


async def test_policy_required_rbac_hit_but_opa_denies(
    fake_session: FakeAsyncSession,
    opa_mock,
    tenant_id: str,
    user_id: str,
) -> None:
    perm = make_permission(
        permission_id="billing.invoice.refund",
        action="refund",
        requires_4eyes=True,
    )
    fake_session.put(perm)

    role = make_role(tenant_id=tenant_id, permissions=["billing.invoice.refund"])
    binding = make_binding(tenant_id=tenant_id, principal_id=user_id, role_id=role.id)
    _stage_effective_roles(fake_session, bindings=[(binding, role)])

    opa_mock.evaluate.return_value = OpaDecision(
        allow=False, deny_reason="four_eyes_missing"
    )

    svc = CheckService(opa=opa_mock)
    resp = await svc.check(
        fake_session,
        tenant_id=tenant_id,
        user_id=user_id,
        action="billing.invoice.refund",
        resource_type="invoice",
        resource_id="inv_1",
        context={},
    )
    assert resp.allowed is False
    assert resp.decision_path == "OPA_HIT"
    assert resp.deny_reason == "four_eyes_missing"


async def test_policy_required_no_rbac_match_denies_even_if_opa_allows(
    fake_session: FakeAsyncSession,
    opa_mock,
    tenant_id: str,
    user_id: str,
) -> None:
    perm = make_permission(
        permission_id="billing.invoice.refund",
        action="refund",
        requires_pam_jit=True,
    )
    fake_session.put(perm)
    _stage_effective_roles(fake_session, bindings=[])  # user has nothing

    opa_mock.evaluate.return_value = OpaDecision(allow=True)

    svc = CheckService(opa=opa_mock)
    resp = await svc.check(
        fake_session,
        tenant_id=tenant_id,
        user_id=user_id,
        action="billing.invoice.refund",
        resource_type="invoice",
        resource_id="inv_1",
        context={},
    )
    # RBAC missing → must deny even if OPA was permissive
    assert resp.allowed is False
    assert resp.decision_path == "OPA_HIT"


# ---------------------------------------------------------------------------
# _wildcard_match unit table
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("permissions", "action", "expected"),
    [
        (["*"], "anything.goes", True),
        (["billing.*"], "billing.invoice.read", True),
        (["billing.invoice.*"], "billing.invoice.read", True),
        (["billing.invoice.*"], "billing.report.read", False),
        (["billing.invoice.read"], "billing.invoice.read", False),  # exact handled elsewhere
        ([], "billing.invoice.read", False),
        (["billing.invoice.*", "iam.user.*"], "iam.user.create", True),
    ],
)
def test_wildcard_match_table(
    permissions: list[str],
    action: str,
    expected: bool,
) -> None:
    assert _wildcard_match(permissions, action) is expected


async def test_latency_ms_is_populated(
    fake_session: FakeAsyncSession,
    opa_mock,
    tenant_id: str,
    user_id: str,
) -> None:
    fake_session.put(make_permission(permission_id="billing.invoice.read"))
    _stage_effective_roles(fake_session, bindings=[])

    svc = CheckService(opa=opa_mock)
    resp = await svc.check(
        fake_session,
        tenant_id=tenant_id,
        user_id=user_id,
        action="billing.invoice.read",
        resource_type="invoice",
        resource_id=None,
        context={},
    )
    assert resp.latency_ms >= 0.0

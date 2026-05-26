# opa test 入口；CI 会跑 `opa test config/opa/policies/`
# 详见 docs/design/authz-v1.md §10.2

package foundation.authz

import future.keywords.if
import future.keywords.in

test_kill_switch_hard_deny if {
    deny with input as {"policy_id": "billing.invoice.void"}
              with data as {"kill_switch": {"billing.invoice.void": true}}
}

test_no_grant_denies if {
    not allow with input as {
        "policy_id": "identity.user.read",
        "action": "identity.user.read",
        "user": {"tenant_id": "tnt_a", "role_grants": []},
        "resource": {"tenant_id": "tnt_a"},
        "tenant": {"compliance_modes": ["pipl"], "data_residency": "cn-only"},
        "request": {"mfa_satisfied": true, "country": "CN", "destination_country": "CN"},
        "permission_definition": {"risk_level": "LOW"},
        "now": "2026-05-22T10:00:00Z"
    }
}

test_tenant_grant_allows_same_tenant_resource if {
    allow with input as {
        "policy_id": "identity.user.read",
        "action": "identity.user.read",
        "user": {
            "tenant_id": "tnt_a",
            "role_grants": [
                {"permission": "identity.user.read",
                 "scope": {"kind": "TENANT", "id": "tnt_a"}}
            ]
        },
        "resource": {"tenant_id": "tnt_a"},
        "tenant": {"compliance_modes": ["pipl"], "data_residency": "cn-only"},
        "request": {"mfa_satisfied": true, "country": "CN", "destination_country": "CN"},
        "permission_definition": {"risk_level": "LOW"},
        "now": "2026-05-22T10:00:00Z"
    }
}

test_cross_tenant_denies if {
    not allow with input as {
        "policy_id": "identity.user.read",
        "action": "identity.user.read",
        "user": {
            "tenant_id": "tnt_a",
            "role_grants": [
                {"permission": "identity.user.read",
                 "scope": {"kind": "TENANT", "id": "tnt_a"}}
            ]
        },
        "resource": {"tenant_id": "tnt_b"},
        "tenant": {"compliance_modes": ["pipl"], "data_residency": "cn-only"},
        "request": {"mfa_satisfied": true, "country": "CN", "destination_country": "CN"},
        "permission_definition": {"risk_level": "LOW"},
        "now": "2026-05-22T10:00:00Z"
    }
}

test_mfa_required_but_missing_denies if {
    not allow with input as {
        "policy_id": "identity.user.freeze",
        "action": "identity.user.freeze",
        "user": {
            "tenant_id": "tnt_a",
            "role_grants": [
                {"permission": "identity.user.freeze",
                 "scope": {"kind": "TENANT", "id": "tnt_a"}}
            ]
        },
        "resource": {"tenant_id": "tnt_a"},
        "tenant": {"compliance_modes": ["pipl"], "data_residency": "cn-only"},
        "request": {"mfa_satisfied": false, "country": "CN", "destination_country": "CN"},
        "permission_definition": {"risk_level": "HIGH", "requires_mfa": true},
        "now": "2026-05-22T10:00:00Z"
    }
}

test_pipl_cross_border_export_denies if {
    not allow with input as {
        "policy_id": "data.export",
        "action": "data.export",
        "user": {
            "tenant_id": "tnt_a",
            "role_grants": [
                {"permission": "data.export",
                 "scope": {"kind": "TENANT", "id": "tnt_a"}}
            ]
        },
        "resource": {"tenant_id": "tnt_a"},
        "tenant": {"compliance_modes": ["pipl"], "data_residency": "cn-only"},
        "request": {"mfa_satisfied": true, "country": "CN", "destination_country": "US"},
        "permission_definition": {"risk_level": "HIGH", "requires_mfa": true},
        "now": "2026-05-22T10:00:00Z"
    }
}

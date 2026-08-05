# opa test 入口；CI 会跑 `opa test config/opa/policies/`
# 详见 docs/design/authz-v1.md §10.2

package foundation.authz

import future.keywords.if
import future.keywords.in

test_kill_switch_hard_deny if {
    deny with input as {"policy_id": "billing.invoice.void"}
         with data.foundation.authz.kill_switch_meta.permissions as {
             "billing.invoice.void": true
         }
}

test_no_grant_denies if {
    not allow with input as {
        "policy_id": "identity.user.read",
        "action": "identity.user.read",
        "user": {"tenant_id": "tnt_a", "clearance": "L3", "role_grants": []},
        "resource": {"tenant_id": "tnt_a", "sensitivity": "L2"},
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
            "clearance": "L3",
            "role_grants": [
                {"permission": "identity.user.read",
                 "scope": {"kind": "TENANT", "id": "tnt_a"}}
            ]
        },
        "resource": {"tenant_id": "tnt_a", "sensitivity": "L2"},
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
            "clearance": "L3",
            "role_grants": [
                {"permission": "identity.user.read",
                 "scope": {"kind": "TENANT", "id": "tnt_a"}}
            ]
        },
        "resource": {"tenant_id": "tnt_b", "sensitivity": "L2"},
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
            "clearance": "L3",
            "role_grants": [
                {"permission": "identity.user.freeze",
                 "scope": {"kind": "TENANT", "id": "tnt_a"}}
            ]
        },
        "resource": {"tenant_id": "tnt_a", "sensitivity": "L2"},
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
            "clearance": "L3",
            "role_grants": [
                {"permission": "data.export",
                 "scope": {"kind": "TENANT", "id": "tnt_a"}}
            ]
        },
        "resource": {"tenant_id": "tnt_a", "sensitivity": "L2"},
        "tenant": {"compliance_modes": ["pipl"], "data_residency": "cn-only"},
        "request": {"mfa_satisfied": true, "country": "CN", "destination_country": "US"},
        "permission_definition": {"risk_level": "HIGH", "requires_mfa": true},
        "now": "2026-05-22T10:00:00Z"
    }
}

test_clearance_below_sensitivity_denies if {
    not allow with input as {
        "policy_id": "document.read",
        "action": "document.read",
        "user": {"tenant_id": "tnt_a", "clearance": "L3"},
        "resource": {"tenant_id": "tnt_a", "sensitivity": "L4"},
        "rbac": {"matched": true},
        "tenant": {"compliance_modes": []},
        "request": {},
        "permission_definition": {"risk_level": "LOW"}
    }
}

test_equal_clearance_and_sensitivity_allows if {
    allow with input as {
        "policy_id": "document.read",
        "action": "document.read",
        "user": {"tenant_id": "tnt_a", "clearance": "L4"},
        "resource": {"tenant_id": "tnt_a", "sensitivity": "L4"},
        "rbac": {"matched": true},
        "tenant": {"compliance_modes": []},
        "request": {},
        "permission_definition": {"risk_level": "LOW"}
    }
}

test_unknown_clearance_label_denies if {
    not allow with input as {
        "policy_id": "document.read",
        "action": "document.read",
        "user": {"tenant_id": "tnt_a", "clearance": "L10"},
        "resource": {"tenant_id": "tnt_a", "sensitivity": "L5"},
        "rbac": {"matched": true},
        "tenant": {"compliance_modes": []},
        "request": {},
        "permission_definition": {"risk_level": "LOW"}
    }
}

test_four_eyes_required_but_missing_denies if {
    not allow with input as {
        "policy_id": "billing.subscription.cancel",
        "action": "billing.subscription.cancel",
        "user": {"tenant_id": "tnt_a", "clearance": "L4"},
        "resource": {"tenant_id": "tnt_a", "sensitivity": "L3"},
        "rbac": {"matched": true},
        "tenant": {"compliance_modes": []},
        "request": {"four_eyes_satisfied": false},
        "permission_definition": {"risk_level": "CRITICAL", "requires_4eyes": true}
    }
}

test_pam_required_but_missing_denies if {
    not allow with input as {
        "policy_id": "admin.secret.rotate",
        "action": "admin.secret.rotate",
        "user": {"tenant_id": "tnt_a", "clearance": "L5"},
        "resource": {"tenant_id": "tnt_a", "sensitivity": "L5"},
        "rbac": {"matched": true},
        "tenant": {"compliance_modes": []},
        "request": {"pam_elevated": false},
        "permission_definition": {"risk_level": "HIGH", "requires_pam_jit": true}
    }
}

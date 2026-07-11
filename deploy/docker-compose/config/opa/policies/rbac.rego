# rbac.rego —— RBAC 决策
# input.user.role_grants 是 SDK 从 authz.role_binding 查出的当前用户在当前租户的有效授权

package foundation.authz.rbac

import future.keywords.if
import future.keywords.in

default allow := false
default deny_reason := "rbac.permission_not_granted"

# The authz service computes this bit from its database-backed effective-role
# walk.  It is not accepted from the public check request body.
allow if {
    input.rbac.matched == true
}

# Legacy/full-bundle input remains supported for policy tests and direct OPA
# evaluation tools.
allow if {
    some grant in input.user.role_grants
    grant.permission == input.action
    scope_matches(grant.scope, input.resource)
}

# scope 匹配 ─────────────────────────────────
scope_matches(scope, resource) if {
    scope.kind == "GLOBAL_SYSTEM"
}

scope_matches(scope, resource) if {
    scope.kind == "TENANT"
    scope.id == resource.tenant_id
}

scope_matches(scope, resource) if {
    scope.kind == "ORG_UNIT"
    # 资源所在 OU path 必须以 grant 的 OU path 为前缀
    startswith(resource.org_unit_path, scope.path)
}

scope_matches(scope, resource) if {
    scope.kind == "TEAM"
    scope.id == resource.team_id
}

scope_matches(scope, resource) if {
    scope.kind == "RESOURCE"
    scope.id == resource.id
}

# 跨租户访问硬拒（兜底；正常 RBAC 不应放跨租户 grant，但防漏）
deny_reason := "rbac.tenant_mismatch" if {
    input.user.tenant_id != input.resource.tenant_id
}

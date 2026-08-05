# abac.rego —— 属性条件判定
# 详见 docs/design/authz-v1.md §4.3

package foundation.authz.abac

import future.keywords.if
import future.keywords.in
import future.keywords.contains

default allow := false
default deny_reason := "abac.unspecified"

allow if {
    count(violations) == 0
}

deny_reason := concat(",", v) if {
    v := [reason | reason := violations[_]]
    count(v) > 0
}

# ───── violations ─────

violations contains "mfa_required" if {
    input.permission_definition.requires_mfa
    not input.request.mfa_satisfied
}

violations contains "four_eyes_required" if {
    input.permission_definition.requires_4eyes
    not input.request.four_eyes_satisfied
}

violations contains "pam_elevation_required" if {
    input.permission_definition.requires_pam_jit
    not input.request.pam_elevated
}

violations contains "outside_business_hours" if {
    input.permission_definition.requires_business_hours
    not in_business_hours
}

violations contains "ip_not_allowed" if {
    count(input.user.allowed_ip_cidrs) > 0
    not ip_in_allowed
}

violations contains "device_not_compliant" if {
    input.permission_definition.requires_compliant_device
    not input.user.device.is_compliant
}

violations contains "classification_too_high" if {
    input.permission_definition.requires_classification_lte != null
    input.resource.classification > input.permission_definition.requires_classification_lte
}

# ───── helpers ─────

in_business_hours if {
    h := time.clock(time.parse_rfc3339_ns(input.now))[0]
    h >= input.tenant.business_hours_start
    h < input.tenant.business_hours_end
}

ip_in_allowed if {
    some cidr in input.user.allowed_ip_cidrs
    net.cidr_contains(cidr, input.request.ip)
}

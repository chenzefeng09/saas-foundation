# mac.rego —— mandatory clearance/sensitivity gate
#
# Never compare levels as strings.  Only the closed L1-L5 vocabulary is valid,
# and numeric ranks define the ordering used by the authorization decision.

package foundation.authz.mac

import future.keywords.if

clearance_rank := {
    "L1": 1,
    "L2": 2,
    "L3": 3,
    "L4": 4,
    "L5": 5,
}

default allow := false
default deny_reason := "mac.clearance_insufficient"

valid_user_clearance if {
    clearance_rank[input.user.clearance]
}

valid_resource_sensitivity if {
    clearance_rank[input.resource.sensitivity]
}

allow if {
    user_rank := clearance_rank[input.user.clearance]
    resource_rank := clearance_rank[input.resource.sensitivity]
    user_rank >= resource_rank
}

deny_reason := "mac.invalid_user_clearance" if {
    not valid_user_clearance
}

deny_reason := "mac.invalid_resource_sensitivity" if {
    valid_user_clearance
    not valid_resource_sensitivity
}

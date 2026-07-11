# core.rego —— foundation authz 入口
# 详见 docs/design/authz-v1.md §4.3
#
# 入口决策 `allow` / `deny_reason`：
#   - 默认拒
#   - kill switch 命中：硬拒
#   - 必须 RBAC + MAC + ABAC + compliance 四关全过

package foundation.authz

# OPA 1.x: future.keywords.* 已默认开启；显式 import 仍接受但不必要。
# 关键：跨包引用必须显式 import 子包。
import data.foundation.authz.abac
import data.foundation.authz.compliance
import data.foundation.authz.mac
import data.foundation.authz.rbac

# 便利别名：kill switch 数据落点（见 data/kill_switch.json）
kill_switch := data.foundation.authz.kill_switch_meta.permissions

default allow := false
default deny_reason := "default_deny"

# ───── kill switch 硬拒 ─────
deny if {
    kill_switch[input.policy_id]
}

# ───── 主决策 ─────
allow if {
    not deny
    rbac.allow
    mac.allow
    abac.allow
    compliance.allow
}

# ───── 失败原因（优先级：kill switch → RBAC → MAC → ABAC → Compliance）─────
deny_reason := "kill_switch_deny" if {
    kill_switch[input.policy_id]
}

deny_reason := r if {
    not kill_switch[input.policy_id]
    not rbac.allow
    r := rbac.deny_reason
}

deny_reason := r if {
    not kill_switch[input.policy_id]
    rbac.allow
    not mac.allow
    r := mac.deny_reason
}

deny_reason := r if {
    not kill_switch[input.policy_id]
    rbac.allow
    mac.allow
    not abac.allow
    r := abac.deny_reason
}

deny_reason := r if {
    not kill_switch[input.policy_id]
    rbac.allow
    mac.allow
    abac.allow
    not compliance.allow
    r := compliance.deny_reason
}

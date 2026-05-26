# compliance.rego —— 合规模式驱动的硬约束
# 详见 docs/design/authz-v1.md §8

package foundation.authz.compliance

import future.keywords.if
import future.keywords.in
import future.keywords.contains

default allow := true
default deny_reason := "compliance.unspecified"

allow if {
    count(violations) == 0
}

deny_reason := concat(",", v) if {
    v := [r | r := violations[_]]
    count(v) > 0
}

# ───── 合规规则 ─────

# 金融模式：所有 CRITICAL 风险动作强制 4 眼 + 数据分级 ≤ L4 才能下载
violations contains "finance.critical_requires_4eyes" if {
    "finance_jrt0071" in input.tenant.compliance_modes
    input.permission_definition.risk_level == "CRITICAL"
    not input.request.four_eyes_satisfied
}

violations contains "finance.download_classification_cap" if {
    "finance_jrt0071" in input.tenant.compliance_modes
    contains(input.action, "download")
    input.resource.classification > 4
}

# 等保四级：所有 HIGH 必须经 PAM JIT 提权
violations contains "equal_protection_4.high_requires_pam" if {
    "equal_protection_4" in input.tenant.compliance_modes
    input.permission_definition.risk_level == "HIGH"
    not input.request.pam_elevated
}

# 等保三级：异常 IP 直接拒（与 ABAC 双保险）
violations contains "equal_protection_3.cross_border" if {
    "equal_protection_3" in input.tenant.compliance_modes
    input.request.country != input.tenant.expected_country
    input.permission_definition.risk_level != "LOW"
}

# PIPL：跨境数据传输硬阻断
violations contains "pipl.cross_border_data_transfer" if {
    "pipl" in input.tenant.compliance_modes
    input.tenant.data_residency == "cn-only"
    input.action == "data.export"
    input.request.destination_country != "CN"
}

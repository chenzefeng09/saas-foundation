from dataclasses import dataclass
from typing import Any, Final


@dataclass(frozen=True, slots=True)
class ErrorCode:
    code: str
    http_status: int
    title: str
    default_detail: str
    default_user_message: str


class FoundationError(Exception):
    def __init__(
        self,
        error_code: ErrorCode,
        detail: str | None = None,
        user_message: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        self.error_code = error_code
        self.detail = detail or error_code.default_detail
        self.user_message = user_message or error_code.default_user_message
        self.extra = extra or {}
        super().__init__(f"{error_code.code}: {self.detail}")


VALIDATION_FAILED: Final = ErrorCode(
    "FOUNDATION.SECURITY_OPS.INPUT.VALIDATION_FAILED",
    422, "Validation failed",
    "Input failed semantic validation.", "输入校验未通过。",
)
UNEXPECTED: Final = ErrorCode(
    "FOUNDATION.SECURITY_OPS.INTERNAL.UNEXPECTED",
    500, "Unexpected error",
    "An unexpected internal error occurred.", "服务异常。",
)
SCAN_THRESHOLD_VIOLATED: Final = ErrorCode(
    "FOUNDATION.SECURITY_OPS.SCAN.THRESHOLD_VIOLATED",
    422, "Scan threshold violated",
    "Scan findings exceed the defined threshold.", "扫描结果超出阈值，合并被阻断。",
)
VULN_NOT_FOUND: Final = ErrorCode(
    "FOUNDATION.SECURITY_OPS.VULN.NOT_FOUND",
    404, "Vulnerability not found",
    "The requested vulnerability record does not exist.", "漏洞记录不存在。",
)
VULN_EXCEPTION_EXPIRED: Final = ErrorCode(
    "FOUNDATION.SECURITY_OPS.VULN.EXCEPTION_EXPIRED",
    410, "Vulnerability exception expired",
    "The exemption for this vulnerability has expired.", "漏洞豁免已过期。",
)
VULN_SLA_OVERDUE: Final = ErrorCode(
    "FOUNDATION.SECURITY_OPS.VULN.SLA_OVERDUE",
    409, "Vulnerability SLA overdue",
    "This vulnerability has exceeded its SLA deadline.", "漏洞已超出 SLA 修复期限。",
)
SBOM_MISSING_ATTESTATION: Final = ErrorCode(
    "FOUNDATION.SECURITY_OPS.SBOM.MISSING_ATTESTATION",
    412, "SBOM attestation missing",
    "No SBOM attestation found for this image.", "镜像缺少 SBOM attestation。",
)
SBOM_SIGNATURE_INVALID: Final = ErrorCode(
    "FOUNDATION.SECURITY_OPS.SBOM.SIGNATURE_INVALID",
    422, "SBOM signature invalid",
    "SBOM cosign signature verification failed.", "SBOM 签名验证失败。",
)
INCIDENT_NOT_FOUND: Final = ErrorCode(
    "FOUNDATION.SECURITY_OPS.INCIDENT.NOT_FOUND",
    404, "Incident not found",
    "The requested incident does not exist.", "应急事件记录不存在。",
)
SCAN_NOT_FOUND: Final = ErrorCode(
    "FOUNDATION.SECURITY_OPS.SCAN.NOT_FOUND",
    404, "Scan run not found",
    "The requested scan run does not exist.", "扫描记录不存在。",
)
DRILL_NOT_FOUND: Final = ErrorCode(
    "FOUNDATION.SECURITY_OPS.DRILL.NOT_FOUND",
    404, "Drill not found",
    "The requested drill does not exist.", "演练记录不存在。",
)

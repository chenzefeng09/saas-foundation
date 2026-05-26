"""Org service error codes (FOUNDATION.ORG.<CAT>.<NAME>)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final


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
        extra: dict[str, str] | None = None,
    ) -> None:
        self.error_code = error_code
        self.detail = detail or error_code.default_detail
        self.user_message = user_message or error_code.default_user_message
        self.extra: dict[str, str] = extra or {}
        super().__init__(f"{error_code.code}: {self.detail}")


def _ec(category: str, name: str, http: int, title: str, detail: str, user_msg: str) -> ErrorCode:
    return ErrorCode(
        code=f"FOUNDATION.ORG.{category}.{name}",
        http_status=http,
        title=title,
        default_detail=detail,
        default_user_message=user_msg,
    )


# --- POLICY (403) ---
PERMISSION_DENIED: Final = _ec(
    "POLICY", "PERMISSION_DENIED", 403,
    "Permission denied",
    "Subject does not have the requested permission on this org resource.",
    "您没有执行此操作的权限。",
)
TENANT_MISMATCH: Final = _ec(
    "POLICY", "TENANT_MISMATCH", 403,
    "Tenant mismatch",
    "Resource belongs to a different tenant than the authenticated context.",
    "租户上下文不匹配。",
)


# --- INPUT (400 / 422) ---
INVALID_FORMAT: Final = _ec(
    "INPUT", "INVALID_FORMAT", 400,
    "Invalid input format",
    "Request payload is malformed.",
    "请求参数格式错误。",
)
VALIDATION_FAILED: Final = _ec(
    "INPUT", "VALIDATION_FAILED", 422,
    "Validation failed",
    "Input failed semantic validation.",
    "输入校验未通过。",
)
INVALID_OU_CODE: Final = _ec(
    "INPUT", "INVALID_OU_CODE", 422,
    "Invalid org-unit code",
    "org_unit.code must be ASCII slug ([a-z0-9_-], 1-32 chars); use `name` for non-ASCII.",
    "部门编码格式不合法（仅限小写字母/数字/下划线/连字符）。",
)


# --- RESOURCE (404 / 409) ---
ORG_UNIT_NOT_FOUND: Final = _ec(
    "RESOURCE", "ORG_UNIT_NOT_FOUND", 404,
    "Org unit not found",
    "Org unit does not exist in this tenant.",
    "部门不存在。",
)
TEAM_NOT_FOUND: Final = _ec(
    "RESOURCE", "TEAM_NOT_FOUND", 404,
    "Team not found",
    "Team does not exist in this tenant.",
    "团队不存在。",
)
MEMBERSHIP_NOT_FOUND: Final = _ec(
    "RESOURCE", "MEMBERSHIP_NOT_FOUND", 404,
    "Membership not found",
    "User has no primary org-unit membership in this tenant.",
    "用户没有主属部门记录。",
)
ORG_UNIT_CODE_CONFLICT: Final = _ec(
    "RESOURCE", "ORG_UNIT_CODE_CONFLICT", 409,
    "Org-unit code conflict",
    "An org-unit with this code already exists under the same parent.",
    "同级部门下已存在相同编码。",
)
TEAM_CODE_CONFLICT: Final = _ec(
    "RESOURCE", "TEAM_CODE_CONFLICT", 409,
    "Team code conflict",
    "A team with this code already exists in this org-unit.",
    "同部门下已存在相同团队编码。",
)


# --- STATE (409 / 422) ---
ORG_UNIT_NOT_EMPTY: Final = _ec(
    "STATE", "NOT_EMPTY", 422,
    "Org unit is not empty",
    "Cannot archive or delete an org-unit that still has descendants, teams, or members.",
    "该部门下仍有子部门 / 团队 / 成员，无法归档或删除。",
)
ORG_UNIT_ARCHIVED: Final = _ec(
    "STATE", "ORG_UNIT_ARCHIVED", 409,
    "Org unit archived",
    "Cannot operate under an archived parent org-unit.",
    "父部门已归档，无法在其下创建子部门。",
)
ORG_UNIT_CYCLE: Final = _ec(
    "STATE", "ORG_UNIT_CYCLE", 409,
    "Org unit move would create a cycle",
    "Cannot move an org-unit into one of its own descendants.",
    "不能将部门移动到自己的子孙节点下。",
)
ORG_UNIT_DEPTH_EXCEEDED: Final = _ec(
    "STATE", "DEPTH_EXCEEDED", 422,
    "Org unit depth exceeded",
    "Org-unit nesting depth exceeds the configured maximum.",
    "部门层级超过最大限制。",
)
ORG_UNIT_IMMUTABLE_CODE: Final = _ec(
    "STATE", "IMMUTABLE_CODE", 409,
    "Org unit code immutable",
    "org_unit.code is immutable after creation; use move + alias to rename.",
    "部门编码不可修改；如需重命名请使用 move + 旧编码保留 30 天。",
)
MEMBER_ALREADY_IN_TEAM: Final = _ec(
    "STATE", "MEMBER_ALREADY_IN_TEAM", 409,
    "Member already in team",
    "User is already an active member of this team.",
    "用户已是该团队成员。",
)
MEMBER_NOT_IN_TEAM: Final = _ec(
    "STATE", "MEMBER_NOT_IN_TEAM", 404,
    "Member not in team",
    "User is not an active member of this team.",
    "用户不是该团队成员。",
)


# --- DEPENDENCY (502 / 503) ---
IDENTITY_UNAVAILABLE: Final = _ec(
    "DEPENDENCY", "IDENTITY_UNAVAILABLE", 503,
    "Identity service unavailable",
    "Identity service is unreachable; cannot validate user reference.",
    "身份服务暂不可用。",
)


# --- INTERNAL (500) ---
UNEXPECTED: Final = _ec(
    "INTERNAL", "UNEXPECTED", 500,
    "Unexpected error",
    "An unexpected internal error occurred.",
    "服务异常，请联系管理员。",
)


@dataclass(frozen=True, slots=True)
class _Registry:
    codes: tuple[ErrorCode, ...] = field(default=())

    @classmethod
    def build(cls) -> _Registry:
        import inspect

        codes = tuple(
            obj
            for _, obj in inspect.getmembers(__import__(__name__, fromlist=["*"]))
            if isinstance(obj, ErrorCode)
        )
        seen: set[str] = set()
        for c in codes:
            if c.code in seen:
                raise RuntimeError(f"Duplicate error code: {c.code}")
            seen.add(c.code)
        return cls(codes=codes)


REGISTRY: Final = _Registry.build()

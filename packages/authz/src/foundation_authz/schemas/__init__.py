"""Pydantic schemas — align with contracts/openapi/authz.yaml."""

from foundation_authz.schemas.binding import (
    CreateBindingRequest,
    RoleBindingRead,
)
from foundation_authz.schemas.check import (
    BatchCheckRequest,
    BatchCheckResponse,
    CheckRequest,
    CheckResponse,
    ListAccessibleIdsRequest,
    ListAccessibleIdsResponse,
)
from foundation_authz.schemas.common import (
    CursorPage,
    HealthStatus,
    ProblemDetails,
    ValidationProblemDetails,
)
from foundation_authz.schemas.permission import PermissionRead
from foundation_authz.schemas.role import (
    CreateRoleRequest,
    RoleRead,
    UpdateRoleRequest,
)

__all__ = [
    "BatchCheckRequest",
    "BatchCheckResponse",
    "CheckRequest",
    "CheckResponse",
    "CreateBindingRequest",
    "CreateRoleRequest",
    "CursorPage",
    "HealthStatus",
    "ListAccessibleIdsRequest",
    "ListAccessibleIdsResponse",
    "PermissionRead",
    "ProblemDetails",
    "RoleBindingRead",
    "RoleRead",
    "UpdateRoleRequest",
    "ValidationProblemDetails",
]

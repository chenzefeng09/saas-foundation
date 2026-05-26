"""Pydantic schemas — align with contracts/openapi/identity.yaml.

Naming convention: <Resource>Read / <Resource>CreateRequest / <Resource>UpdateRequest
(matches OpenAPI component names where practical).
"""

from foundation_identity.schemas.common import (
    CursorPage,
    HealthStatus,
    ProblemDetails,
    ValidationProblemDetails,
)
from foundation_identity.schemas.mfa import (
    MfaChallengeResponse,
    MfaConfirmRequest,
    MfaEnrollResponse,
    MfaMethodRead,
    MfaVerifyRequest,
)
from foundation_identity.schemas.policy import PasswordPolicyRead, PasswordPolicyUpdate
from foundation_identity.schemas.session import CreateSessionRequest, SessionRead
from foundation_identity.schemas.sso import (
    CreateSsoProviderRequest,
    SocialProviderRead,
    SsoProviderRead,
)
from foundation_identity.schemas.user import (
    InviteUserRequest,
    UpdateUserRequest,
    UserRead,
)

__all__ = [
    "CreateSessionRequest",
    "CreateSsoProviderRequest",
    "CursorPage",
    "HealthStatus",
    "InviteUserRequest",
    "MfaChallengeResponse",
    "MfaConfirmRequest",
    "MfaEnrollResponse",
    "MfaMethodRead",
    "MfaVerifyRequest",
    "PasswordPolicyRead",
    "PasswordPolicyUpdate",
    "ProblemDetails",
    "SessionRead",
    "SocialProviderRead",
    "SsoProviderRead",
    "UpdateUserRequest",
    "UserRead",
    "ValidationProblemDetails",
]

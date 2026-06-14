"""Check API schemas."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

DecisionPath = Literal["RBAC_HIT", "OPA_HIT", "DEFAULT_DENY", "KILL_SWITCH_DENY"]


class CheckRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: str = Field(pattern=r"^usr_[0-9A-Z]{26}$")
    action: str = Field(min_length=1, max_length=120, examples=["billing.invoice.read"])
    resource_type: str = Field(min_length=1, max_length=50)
    resource_id: str | None = None
    context: dict[str, Any] = Field(default_factory=dict)


class CheckResponse(BaseModel):
    allowed: bool
    decision_path: DecisionPath
    matched_role: str | None = None
    matched_policy: str | None = None
    deny_reason: str | None = None
    latency_ms: float = 0.0


class BatchCheckRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    checks: list[CheckRequest] = Field(min_length=1, max_length=100)


class BatchCheckResponse(BaseModel):
    results: list[CheckResponse]


class ListAccessibleIdsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: str = Field(pattern=r"^usr_[0-9A-Z]{26}$")
    resource_type: str
    action: str
    max: int = Field(default=10000, ge=1, le=100000)


class ListAccessibleIdsResponse(BaseModel):
    ids: list[str]
    complete: bool = True
    # True when the user has a TENANT- or GLOBAL_SYSTEM-scoped binding that
    # grants the requested action, meaning they can access ALL resources of that
    # type within the tenant.  Callers should treat this as "no ACL filter needed".
    all_in_tenant: bool = False


class EffectivePermissionsResponse(BaseModel):
    """The caller's flattened, inheritance-expanded permission tokens.

    ``permissions`` is sorted for a stable, deterministic payload so callers
    (BFF / SPA) can diff / cache it cheaply.  An unauthenticated context
    (no user_id) yields an empty list rather than an error.
    """

    permissions: list[str]

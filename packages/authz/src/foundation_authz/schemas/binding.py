"""Role binding schemas."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, Field, computed_field

PrincipalKind = Literal["USER", "TEAM", "ORG_UNIT", "API_KEY", "SERVICE_ACCOUNT"]
ScopeKind = Literal["TENANT", "ORG_UNIT", "TEAM", "RESOURCE", "GLOBAL_SYSTEM"]

# Lifecycle state of a binding.  Exactly one applies at any instant:
#   REVOKED — revoked_at is set (revocation wins over expiry);
#   EXPIRED — not revoked, but expires_at is in the past;
#   ACTIVE  — everything else: the bindings CheckService honours.
BindingStatus = Literal["ACTIVE", "EXPIRED", "REVOKED"]
BINDING_STATUSES: Final[tuple[BindingStatus, ...]] = ("ACTIVE", "EXPIRED", "REVOKED")
# GET /bindings without filter.status lists ACTIVE bindings only; EXPIRED and
# REVOKED rows are audit history and must be asked for explicitly.
DEFAULT_LIST_STATUSES: Final[frozenset[BindingStatus]] = frozenset({"ACTIVE"})


def binding_status(
    *,
    revoked_at: datetime | None,
    expires_at: datetime | None,
    now: datetime,
) -> BindingStatus:
    """Classify a binding at ``now`` with the same rule CheckService applies."""
    if revoked_at is not None:
        return "REVOKED"
    if expires_at is not None and expires_at < now:
        return "EXPIRED"
    return "ACTIVE"


class RoleBindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str = Field(pattern=r"^rbd_[0-9A-Z]{26}$")
    tenant_id: str = Field(pattern=r"^tnt_[0-9A-Z]{26}$")
    principal_kind: PrincipalKind
    principal_id: str
    role_id: str = Field(pattern=r"^rol_[0-9A-Z]{26}$")
    scope_kind: ScopeKind
    scope_id: str | None = None
    granted_at: datetime
    expires_at: datetime | None = None
    granted_by: str
    grant_reason: str | None = None
    revoked_at: datetime | None = None
    revoked_by: str | None = None
    revoked_reason: str | None = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def status(self) -> BindingStatus:
        return binding_status(
            revoked_at=self.revoked_at,
            expires_at=self.expires_at,
            now=datetime.now(UTC),
        )


class CreateBindingRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    principal_kind: PrincipalKind
    principal_id: str = Field(min_length=1, max_length=64)
    role_id: str = Field(pattern=r"^rol_[0-9A-Z]{26}$")
    scope_kind: ScopeKind = "TENANT"
    scope_id: str | None = None
    expires_at: datetime | None = None
    grant_reason: str | None = Field(default=None, max_length=500)

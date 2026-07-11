"""User schemas — align with contracts/openapi/identity.yaml `User`."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

USER_ID_PATTERN = r"^usr_[0-9A-Z]{26}$"
TENANT_ID_PATTERN = r"^tnt_[0-9A-Z]{26}$"

# Loose email pattern that allows special-use TLDs like .local/.test (used by the
# dev/test seed users) while still requiring a basic user@host.tld structure.
# Pydantic's strict ``EmailStr`` uses email-validator, which rejects RFC-6761
# reserved TLDs; serializing a stored ``.local`` address through ``EmailStr``
# raises a ValidationError and turns ``GET /users/{id}`` into a 500 — the exact
# endpoint authz/dlp rely on to resolve authoritative clearance.  This mirrors
# the permissive validator already used in schemas/session.py.
_LOOSE_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _validate_loose_email(v: str) -> str:
    if not _LOOSE_EMAIL_RE.match(v):
        raise ValueError(f"Invalid email address: {v!r}")
    return v.lower()


UserStatus = Literal["ACTIVE", "INVITED", "SUSPENDED", "LOCKED", "DEACTIVATED", "FROZEN"]
ClearanceLevel = Literal["L1", "L2", "L3", "L4", "L5"]


def _default_clearance() -> ClearanceLevel:
    """Default for optional create/patch inputs without making ``null`` valid."""
    return "L3"


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str = Field(pattern=USER_ID_PATTERN)
    tenant_id: str = Field(pattern=TENANT_ID_PATTERN)
    email: str
    display_name: str | None = None
    status: UserStatus
    roles: list[str] = Field(default_factory=list)
    clearance: ClearanceLevel
    last_login_at: datetime | None = None
    mfa_enabled: bool = False
    external_id: str | None = None
    created_at: datetime
    updated_at: datetime
    deleted_at: datetime | None = None

    @field_validator("email")
    @classmethod
    def _accept_special_use_tlds(cls, v: str) -> str:
        return _validate_loose_email(v)

    @field_validator("clearance", mode="before")
    @classmethod
    def legacy_null_clearance_defaults_to_l3(cls, value: object) -> object:
        """Project pre-migration NULL rows as the effective employee default."""
        return "L3" if value is None else value


class InviteUserRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str
    display_name: str | None = Field(default=None, max_length=200)
    roles: list[str] = Field(default_factory=list)
    clearance: ClearanceLevel = Field(default_factory=_default_clearance)
    send_invite_email: bool = True

    @field_validator("email")
    @classmethod
    def _accept_special_use_tlds(cls, v: str) -> str:
        return _validate_loose_email(v)


class UpdateUserRequest(BaseModel):
    """JSON Merge Patch — all fields optional."""

    model_config = ConfigDict(extra="forbid")

    display_name: str | None = None
    status: UserStatus | None = None
    roles: list[str] | None = None
    # A default factory makes the field optional for merge-patch while keeping
    # explicit JSON null invalid.  The route uses exclude_unset=True, so omission
    # never resets an existing user to L3.
    clearance: ClearanceLevel = Field(default_factory=_default_clearance)


class FreezeUserRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=5, max_length=500)


class ProfileSelfUpdate(BaseModel):
    """Self-service profile patch — the caller may only edit their own ``display_name``.

    Deliberately narrow: this endpoint exists solely to set the caller's display
    name, so it exposes none of the privileged fields (``status`` / ``roles``)
    that ``UpdateUserRequest`` carries.  ``extra="forbid"`` rejects any attempt
    to smuggle those fields through.
    """

    model_config = ConfigDict(extra="forbid")

    display_name: str | None = Field(default=None, max_length=200)


class ChangeOwnPasswordRequest(BaseModel):
    """Self-service change-password body — the caller changes ONLY their own password.

    The target user is always the authenticated caller (resolved from the bearer
    token), never a path/body parameter, so this carries only the two passwords.
    The new-password length floor is enforced server-side in the service layer
    against the configured policy, not here, so the same hard floor applies to
    every caller regardless of client.  ``extra="forbid"`` blocks smuggling.
    """

    model_config = ConfigDict(extra="forbid")

    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=1, max_length=256)

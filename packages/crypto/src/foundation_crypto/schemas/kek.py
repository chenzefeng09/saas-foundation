"""KEK schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from foundation_crypto.schemas.common import (
    ALGORITHM_ID_PATTERN,
    KEK_ID_PATTERN,
    KEK_LABEL_PATTERN,
    TENANT_ID_PATTERN,
    USER_ID_PATTERN,
)

KEKPurpose = Literal["FIELD_ENCRYPT", "AUDIT_HMAC", "JWT_SIGN", "FILE_ENCRYPT"]
KEKStatus = Literal["ACTIVE", "SUSPENDED", "MARKED_FOR_DESTRUCTION", "DESTROYED"]


class KEKRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str = Field(pattern=KEK_ID_PATTERN)
    tenant_id: str = Field(pattern=TENANT_ID_PATTERN)
    label: str = Field(pattern=KEK_LABEL_PATTERN)
    purpose: KEKPurpose
    algorithm_id: str = Field(pattern=ALGORITHM_ID_PATTERN)
    vault_path: str
    current_version: int = Field(ge=1)
    min_decryption_version: int = Field(ge=1)
    auto_rotate_days: int = Field(ge=1, le=730)
    last_rotated_at: datetime
    status: KEKStatus
    destruction_scheduled_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class CreateKEKRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: str = Field(pattern=KEK_LABEL_PATTERN)
    purpose: KEKPurpose
    algorithm_id: str = Field(pattern=ALGORITHM_ID_PATTERN)
    auto_rotate_days: int = Field(default=90, ge=1, le=730)


class RotateKEKRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str | None = Field(default=None, max_length=500)


class MarkForDestructionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=1, max_length=500)
    # Optional override (24h floor); enforced in service layer.
    cooling_off_days_override: int | None = Field(default=None, ge=1, le=365)


class DestroyKEKRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    approver_user_id: str = Field(pattern=USER_ID_PATTERN)
    confirmation_phrase: str = Field(min_length=1, max_length=200)


class KEKHistoryEntry(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    transition: str
    changed_at: datetime
    changed_by: str
    from_status: str | None = None
    to_status: str | None = None
    reason: str | None = None
    approver_user_id: str | None = None

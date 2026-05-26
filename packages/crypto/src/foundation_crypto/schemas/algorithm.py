"""Algorithm registry + tenant policy schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from foundation_crypto.schemas.common import (
    ALGORITHM_ID_PATTERN,
    TENANT_ID_PATTERN,
)

AlgorithmKind = Literal[
    "SYMMETRIC", "ASYMMETRIC_SIGN", "ASYMMETRIC_ENCRYPT",
    "HASH", "HMAC", "KDF", "PASSWORD_HASH", "TLS_SUITE", "RNG",
]
ProviderName = Literal["openssl", "tongsuo", "gmssl", "hsm", "vault"]


class AlgorithmRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str = Field(pattern=ALGORITHM_ID_PATTERN)
    kind: AlgorithmKind
    family: str
    provider: ProviderName
    key_size_bits: int | None = None
    fips_140: bool = False
    gm_certified: bool = False
    deprecated: bool = False
    description: str | None = None
    min_compliance_modes: list[str] = Field(default_factory=list)


class TenantAlgorithmPolicyRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    tenant_id: str = Field(pattern=TENANT_ID_PATTERN)
    symmetric_default: str | None = None
    sign_default: str | None = None
    hash_default: str | None = None
    password_hash_default: str | None = None
    locked_by_compliance: list[str] = Field(default_factory=list)
    updated_at: datetime


class UpdateTenantPolicyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    symmetric_default: str | None = Field(default=None, pattern=ALGORITHM_ID_PATTERN)
    sign_default: str | None = Field(default=None, pattern=ALGORITHM_ID_PATTERN)
    hash_default: str | None = Field(default=None, pattern=ALGORITHM_ID_PATTERN)
    password_hash_default: str | None = Field(default=None, pattern=ALGORITHM_ID_PATTERN)
    locked_by_compliance: list[str] | None = None

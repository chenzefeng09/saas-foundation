"""Signature schemas."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from foundation_crypto.schemas.common import KEK_LABEL_PATTERN


class SignRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key_label: str = Field(pattern=KEK_LABEL_PATTERN)
    data_b64: str = Field(min_length=1, max_length=8_388_608)
    detached: bool = True  # detached signature; data is not embedded
    # When True, the service hashes `data_b64` with the KEK's hash algorithm
    # before signing. When False, the caller has already hashed the input.
    prehash: bool = True


class SignResponse(BaseModel):
    algorithm: str
    kek_id: str
    kek_version: int
    signature_b64: str


class VerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key_label: str = Field(pattern=KEK_LABEL_PATTERN)
    data_b64: str
    signature_b64: str
    kek_version: int | None = None  # default: any active version
    prehash: bool = True


class VerifyResponse(BaseModel):
    valid: bool
    algorithm: str
    kek_id: str
    kek_version: int

"""Envelope encryption schemas.

The envelope itself is a versioned JSON document — see
`foundation_crypto.domain.envelope` for the canonical structure.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from foundation_crypto.schemas.common import KEK_LABEL_PATTERN


class Envelope(BaseModel):
    """Wire format for an encrypted value (b64-encoded blobs)."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(ge=1)
    algorithm: str
    kek_id: str
    kek_version: int
    wrapped_dek_b64: str
    nonce_b64: str
    ciphertext_b64: str
    aad: dict[str, Any] = Field(default_factory=dict)


class EncryptRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key_label: str = Field(pattern=KEK_LABEL_PATTERN)
    plaintext_b64: str = Field(min_length=1, max_length=8_388_608)  # 8 MiB hard cap
    context: dict[str, Any] = Field(default_factory=dict)


class EncryptResponse(BaseModel):
    envelope: Envelope


class DecryptRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    envelope: Envelope
    expected_context: dict[str, Any] | None = None


class DecryptResponse(BaseModel):
    plaintext_b64: str


class BatchEncryptRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    items: list[EncryptRequest] = Field(min_length=1, max_length=200)


class BatchEncryptResponse(BaseModel):
    envelopes: list[Envelope]


class RewrapRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    envelope: Envelope
    # Rewrap to current KEK version. Target_version=None → use current.
    target_kek_version: int | None = Field(default=None, ge=1)


class RewrapResponse(BaseModel):
    envelope: Envelope

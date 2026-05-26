"""Envelope encryption service (crypto-v1 §7.1-7.2).

Envelope encryption flow:
  1. Look up KEK metadata from DB by (tenant_id, label).
  2. Call key_provider.generate_data_key() → get plaintext DEK + wrapped DEK.
  3. AES-256-GCM encrypt plaintext with plaintext DEK.
  4. Zeroise plaintext DEK from memory.
  5. Return Envelope {schema_version, algorithm, kek_id, kek_version,
     wrapped_dek_b64, nonce_b64, ciphertext_b64, aad=context}.

Decryption flow:
  1. Parse envelope → extract kek_id, kek_version, wrapped_dek, nonce, ciphertext.
  2. Validate envelope schema version.
  3. Validate KEK exists, is active (or at least not DESTROYED).
  4. key_provider.decrypt_data_key() → unwrap DEK.
  5. AES-256-GCM decrypt ciphertext with DEK.
  6. Zeroise DEK.
  7. Return plaintext.

Integrity: the ciphertext includes AAD (bound to context dict), so any modification
to the envelope or context mismatch results in AEAD decryption failure →
ENVELOPE_TAMPERED.

Performance budget: P99 < 5ms end-to-end (incl. Vault RPC).
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidTag as _AESGCMInvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_crypto.adapters.key_provider import KeyProvider
from foundation_crypto.domain.models import KEK
from foundation_crypto.errors import (
    ENVELOPE_TAMPERED,
    KEK_DESTROYED,
    KEK_NOT_FOUND,
    FoundationError,
)
from foundation_crypto.observability import get_logger
from foundation_crypto.schemas.envelope import (
    BatchEncryptRequest,
    BatchEncryptResponse,
    DecryptRequest,
    DecryptResponse,
    EncryptRequest,
    EncryptResponse,
    Envelope,
    RewrapRequest,
    RewrapResponse,
)

log = get_logger(__name__)

CURRENT_SCHEMA_VERSION = 1
MAX_ENVELOPE_SCHEMA_VERSION = 1  # Only v1 supported in M1


@dataclass(frozen=True, slots=True)
class _KEKContext:
    id: str
    algorithm_id: str
    vault_path: str
    current_version: int


class EnvelopeService:
    """Orchestrate envelope encrypt/decrypt/rewrap over a KeyProvider."""

    def __init__(self, key_provider: KeyProvider) -> None:
        self._kp = key_provider

    # ------------------------------------------------------------------ Encrypt

    async def encrypt(
        self, session: AsyncSession, *, tenant_id: str, label: str, plaintext: bytes,
        context: dict[str, Any] | None = None,
    ) -> Envelope:
        if context is None:
            context = {}
        # 1. Look up KEK
        kek = await self._resolve_kek(session, tenant_id, label)
        # 2. Generate DEK
        dk = await self._kp.generate_data_key(vault_path=kek.vault_path, bits=256)
        # 3. Local AES-256-GCM encrypt
        nonce = os.urandom(12)
        aad_bytes = _serialise_aad(context)
        aesgcm = AESGCM(dk.plaintext)
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad_bytes)
        # 4. Zeroise
        _zeroise(dk.plaintext)
        return Envelope(
            schema_version=CURRENT_SCHEMA_VERSION,
            algorithm=kek.algorithm_id,
            kek_id=kek.id,
            kek_version=dk.kek_version,
            wrapped_dek_b64=_b64e(dk.wrapped),
            nonce_b64=_b64e(nonce),
            ciphertext_b64=_b64e(ciphertext),
            aad=context,
        )

    # ------------------------------------------------------------------ Decrypt

    async def decrypt(
        self, session: AsyncSession, *, envelope: Envelope,
        expected_context: dict[str, Any] | None = None,
    ) -> bytes:
        # 1. Validate schema
        if envelope.schema_version > MAX_ENVELOPE_SCHEMA_VERSION:
            raise FoundationError(ENVELOPE_TAMPERED, detail="Unsupported envelope schema version")
        # 2. Resolve KEK (must exist and not DESTROYED)
        kek = await self._resolve_kek_by_id(session, envelope.kek_id)
        if kek is None:
            raise FoundationError(KEK_NOT_FOUND, detail=f"KEK {envelope.kek_id} not found")
        # 3. Unwrap DEK
        wrapped = _b64d(envelope.wrapped_dek_b64)
        try:
            dek = await self._kp.decrypt_data_key(
                vault_path=kek.vault_path,
                wrapped=wrapped,
                kek_version=envelope.kek_version,
            )
        except FoundationError:
            raise
        except Exception as exc:
            raise FoundationError(ENVELOPE_TAMPERED, detail=str(exc)) from exc
        # 4. AES-256-GCM decrypt
        nonce = _b64d(envelope.nonce_b64)
        ciphertext = _b64d(envelope.ciphertext_b64)
        aad_context = expected_context if expected_context is not None else envelope.aad
        aad_bytes = _serialise_aad(aad_context)
        aesgcm = AESGCM(dek)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, aad_bytes)
        except _AESGCMInvalidTag as exc:
            raise FoundationError(
                ENVELOPE_TAMPERED,
                detail="AEAD authentication failed — envelope may have been tampered with",
            ) from exc
        finally:
            _zeroise(dek)
        return plaintext

    # ------------------------------------------------------------------ Rewrap

    async def rewrap(
        self, session: AsyncSession, *, envelope: Envelope, target_kek_version: int | None = None,
    ) -> Envelope:
        kek = await self._resolve_kek_by_id(session, envelope.kek_id)
        if kek is None:
            raise FoundationError(KEK_NOT_FOUND, detail=f"KEK {envelope.kek_id} not found")
        wrapped = _b64d(envelope.wrapped_dek_b64)
        new_wrapped, new_version = await self._kp.rewrap_data_key(
            vault_path=kek.vault_path, wrapped=wrapped,
        )
        return Envelope(
            schema_version=envelope.schema_version,
            algorithm=envelope.algorithm,
            kek_id=envelope.kek_id,
            kek_version=new_version,
            wrapped_dek_b64=_b64e(new_wrapped),
            nonce_b64=envelope.nonce_b64,
            ciphertext_b64=envelope.ciphertext_b64,
            aad=envelope.aad,
        )

    # ------------------------------------------------------------------ Helpers

    async def _resolve_kek(
        self, session: AsyncSession, tenant_id: str, label: str,
    ) -> _KEKContext:
        stmt = select(KEK).where(
            KEK.tenant_id == tenant_id,
            KEK.label == label,
            KEK.status != "DESTROYED",
        ).limit(1)
        row = (await session.execute(stmt)).scalar_one_or_none()
        if row is None:
            raise FoundationError(KEK_NOT_FOUND, detail=f"KEK '{label}' not found in tenant {tenant_id}")
        return _KEKContext(
            id=row.id,
            algorithm_id=row.algorithm_id,
            vault_path=row.vault_path,
            current_version=row.current_version,
        )

    async def _resolve_kek_by_id(
        self, session: AsyncSession, kek_id: str,
    ) -> _KEKContext | None:
        stmt = select(KEK).where(KEK.id == kek_id, KEK.status != "DESTROYED").limit(1)
        row = (await session.execute(stmt)).scalar_one_or_none()
        if row is None:
            return None
        return _KEKContext(
            id=row.id,
            algorithm_id=row.algorithm_id,
            vault_path=row.vault_path,
            current_version=row.current_version,
        )


# ------------------------------------------------------------------ Helpers

def _serialise_aad(context: dict[str, Any]) -> bytes:
    """Canonical AAD serialisation: sorted JSON keys, no whitespace."""
    import json
    return json.dumps(context, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s)


def _zeroise(buf: bytes) -> None:
    """Overwrite buffer in-place to reduce key material lifetime in memory."""
    try:
        # ctypes memset to 0
        import ctypes
        ctypes.memset(ctypes.c_char_p(buf), 0, len(buf))  # type: ignore[arg-type]
    except Exception:
        pass

"""Key provider abstraction.

A `KeyProvider` is the boundary between this service and whatever holds the
KEK bytes — Vault transit (default), softhsm2 (v1.1), real HSM via PKCS#11
(v1.1), or a process-local test backend (unit tests).

All methods are async. Return values use bytes (not b64) so callers don't
double-encode. Sensitive plaintext (DEK / signing private material) never
leaves the provider; the provider does the wrap/unwrap/sign itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class DataKey:
    """A freshly generated DEK plus its wrapped form."""

    plaintext: bytes
    wrapped: bytes
    kek_version: int


@dataclass(frozen=True, slots=True)
class SignatureBundle:
    signature: bytes
    algorithm: str
    kek_version: int


class KeyProvider(Protocol):
    """Boundary to Vault / HSM."""

    async def create_key(
        self,
        *,
        vault_path: str,
        algorithm: str,
    ) -> None: ...

    async def rotate_key(self, *, vault_path: str) -> int:
        """Return the new current version."""
        ...

    async def delete_key(self, *, vault_path: str) -> None:
        """Permanent deletion. Must be guarded by service-layer policy."""
        ...

    async def generate_data_key(
        self,
        *,
        vault_path: str,
        bits: int = 256,
    ) -> DataKey: ...

    async def decrypt_data_key(
        self,
        *,
        vault_path: str,
        wrapped: bytes,
        kek_version: int | None = None,
    ) -> bytes: ...

    async def rewrap_data_key(
        self,
        *,
        vault_path: str,
        wrapped: bytes,
    ) -> tuple[bytes, int]:
        """Re-wrap `wrapped` to the current KEK version.

        Returns (new_wrapped, new_kek_version).
        """
        ...

    async def sign(
        self,
        *,
        vault_path: str,
        data: bytes,
        prehashed: bool,
    ) -> SignatureBundle: ...

    async def verify(
        self,
        *,
        vault_path: str,
        data: bytes,
        signature: bytes,
        prehashed: bool,
        kek_version: int | None = None,
    ) -> bool: ...

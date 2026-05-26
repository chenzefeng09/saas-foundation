"""Hashicorp Vault transit secrets engine — KeyProvider implementation.

Backend selection (config.crypto_provider == "vault"):

  - `VaultKeyProvider` wraps hvac to call Vault transit endpoints.
  - KEK = a transit named key at `{mount}/{path}`, type depends on algorithm:
      - AES-256-GCM → type = "aes256-gcm96" (default).
      - SM4-GCM → type = "aes256-gcm96" (backed by Tongsuo-patched Vault / softhsm;
        the real SM4 support is v1.1 via PKCS#11).
      - Ed25519 / ECDSA-P256 → type = "ed25519" / "ecdsa-p256".
      - SM2 → type = "ecdsa-p256" (placeholder until Tongsuo PKCS#11 in v1.1).
  - KEK rotation: Vault transit key rotation (POST transit/keys/<name>/rotate).
  - Envelope: datakey/plaintext → generate DEK, datakey/decrypt → unwrap DEK.
  - Sign / verify: transit/sign/<name>, transit/verify/<name>.

Fail-closed: if Vault is unreachable or times out → VAULT_UNAVAILABLE / VAULT_TIMEOUT error.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import hvac
from hvac.exceptions import InvalidRequest, VaultError

from foundation_crypto.adapters.key_provider import DataKey, KeyProvider, SignatureBundle
from foundation_crypto.config import get_settings
from foundation_crypto.errors import (
    VAULT_DECISION_ERROR,
    VAULT_TIMEOUT,
    VAULT_UNAVAILABLE,
    FoundationError,
)
from foundation_crypto.observability import get_logger

log = get_logger(__name__)

# Map algorithm IDs → Vault transit key types.
_ALGORITHM_TO_TRANSIT_TYPE: dict[str, str] = {
    "AES-256-GCM": "aes256-gcm96",
    "SM4-GCM": "aes256-gcm96",  # placeholder; v1.1 Tongsuo PKCS#11
    "ECDSA-P256": "ecdsa-p256",
    "Ed25519": "ed25519",
    "SM2": "ecdsa-p256",  # placeholder; v1.1 PKCS#11
    "RSA-4096": "rsa-4096",
}

# Map algorithm IDs → Vault sign/verify hash algorithm.
_ALGORITHM_TO_SIGN_HASH: dict[str, str] = {
    "ECDSA-P256": "sha2-256",
    "Ed25519": "",  # no prehash needed for Ed25519
    "SM2": "sha2-256",  # placeholder; v1.1 SM3
    "RSA-4096": "sha2-256",
}


@dataclass(frozen=True, slots=True)
class _VaultTransit:
    """Internal state: hvac client + mount path."""

    client: hvac.Client
    mount: str

    def _key_path(self, vault_path: str) -> str:
        """Return the key name relative to the transit mount."""
        # vault_path looks like "transit/keys/pii_phone_tnt_01J..."
        # We need just "pii_phone_tnt_01J..."
        prefix = f"{self.mount}/keys/"
        if vault_path.startswith(prefix):
            return vault_path[len(prefix) :]
        # Be lenient: strip leading mount prefix if present
        if vault_path.startswith(f"{self.mount}/"):
            return vault_path[len(self.mount) + 1 :]
        return vault_path


def _client() -> hvac.Client:
    settings = get_settings()
    client = hvac.Client(url=str(settings.vault_url), token=settings.vault_token)
    if not client.is_authenticated():
        raise FoundationError(
            VAULT_UNAVAILABLE,
            detail="Vault is reachable but authentication failed — check CRYPTO_VAULT_TOKEN",
        )
    return client


class VaultKeyProvider:
    """Vault transit secrets engine implementation of KeyProvider."""

    def __init__(self) -> None:
        self._st = _VaultTransit(client=_client(), mount=get_settings().vault_transit_mount)

    # ------------------------------------------------------------------ Key lifecycle

    async def create_key(self, *, vault_path: str, algorithm: str) -> None:
        transit_type = _ALGORITHM_TO_TRANSIT_TYPE.get(algorithm)
        if transit_type is None:
            raise FoundationError(
                VAULT_DECISION_ERROR,
                detail=f"Algorithm {algorithm} cannot be backed by Vault transit — "
                "use a PKCS#11 HSM provider instead.",
            )
        name = self._st._key_path(vault_path)
        log.info("vault.create_key", name=name, type=transit_type, algorithm=algorithm)
        await self._exec(
            lambda: self._st.client.secrets.transit.create_key(
                name=name, key_type=transit_type, mount_point=self._st.mount,
            )
        )

    async def rotate_key(self, *, vault_path: str) -> int:
        """Returns the new current version after rotation."""
        name = self._st._key_path(vault_path)
        log.info("vault.rotate_key", name=name)
        result = await self._exec(
            lambda: self._st.client.secrets.transit.rotate_key(
                name=name, mount_point=self._st.mount,
            )
        )
        # Vault returns nothing useful; re-read the key to get the new version.
        key_info = await self._exec(
            lambda: self._st.client.secrets.transit.read_key(
                name=name, mount_point=self._st.mount,
            )
        )
        new_version = int(key_info["data"]["latest_version"])
        return new_version

    async def delete_key(self, *, vault_path: str) -> None:
        """Permanently delete the transit key. Irreversible."""
        name = self._st._key_path(vault_path)
        log.info("vault.delete_key", name=name)
        # Vault requires allow_deletion = True on the key config first.
        try:
            await self._exec(
                lambda: self._st.client.secrets.transit.update_key_configuration(
                    name=name, deletion_allowed=True, mount_point=self._st.mount,
                )
            )
        except VaultError:
            # Key may already allow deletion; proceed.
            pass
        await self._exec(
            lambda: self._st.client.secrets.transit.delete_key(
                name=name, mount_point=self._st.mount,
            )
        )

    # ------------------------------------------------------------------ Envelope

    async def generate_data_key(self, *, vault_path: str, bits: int = 256) -> DataKey:
        name = self._st._key_path(vault_path)
        result = await self._exec(
            lambda: self._st.client.secrets.transit.generate_data_key(
                name=name,
                key_type="plaintext",
                bits=bits,
                mount_point=self._st.mount,
            )
        )
        data = result["data"]
        return DataKey(
            plaintext=_b64decode(data["plaintext"]),
            wrapped=_b64decode(data["ciphertext"]),
            kek_version=int(data["key_version"]),
        )

    async def decrypt_data_key(
        self, *, vault_path: str, wrapped: bytes, kek_version: int | None = None,
    ) -> bytes:
        name = self._st._key_path(vault_path)
        params: dict[str, Any] = {
            "name": name,
            "ciphertext": _b64encode(wrapped),
            "mount_point": self._st.mount,
        }
        if kek_version is not None:
            params["key_version"] = kek_version
        result = await self._exec(
            lambda: self._st.client.secrets.transit.decrypt_data(**params)  # type: ignore[arg-type]
        )
        return _b64decode(result["data"]["plaintext"])

    async def rewrap_data_key(
        self, *, vault_path: str, wrapped: bytes,
    ) -> tuple[bytes, int]:
        name = self._st._key_path(vault_path)
        result = await self._exec(
            lambda: self._st.client.secrets.transit.rewrap_data(
                name=name,
                ciphertext=_b64encode(wrapped),
                mount_point=self._st.mount,
            )
        )
        data = result["data"]
        return (
            _b64decode(data["ciphertext"]),
            int(data["key_version"]),
        )

    # ------------------------------------------------------------------ Sign / Verify

    async def sign(
        self, *, vault_path: str, data: bytes, prehashed: bool,
    ) -> SignatureBundle:
        name = self._st._key_path(vault_path)
        # Determine the hash_algorithm to pass to Vault.
        key_info = await self._exec(
            lambda: self._st.client.secrets.transit.read_key(
                name=name, mount_point=self._st.mount,
            )
        )
        key_type = key_info["data"]["type"]
        sign_algorithm = _transit_type_to_sign_alg(key_type)

        params: dict[str, Any] = {
            "name": name,
            "input": _b64encode(data),
            "mount_point": self._st.mount,
        }
        if prehashed and sign_algorithm:
            params["hash_algorithm"] = sign_algorithm
        result = await self._exec(
            lambda: self._st.client.secrets.transit.sign_data(**params)  # type: ignore[arg-type]
        )
        sig_data = result["data"]
        return SignatureBundle(
            signature=_b64decode(sig_data["signature"]),
            algorithm=_transit_type_to_alg_name(key_type),
            kek_version=int(sig_data.get("key_version", 1)),
        )

    async def verify(
        self,
        *,
        vault_path: str,
        data: bytes,
        signature: bytes,
        prehashed: bool,
        kek_version: int | None = None,
    ) -> bool:
        name = self._st._key_path(vault_path)
        key_info = await self._exec(
            lambda: self._st.client.secrets.transit.read_key(
                name=name, mount_point=self._st.mount,
            )
        )
        key_type = key_info["data"]["type"]
        sign_algorithm = _transit_type_to_sign_alg(key_type)

        params: dict[str, Any] = {
            "name": name,
            "input": _b64encode(data),
            "signature": _b64encode(signature),
            "mount_point": self._st.mount,
        }
        if prehashed and sign_algorithm:
            params["hash_algorithm"] = sign_algorithm
        try:
            await self._exec(
                lambda: self._st.client.secrets.transit.verify_signed_data(**params)  # type: ignore[arg-type]
            )
            return True
        except FoundationError as e:
            if e.error_code.http_status == 422:
                # Vault returns 400/422 for invalid signature
                return False
            raise

    # ------------------------------------------------------------------ Internal

    async def _exec(self, fn):  # type: ignore[no-untyped-def]
        """Wrap a sync hvac call in an async executor, translating errors."""
        import asyncio

        settings = get_settings()
        try:
            loop = asyncio.get_running_loop()
            return await asyncio.wait_for(
                loop.run_in_executor(None, fn),
                timeout=settings.vault_timeout_seconds,
            )
        except asyncio.TimeoutError:
            raise FoundationError(
                VAULT_TIMEOUT,
                detail=f"Vault operation timed out after {settings.vault_timeout_seconds}s",
            ) from None
        except InvalidRequest as exc:
            detail = _format_vault_error(exc)
            if "signature" in detail.lower():
                # Treat signature verification failure as a 422
                raise FoundationError(
                    VAULT_DECISION_ERROR,
                    detail=detail,
                    user_message="签名验证失败。",
                ) from exc
            raise FoundationError(
                VAULT_DECISION_ERROR,
                detail=detail,
            ) from exc
        except VaultError as exc:
            raise FoundationError(
                VAULT_UNAVAILABLE,
                detail=f"Vault error: {_format_vault_error(exc)}",
            ) from exc


# ------------------------------------------------------------------ Helpers

def _b64decode(s: str) -> bytes:
    import base64
    return base64.b64decode(s)


def _b64encode(b: bytes) -> str:
    import base64
    return base64.b64encode(b).decode("ascii")


def _format_vault_error(exc: VaultError) -> str:
    """Extract a readable message from a VaultError."""
    msg = str(exc)
    # hvac wraps errors with JSON; try to extract .errors
    try:
        if hasattr(exc, "errors") and exc.errors:
            return "; ".join(str(e) for e in exc.errors)
    except Exception:
        pass
    return msg[:500]


def _transit_type_to_sign_alg(transit_type: str) -> str:
    """Map Vault transit key type to hash algorithm for sign/verify."""
    mapping: dict[str, str] = {
        "ecdsa-p256": "sha2-256",
        "ecdsa-p384": "sha2-384",
        "ecdsa-p521": "sha2-512",
        "rsa-2048": "sha2-256",
        "rsa-4096": "sha2-256",
        "ed25519": "",  # Ed25519 uses its own internal hash
    }
    return mapping.get(transit_type, "sha2-256")


def _transit_type_to_alg_name(transit_type: str) -> str:
    mapping: dict[str, str] = {
        "aes256-gcm96": "AES-256-GCM",
        "ecdsa-p256": "ECDSA-P256",
        "ed25519": "Ed25519",
        "rsa-2048": "RSA-2048",
        "rsa-4096": "RSA-4096",
    }
    return mapping.get(transit_type, transit_type)

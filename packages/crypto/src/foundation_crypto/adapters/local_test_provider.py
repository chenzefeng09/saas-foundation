"""In-process KeyProvider for unit tests — no Vault dependency.

Uses `cryptography` primitives directly:
  - AES-256-GCM for symmetric encryption of DEKs.
  - Ed25519 for signing.
  - ECDSA-P256 for signing (fallback).
  - SM2 for signing: uses ECDSA over SM2P256V1 curve (GB/T 32918).
    In production this would go through Tongsuo/PKCS#11; here we use
    the `cryptography` library's SEC p256k1 or, if unavailable, fall
    back to SECP256R1 with algorithm tag "SM2" to keep the code path
    testable without a Tongsuo build.
  - RSA-4096 for asymmetric encryption (wrap/unwrap).

Keys are stored in a dict keyed by `vault_path`. All operations are
synchronous but wrapped in async to match the KeyProvider interface.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature as _CryptographyInvalidSig
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from foundation_crypto.adapters.key_provider import DataKey, KeyProvider, SignatureBundle
from foundation_crypto.errors import VAULT_DECISION_ERROR, FoundationError
from foundation_crypto.observability import get_logger

log = get_logger(__name__)


@dataclass
class _LocalKey:
    algorithm: str
    symmetric_key: bytes | None = None
    private_key: Any = None
    public_key: Any = None
    version: int = 1
    deleted: bool = False


class LocalTestKeyProvider:
    """In-process crypto for tests. Not for production use."""

    def __init__(self) -> None:
        self._keys: dict[str, _LocalKey] = {}

    # ------------------------------------------------------------------ Key lifecycle

    async def create_key(self, *, vault_path: str, algorithm: str) -> None:
        if vault_path in self._keys and not self._keys[vault_path].deleted:
            raise FoundationError(
                VAULT_DECISION_ERROR,
                detail=f"Key already exists at {vault_path}",
            )
        key = _LocalKey(algorithm=algorithm, version=1)
        if algorithm in ("AES-256-GCM", "SM4-GCM"):
            import os
            key.symmetric_key = os.urandom(32)  # 256 bits
        elif algorithm == "Ed25519":
            priv = ed25519.Ed25519PrivateKey.generate()
            key.private_key = priv
            key.public_key = priv.public_key()
        elif algorithm == "ECDSA-P256":
            priv = ec.generate_private_key(ec.SECP256R1())
            key.private_key = priv
            key.public_key = priv.public_key()
        elif algorithm == "RSA-4096":
            priv = rsa.generate_private_key(public_exponent=65537, key_size=4096)
            key.private_key = priv
            key.public_key = priv.public_key()
        elif algorithm == "SM2":
            # SM2 uses the SM2P256V1 elliptic curve (GB/T 32918).
            # The `cryptography` library does not ship SM2P256V1 in its
            # built-in set, but it is available via Tongsuo in production.
            # For the test provider we use SECP256K1 (closest available curve
            # that the library ships cross-platform) and tag the algorithm
            # as "SM2" so callers can round-trip sign/verify correctly.
            # When Tongsuo PKCS#11 is present, production code never reaches
            # this branch.
            priv = ec.generate_private_key(ec.SECP256K1())
            key.private_key = priv
            key.public_key = priv.public_key()
        else:
            raise FoundationError(
                VAULT_DECISION_ERROR,
                detail=f"Algorithm {algorithm} not supported by LocalTestKeyProvider",
            )
        self._keys[vault_path] = key

    async def rotate_key(self, *, vault_path: str) -> int:
        key = self._keys.get(vault_path)
        if key is None or key.deleted:
            raise FoundationError(VAULT_DECISION_ERROR, detail=f"Key not found: {vault_path}")
        key.version += 1
        return key.version

    async def delete_key(self, *, vault_path: str) -> None:
        key = self._keys.get(vault_path)
        if key is None:
            return
        key.deleted = True
        key.symmetric_key = None
        key.private_key = None
        key.public_key = None

    # ------------------------------------------------------------------ Envelope

    async def generate_data_key(self, *, vault_path: str, bits: int = 256) -> DataKey:
        key = self._keys.get(vault_path)
        if key is None or key.deleted:
            raise FoundationError(VAULT_DECISION_ERROR, detail=f"Key not found: {vault_path}")
        import os
        dek = os.urandom(bits // 8)
        wrapped = self._wrap_with_kek(key, dek)
        return DataKey(
            plaintext=dek,
            wrapped=wrapped,
            kek_version=key.version,
        )

    async def decrypt_data_key(
        self, *, vault_path: str, wrapped: bytes, kek_version: int | None = None,
    ) -> bytes:
        key = self._keys.get(vault_path)
        if key is None or key.deleted:
            raise FoundationError(VAULT_DECISION_ERROR, detail=f"Key not found: {vault_path}")
        return self._unwrap_with_kek(key, wrapped)

    async def rewrap_data_key(
        self, *, vault_path: str, wrapped: bytes,
    ) -> tuple[bytes, int]:
        key = self._keys.get(vault_path)
        if key is None or key.deleted:
            raise FoundationError(VAULT_DECISION_ERROR, detail=f"Key not found: {vault_path}")
        dek = self._unwrap_with_kek(key, wrapped)
        new_wrapped = self._wrap_with_kek(key, dek)
        return (new_wrapped, key.version)

    # ------------------------------------------------------------------ Sign / Verify

    async def sign(
        self, *, vault_path: str, data: bytes, prehashed: bool,
    ) -> SignatureBundle:
        key = self._keys.get(vault_path)
        if key is None or key.deleted:
            raise FoundationError(VAULT_DECISION_ERROR, detail=f"Key not found: {vault_path}")
        if key.private_key is None:
            raise FoundationError(
                VAULT_DECISION_ERROR,
                detail=f"Key at {vault_path} is not a signing key",
            )
        priv = key.private_key
        if isinstance(priv, ed25519.Ed25519PrivateKey):
            signature = priv.sign(data)
            alg = "Ed25519"
        elif isinstance(priv, ec.EllipticCurvePrivateKey):
            if key.algorithm == "SM2":
                # SM2 signature: sign data with SM3 as the hash algorithm.
                # hashes.SM3() is available in the `cryptography` library via
                # its OpenSSL backend (requires OpenSSL with SM3 support, which
                # is standard on macOS/Linux with OpenSSL ≥ 1.1.1).
                # In production this runs via Tongsuo PKCS#11; here we use the
                # SECP256K1-proxy key with SM3 to keep the code path testable.
                signature = priv.sign(data, ec.ECDSA(hashes.SM3()))
                alg = "SM2"
            else:
                chosen_hash: hashes.HashAlgorithm = hashes.SHA256()
                signature = priv.sign(data, ec.ECDSA(chosen_hash))
                alg = "ECDSA-P256"
        elif isinstance(priv, rsa.RSAPrivateKey):
            signature = priv.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                        salt_length=padding.PSS.MAX_LENGTH),
                                 hashes.SHA256())
            alg = "RSA-4096"
        else:
            raise FoundationError(VAULT_DECISION_ERROR, detail="Unknown key type for signing")
        return SignatureBundle(
            signature=signature,
            algorithm=alg,
            kek_version=key.version,
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
        key = self._keys.get(vault_path)
        if key is None or key.deleted:
            return False
        pub = key.public_key
        if pub is None:
            return False
        try:
            if isinstance(pub, ed25519.Ed25519PublicKey):
                pub.verify(signature, data)
            elif isinstance(pub, ec.EllipticCurvePublicKey):
                if key.algorithm == "SM2":
                    # Mirror sign(): verify with SM3 hash via hashes.SM3()
                    pub.verify(signature, data, ec.ECDSA(hashes.SM3()))
                else:
                    pub.verify(signature, data, ec.ECDSA(hashes.SHA256()))
            elif isinstance(pub, rsa.RSAPublicKey):
                pub.verify(
                    signature, data,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                               salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256(),
                )
            else:
                return False
            return True
        except _CryptographyInvalidSig:
            return False

    # ------------------------------------------------------------------ Internal helpers

    def _wrap_with_kek(self, key: _LocalKey, dek: bytes) -> bytes:
        """Wrap DEK using the KEK material."""
        if key.symmetric_key is not None:
            # AES-GCM key wrap
            import os
            aesgcm = AESGCM(key.symmetric_key)
            nonce = os.urandom(12)
            # Prepend nonce: format = nonce(12) || ciphertext(32+16=48)
            return nonce + aesgcm.encrypt(nonce, dek, None)
        elif key.public_key is not None and isinstance(key.public_key, rsa.RSAPublicKey):
            return key.public_key.encrypt(
                dek,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        else:
            # Fallback: "wrap" by plain copy (only for test)
            return dek

    def _unwrap_with_kek(self, key: _LocalKey, wrapped: bytes) -> bytes:
        """Unwrap DEK using the KEK material."""
        if key.symmetric_key is not None:
            nonce = wrapped[:12]
            ciphertext = wrapped[12:]
            aesgcm = AESGCM(key.symmetric_key)
            return aesgcm.decrypt(nonce, ciphertext, None)
        elif key.private_key is not None and isinstance(key.private_key, rsa.RSAPrivateKey):
            return key.private_key.decrypt(
                wrapped,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        else:
            return wrapped

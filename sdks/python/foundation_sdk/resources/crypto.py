"""Crypto resource — envelope encryption, KEK lifecycle, signing, password hashing."""

from __future__ import annotations

from typing import Any

from foundation_sdk._transport import Transport


class CryptoResource:
    """Cryptographic operations: encrypt, decrypt, sign, verify, password hashing."""

    def __init__(self, transport: Transport) -> None:
        self._t = transport

    # --- Envelope Encryption ---

    def encrypt(self, plaintext: str, *, kek_label: str = "default",
                aad: str | None = None) -> dict[str, Any]:
        return self._t.request("POST", "/api/crypto/v1/encrypt",
                                json={"plaintext": plaintext, "kek_label": kek_label,
                                      "aad": aad})

    async def encrypt_async(self, plaintext: str, *, kek_label: str = "default") -> dict[str, Any]:
        return await self._t.request_async("POST", "/api/crypto/v1/encrypt",
                                            json={"plaintext": plaintext,
                                                  "kek_label": kek_label})

    def decrypt(self, envelope: dict[str, Any], *, aad: str | None = None) -> dict[str, Any]:
        return self._t.request("POST", "/api/crypto/v1/decrypt",
                                json={"envelope": envelope, "aad": aad})

    def rewrap(self, envelope: dict[str, Any], *, target_kek_label: str) -> dict[str, Any]:
        return self._t.request("POST", "/api/crypto/v1/rewrap",
                                json={"envelope": envelope,
                                      "target_kek_label": target_kek_label})

    # --- KEK Lifecycle ---

    def create_kek(self, *, label: str, algorithm: str = "AES-256-GCM") -> dict[str, Any]:
        return self._t.request("POST", "/api/crypto/v1/keks",
                                json={"label": label, "algorithm": algorithm})

    def rotate_kek(self, kek_id: str) -> dict[str, Any]:
        return self._t.request("POST", f"/api/crypto/v1/keks/{kek_id}/rotate")

    def list_keks(self) -> dict[str, Any]:
        return self._t.request("GET", "/api/crypto/v1/keks")

    # --- Signing ---

    def sign(self, data: str, *, algorithm: str = "ECDSA-P256") -> dict[str, Any]:
        return self._t.request("POST", "/api/crypto/v1/sign",
                                json={"data": data, "algorithm": algorithm})

    def verify(self, *, data: str, signature: str, algorithm: str = "ECDSA-P256") -> dict[str, Any]:
        return self._t.request("POST", "/api/crypto/v1/verify",
                                json={"data": data, "signature": signature,
                                      "algorithm": algorithm})

    # --- Password Hashing ---

    def hash_password(self, password: str) -> dict[str, Any]:
        return self._t.request("POST", "/api/crypto/v1/hash-password",
                                json={"password": password})

    def verify_password(self, *, password: str, password_hash: str) -> dict[str, Any]:
        return self._t.request("POST", "/api/crypto/v1/verify-password",
                                json={"password": password,
                                      "password_hash": password_hash})

    # --- Algorithms ---

    def list_algorithms(self) -> dict[str, Any]:
        return self._t.request("GET", "/api/crypto/v1/algorithms")

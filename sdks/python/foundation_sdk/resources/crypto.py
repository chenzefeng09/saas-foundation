"""Crypto resource — envelope encryption, KEK lifecycle, signing, password hashing."""

from __future__ import annotations

import base64
from typing import Any

from foundation_sdk._transport import Transport


def _b64(data: str | bytes) -> str:
    """The routes take bytes as base64; ``str`` is sent as its UTF-8 encoding."""
    raw = data.encode() if isinstance(data, str) else data
    return base64.b64encode(raw).decode("ascii")


def _encrypt_body(plaintext: str | bytes, key_label: str,
                  context: dict[str, str] | None) -> dict[str, Any]:
    body: dict[str, Any] = {"key_label": key_label, "plaintext_b64": _b64(plaintext)}
    if context is not None:
        body["context"] = context
    return body


class CryptoResource:
    """Cryptographic operations: encrypt, decrypt, sign, verify, password hashing."""

    def __init__(self, transport: Transport) -> None:
        self._t = transport

    # --- Envelope Encryption ---

    def encrypt(self, plaintext: str | bytes, *, kek_label: str = "default",
                context: dict[str, str] | None = None) -> dict[str, Any]:
        """Envelope-encrypt under the KEK labelled ``kek_label``.

        ``context`` is bound as AAD; ``decrypt`` must present the same one.
        Returns ``{envelope}``.
        """
        return self._t.request("POST", "/api/crypto/v1/encrypt",
                                json=_encrypt_body(plaintext, kek_label, context))

    async def encrypt_async(self, plaintext: str | bytes, *, kek_label: str = "default",
                            context: dict[str, str] | None = None) -> dict[str, Any]:
        return await self._t.request_async("POST", "/api/crypto/v1/encrypt",
                                            json=_encrypt_body(plaintext, kek_label, context))

    def decrypt(self, envelope: dict[str, Any], *,
                context: dict[str, str] | None = None) -> dict[str, Any]:
        """Returns ``{plaintext_b64}``; ``context`` must equal the one used to encrypt."""
        body: dict[str, Any] = {"envelope": envelope}
        if context is not None:
            body["expected_context"] = context
        return self._t.request("POST", "/api/crypto/v1/decrypt", json=body)

    def rewrap(self, envelope: dict[str, Any], *,
               target_kek_version: int | None = None) -> dict[str, Any]:
        """Re-wrap the DEK under another version of the same KEK (default: the active one)."""
        body: dict[str, Any] = {"envelope": envelope}
        if target_kek_version is not None:
            body["target_kek_version"] = target_kek_version
        return self._t.request("POST", "/api/crypto/v1/rewrap", json=body)

    # --- KEK Lifecycle ---

    def create_kek(self, *, label: str, purpose: str, algorithm: str = "AES-256-GCM",
                   auto_rotate_days: int | None = None) -> dict[str, Any]:
        """``purpose`` is FIELD_ENCRYPT, AUDIT_HMAC, JWT_SIGN or FILE_ENCRYPT;
        ``algorithm`` is an id from ``list_algorithms``.
        """
        body: dict[str, Any] = {"label": label, "algorithm_id": algorithm, "purpose": purpose}
        if auto_rotate_days is not None:
            body["auto_rotate_days"] = auto_rotate_days
        return self._t.request("POST", "/api/crypto/v1/keks", json=body)

    def rotate_kek(self, kek_id: str) -> dict[str, Any]:
        return self._t.request("POST", f"/api/crypto/v1/keks/{kek_id}/rotate")

    def list_keks(self) -> dict[str, Any]:
        return self._t.request("GET", "/api/crypto/v1/keks")

    # --- Signing ---

    def sign(self, data: str | bytes, *, key_label: str,
             prehash: bool | None = None, detached: bool | None = None) -> dict[str, Any]:
        """Sign with the KEK labelled ``key_label``; its algorithm decides the scheme.

        Returns ``{signature_b64, kek_version, ...}``.
        """
        body: dict[str, Any] = {"key_label": key_label, "data_b64": _b64(data)}
        for key, value in (("prehash", prehash), ("detached", detached)):
            if value is not None:
                body[key] = value
        return self._t.request("POST", "/api/crypto/v1/sign", json=body)

    def verify(self, *, data: str | bytes, signature: str, key_label: str,
               kek_version: int | None = None, prehash: bool | None = None) -> dict[str, Any]:
        """``signature`` is the ``signature_b64`` that ``sign`` returned."""
        body: dict[str, Any] = {"key_label": key_label, "data_b64": _b64(data),
                                "signature_b64": signature}
        for key, value in (("kek_version", kek_version), ("prehash", prehash)):
            if value is not None:
                body[key] = value
        return self._t.request("POST", "/api/crypto/v1/verify", json=body)

    # --- Password Hashing ---

    def hash_password(self, password: str) -> dict[str, Any]:
        """Returns ``{encoded, algorithm}``; store ``encoded``."""
        return self._t.request("POST", "/api/crypto/v1/password-hash",
                                json={"password": password})

    def verify_password(self, *, password: str, password_hash: str) -> dict[str, Any]:
        """``password_hash`` is the ``encoded`` string ``hash_password`` returned."""
        return self._t.request("POST", "/api/crypto/v1/password-verify",
                                json={"password": password, "encoded": password_hash})

    # --- Algorithms ---

    def list_algorithms(self) -> dict[str, Any]:
        return self._t.request("GET", "/api/crypto/v1/algorithms")

"""Crypto-service HTTP client for signing Merkle roots.

Endpoint: POST {crypto_url}/sign
Request body:
  {
    "key_label": "<key_label>",
    "data_b64": "<base64(bytes.fromhex(merkle_root))>",
    "prehash": true
  }
Response:
  {
    "algorithm": "<Ed25519|SM2|...>",
    "kek_id": "<key version / fingerprint>",
    "kek_version": <int>,
    "signature_b64": "<base64-encoded signature>"
  }

Algorithm selection:
  - hash_algorithm == "SHA-256" (default): uses `crypto_signing_key_label`
    (Ed25519 or ECDSA-P256 KEK in crypto-service).
  - hash_algorithm == "SM3" (国密优先): uses `crypto_signing_key_label_sm2`
    (SM2 KEK in crypto-service). Signature encoding is DER (ASN.1).

The algorithm is fully determined by the KEK stored in crypto-service;
the client selects the correct key label based on hash_algorithm config.
"""

from __future__ import annotations

import base64
from typing import Any

import httpx

from foundation_audit.config import get_settings
from foundation_audit.observability import get_logger

log = get_logger(__name__)

# Module-level reusable async client (keep-alive connection pool)
_http_client: httpx.AsyncClient | None = None


def _get_http_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None:
        s = get_settings()
        _http_client = httpx.AsyncClient(
            base_url=str(s.crypto_url),
            timeout=10.0,
            http2=True,
        )
    return _http_client


def _active_key_label() -> str:
    """Return the key label for the current hash_algorithm mode.

    - SHA-256 mode → crypto_signing_key_label (Ed25519 / ECDSA-P256)
    - SM3 mode     → crypto_signing_key_label_sm2 (SM2, 国密优先)
    """
    s = get_settings()
    if s.hash_algorithm == "SM3":
        return s.crypto_signing_key_label_sm2
    return s.crypto_signing_key_label


async def sign_merkle_root(
    root_hex: str,
    *,
    tenant_id: str,
) -> tuple[str, str]:
    """Sign the Merkle root via crypto-service.

    Args:
        root_hex: 64-char hex string (SHA-256 or SM3 Merkle root).
        tenant_id: Used for X-Tenant-Id header routing.

    Returns:
        (signature_b64, kek_id) — both strings.

    Raises:
        httpx.HTTPStatusError: on non-2xx responses.
        httpx.RequestError: on network failures.

    Algorithm selection:
        The key label sent to crypto-service determines the signing algorithm.
        When hash_algorithm == "SM3", the SM2 key label is used automatically;
        crypto-service signs with SM2 (DER-encoded signature) using the KEK's
        algorithm. No explicit "algorithm" field is required in the request —
        crypto-service derives it from the KEK record.
    """
    client = _get_http_client()
    key_label = _active_key_label()

    root_bytes = bytes.fromhex(root_hex)
    data_b64 = base64.b64encode(root_bytes).decode()

    payload: dict[str, Any] = {
        "key_label": key_label,
        "data_b64": data_b64,
        "prehash": True,
    }

    log.debug(
        "crypto.sign.request",
        key_label=key_label,
        hash_algorithm=get_settings().hash_algorithm,
    )

    resp = await client.post(
        "/sign",
        json=payload,
        headers={"X-Tenant-Id": tenant_id},
    )
    resp.raise_for_status()
    body = resp.json()
    # Crypto API returns kek_id; handle both kek_id and key_id for compatibility
    kek_id = body.get("kek_id") or body.get("key_id") or ""
    return body["signature_b64"], kek_id


async def verify_signature(
    root_hex: str,
    signature_b64: str,
    kek_id: str,  # kept as positional arg name for backwards compat; unused by API
    *,
    tenant_id: str,
    key_label: str | None = None,
) -> bool:
    """Verify a signature via crypto-service.

    Args:
        root_hex: 64-char hex Merkle root (SHA-256 or SM3).
        signature_b64: base64-encoded signature from sign_merkle_root.
        kek_id: Kept for backward-compatibility; not sent to the API.
                The crypto VerifyRequest identifies keys by key_label + kek_version.
        tenant_id: X-Tenant-Id routing header.
        key_label: Override the key label (e.g. when verifying historical batches
                   signed with a specific key). Defaults to _active_key_label().

    Returns:
        True if signature is valid, False otherwise.

    Note:
        If crypto-service is unreachable, logs a warning and returns False
        (conservative — treat as invalid for integrity checks).
        Works for both Ed25519 (SHA-256 mode) and SM2/DER (SM3 mode).
    """
    client = _get_http_client()
    used_label = key_label if key_label is not None else _active_key_label()

    root_bytes = bytes.fromhex(root_hex)
    data_b64 = base64.b64encode(root_bytes).decode()

    payload: dict[str, Any] = {
        "key_label": used_label,
        "data_b64": data_b64,
        "signature_b64": signature_b64,
        "prehash": True,
    }

    try:
        resp = await client.post(
            "/verify",
            json=payload,
            headers={"X-Tenant-Id": tenant_id},
        )
        resp.raise_for_status()
        body = resp.json()
        return bool(body.get("valid", False))
    except (httpx.HTTPStatusError, httpx.RequestError):
        log.warning(
            "crypto.verify.failed",
            key_label=used_label,
            tenant_id=tenant_id,
        )
        return False


async def close() -> None:
    """Close the underlying HTTP connection pool (call on app shutdown)."""
    global _http_client
    if _http_client is not None:
        await _http_client.aclose()
        _http_client = None

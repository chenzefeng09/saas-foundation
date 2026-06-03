"""Crypto-service HTTP client for signing Merkle roots.

Endpoint: POST {crypto_url}/sign
Request body:
  {
    "key_label": "<settings.crypto_signing_key_label>",
    "data_b64": "<base64(bytes.fromhex(merkle_root))>",
    "prehash": true
  }
Response:
  {
    "signature_b64": "<base64-encoded Ed25519 signature>",
    "key_id": "<key version / fingerprint>"
  }

Ed25519 is chosen by the KEK algorithm stored in crypto-service;
the client does not need to specify the algorithm.

# TODO(SM2/SM3 — crypto v1.1):
#   When crypto-service adds Tongsuo PKCS#11 backend support for SM2:
#   - Set key_label to the SM2 KEK (e.g. "audit.hashchain.sm2")
#   - Pass "algorithm": "sm2" in the request body (crypto v1.1 API extension)
#   - Signature encoding changes to DER (ASN.1), adjust verify accordingly
#   - This code path is gated by settings.hash_algorithm == "SM3"
#   No implementation here — dependency: crypto-service v1.1 + Tongsuo build.
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


async def sign_merkle_root(
    root_hex: str,
    *,
    tenant_id: str,
) -> tuple[str, str]:
    """Sign the Merkle root via crypto-service.

    Args:
        root_hex: 64-char hex string (SHA-256 Merkle root).
        tenant_id: Used for X-Tenant-Id header routing.

    Returns:
        (signature_b64, key_id) — both strings.

    Raises:
        httpx.HTTPStatusError: on non-2xx responses.
        httpx.RequestError: on network failures.
    """
    s = get_settings()
    client = _get_http_client()

    root_bytes = bytes.fromhex(root_hex)
    data_b64 = base64.b64encode(root_bytes).decode()

    payload: dict[str, Any] = {
        "key_label": s.crypto_signing_key_label,
        "data_b64": data_b64,
        "prehash": True,
    }

    # TODO(SM2/SM3): when hash_algorithm == "SM3", add "algorithm": "sm2"
    # and ensure key_label points to an SM2 KEK (crypto v1.1 required).

    resp = await client.post(
        "/sign",
        json=payload,
        headers={"X-Tenant-Id": tenant_id},
    )
    resp.raise_for_status()
    body = resp.json()
    return body["signature_b64"], body["key_id"]


async def verify_signature(
    root_hex: str,
    signature_b64: str,
    key_id: str,
    *,
    tenant_id: str,
) -> bool:
    """Verify an Ed25519 signature via crypto-service.

    Args:
        root_hex: 64-char hex Merkle root.
        signature_b64: base64-encoded signature from sign_merkle_root.
        key_id: key version / fingerprint returned by sign.
        tenant_id: X-Tenant-Id routing header.

    Returns:
        True if signature is valid, False otherwise.

    Note:
        If crypto-service is unreachable, logs a warning and returns False
        (conservative — treat as invalid for integrity checks).

    # TODO(SM2/SM3): Add "algorithm": "sm2" to verify payload when using SM2 key.
    """
    client = _get_http_client()

    root_bytes = bytes.fromhex(root_hex)
    data_b64 = base64.b64encode(root_bytes).decode()

    payload: dict[str, Any] = {
        "key_id": key_id,
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
        log.warning("crypto.verify.failed", key_id=key_id, tenant_id=tenant_id)
        return False


async def close() -> None:
    """Close the underlying HTTP connection pool (call on app shutdown)."""
    global _http_client
    if _http_client is not None:
        await _http_client.aclose()
        _http_client = None

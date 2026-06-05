"""Hash chain computation for audit events (audit-v1 §3.1).

Produces:
  - prev_hash: hash of the previous event in the chain (per tenant × service).
  - curr_hash: H(prev_hash || canonical_json(event)).

Hash algorithm is configurable (settings.hash_algorithm):
  - "SHA-256" (default, FIPS 140-2): uses hashlib.sha256.
  - "SM3" (国密优先模式, GB/T 32905-2016): uses foundation_crypto.sm3
    pure-Python implementation (hardware-accelerated on Tongsuo builds).

The chain is per (tenant_id, service) — so each service in each tenant
has its own independent hash chain. This makes it feasible to verify
a single tenant's audit trail without scanning everything.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def _make_hasher(hash_algorithm: str):
    """Return a hasher object for the given algorithm name.

    Supports "SHA-256" (via hashlib) and "SM3" (via foundation_crypto.sm3).
    For any other value, falls through to hashlib.new() which will raise
    a ValueError if the algorithm is unsupported.
    """
    normalized = hash_algorithm.upper().replace("-", "")
    if normalized == "SM3":
        # Import here to avoid a hard dependency when running in SHA-256 mode.
        from foundation_crypto.sm3 import SM3  # type: ignore[import]
        return SM3()
    # SHA256 → "sha256", SHA-256 → "sha256", etc.
    return hashlib.new(hash_algorithm.lower().replace("-", ""))


def compute_chain_hash(
    *,
    prev_hash: str | None,
    event_data: dict[str, Any],
    hash_algorithm: str = "SHA-256",
) -> tuple[str, str]:
    """Compute (prev_hash, curr_hash) for an event.

    prev_hash is H(previous event) — all-zero hex string if first in chain.
    curr_hash is H(prev_hash_bytes || canonical_json(event_data)).

    Returns (prev_hash_hex, curr_hash_hex), both 64-char hex strings.
    Works for both SHA-256 and SM3 (both produce 256-bit / 64-char hex output).
    """
    canon = _canonical_bytes(event_data)

    if prev_hash is None:
        prev_hash = "0" * 64  # genesis block

    h = _make_hasher(hash_algorithm)
    h.update(bytes.fromhex(prev_hash))
    h.update(canon)
    curr_hash = h.hexdigest()

    return prev_hash, curr_hash


def compute_merkle_root(leaf_hashes: list[str], hash_algorithm: str = "SHA-256") -> str:
    """Compute Merkle tree root from a list of leaf hashes.

    Pads with last leaf to make a power-of-two count.
    Returns 64-char hex string.
    Works for both SHA-256 and SM3.
    """
    if not leaf_hashes:
        return "0" * 64

    leaves = list(leaf_hashes)

    # Pad to power of 2
    while len(leaves) & (len(leaves) - 1):
        leaves.append(leaves[-1])

    while len(leaves) > 1:
        next_level: list[str] = []
        for i in range(0, len(leaves), 2):
            h = _make_hasher(hash_algorithm)
            h.update(bytes.fromhex(leaves[i]))
            h.update(bytes.fromhex(leaves[i + 1]))
            next_level.append(h.hexdigest())
        leaves = next_level
    return leaves[0]


def _canonical_bytes(data: dict[str, Any]) -> bytes:
    """Canonical JSON representation: sorted keys, no whitespace, ASCII."""
    # We remove hash-related fields that are set by the server
    clean = {
        k: v
        for k, v in data.items()
        if k not in ("prev_hash", "curr_hash", "merkle_batch_id", "merkle_leaf_idx", "batch_signature")
    }
    return json.dumps(clean, sort_keys=True, separators=(",", ":")).encode("utf-8")

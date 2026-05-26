"""Hash chain computation for audit events (audit-v1 §3.1).

Produces:
  - prev_hash: SHA-256 of the previous event in the chain (per tenant × service).
  - curr_hash: SHA-256(prev_hash || canonical_json(event)).

The chain is per (tenant_id, service) — so each service in each tenant
has its own independent hash chain. This makes it feasible to verify
a single tenant's audit trail without scanning everything.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def compute_chain_hash(
    *,
    prev_hash: str | None,
    event_data: dict[str, Any],
    hash_algorithm: str = "SHA-256",
) -> tuple[str, str]:
    """Compute (prev_hash, curr_hash) for an event.

    prev_hash is SHA-256 of the previous event (all-zero if first in chain).
    curr_hash is SHA-256(prev_hash || canonical(event_data)).

    Returns (prev_hash_hex, curr_hash_hex), both 64-char hex strings.
    """
    canon = _canonical_bytes(event_data)

    if prev_hash is None:
        prev_hash = "0" * 64  # genesis block

    h = hashlib.new(hash_algorithm.lower().replace("-", ""))
    h.update(bytes.fromhex(prev_hash))
    h.update(canon)
    curr_hash = h.hexdigest()

    # Pad to 64 chars (SHA-256 default; SM3 = 64 chars too)
    return prev_hash, curr_hash


def compute_merkle_root(leaf_hashes: list[str], hash_algorithm: str = "SHA-256") -> str:
    """Compute Merkle tree root from a list of leaf hashes.

    Pads with last leaf to make a power-of-two count.
    Returns 64-char hex string.
    """
    if not leaf_hashes:
        return "0" * 64

    leaves = list(leaf_hashes)

    # Pad to power of 2
    while len(leaves) & (len(leaves) - 1):
        leaves.append(leaves[-1])

    h = hashlib.new(hash_algorithm.lower().replace("-", ""))
    while len(leaves) > 1:
        next_level: list[str] = []
        for i in range(0, len(leaves), 2):
            h = hashlib.new(hash_algorithm.lower().replace("-", ""))
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

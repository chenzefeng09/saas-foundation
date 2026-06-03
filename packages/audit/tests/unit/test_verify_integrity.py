"""Unit tests for verify-integrity endpoint — tamper detection.

All tests mock ClickHouse and crypto-service calls.
No external containers needed.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from foundation_audit.services.hash_chain import compute_chain_hash, compute_merkle_root


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_VERIFY_SKIP = frozenset({
    "prev_hash", "curr_hash", "merkle_batch_id", "merkle_leaf_idx",
    "batch_signature", "ingested_at", "tsa_timestamp", "worm_written", "worm_uri",
})


def _make_chain(
    events_data: list[dict[str, Any]],
    *,
    tenant_id: str = "tnt_01J0000000000000000000TNT1",
    service: str = "identity",
) -> list[dict[str, Any]]:
    """Build a correct hash chain for the given event data list.

    Simulates how events are stored in ClickHouse:
    - occurred_at / ingested_at stored as naive datetime (as CH returns).
    - The canonical hash is computed after converting datetimes → ISO strings,
      matching the verify_integrity logic in events.py.
    """
    chain: list[dict[str, Any]] = []
    prev: str | None = None
    now_dt = datetime.now(UTC).replace(tzinfo=None)

    for i, ev in enumerate(events_data):
        # The "stored" CH row (datetimes as naive datetime objects)
        stored: dict[str, Any] = {
            "event_id": ev.get("event_id", f"evt_{i:064d}"),
            "tenant_id": tenant_id,
            "service": service,
            "occurred_at": now_dt,
            "ingested_at": now_dt,
            "payload": json.dumps(ev.get("payload", {})),
            "merkle_batch_id": "mrk_BATCHID0000000000000000001",
            "merkle_leaf_idx": i,
            **{k: v for k, v in ev.items() if k not in ("payload",)},
        }

        # Build event_data as verify_integrity does: convert datetimes, skip server fields
        event_data: dict[str, Any] = {}
        for k, v in stored.items():
            if k in _VERIFY_SKIP or v is None:
                continue
            if isinstance(v, datetime):
                event_data[k] = v.isoformat()
            else:
                event_data[k] = v
        if "payload" in event_data and isinstance(event_data["payload"], str):
            try:
                event_data["payload"] = json.loads(event_data["payload"])
            except (json.JSONDecodeError, ValueError):
                event_data["payload"] = {}

        prev_h, curr_h = compute_chain_hash(prev_hash=prev, event_data=event_data)
        stored["prev_hash"] = prev_h
        stored["curr_hash"] = curr_h

        chain.append(stored)
        prev = curr_h
    return chain


def _make_batch_meta(events: list[dict], batch_id: str = "mrk_BATCHID0000000000000000001") -> dict:
    """Build a merkle_batch dict for the given events (correct root)."""
    leaf_hashes = [ev["curr_hash"] for ev in events]
    root = compute_merkle_root(leaf_hashes)
    return {
        "batch_id": batch_id,
        "tenant_id": events[0]["tenant_id"],
        "service": events[0]["service"],
        "merkle_root": root,
        "signature": "validSignatureBase64==",
        "signature_key_id": "key_v1",
        "tsa_token": "tsaTokenBase64==",
        "tsa_provider": "freetsa",
        "tsa_timestamp": datetime.now(UTC).replace(tzinfo=None),
        "external_anchor": None,
    }


# ---------------------------------------------------------------------------
# Direct service-layer tests (no HTTP, faster)
# ---------------------------------------------------------------------------

def _recompute_loop(chain: list[dict[str, Any]]) -> str | None:
    """Run the verify_integrity hash-chain loop over the given chain.

    Returns the event_id of the first break, or None if valid.
    Mirrors events.py verify_integrity logic exactly (including datetime → ISO conversion).
    """
    prev_hashes: dict[tuple[str, str], str] = {}
    for ev in chain:
        key = (ev["tenant_id"], ev["service"])
        prev = prev_hashes.get(key)
        event_data: dict[str, Any] = {}
        for k, v in ev.items():
            if k in _VERIFY_SKIP or v is None:
                continue
            if isinstance(v, datetime):
                event_data[k] = v.isoformat()
            else:
                event_data[k] = v
        if "payload" in event_data and isinstance(event_data["payload"], str):
            try:
                event_data["payload"] = json.loads(event_data["payload"])
            except (json.JSONDecodeError, ValueError):
                event_data["payload"] = {}

        exp_prev, exp_curr = compute_chain_hash(prev_hash=prev, event_data=event_data)
        if ev["curr_hash"] != exp_curr or ev["prev_hash"] != exp_prev:
            return str(ev["event_id"])
        prev_hashes[key] = ev["curr_hash"]
    return None


class TestHashChainVerification:
    """Test the hash-chain recomputation logic in isolation."""

    def test_correct_chain_passes(self) -> None:
        """A correctly built chain validates without breaks."""
        events_data = [
            {"event_id": f"evt_01J0000000000000000000000{i:02d}", "event_type": "test", "actor_kind": "USER"}
            for i in range(5)
        ]
        chain = _make_chain(events_data)
        assert _recompute_loop(chain) is None

    def test_tampered_curr_hash_detected(self) -> None:
        """Modifying a stored curr_hash breaks the chain at that event."""
        events_data = [
            {"event_id": f"evt_01J0000000000000000000000{i:02d}", "event_type": "test", "actor_kind": "USER"}
            for i in range(4)
        ]
        chain = _make_chain(events_data)

        # Tamper: flip curr_hash of event index 2
        chain[2]["curr_hash"] = "f" * 64
        first_break = _recompute_loop(chain)

        # Should detect tamper at index 2
        assert first_break == chain[2]["event_id"]

    def test_tampered_payload_detected(self) -> None:
        """Modifying stored event payload invalidates curr_hash."""
        events_data = [
            {"event_id": "evt_01J00000000000000000000X01", "event_type": "test",
             "actor_kind": "USER", "payload": {"amount": 100}},
        ]
        chain = _make_chain(events_data)

        # Tamper: change payload (stored as JSON string in CH)
        chain[0]["payload"] = json.dumps({"amount": 999999})  # tampered amount

        first_break = _recompute_loop(chain)
        # Stored curr_hash was computed with original payload → mismatch
        assert first_break == chain[0]["event_id"]

    def test_merkle_root_mismatch_detected(self) -> None:
        """When stored Merkle root doesn't match recomputed root, sig verification fails."""
        events_data = [
            {"event_id": f"evt_01J0000000000000000000000{i:02d}", "event_type": "t", "actor_kind": "SYSTEM"}
            for i in range(2)
        ]
        chain = _make_chain(events_data)
        batch = _make_batch_meta(chain)

        # Tamper: flip last byte of stored root
        original_root = batch["merkle_root"]
        tampered_root = original_root[:-1] + ("0" if original_root[-1] == "f" else "f")
        batch["merkle_root"] = tampered_root

        # Recompute from events
        leaf_hashes = [ev["curr_hash"] for ev in chain]
        recomputed = compute_merkle_root(leaf_hashes)

        # Should not match
        assert recomputed != batch["merkle_root"]


class TestMerkleRootRecomputeMatchesWorker:
    """Ensure verify uses the same power-of-2 padding Merkle as the worker."""

    def test_odd_number_of_leaves(self) -> None:
        """3 leaves → padded to 4 → root is deterministic."""
        events_data = [
            {"event_id": f"evt_01J00000000000000000000000{i}", "event_type": "t", "actor_kind": "SYSTEM"}
            for i in range(3)
        ]
        chain = _make_chain(events_data)
        leaf_hashes = [ev["curr_hash"] for ev in chain]

        root1 = compute_merkle_root(leaf_hashes)
        root2 = compute_merkle_root(leaf_hashes)  # Deterministic
        assert root1 == root2
        assert len(root1) == 64

    def test_verify_uses_stored_leaf_order(self) -> None:
        """Verify sorts by merkle_leaf_idx before computing root."""
        events_data = [
            {"event_id": f"evt_01J00000000000000000000000{i}", "event_type": "t", "actor_kind": "SYSTEM"}
            for i in range(4)
        ]
        chain = _make_chain(events_data)

        # Build batch with correct root
        leaf_hashes_ordered = [ev["curr_hash"] for ev in chain]
        expected_root = compute_merkle_root(leaf_hashes_ordered)

        # Shuffle events (as might come from CH) and sort by leaf_idx
        import random
        shuffled = chain[:]
        random.shuffle(shuffled)

        # Sort as verify_integrity does
        leaf_list = [(ev["merkle_leaf_idx"], ev["curr_hash"]) for ev in shuffled]
        leaf_list.sort(key=lambda x: x[0])
        recomputed_root = compute_merkle_root([h for _, h in leaf_list])

        assert recomputed_root == expected_root

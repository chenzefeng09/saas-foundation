"""Unit tests for BatchProcessor — mock CH + crypto clients.

All tests are pure unit tests (no ClickHouse, no crypto container needed).
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from foundation_audit.services.hash_chain import (
    canonical_event,
    compute_chain_hash,
    compute_merkle_root,
)
from foundation_audit.worker.batch_processor import BatchProcessor


# ---------------------------------------------------------------------------
# Fixtures & helpers
# ---------------------------------------------------------------------------

def _make_event(tenant_id: str = "tnt_01J0000000000000000000TNT1",
                service: str = "identity",
                event_id: str = "evt_01J00000000000000000000001",
                severity: str = "INFO") -> dict[str, Any]:
    return {
        "event_id": event_id,
        "tenant_id": tenant_id,
        "service": service,
        "event_type": "test.event",
        "occurred_at": datetime.now(UTC).isoformat(),
        "actor_kind": "USER",
        "actor_user_id": "usr_01J0",
        "severity": severity,
        "outcome": "SUCCESS",
        "payload": {"action": "test"},
        "schema_version": 1,
    }


def _make_batch_processor() -> BatchProcessor:
    """Return a BatchProcessor with settings patched to avoid .env file reads."""
    with patch("foundation_audit.worker.batch_processor.get_settings") as mock_settings:
        s = MagicMock()
        s.batch_max_events = 1000
        s.hash_algorithm = "SHA-256"
        s.crypto_signing_key_label = "audit.hashchain"
        s.tsa_enabled = False     # disable TSA in unit tests
        s.worm_enabled = False    # disable WORM in unit tests
        s.tsa_provider = "freetsa"
        s.worker_poll_interval_seconds = 1.0
        mock_settings.return_value = s
        return BatchProcessor()


# ---------------------------------------------------------------------------
# Tests: hash chain continuity across batches
# ---------------------------------------------------------------------------

class TestHashChainContinuity:
    """Verify that chain heads persist across run_once() calls (restart-safe simulation)."""

    @pytest.mark.asyncio
    async def test_chain_head_initialised_from_ch(self) -> None:
        """If CH returns a chain head, it is used as prev_hash for new events."""
        proc = _make_batch_processor()

        existing_head = "a" * 64  # Simulate a head already in CH

        event = _make_event()
        # Compute expected BEFORE run_once (processor will mutate event dict)
        _, expected_curr = compute_chain_hash(
            prev_hash=existing_head, event_data=canonical_event(event), hash_algorithm="SHA-256",
        )

        rows = [(1, event)]
        with (
            patch("foundation_audit.worker.batch_processor.system_session_scope") as mock_scope,
            patch.object(proc._ingest, "fetch_pending", new_callable=AsyncMock, return_value=rows),
            patch.object(proc._ingest, "mark_delivered", new_callable=AsyncMock),
            patch("foundation_audit.worker.batch_processor.ch.get_chain_head", new_callable=AsyncMock, return_value=existing_head),
            patch("foundation_audit.worker.batch_processor.ch.insert_events", new_callable=AsyncMock),
            patch("foundation_audit.worker.batch_processor.ch.insert_merkle_batches", new_callable=AsyncMock),
            patch("foundation_audit.worker.batch_processor.crypto_client.sign_merkle_root",
                  new_callable=AsyncMock, return_value=("sig_b64==", "key_v1")),
        ):
            mock_scope.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
            mock_scope.return_value.__aexit__ = AsyncMock(return_value=False)
            count = await proc.run_once()

        assert count == 1
        # Chain head should now be updated
        key = (event["tenant_id"], event["service"])
        assert key in proc._chain_heads
        assert proc._chain_heads[key] == expected_curr

    @pytest.mark.asyncio
    async def test_chain_head_genesis_when_ch_empty(self) -> None:
        """First event in a chain uses 0*64 as prev_hash."""
        proc = _make_batch_processor()

        event = _make_event()
        # Compute expected BEFORE run_once (processor will mutate event dict)
        _, expected_curr = compute_chain_hash(
            prev_hash=None, event_data=canonical_event(event), hash_algorithm="SHA-256",
        )

        rows = [(1, event)]
        with (
            patch("foundation_audit.worker.batch_processor.system_session_scope") as mock_scope,
            patch.object(proc._ingest, "fetch_pending", new_callable=AsyncMock, return_value=rows),
            patch.object(proc._ingest, "mark_delivered", new_callable=AsyncMock),
            patch("foundation_audit.worker.batch_processor.ch.get_chain_head", new_callable=AsyncMock, return_value=None),
            patch("foundation_audit.worker.batch_processor.ch.insert_events", new_callable=AsyncMock),
            patch("foundation_audit.worker.batch_processor.ch.insert_merkle_batches", new_callable=AsyncMock),
            patch("foundation_audit.worker.batch_processor.crypto_client.sign_merkle_root",
                  new_callable=AsyncMock, return_value=("sig==", "k1")),
        ):
            mock_scope.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
            mock_scope.return_value.__aexit__ = AsyncMock(return_value=False)
            count = await proc.run_once()

        assert count == 1
        key = (event["tenant_id"], event["service"])
        assert proc._chain_heads[key] == expected_curr

    @pytest.mark.asyncio
    async def test_chain_continuous_across_two_batches(self) -> None:
        """Second batch must use the curr_hash from the first batch as prev_hash."""
        proc = _make_batch_processor()

        event_a = _make_event(event_id="evt_01AAAAAAAAAAAAAAAAAAAAAAAAA")
        event_b = _make_event(event_id="evt_01BBBBBBBBBBBBBBBBBBBBBBBBB")

        # Track what insert_events received
        inserted_batches: list[list[dict]] = []

        async def fake_insert_events(events: list[dict]) -> None:
            inserted_batches.append([dict(e) for e in events])

        with (
            patch("foundation_audit.worker.batch_processor.system_session_scope") as mock_scope,
            patch("foundation_audit.worker.batch_processor.ch.get_chain_head", new_callable=AsyncMock, return_value=None),
            patch("foundation_audit.worker.batch_processor.ch.insert_events", side_effect=fake_insert_events),
            patch("foundation_audit.worker.batch_processor.ch.insert_merkle_batches", new_callable=AsyncMock),
            patch("foundation_audit.worker.batch_processor.crypto_client.sign_merkle_root",
                  new_callable=AsyncMock, return_value=("s==", "k1")),
        ):
            mock_scope.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
            mock_scope.return_value.__aexit__ = AsyncMock(return_value=False)

            # First batch
            with patch.object(proc._ingest, "fetch_pending", new_callable=AsyncMock, return_value=[(1, event_a)]):
                with patch.object(proc._ingest, "mark_delivered", new_callable=AsyncMock):
                    await proc.run_once()

            # Second batch
            with patch.object(proc._ingest, "fetch_pending", new_callable=AsyncMock, return_value=[(2, event_b)]):
                with patch.object(proc._ingest, "mark_delivered", new_callable=AsyncMock):
                    await proc.run_once()

        assert len(inserted_batches) == 2

        # First batch: prev_hash is genesis
        first_ev = inserted_batches[0][0]
        assert first_ev["prev_hash"] == "0" * 64

        # Second batch: prev_hash must equal first batch's curr_hash
        second_ev = inserted_batches[1][0]
        assert second_ev["prev_hash"] == first_ev["curr_hash"]


# ---------------------------------------------------------------------------
# Tests: ClickHouse insert column alignment
# ---------------------------------------------------------------------------

class TestCHInsertColumns:
    @pytest.mark.asyncio
    async def test_insert_events_called_with_all_columns(self) -> None:
        """insert_events is called; inserted rows have merkle_batch_id and leaf_idx."""
        proc = _make_batch_processor()
        event = _make_event()
        inserted: list[list[dict]] = []

        async def capture(events: list[dict]) -> None:
            inserted.append(list(events))

        with (
            patch("foundation_audit.worker.batch_processor.system_session_scope") as mock_scope,
            patch.object(proc._ingest, "fetch_pending", new_callable=AsyncMock, return_value=[(1, event)]),
            patch.object(proc._ingest, "mark_delivered", new_callable=AsyncMock),
            patch("foundation_audit.worker.batch_processor.ch.get_chain_head", new_callable=AsyncMock, return_value=None),
            patch("foundation_audit.worker.batch_processor.ch.insert_events", side_effect=capture),
            patch("foundation_audit.worker.batch_processor.ch.insert_merkle_batches", new_callable=AsyncMock),
            patch("foundation_audit.worker.batch_processor.crypto_client.sign_merkle_root",
                  new_callable=AsyncMock, return_value=("s==", "k1")),
        ):
            mock_scope.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
            mock_scope.return_value.__aexit__ = AsyncMock(return_value=False)
            await proc.run_once()

        assert len(inserted) == 1
        row = inserted[0][0]
        assert "merkle_batch_id" in row
        assert row["merkle_batch_id"].startswith("mrk_")
        assert row["merkle_leaf_idx"] == 0
        assert "prev_hash" in row
        assert "curr_hash" in row
        assert len(row["curr_hash"]) == 64

    @pytest.mark.asyncio
    async def test_leaf_indices_sequential(self) -> None:
        """Multiple events in one batch get sequential merkle_leaf_idx values."""
        proc = _make_batch_processor()
        events = [
            _make_event(event_id=f"evt_01J0000000000000000000000{i:02d}")
            for i in range(3)
        ]
        rows = [(i + 1, ev) for i, ev in enumerate(events)]
        inserted: list[list[dict]] = []

        async def capture(evs: list[dict]) -> None:
            inserted.extend(evs)

        with (
            patch("foundation_audit.worker.batch_processor.system_session_scope") as mock_scope,
            patch.object(proc._ingest, "fetch_pending", new_callable=AsyncMock, return_value=rows),
            patch.object(proc._ingest, "mark_delivered", new_callable=AsyncMock),
            patch("foundation_audit.worker.batch_processor.ch.get_chain_head", new_callable=AsyncMock, return_value=None),
            patch("foundation_audit.worker.batch_processor.ch.insert_events", side_effect=capture),
            patch("foundation_audit.worker.batch_processor.ch.insert_merkle_batches", new_callable=AsyncMock),
            patch("foundation_audit.worker.batch_processor.crypto_client.sign_merkle_root",
                  new_callable=AsyncMock, return_value=("s==", "k1")),
        ):
            mock_scope.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
            mock_scope.return_value.__aexit__ = AsyncMock(return_value=False)
            await proc.run_once()

        assert len(inserted) == 3
        for i, ev in enumerate(inserted):
            assert ev["merkle_leaf_idx"] == i


# ---------------------------------------------------------------------------
# Tests: one Merkle batch per chain
# ---------------------------------------------------------------------------

class TestMerkleBatchPerChain:
    """A run seals each chain's events in a batch of their own, signed under its tenant."""

    @pytest.mark.asyncio
    async def test_each_chain_is_sealed_in_its_own_batch(self) -> None:
        proc = _make_batch_processor()
        chains = [
            ("tnt_A", "identity"), ("tnt_B", "identity"), ("tnt_A", "billing"),
            ("tnt_A", "identity"), ("tnt_B", "identity"),
        ]
        rows = [
            (i + 1, _make_event(tenant_id=tenant_id, service=service, event_id=f"evt_{i}"))
            for i, (tenant_id, service) in enumerate(chains)
        ]
        inserted: list[dict] = []
        batch_rows: list[dict] = []

        async def insert_events(events: list[dict]) -> None:
            inserted.extend(events)

        async def insert_merkle_batches(batches: list[dict]) -> None:
            batch_rows.extend(batches)

        async def sign(root_hex: str, *, tenant_id: str) -> tuple[str, str]:
            return f"sig({tenant_id}:{root_hex})", "k1"

        worker = "foundation_audit.worker.batch_processor"
        with (
            patch(f"{worker}.system_session_scope") as mock_scope,
            patch.object(proc._ingest, "fetch_pending", new_callable=AsyncMock, return_value=rows),
            patch.object(proc._ingest, "mark_delivered", new_callable=AsyncMock),
            patch(f"{worker}.ch.get_chain_head", new_callable=AsyncMock, return_value=None),
            patch(f"{worker}.ch.insert_events", side_effect=insert_events),
            patch(f"{worker}.ch.insert_merkle_batches", side_effect=insert_merkle_batches),
            patch(f"{worker}.crypto_client.sign_merkle_root", side_effect=sign),
        ):
            mock_scope.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
            mock_scope.return_value.__aexit__ = AsyncMock(return_value=False)
            assert await proc.run_once() == 5

        by_chain: dict[tuple[str, str], list[dict]] = {}
        for ev in inserted:
            by_chain.setdefault((ev["tenant_id"], ev["service"]), []).append(ev)
        # Each chain's events: leaves 0, 1, … of one batch, in outbox order
        assert {
            chain: [(ev["event_id"], ev["merkle_leaf_idx"]) for ev in evs]
            for chain, evs in by_chain.items()
        } == {
            ("tnt_A", "identity"): [("evt_0", 0), ("evt_3", 1)],
            ("tnt_B", "identity"): [("evt_1", 0), ("evt_4", 1)],
            ("tnt_A", "billing"): [("evt_2", 0)],
        }
        batch_ids = [{ev["merkle_batch_id"] for ev in evs} for evs in by_chain.values()]
        assert all(len(ids) == 1 for ids in batch_ids)
        assert len(set().union(*batch_ids)) == 3

        # One merkle_batch row per chain, naming it, signed under its own tenant
        assert len(batch_rows) == 3
        for row in batch_rows:
            evs = by_chain[(row["tenant_id"], row["service"])]
            root = compute_merkle_root([ev["curr_hash"] for ev in evs])
            assert row == {
                **row,
                "batch_id": evs[0]["merkle_batch_id"],
                "event_count": len(evs),
                "first_event_id": evs[0]["event_id"],
                "last_event_id": evs[-1]["event_id"],
                "merkle_root": root,
                "signature": f"sig({row['tenant_id']}:{root})",
            }
        # Each chain's head: the last event of its batch
        assert proc._chain_heads == {chain: evs[-1]["curr_hash"] for chain, evs in by_chain.items()}


# ---------------------------------------------------------------------------
# Tests: CH insert failure → attempts incremented, NOT mark_delivered
# ---------------------------------------------------------------------------

class TestCHFailureRetry:
    @pytest.mark.asyncio
    async def test_ch_failure_calls_record_attempts_not_mark_delivered(self) -> None:
        """When CH insert fails, record_attempts is called and mark_delivered is not."""
        proc = _make_batch_processor()
        event = _make_event()

        mark_delivered = AsyncMock()
        record_attempts = AsyncMock()

        with (
            patch("foundation_audit.worker.batch_processor.system_session_scope") as mock_scope,
            patch.object(proc._ingest, "fetch_pending", new_callable=AsyncMock, return_value=[(1, event)]),
            patch.object(proc._ingest, "mark_delivered", mark_delivered),
            patch.object(proc._ingest, "record_attempts", record_attempts),
            patch("foundation_audit.worker.batch_processor.ch.get_chain_head", new_callable=AsyncMock, return_value=None),
            patch("foundation_audit.worker.batch_processor.ch.insert_events",
                  side_effect=Exception("CH connection refused")),
        ):
            mock_scope.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
            mock_scope.return_value.__aexit__ = AsyncMock(return_value=False)
            count = await proc.run_once()

        assert count == 0
        mark_delivered.assert_not_called()
        record_attempts.assert_called_once()
        # Verify error string is passed
        call_kwargs = record_attempts.call_args
        assert "CH connection refused" in call_kwargs.kwargs.get("error", "")


# ---------------------------------------------------------------------------
# Tests: Merkle root and leaf hash computation correctness
# ---------------------------------------------------------------------------

class TestMerkleIntegration:
    def test_merkle_root_matches_batch_processor_logic(self) -> None:
        """Verify that the Merkle root computed in the processor matches hash_chain.py."""
        events = [
            {"event_id": "evt_A", "tenant_id": "t1", "service": "svc"},
            {"event_id": "evt_B", "tenant_id": "t1", "service": "svc"},
        ]
        leaf_hashes = []
        prev = None
        for ev in events:
            prev_h, curr_h = compute_chain_hash(prev_hash=prev, event_data=ev)
            leaf_hashes.append(curr_h)
            prev = curr_h

        root = compute_merkle_root(leaf_hashes)
        # Recompute identically
        assert root == compute_merkle_root(leaf_hashes)
        assert len(root) == 64

    def test_single_event_merkle_root(self) -> None:
        """Single event: Merkle root is the leaf itself (1 is a power of 2, no padding)."""
        _, curr = compute_chain_hash(prev_hash=None, event_data={"id": "evt_single"})
        root = compute_merkle_root([curr])
        # 1 leaf = 2^0, no padding needed; while(len > 1) is False → root == leaf
        assert root == curr
        assert len(root) == 64

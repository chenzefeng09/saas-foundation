"""Tests for hash chain computation."""

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from foundation_audit.adapters.clickhouse import EVENTS_COLUMNS
from foundation_audit.schemas.event import AuditEvent
from foundation_audit.services.hash_chain import (
    CHAINED_FIELDS,
    canonical_event,
    compute_chain_hash,
    compute_merkle_root,
)


@pytest.mark.usefixtures("local_time_not_utc")
class TestCanonicalEvent:
    """The one form of an event that both its outbox JSON and its stored row give."""

    @pytest.mark.parametrize(
        "occurred_at",
        [
            "2026-10-30T12:00:00.250999Z",  # outbox JSON, to the microsecond
            "2026-10-30T20:00:00.250+08:00",
            "2026-10-30T12:00:00.25",  # sent without an offset: UTC
            datetime(2026, 10, 30, 12, 0, 0, 250000),  # as ClickHouse hands it back
            datetime(2026, 10, 30, 7, 0, 0, 250999, tzinfo=timezone(timedelta(hours=-5))),
        ],
    )
    def test_occurred_at_is_the_utc_millisecond(self, occurred_at: datetime | str) -> None:
        assert canonical_event({"occurred_at": occurred_at}) == {
            "occurred_at": "2026-10-30T12:00:00.250Z",
        }

    def test_empty_and_missing_fields_are_left_out(self) -> None:
        event = {"event_id": "evt_1", "request_id": "", "actor_user_id": None, "payload": {}}

        assert canonical_event(event) == {"event_id": "evt_1", "payload": {}}

    def test_payload_text_is_read_as_json(self) -> None:
        assert canonical_event({"payload": '{"b": [1, 2.5], "a": "é"}'}) == {
            "payload": {"a": "é", "b": [1, 2.5]},
        }

    def test_payload_text_that_is_not_json_stays_text(self) -> None:
        assert canonical_event({"payload": "{not json"}) == {"payload": "{not json"}

    def test_only_chained_fields_count(self) -> None:
        server_side: dict[str, Any] = {
            "ingested_at": datetime(2026, 10, 30, 12, 0, 1),
            "prev_hash": "0" * 64,
            "curr_hash": "a" * 64,
            "merkle_batch_id": "mrk_1",
            "merkle_leaf_idx": 0,
            "payload_size": 2,
            "worm_written": False,
            "sensitive_fields": ["email"],  # not stored
        }

        assert canonical_event({"event_id": "evt_1", **server_side}) == {"event_id": "evt_1"}

    def test_every_stored_event_field_is_chained(self) -> None:
        """A field added to AuditEvent is chained, or deliberately left out, before it ships."""
        assert set(CHAINED_FIELDS) == set(AuditEvent.model_fields) - {"sensitive_fields"}
        assert set(CHAINED_FIELDS) <= set(EVENTS_COLUMNS)


class TestHashChain:
    def test_genesis_event(self) -> None:
        prev, curr = compute_chain_hash(prev_hash=None, event_data={"event_id": "evt_1", "tenant_id": "tnt_1"})
        assert prev == "0" * 64
        assert len(curr) == 64
        assert curr != prev

    def test_chain_deterministic(self) -> None:
        _, c1 = compute_chain_hash(prev_hash=None, event_data={"a": 1, "b": 2})
        _, c2 = compute_chain_hash(prev_hash=None, event_data={"a": 1, "b": 2})
        assert c1 == c2  # same input → same hash

    def test_chain_different_data_different_hash(self) -> None:
        _, c1 = compute_chain_hash(prev_hash=None, event_data={"x": 1})
        _, c2 = compute_chain_hash(prev_hash=None, event_data={"x": 2})
        assert c1 != c2

    def test_chain_linked(self) -> None:
        _, h1 = compute_chain_hash(prev_hash=None, event_data={"id": 1})
        _, h2 = compute_chain_hash(prev_hash=h1, event_data={"id": 2})
        _, h3 = compute_chain_hash(prev_hash=h2, event_data={"id": 3})
        # All different
        assert h1 != h2 != h3
        assert len(h1) == len(h2) == len(h3) == 64

    def test_chain_fields_excluded_from_hash(self) -> None:
        """prev_hash and curr_hash fields are excluded from canonical JSON."""
        _, c1 = compute_chain_hash(prev_hash=None, event_data={"event_id": "evt_1", "prev_hash": "abc", "curr_hash": "def"})
        _, c2 = compute_chain_hash(prev_hash=None, event_data={"event_id": "evt_1", "prev_hash": "xxx", "curr_hash": "yyy"})
        assert c1 == c2  # hash fields are stripped, so same output


class TestMerkleTree:
    def test_single_leaf(self) -> None:
        root = compute_merkle_root(["a" * 64])
        assert len(root) == 64

    def test_two_leaves(self) -> None:
        root = compute_merkle_root(["a" * 64, "b" * 64])
        assert len(root) == 64

    def test_three_leaves_padded(self) -> None:
        root = compute_merkle_root(["a" * 64, "b" * 64, "c" * 64])
        assert len(root) == 64

    def test_empty(self) -> None:
        root = compute_merkle_root([])
        assert root == "0" * 64

    def test_deterministic(self) -> None:
        leaves = [f"{i:064d}" for i in range(4)]
        r1 = compute_merkle_root(leaves)
        r2 = compute_merkle_root(leaves)
        assert r1 == r2

"""Tests for hash chain computation."""

from foundation_audit.services.hash_chain import compute_chain_hash, compute_merkle_root


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

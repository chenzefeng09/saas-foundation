"""End-to-end SM2/SM3 sign + verify tests (国密路径).

These tests exercise:
1. LocalTestKeyProvider: create SM2 key → sign with SM3 hash → verify.
2. SignService orchestration with an SM2 KEK (mocked DB session).
3. Round-trip: data signed under SM2 key cannot be verified by Ed25519 key.
4. SM3 hash chain: compute_chain_hash / compute_merkle_root with hash_algorithm="SM3".

No Tongsuo/PKCS#11 dependency is required — LocalTestKeyProvider proxies SM2
via SECP256K1 + SM3 hash so the code path is fully testable in a standard env.
"""

from __future__ import annotations

import base64

import pytest

from foundation_crypto.adapters.local_test_provider import LocalTestKeyProvider
from foundation_crypto.sm3 import sm3_hash, sm3_hexdigest, SM3


# ---------------------------------------------------------------------------
# 1. LocalTestKeyProvider: SM2 sign / verify round-trip
# ---------------------------------------------------------------------------

class TestLocalProviderSM2:
    """Direct LocalTestKeyProvider tests — no service layer involved."""

    @pytest.fixture
    def provider(self) -> LocalTestKeyProvider:
        return LocalTestKeyProvider()

    @pytest.mark.asyncio
    async def test_create_sm2_key(self, provider: LocalTestKeyProvider) -> None:
        """Creating a key with algorithm="SM2" succeeds."""
        await provider.create_key(vault_path="test/sm2key", algorithm="SM2")
        key = provider._keys.get("test/sm2key")
        assert key is not None
        assert key.algorithm == "SM2"
        assert key.private_key is not None
        assert key.public_key is not None

    @pytest.mark.asyncio
    async def test_sm2_sign_returns_correct_algorithm(self, provider: LocalTestKeyProvider) -> None:
        """sign() on an SM2 key returns algorithm='SM2'."""
        await provider.create_key(vault_path="test/sm2key", algorithm="SM2")
        data = b"hello sm2 world"
        bundle = await provider.sign(vault_path="test/sm2key", data=data, prehashed=False)
        assert bundle.algorithm == "SM2"
        assert len(bundle.signature) > 0
        assert bundle.kek_version == 1

    @pytest.mark.asyncio
    async def test_sm2_sign_verify_roundtrip(self, provider: LocalTestKeyProvider) -> None:
        """Data signed with SM2 key verifies successfully."""
        await provider.create_key(vault_path="test/sm2key", algorithm="SM2")
        data = b"audit merkle root bytes for SM2 test"
        bundle = await provider.sign(vault_path="test/sm2key", data=data, prehashed=False)
        assert bundle.algorithm == "SM2"

        valid = await provider.verify(
            vault_path="test/sm2key",
            data=data,
            signature=bundle.signature,
            prehashed=False,
        )
        assert valid is True

    @pytest.mark.asyncio
    async def test_sm2_verify_wrong_data_fails(self, provider: LocalTestKeyProvider) -> None:
        """A signature on one data blob does not verify against different data."""
        await provider.create_key(vault_path="test/sm2key", algorithm="SM2")
        data = b"correct data"
        bundle = await provider.sign(vault_path="test/sm2key", data=data, prehashed=False)

        valid = await provider.verify(
            vault_path="test/sm2key",
            data=b"tampered data",
            signature=bundle.signature,
            prehashed=False,
        )
        assert valid is False

    @pytest.mark.asyncio
    async def test_sm2_verify_wrong_key_fails(self, provider: LocalTestKeyProvider) -> None:
        """A signature created with key A does not verify under key B."""
        await provider.create_key(vault_path="test/sm2key_a", algorithm="SM2")
        await provider.create_key(vault_path="test/sm2key_b", algorithm="SM2")
        data = b"data signed under key A"
        bundle = await provider.sign(vault_path="test/sm2key_a", data=data, prehashed=False)

        valid = await provider.verify(
            vault_path="test/sm2key_b",
            data=data,
            signature=bundle.signature,
            prehashed=False,
        )
        assert valid is False

    @pytest.mark.asyncio
    async def test_sm2_versus_ed25519_not_interchangeable(self, provider: LocalTestKeyProvider) -> None:
        """SM2 and Ed25519 signatures are not interchangeable."""
        await provider.create_key(vault_path="test/ed25519key", algorithm="Ed25519")
        await provider.create_key(vault_path="test/sm2key", algorithm="SM2")
        data = b"shared data"

        ed_bundle = await provider.sign(vault_path="test/ed25519key", data=data, prehashed=False)
        sm2_bundle = await provider.sign(vault_path="test/sm2key", data=data, prehashed=False)

        # Ed25519 sig cannot verify under SM2 key
        assert not await provider.verify(
            vault_path="test/sm2key", data=data,
            signature=ed_bundle.signature, prehashed=False,
        )
        # SM2 sig cannot verify under Ed25519 key
        assert not await provider.verify(
            vault_path="test/ed25519key", data=data,
            signature=sm2_bundle.signature, prehashed=False,
        )

    @pytest.mark.asyncio
    async def test_sm2_sign_hex_merkle_root(self, provider: LocalTestKeyProvider) -> None:
        """Simulate exactly what audit does: sign bytes of a hex Merkle root."""
        await provider.create_key(vault_path="test/audit.hashchain.sm2", algorithm="SM2")

        # Simulate batch_processor: merkle_root is a 64-char hex string → bytes
        merkle_root_hex = "a" * 64
        root_bytes = bytes.fromhex(merkle_root_hex)

        bundle = await provider.sign(
            vault_path="test/audit.hashchain.sm2",
            data=root_bytes,
            prehashed=False,
        )
        assert bundle.algorithm == "SM2"

        signature_b64 = base64.b64encode(bundle.signature).decode()
        # Decode and verify
        sig_bytes = base64.b64decode(signature_b64)
        valid = await provider.verify(
            vault_path="test/audit.hashchain.sm2",
            data=root_bytes,
            signature=sig_bytes,
            prehashed=False,
        )
        assert valid is True


# ---------------------------------------------------------------------------
# 2. SignService end-to-end with SM2 KEK (mocked DB)
# ---------------------------------------------------------------------------

class TestSignServiceSM2:
    """SignService + LocalTestKeyProvider with an SM2 KEK, using the fake DB session."""

    @pytest.fixture
    def provider(self) -> LocalTestKeyProvider:
        return LocalTestKeyProvider()

    @pytest.mark.asyncio
    async def test_sign_service_sm2_sign_and_verify(
        self, fake_session, provider: LocalTestKeyProvider, tenant_id: str,
    ) -> None:
        """SignService.sign() + verify() round-trip with SM2 KEK."""
        from foundation_crypto.services.sign_service import SignService
        from foundation_crypto.schemas.sign import SignRequest, VerifyRequest
        from tests._factories import make_sm2_signing_kek

        svc = SignService(key_provider=provider)
        kek = make_sm2_signing_kek(tenant_id=tenant_id)
        await provider.create_key(vault_path=kek.vault_path, algorithm="SM2")

        # Queue the KEK for session lookup (sign)
        fake_session.queue_execute([kek])

        data = b"SM2 test data for sign service"
        data_b64 = base64.b64encode(data).decode()

        sign_resp = await svc.sign(
            fake_session,
            tenant_id=tenant_id,
            request=SignRequest(
                key_label=kek.label,
                data_b64=data_b64,
                prehash=False,
            ),
        )
        assert sign_resp.algorithm == "SM2"
        assert sign_resp.kek_id == kek.id
        assert sign_resp.kek_version == 1
        assert len(sign_resp.signature_b64) > 0

        # Now verify
        fake_session.queue_execute([kek])

        verify_resp = await svc.verify(
            fake_session,
            tenant_id=tenant_id,
            request=VerifyRequest(
                key_label=kek.label,
                data_b64=data_b64,
                signature_b64=sign_resp.signature_b64,
                prehash=False,
            ),
        )
        assert verify_resp.valid is True
        assert verify_resp.algorithm == "SM2"


# ---------------------------------------------------------------------------
# 3. SM3 hash correctness (pure-Python implementation)
# ---------------------------------------------------------------------------

class TestSM3Hash:
    """Verify the pure-Python SM3 implementation against known test vectors."""

    def test_sm3_empty_message(self) -> None:
        """SM3("") known digest per GB/T 32905-2016 test vector."""
        # From the standard: SM3("") = 1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b
        expected = "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"
        assert sm3_hexdigest(b"") == expected

    def test_sm3_abc(self) -> None:
        """SM3("abc") known digest per standard."""
        expected = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
        assert sm3_hexdigest(b"abc") == expected

    def test_sm3_repeated_a(self) -> None:
        """SM3("abcd" * 16) known digest per standard."""
        # "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
        msg = b"abcd" * 16
        expected = "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"
        assert sm3_hexdigest(msg) == expected

    def test_sm3_output_length(self) -> None:
        """SM3 always produces 32 bytes / 64 hex chars."""
        assert len(sm3_hash(b"anything")) == 32
        assert len(sm3_hexdigest(b"anything")) == 64

    def test_sm3_object_update_matches_oneshot(self) -> None:
        """Incremental SM3 update matches one-shot sm3_hash."""
        data = b"hello world this is a test message for SM3"
        h = SM3()
        h.update(data[:10])
        h.update(data[10:])
        assert h.hexdigest() == sm3_hexdigest(data)

    def test_sm3_copy(self) -> None:
        """SM3.copy() correctly forks the state."""
        h = SM3()
        h.update(b"prefix")
        h2 = h.copy()
        h.update(b"_suffix_a")
        h2.update(b"_suffix_b")
        # They should differ since suffixes differ
        assert h.hexdigest() != h2.hexdigest()


# ---------------------------------------------------------------------------
# 4. SM3 hash chain integration
# ---------------------------------------------------------------------------

class TestSM3HashChain:
    """compute_chain_hash / compute_merkle_root with hash_algorithm="SM3"."""

    def test_sm3_chain_hash_genesis(self) -> None:
        from foundation_audit.services.hash_chain import compute_chain_hash
        prev, curr = compute_chain_hash(
            prev_hash=None,
            event_data={"event_id": "evt_sm3_001", "tenant_id": "tnt_test"},
            hash_algorithm="SM3",
        )
        assert prev == "0" * 64
        assert len(curr) == 64
        assert curr != prev

    def test_sm3_chain_hash_deterministic(self) -> None:
        from foundation_audit.services.hash_chain import compute_chain_hash
        _, c1 = compute_chain_hash(
            prev_hash=None, event_data={"a": 1}, hash_algorithm="SM3",
        )
        _, c2 = compute_chain_hash(
            prev_hash=None, event_data={"a": 1}, hash_algorithm="SM3",
        )
        assert c1 == c2

    def test_sm3_chain_hash_differs_from_sha256(self) -> None:
        """SM3 and SHA-256 produce different chain hashes for the same input."""
        from foundation_audit.services.hash_chain import compute_chain_hash
        event = {"event_id": "evt_cross_001", "action": "login"}
        _, sha256_hash = compute_chain_hash(
            prev_hash=None, event_data=event, hash_algorithm="SHA-256",
        )
        _, sm3_hash_val = compute_chain_hash(
            prev_hash=None, event_data=event, hash_algorithm="SM3",
        )
        assert sha256_hash != sm3_hash_val

    def test_sm3_chain_linked(self) -> None:
        from foundation_audit.services.hash_chain import compute_chain_hash
        _, h1 = compute_chain_hash(prev_hash=None, event_data={"id": 1}, hash_algorithm="SM3")
        _, h2 = compute_chain_hash(prev_hash=h1, event_data={"id": 2}, hash_algorithm="SM3")
        _, h3 = compute_chain_hash(prev_hash=h2, event_data={"id": 3}, hash_algorithm="SM3")
        assert h1 != h2
        assert h2 != h3
        assert len(h1) == len(h2) == len(h3) == 64

    def test_sm3_merkle_root_single_leaf(self) -> None:
        from foundation_audit.services.hash_chain import compute_merkle_root
        root = compute_merkle_root(["a" * 64], hash_algorithm="SM3")
        assert len(root) == 64

    def test_sm3_merkle_root_four_leaves(self) -> None:
        from foundation_audit.services.hash_chain import compute_merkle_root
        leaves = [f"{i:064d}" for i in range(4)]
        root = compute_merkle_root(leaves, hash_algorithm="SM3")
        assert len(root) == 64
        # Deterministic
        assert compute_merkle_root(leaves, hash_algorithm="SM3") == root

    def test_sm3_merkle_root_differs_from_sha256(self) -> None:
        from foundation_audit.services.hash_chain import compute_merkle_root
        leaves = ["a" * 64, "b" * 64]
        sha256_root = compute_merkle_root(leaves, hash_algorithm="SHA-256")
        sm3_root = compute_merkle_root(leaves, hash_algorithm="SM3")
        assert sha256_root != sm3_root


# ---------------------------------------------------------------------------
# 5. Full end-to-end: SM3 Merkle root → SM2 sign → verify
# ---------------------------------------------------------------------------

class TestSM3MerkleRootSM2Sign:
    """Full 国密 path: events → SM3 hash chain → SM3 Merkle root → SM2 sign → verify."""

    @pytest.mark.asyncio
    async def test_full_gm_pipeline(self) -> None:
        """Simulate BatchProcessor's 国密 path end-to-end:
        1. Compute SM3 hash chain for 3 events.
        2. Compute SM3 Merkle root.
        3. Sign Merkle root bytes with SM2.
        4. Verify the SM2 signature.
        """
        from foundation_audit.services.hash_chain import compute_chain_hash, compute_merkle_root

        provider = LocalTestKeyProvider()
        await provider.create_key(vault_path="audit/hashchain.sm2", algorithm="SM2")

        # Step 1: SM3 hash chain
        events = [
            {"event_id": f"evt_gm_{i:03d}", "tenant_id": "tnt_gm_test", "action": "login"}
            for i in range(3)
        ]
        leaf_hashes: list[str] = []
        prev: str | None = None
        for event in events:
            prev, curr = compute_chain_hash(
                prev_hash=prev, event_data=event, hash_algorithm="SM3",
            )
            leaf_hashes.append(curr)
            prev = curr

        assert len(leaf_hashes) == 3
        assert all(len(h) == 64 for h in leaf_hashes)

        # Step 2: SM3 Merkle root
        merkle_root = compute_merkle_root(leaf_hashes, hash_algorithm="SM3")
        assert len(merkle_root) == 64

        # Step 3: SM2 sign Merkle root
        root_bytes = bytes.fromhex(merkle_root)
        bundle = await provider.sign(
            vault_path="audit/hashchain.sm2",
            data=root_bytes,
            prehashed=False,
        )
        assert bundle.algorithm == "SM2"

        # Step 4: SM2 verify
        valid = await provider.verify(
            vault_path="audit/hashchain.sm2",
            data=root_bytes,
            signature=bundle.signature,
            prehashed=False,
        )
        assert valid is True

        # Sanity: tampered root fails
        tampered = bytes([root_bytes[0] ^ 0xFF]) + root_bytes[1:]
        tampered_valid = await provider.verify(
            vault_path="audit/hashchain.sm2",
            data=tampered,
            signature=bundle.signature,
            prehashed=False,
        )
        assert tampered_valid is False

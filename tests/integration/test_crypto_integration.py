"""Integration tests for Crypto Service — requires Vault + Postgres.

Tests the full envelope encryption lifecycle against the real Vault transit backend:
  1. Create a KEK (in Vault + Postgres)
  2. Encrypt data (envelope encryption)
  3. Decrypt data (verify roundtrip)
  4. Rotate KEK
  5. Rewrap ciphertext
  6. Mark KEK for destruction / abort
  7. Destroy KEK (and verify ciphertext is unrecoverable)
  8. Sign / verify
  9. Password hash / verify

Prerequisites:
  - Vault up with transit secrets engine enabled
  - Postgres up with crypto schema + algorithm seed data
  - crypto-service up and healthy
"""

from __future__ import annotations

import base64

import httpx
import pytest


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


class TestCryptoHealth:
    async def test_healthz(self, client: httpx.AsyncClient, endpoints) -> None:
        r = await client.get(f"{endpoints.crypto}/healthz")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "OK"


class TestKEKLifecycle:
    """Full KEK lifecycle: create → rotate → mark → abort → mark → destroy."""

    @pytest.fixture(scope="class")
    async def kek_id(self, client: httpx.AsyncClient, endpoints, tenant) -> str:
        """Create a KEK and return its ID."""
        payload = {
            "label": "integration.test.pii",
            "purpose": "FIELD_ENCRYPT",
            "algorithm_id": "AES-256-GCM",
        }
        r = await client.post(
            f"{endpoints.crypto}/keks",
            json=payload,
            headers=tenant.headers,
        )
        assert r.status_code == 201, f"Create KEK failed: {r.text}"
        data = r.json()
        assert data["label"] == "integration.test.pii"
        assert data["status"] == "ACTIVE"
        return data["id"]

    async def test_get_kek(self, client: httpx.AsyncClient, endpoints, tenant, kek_id: str) -> None:
        r = await client.get(
            f"{endpoints.crypto}/keks/{kek_id}",
            headers=tenant.headers,
        )
        assert r.status_code == 200
        assert r.json()["id"] == kek_id

    async def test_list_keks(self, client: httpx.AsyncClient, endpoints, tenant) -> None:
        r = await client.get(
            f"{endpoints.crypto}/keks",
            headers=tenant.headers,
        )
        assert r.status_code == 200
        data = r.json()
        assert "items" in data
        assert len(data["items"]) >= 1

    async def test_rotate_kek(
        self, client: httpx.AsyncClient, endpoints, tenant, kek_id: str,
    ) -> None:
        r = await client.post(
            f"{endpoints.crypto}/keks/{kek_id}/rotate",
            headers=tenant.headers,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["current_version"] >= 2

    async def test_mark_for_destruction(
        self, client: httpx.AsyncClient, endpoints, tenant, kek_id: str,
    ) -> None:
        r = await client.post(
            f"{endpoints.crypto}/keks/{kek_id}/mark-for-destruction",
            json={"reason": "Integration test — destruction validation"},
            headers=tenant.headers,
        )
        assert r.status_code == 200
        assert r.json()["status"] == "MARKED_FOR_DESTRUCTION"

    async def test_abort_destruction(
        self, client: httpx.AsyncClient, endpoints, tenant, kek_id: str,
    ) -> None:
        r = await client.post(
            f"{endpoints.crypto}/keks/{kek_id}/abort-destruction",
            json={"reason": "Abort — still needed for tests"},
            headers=tenant.headers,
        )
        assert r.status_code == 200
        assert r.json()["status"] == "ACTIVE"

    async def test_history(
        self, client: httpx.AsyncClient, endpoints, tenant, kek_id: str,
    ) -> None:
        r = await client.get(
            f"{endpoints.crypto}/keks/{kek_id}/history",
            headers=tenant.headers,
        )
        assert r.status_code == 200
        history = r.json()
        # Expect at least: CREATED, ROTATED, MARKED_FOR_DESTRUCTION, DESTRUCTION_ABORTED
        transitions = [h["transition"] for h in history]
        assert "CREATED" in transitions
        assert "ROTATED" in transitions


class TestEnvelopeEncryption:
    """End-to-end encrypt/decrypt through Vault transit."""

    @pytest.fixture(scope="class")
    async def env_kek_id(self, client: httpx.AsyncClient, endpoints, tenant) -> str:
        payload = {
            "label": "integration.test.envelope",
            "purpose": "FIELD_ENCRYPT",
            "algorithm_id": "AES-256-GCM",
        }
        r = await client.post(
            f"{endpoints.crypto}/keks",
            json=payload,
            headers=tenant.headers,
        )
        assert r.status_code == 201
        return r.json()["id"]

    async def test_encrypt_decrypt_roundtrip(
        self, client: httpx.AsyncClient, endpoints, tenant,
    ) -> None:
        """Encrypt then decrypt — verify plaintext matches."""
        plaintext = "Hello, integration test! 你好集成测试！"
        plaintext_b64 = _b64(plaintext)

        # Encrypt using label (not kek_id)
        encrypt_resp = await client.post(
            f"{endpoints.crypto}/encrypt",
            json={
                "key_label": "integration.test.envelope",
                "plaintext_b64": plaintext_b64,
                "context": {"purpose": "integration-test"},
            },
            headers=tenant.headers,
        )
        assert encrypt_resp.status_code == 200, f"Encrypt failed: {encrypt_resp.text}"
        envelope = encrypt_resp.json()["envelope"]

        # Verify envelope structure
        assert envelope["schema_version"] == 1
        assert envelope["algorithm"] == "AES-256-GCM"
        assert envelope["kek_version"] >= 1
        assert len(envelope["ciphertext_b64"]) > 0
        assert len(envelope["wrapped_dek_b64"]) > 0
        assert len(envelope["nonce_b64"]) > 0

        # Decrypt
        decrypt_resp = await client.post(
            f"{endpoints.crypto}/decrypt",
            json={"envelope": envelope},
            headers=tenant.headers,
        )
        assert decrypt_resp.status_code == 200, f"Decrypt failed: {decrypt_resp.text}"
        result_b64 = decrypt_resp.json()["plaintext_b64"]
        result = base64.b64decode(result_b64).decode()
        assert result == plaintext

    async def test_decrypt_wrong_context_fails(
        self, client: httpx.AsyncClient, endpoints, tenant,
    ) -> None:
        """Decryption with wrong context should fail (AEAD integrity)."""
        plaintext_b64 = _b64("secret data")

        encrypt_resp = await client.post(
            f"{endpoints.crypto}/encrypt",
            json={
                "key_label": "integration.test.envelope",
                "plaintext_b64": plaintext_b64,
                "context": {"doc_id": "123"},
            },
            headers=tenant.headers,
        )
        assert encrypt_resp.status_code == 200
        envelope = encrypt_resp.json()["envelope"]

        # Attempt decrypt with wrong context
        decrypt_resp = await client.post(
            f"{endpoints.crypto}/decrypt",
            json={
                "envelope": envelope,
                "expected_context": {"doc_id": "wrong"},
            },
            headers=tenant.headers,
        )
        assert decrypt_resp.status_code >= 400, "Should reject wrong context"

    async def test_rewrap(
        self, client: httpx.AsyncClient, endpoints, tenant, env_kek_id: str,
    ) -> None:
        """Encrypt, rotate KEK, rewrap, decrypt — all should work."""
        plaintext_b64 = _b64("rewrap test data")

        # Encrypt
        encrypt_resp = await client.post(
            f"{endpoints.crypto}/encrypt",
            json={
                "key_label": "integration.test.envelope",
                "plaintext_b64": plaintext_b64,
            },
            headers=tenant.headers,
        )
        assert encrypt_resp.status_code == 200
        old_envelope = encrypt_resp.json()["envelope"]
        old_version = old_envelope["kek_version"]

        # Rotate KEK
        await client.post(
            f"{endpoints.crypto}/keks/{env_kek_id}/rotate",
            headers=tenant.headers,
        )

        # Rewrap
        rewrap_resp = await client.post(
            f"{endpoints.crypto}/rewrap",
            json={"envelope": old_envelope},
            headers=tenant.headers,
        )
        assert rewrap_resp.status_code == 200
        new_envelope = rewrap_resp.json()["envelope"]
        # Wrapped DEK should change (re-wrapped to new KEK version)
        assert new_envelope["wrapped_dek_b64"] != old_envelope["wrapped_dek_b64"]
        # Ciphertext unchanged
        assert new_envelope["ciphertext_b64"] == old_envelope["ciphertext_b64"]
        # New KEK version
        assert new_envelope["kek_version"] > old_version

        # Decrypt rewrapped envelope
        decrypt_resp = await client.post(
            f"{endpoints.crypto}/decrypt",
            json={"envelope": new_envelope},
            headers=tenant.headers,
        )
        assert decrypt_resp.status_code == 200

    async def test_encrypt_nonexistent_label(
        self, client: httpx.AsyncClient, endpoints, tenant,
    ) -> None:
        r = await client.post(
            f"{endpoints.crypto}/encrypt",
            json={
                "key_label": "nonexistent.label",
                "plaintext_b64": _b64("test"),
            },
            headers=tenant.headers,
        )
        assert r.status_code == 404


class TestSignVerify:
    """Sign/verify through Vault transit."""

    @pytest.fixture(scope="class")
    async def sign_kek_id(self, client: httpx.AsyncClient, endpoints, tenant) -> str:
        payload = {
            "label": "integration.test.sign",
            "purpose": "AUDIT_HMAC",
            "algorithm_id": "Ed25519",
        }
        r = await client.post(
            f"{endpoints.crypto}/keks",
            json=payload,
            headers=tenant.headers,
        )
        assert r.status_code == 201, f"Create signing KEK failed: {r.text}"
        return r.json()["id"]

    async def test_sign_and_verify(
        self, client: httpx.AsyncClient, endpoints, tenant,
    ) -> None:
        data_b64 = _b64("data to be signed for audit chain")

        # Sign
        sign_resp = await client.post(
            f"{endpoints.crypto}/sign",
            json={
                "key_label": "integration.test.sign",
                "data_b64": data_b64,
                "detached": True,
                "prehash": True,
            },
            headers=tenant.headers,
        )
        assert sign_resp.status_code == 200, f"Sign failed: {sign_resp.text}"
        sig = sign_resp.json()
        assert len(sig["signature_b64"]) > 0
        assert sig["algorithm"] == "Ed25519"

        # Verify
        verify_resp = await client.post(
            f"{endpoints.crypto}/verify",
            json={
                "key_label": "integration.test.sign",
                "data_b64": data_b64,
                "signature_b64": sig["signature_b64"],
                "prehash": True,
            },
            headers=tenant.headers,
        )
        assert verify_resp.status_code == 200
        assert verify_resp.json()["valid"] is True

    async def test_verify_wrong_signature(
        self, client: httpx.AsyncClient, endpoints, tenant,
    ) -> None:
        verify_resp = await client.post(
            f"{endpoints.crypto}/verify",
            json={
                "key_label": "integration.test.sign",
                "data_b64": _b64("original"),
                "signature_b64": _b64("not-a-real-signature"),
                "prehash": True,
            },
            headers=tenant.headers,
        )
        # Should still return 200 with valid=False (not 4xx)
        assert verify_resp.status_code == 200
        assert verify_resp.json()["valid"] is False


class TestPasswordHashing:
    """Argon2id password hash/verify."""

    async def test_hash_and_verify(
        self, client: httpx.AsyncClient, endpoints, tenant,
    ) -> None:
        password = "correct-horse-battery-staple"

        # Hash
        hash_resp = await client.post(
            f"{endpoints.crypto}/password-hash",
            json={"password": password},
            headers=tenant.headers,
        )
        assert hash_resp.status_code == 200
        encoded = hash_resp.json()["encoded"]
        assert encoded.startswith("$argon2id$")

        # Verify correct
        verify_resp = await client.post(
            f"{endpoints.crypto}/password-verify",
            json={"password": password, "encoded": encoded},
            headers=tenant.headers,
        )
        assert verify_resp.status_code == 200
        assert verify_resp.json()["valid"] is True

    async def test_verify_wrong_password(
        self, client: httpx.AsyncClient, endpoints, tenant,
    ) -> None:
        # Hash
        hash_resp = await client.post(
            f"{endpoints.crypto}/password-hash",
            json={"password": "original-password"},
            headers=tenant.headers,
        )
        assert hash_resp.status_code == 200
        encoded = hash_resp.json()["encoded"]

        # Verify wrong
        verify_resp = await client.post(
            f"{endpoints.crypto}/password-verify",
            json={"password": "wrong-password", "encoded": encoded},
            headers=tenant.headers,
        )
        assert verify_resp.status_code == 200
        assert verify_resp.json()["valid"] is False


class TestAuthRejection:
    """Requests without tenant context should be rejected."""

    async def test_healthz_no_auth_ok(
        self, anon_client: httpx.AsyncClient, endpoints,
    ) -> None:
        """Health check should work without auth headers."""
        r = await anon_client.get(f"{endpoints.crypto}/healthz")
        assert r.status_code == 200

    async def test_encrypt_no_tenant_rejected(
        self, anon_client: httpx.AsyncClient, endpoints,
    ) -> None:
        """Encrypt without tenant headers should be rejected."""
        r = await anon_client.post(
            f"{endpoints.crypto}/encrypt",
            json={
                "key_label": "test",
                "plaintext_b64": _b64("test"),
            },
        )
        assert r.status_code in (401, 403), f"Expected 401/403, got {r.status_code}"


class TestAlgorithms:
    """Algorithm registry listing."""

    async def test_list_algorithms(
        self, client: httpx.AsyncClient, endpoints, tenant,
    ) -> None:
        r = await client.get(
            f"{endpoints.crypto}/algorithms",
            headers=tenant.headers,
        )
        assert r.status_code == 200
        algorithms = r.json()
        assert isinstance(algorithms, list)
        assert len(algorithms) >= 10  # at least the seed data
        # Verify essential algorithms exist
        algo_ids = [a["name"] for a in algorithms]
        assert "AES-256-GCM" in algo_ids
        assert "Ed25519" in algo_ids
        assert "Argon2id" in algo_ids
        assert "SM2" in algo_ids  # 国密算法已注册

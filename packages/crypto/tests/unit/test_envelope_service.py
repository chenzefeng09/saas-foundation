"""Unit tests for envelope_service."""

from __future__ import annotations

import pytest

from foundation_crypto.adapters.local_test_provider import LocalTestKeyProvider
from foundation_crypto.domain.models import Algorithm
from foundation_crypto.errors import KEK_NOT_FOUND, FoundationError
from foundation_crypto.schemas.envelope import EncryptRequest
from foundation_crypto.services.envelope_service import EnvelopeService

from tests._factories import make_algorithm, make_kek


@pytest.fixture
def svc(key_provider: LocalTestKeyProvider) -> EnvelopeService:
    return EnvelopeService(key_provider=key_provider)


class TestEncrypt:
    async def test_encrypt_returns_envelope(
        self, svc: EnvelopeService, fake_session, tenant_id: str, key_provider: LocalTestKeyProvider,
    ) -> None:
        algo = make_algorithm()
        kek = make_kek(tenant_id=tenant_id)
        fake_session.put(algo)
        fake_session.put(kek)
        # Stage the SELECT KEK query
        fake_session.queue_execute([kek])

        # Create KEK in provider first
        await key_provider.create_key(vault_path=kek.vault_path, algorithm=kek.algorithm_id)

        envelope = await svc.encrypt(
            fake_session,
            tenant_id=tenant_id,
            label=kek.label,
            plaintext=b"hello world",
            context={"user_id": "usr_1"},
        )
        assert envelope.schema_version == 1
        assert envelope.algorithm == "AES-256-GCM"
        assert envelope.kek_id == kek.id
        assert envelope.kek_version == 1
        assert len(envelope.wrapped_dek_b64) > 0
        assert len(envelope.nonce_b64) > 0
        assert len(envelope.ciphertext_b64) > 0
        assert envelope.aad == {"user_id": "usr_1"}

    async def test_encrypt_unknown_label_raises(
        self, svc: EnvelopeService, fake_session, tenant_id: str,
    ) -> None:
        fake_session.queue_execute([])
        with pytest.raises(FoundationError) as exc:
            await svc.encrypt(fake_session, tenant_id=tenant_id, label="nonexistent", plaintext=b"x")
        assert exc.value.error_code is KEK_NOT_FOUND


class TestDecrypt:
    async def test_roundtrip(
        self, svc: EnvelopeService, fake_session, tenant_id: str, key_provider: LocalTestKeyProvider,
    ) -> None:
        algo = make_algorithm()
        kek = make_kek(tenant_id=tenant_id)
        fake_session.put(algo)
        fake_session.put(kek)
        fake_session.queue_execute([kek])
        await key_provider.create_key(vault_path=kek.vault_path, algorithm=kek.algorithm_id)

        plaintext = b"hello world roundtrip"
        envelope = await svc.encrypt(fake_session, tenant_id=tenant_id, label=kek.label, plaintext=plaintext)

        # For decrypt, the service looks up KEK by id
        fake_session.queue_execute([kek])

        result = await svc.decrypt(fake_session, envelope=envelope)
        assert result == plaintext

    async def test_decrypt_with_expected_context(
        self, svc: EnvelopeService, fake_session, tenant_id: str, key_provider: LocalTestKeyProvider,
    ) -> None:
        algo = make_algorithm()
        kek = make_kek(tenant_id=tenant_id)
        fake_session.put(algo)
        fake_session.put(kek)
        fake_session.queue_execute([kek])
        await key_provider.create_key(vault_path=kek.vault_path, algorithm=kek.algorithm_id)

        envelope = await svc.encrypt(
            fake_session, tenant_id=tenant_id, label=kek.label,
            plaintext=b"secret", context={"doc": "123"},
        )

        fake_session.queue_execute([kek])
        result = await svc.decrypt(fake_session, envelope=envelope, expected_context={"doc": "123"})
        assert result == b"secret"

    async def test_decrypt_context_mismatch_detected(
        self, svc: EnvelopeService, fake_session, tenant_id: str, key_provider: LocalTestKeyProvider,
    ) -> None:
        algo = make_algorithm()
        kek = make_kek(tenant_id=tenant_id)
        fake_session.put(algo)
        fake_session.put(kek)
        fake_session.queue_execute([kek])
        await key_provider.create_key(vault_path=kek.vault_path, algorithm=kek.algorithm_id)

        envelope = await svc.encrypt(fake_session, tenant_id=tenant_id, label=kek.label, plaintext=b"x")

        fake_session.queue_execute([kek])
        with pytest.raises(FoundationError):
            await svc.decrypt(fake_session, envelope=envelope, expected_context={"wrong": "key"})


class TestRewrap:
    async def test_rewrap_updates_version(
        self, svc: EnvelopeService, fake_session, tenant_id: str, key_provider: LocalTestKeyProvider,
    ) -> None:
        algo = make_algorithm()
        kek = make_kek(tenant_id=tenant_id)
        fake_session.put(algo)
        fake_session.put(kek)
        fake_session.queue_execute([kek])
        await key_provider.create_key(vault_path=kek.vault_path, algorithm=kek.algorithm_id)

        envelope = await svc.encrypt(fake_session, tenant_id=tenant_id, label=kek.label, plaintext=b"rewrap me")
        assert envelope.kek_version == 1

        # Rotate key and rewrap
        await key_provider.rotate_key(vault_path=kek.vault_path)
        fake_session.queue_execute([kek])
        new_env = await svc.rewrap(fake_session, envelope=envelope)
        assert new_env.kek_version == 2
        # ciphertext unchanged, only wrapped_dek changed
        assert new_env.ciphertext_b64 == envelope.ciphertext_b64
        assert new_env.wrapped_dek_b64 != envelope.wrapped_dek_b64

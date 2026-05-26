"""Unit tests for kek_service — KEK lifecycle state machine."""

from __future__ import annotations

import pytest

from foundation_crypto.adapters.local_test_provider import LocalTestKeyProvider
from foundation_crypto.domain.models import Algorithm, KEK, Outbox
from foundation_crypto.errors import (
    KEK_ALREADY_MARKED,
    KEK_DESTROYED,
    KEK_LABEL_CONFLICT,
    KEK_NOT_DESTRUCTIBLE,
    KEK_NOT_FOUND,
    FoundationError,
)
from foundation_crypto.schemas.kek import CreateKEKRequest, DestroyKEKRequest, MarkForDestructionRequest
from foundation_crypto.services.kek_service import KekService

from tests._factories import make_algorithm, make_kek, outbox_events_of_type


@pytest.fixture
def svc(key_provider: LocalTestKeyProvider) -> KekService:
    return KekService(key_provider=key_provider)


class TestCreateKEK:
    async def test_create_success(
        self, svc: KekService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        algo = make_algorithm()
        fake_session.put(algo)
        # No existing KEK with same label → scalar_one_or_none returns None
        fake_session.queue_execute([])

        result = await svc.create(
            fake_session,
            tenant_id=tenant_id,
            request=CreateKEKRequest(label="pii.phone", purpose="FIELD_ENCRYPT", algorithm_id="AES-256-GCM"),
            actor_user_id=actor_id,
            request_id=request_id,
        )
        assert result.label == "pii.phone"
        assert result.status == "ACTIVE"
        assert result.current_version == 1
        assert result.id.startswith("kek_")
        assert result.created_at is not None
        assert result.last_rotated_at is not None

        # Check history was recorded
        history_added = [o for o in fake_session.added if type(o).__name__ == "KEKHistory"]
        assert len(history_added) == 1
        assert history_added[0].transition == "CREATED"

        # Check event emitted
        events = outbox_events_of_type(fake_session.added, "foundation.crypto.kek.created")
        assert len(events) == 1

    async def test_create_label_conflict(
        self, svc: KekService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        algo = make_algorithm()
        fake_session.put(algo)
        existing = make_kek(tenant_id=tenant_id, label="pii.phone")
        fake_session.queue_execute([existing])

        with pytest.raises(FoundationError) as exc:
            await svc.create(
                fake_session, tenant_id=tenant_id,
                request=CreateKEKRequest(label="pii.phone", purpose="FIELD_ENCRYPT", algorithm_id="AES-256-GCM"),
                actor_user_id=actor_id, request_id=request_id,
            )
        assert exc.value.error_code is KEK_LABEL_CONFLICT


class TestRotateKEK:
    async def test_rotate_success(
        self, svc: KekService, fake_session, tenant_id: str, actor_id: str, request_id: str,
        key_provider: LocalTestKeyProvider,
    ) -> None:
        kek = make_kek(tenant_id=tenant_id)
        fake_session.put(kek)
        # _get uses session.execute(select(KEK).where(...))
        fake_session.queue_execute([kek])
        await key_provider.create_key(vault_path=kek.vault_path, algorithm=kek.algorithm_id)

        result = await svc.rotate(fake_session, tenant_id=tenant_id, kek_id=kek.id,
                                  request=None, actor_user_id=actor_id, request_id=request_id)
        assert result.current_version == 2

        events = outbox_events_of_type(fake_session.added, "foundation.crypto.kek.rotated")
        assert len(events) == 1


class TestMarkForDestruction:
    async def test_mark_for_destruction(
        self, svc: KekService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        kek = make_kek(tenant_id=tenant_id)
        fake_session.put(kek)
        fake_session.queue_execute([kek])

        result = await svc.mark_for_destruction(
            fake_session, tenant_id=tenant_id, kek_id=kek.id,
            request=MarkForDestructionRequest(reason="Compliance requirement — data retention expired"),
            actor_user_id=actor_id, request_id=request_id,
        )
        assert result.status == "MARKED_FOR_DESTRUCTION"
        assert result.destruction_scheduled_at is not None

    async def test_mark_twice_raises(
        self, svc: KekService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        kek = make_kek(tenant_id=tenant_id, status="MARKED_FOR_DESTRUCTION")
        fake_session.put(kek)
        fake_session.queue_execute([kek])

        with pytest.raises(FoundationError) as exc:
            await svc.mark_for_destruction(
                fake_session, tenant_id=tenant_id, kek_id=kek.id,
                request=MarkForDestructionRequest(reason="Try again"),
                actor_user_id=actor_id, request_id=request_id,
            )
        assert exc.value.error_code is KEK_ALREADY_MARKED


class TestDestroyKEK:
    async def test_destroy_requires_marked_status(
        self, svc: KekService, fake_session, tenant_id: str, actor_id: str,
        approver_id: str, request_id: str,
    ) -> None:
        kek = make_kek(tenant_id=tenant_id, status="ACTIVE")
        fake_session.put(kek)
        fake_session.queue_execute([kek])

        with pytest.raises(FoundationError) as exc:
            await svc.destroy(
                fake_session, tenant_id=tenant_id, kek_id=kek.id,
                request=DestroyKEKRequest(approver_user_id=approver_id, confirmation_phrase="I confirm"),
                actor_user_id=actor_id, request_id=request_id,
            )
        assert exc.value.error_code is KEK_NOT_DESTRUCTIBLE

    async def test_destroy_success(
        self, svc: KekService, fake_session, tenant_id: str, actor_id: str,
        approver_id: str, request_id: str,
        key_provider: LocalTestKeyProvider,
    ) -> None:
        import os
        os.environ["CRYPTO_KEK_DESTRUCTION_COOLING_OFF_DAYS"] = "0"

        kek = make_kek(tenant_id=tenant_id, status="MARKED_FOR_DESTRUCTION")
        fake_session.put(kek)
        fake_session.queue_execute([kek])
        await key_provider.create_key(vault_path=kek.vault_path, algorithm=kek.algorithm_id)

        await svc.destroy(
            fake_session, tenant_id=tenant_id, kek_id=kek.id,
            request=DestroyKEKRequest(approver_user_id=approver_id, confirmation_phrase="I confirm"),
            actor_user_id=actor_id, request_id=request_id,
        )
        assert kek.status == "DESTROYED"

        events = outbox_events_of_type(fake_session.added, "foundation.crypto.kek.destroyed")
        assert len(events) == 1


class TestAbortDestruction:
    async def test_abort_destruction(
        self, svc: KekService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        kek = make_kek(tenant_id=tenant_id, status="MARKED_FOR_DESTRUCTION")
        fake_session.put(kek)
        fake_session.queue_execute([kek])

        result = await svc.abort_destruction(
            fake_session, tenant_id=tenant_id, kek_id=kek.id,
            reason="Legal hold placed — cannot destroy",
            actor_user_id=actor_id, request_id=request_id,
        )
        assert result.status == "ACTIVE"


class TestGetAndList:
    async def test_get_kek_returns_kek(
        self, svc: KekService, fake_session, tenant_id: str,
    ) -> None:
        kek = make_kek(tenant_id=tenant_id)
        fake_session.put(kek)
        fake_session.queue_execute([kek])

        result = await svc.get_kek(fake_session, tenant_id=tenant_id, kek_id=kek.id)
        assert result.id == kek.id
        assert result.label == kek.label

    async def test_get_kek_not_found(
        self, svc: KekService, fake_session, tenant_id: str,
    ) -> None:
        fake_session.queue_execute([])

        with pytest.raises(FoundationError) as exc:
            await svc.get_kek(fake_session, tenant_id=tenant_id, kek_id="kek_nonexistent")
        assert exc.value.error_code is KEK_NOT_FOUND

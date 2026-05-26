"""Unit tests for NotificationService."""

from __future__ import annotations
import pytest
from foundation_notification.services.notification_service import NotificationService, _event_matches
from foundation_notification.domain.models import NotificationTemplate, NotificationChannel


class TestEventMatching:
    def test_exact_match(self):
        assert _event_matches(["crypto.kek.rotated"], "crypto.kek.rotated") is True

    def test_wildcard_match(self):
        assert _event_matches(["crypto.*"], "crypto.kek.rotated") is True

    def test_star_match(self):
        assert _event_matches(["*"], "anything.here") is True

    def test_no_match(self):
        assert _event_matches(["billing.*"], "crypto.kek.rotated") is False

    def test_multiple_patterns(self):
        assert _event_matches(["billing.*", "crypto.*", "audit.*"], "crypto.kek.rotated") is True


class TestSend:
    @pytest.fixture
    def svc(self):
        return NotificationService()

    async def test_send_with_template(self, svc, fake_session, tenant_id, request_id):
        tmpl = NotificationTemplate(
            id="nt_t1", tenant_id=tenant_id, event_type="test.event",
            locale="zh-CN",
            subject_template="Hello {{ recipient }}",
            body_template="Context: {{ data }}",
            enabled=True)
        fake_session.queue_scalar(tmpl)

        logs = await svc.send(fake_session, tenant_id=tenant_id,
            event_type="test.event", recipients=["user@test.com"],
            context={"data": "test-value"}, channel=None, request_id=request_id)

        assert len(logs) == 1
        assert logs[0].status == "DELIVERED"
        assert logs[0].channel == "EMAIL"
        assert "Hello user@test.com" in logs[0].subject

    async def test_send_without_template_uses_default(self, svc, fake_session, tenant_id, request_id):
        fake_session.queue_scalar(None)  # no template found

        logs = await svc.send(fake_session, tenant_id=tenant_id,
            event_type="unknown.event", recipients=["admin@test.com"],
            context={"alert": "disk full"}, channel=None, request_id=request_id)

        assert len(logs) == 1
        assert "[unknown.event]" in logs[0].subject

    async def test_send_webhook(self, svc, fake_session, tenant_id, request_id):
        fake_session.queue_scalar(None)  # no template
        ch = NotificationChannel(
            id="nc_w1", tenant_id=tenant_id, channel="WEBHOOK",
            config={"url": "http://localhost:9999/webhook"}, enabled=True)
        fake_session.queue_scalar(ch)

        logs = await svc.send(fake_session, tenant_id=tenant_id,
            event_type="test.webhook", recipients=["hook-1"],
            context={"msg": "ping"}, channel="WEBHOOK", request_id=request_id)

        assert len(logs) == 1
        # In test without a real webhook, will fail to connect
        assert logs[0].channel == "WEBHOOK"


class TestSubscription:
    @pytest.fixture
    def svc(self):
        return NotificationService()

    async def test_subscribe(self, svc, fake_session, tenant_id):
        sub = await svc.subscribe(fake_session, tenant_id=tenant_id,
            subscriber_kind="USER", subscriber_id="usr_1",
            event_types=["crypto.*", "audit.*"], channel="EMAIL", config={})
        assert sub.id.startswith("nsub_")
        assert sub.subscriber_id == "usr_1"

    async def test_get_subscriptions(self, svc, fake_session, tenant_id):
        from foundation_notification.domain.models import NotificationSubscription
        sub = NotificationSubscription(
            id="nsub_test", tenant_id=tenant_id, subscriber_kind="USER",
            subscriber_id="usr_1", event_types=["crypto.*"],
            channel="EMAIL", config={}, enabled=True)
        fake_session.queue_scalars([sub])

        results = await svc.get_subscriptions(fake_session, tenant_id=tenant_id,
            event_type="crypto.kek.rotated")
        assert len(results) == 1

    async def test_get_subscriptions_no_match(self, svc, fake_session, tenant_id):
        from foundation_notification.domain.models import NotificationSubscription
        sub = NotificationSubscription(
            id="nsub_test", tenant_id=tenant_id, subscriber_kind="USER",
            subscriber_id="usr_1", event_types=["billing.*"],
            channel="EMAIL", config={}, enabled=True)
        fake_session.queue_scalars([sub])

        results = await svc.get_subscriptions(fake_session, tenant_id=tenant_id,
            event_type="crypto.kek.rotated")
        assert len(results) == 0

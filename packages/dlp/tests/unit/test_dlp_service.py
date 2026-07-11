"""Unit tests for DLP + Classification service."""

from __future__ import annotations

import pytest

from foundation_dlp.errors import (
    SENSITIVITY_IMMUTABLE_DOWNGRADE,
    VALIDATION_FAILED,
    FoundationError,
)
from foundation_dlp.services.dlp_service import DLPService
from tests._factories import make_classification, make_dlp_rule


@pytest.fixture
def svc() -> DLPService:
    return DLPService()


class TestClassification:
    async def test_tag_new_resource(
        self, svc: DLPService, fake_session, tenant_id: str, actor_id: str, request_id: str
    ) -> None:
        fake_session.queue_scalar(None)  # no existing classification
        cls = await svc.tag_resource(
            session=fake_session,
            tenant_id=tenant_id,
            resource_type="document",
            resource_id="doc_1",
            sensitivity="L3",
            tags=["pii"],
            reason="has customer data",
            tagged_by=actor_id,
            request_id=request_id,
        )
        assert cls.sensitivity == "L3"
        assert cls.resource_id == "doc_1"

    async def test_upgrade_allowed(
        self, svc: DLPService, fake_session, tenant_id: str, actor_id: str, request_id: str
    ) -> None:
        existing = make_classification(
            tenant_id=tenant_id, resource_type="doc", resource_id="doc_1", sensitivity="L2"
        )
        fake_session.queue_scalar(existing)
        cls = await svc.tag_resource(
            session=fake_session,
            tenant_id=tenant_id,
            resource_type="doc",
            resource_id="doc_1",
            sensitivity="L4",
            tags=[],
            reason="upgraded",
            tagged_by=actor_id,
            request_id=request_id,
        )
        assert cls.sensitivity == "L4"

    async def test_downgrade_blocked(
        self, svc: DLPService, fake_session, tenant_id: str, actor_id: str, request_id: str
    ) -> None:
        existing = make_classification(
            tenant_id=tenant_id, resource_type="doc", resource_id="doc_1", sensitivity="L4"
        )
        fake_session.queue_scalar(existing)
        with pytest.raises(FoundationError) as exc:
            await svc.tag_resource(
                session=fake_session,
                tenant_id=tenant_id,
                resource_type="doc",
                resource_id="doc_1",
                sensitivity="L2",
                tags=[],
                reason="try downgrade",
                tagged_by=actor_id,
                request_id=request_id,
            )
        assert exc.value.error_code is SENSITIVITY_IMMUTABLE_DOWNGRADE

    async def test_default_sensitivity_is_L3(
        self, svc: DLPService, fake_session, tenant_id: str
    ) -> None:
        fake_session.queue_scalar(None)
        cls = await svc.get_sensitivity(
            session=fake_session, tenant_id=tenant_id, resource_type="doc", resource_id="new_doc"
        )
        assert cls.sensitivity == "L3"

    async def test_default_sensitivity_is_configurable(self, fake_session, tenant_id: str) -> None:
        fake_session.queue_scalar(None)
        svc = DLPService(default_sensitivity="L4")

        cls = await svc.get_sensitivity(
            session=fake_session,
            tenant_id=tenant_id,
            resource_type="doc",
            resource_id="new_doc",
        )

        assert cls.sensitivity == "L4"

    async def test_tag_rejects_invalid_sensitivity(
        self, svc: DLPService, fake_session, tenant_id: str, actor_id: str, request_id: str
    ) -> None:
        with pytest.raises(FoundationError) as exc:
            await svc.tag_resource(
                session=fake_session,
                tenant_id=tenant_id,
                resource_type="doc",
                resource_id="doc_1",
                sensitivity="L6",  # type: ignore[arg-type]
                tags=[],
                reason=None,
                tagged_by=actor_id,
                request_id=request_id,
            )
        assert exc.value.error_code is VALIDATION_FAILED


class TestAccessCheck:
    async def test_check_read_allowed(
        self, svc: DLPService, fake_session, tenant_id: str, actor_id: str, request_id: str
    ) -> None:
        cls = make_classification(tenant_id=tenant_id, sensitivity="L2")
        fake_session.queue_scalar(cls)
        result = await svc.check_read(
            session=fake_session,
            tenant_id=tenant_id,
            user_id="usr_1",
            user_clearance="L3",
            resource_type="doc",
            resource_id="doc_1",
            request_id=request_id,
        )
        assert result["allowed"] is True

    async def test_check_read_denied(
        self, svc: DLPService, fake_session, tenant_id: str, actor_id: str, request_id: str
    ) -> None:
        cls = make_classification(tenant_id=tenant_id, sensitivity="L4")
        fake_session.queue_scalar(cls)
        result = await svc.check_read(
            session=fake_session,
            tenant_id=tenant_id,
            user_id="usr_1",
            user_clearance="L2",
            resource_type="doc",
            resource_id="doc_1",
            request_id=request_id,
        )
        assert result["allowed"] is False

    async def test_check_download_L5_always_denied(
        self, svc: DLPService, fake_session, tenant_id: str, actor_id: str, request_id: str
    ) -> None:
        cls = make_classification(tenant_id=tenant_id, sensitivity="L5")
        fake_session.queue_scalar(cls)
        result = await svc.check_download(
            session=fake_session,
            tenant_id=tenant_id,
            user_id="usr_1",
            user_clearance="L5",
            resource_type="doc",
            resource_id="top_secret",
            destination="laptop",
            request_id=request_id,
        )
        assert result["allowed"] is False
        assert "L5" in str(result.get("reason", ""))

    async def test_invalid_clearance_is_rejected_not_coerced(
        self, svc: DLPService, fake_session, tenant_id: str, request_id: str
    ) -> None:
        with pytest.raises(FoundationError) as exc:
            await svc.check_read(
                session=fake_session,
                tenant_id=tenant_id,
                user_id="usr_1",
                user_clearance="L9",  # type: ignore[arg-type]
                resource_type="doc",
                resource_id="doc_1",
                request_id=request_id,
            )
        assert exc.value.error_code is VALIDATION_FAILED


class TestContentScan:
    async def test_scan_with_keyword_rule(
        self, svc: DLPService, fake_session, tenant_id: str, request_id: str
    ) -> None:
        import json

        rule = make_dlp_rule(
            tenant_id=tenant_id,
            rule_type="KEYWORD",
            pattern=json.dumps(["身份证", "银行卡"]),
            min_sensitivity="L3",
        )
        fake_session.queue_scalars([rule])
        result = await svc.scan_content(
            session=fake_session,
            tenant_id=tenant_id,
            content="这是包含身份证号码的文档",
            resource_type="doc",
            resource_id="doc_1",
            request_id=request_id,
        )
        assert len(result["hits"]) >= 1
        assert result["max_sensitivity"] == "L3"

    async def test_scan_with_regex_rule(
        self, svc: DLPService, fake_session, tenant_id: str, request_id: str
    ) -> None:
        rule = make_dlp_rule(
            tenant_id=tenant_id,
            rule_type="REGEX",
            pattern=r"\b\d{6}(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b",
            min_sensitivity="L4",
        )
        fake_session.queue_scalars([rule])
        result = await svc.scan_content(
            session=fake_session,
            tenant_id=tenant_id,
            content="身份证号 110101199001011234",
            resource_type="doc",
            resource_id="doc_2",
            request_id=request_id,
        )
        assert result["max_sensitivity"] == "L4"

    async def test_scan_clean_content(
        self, svc: DLPService, fake_session, tenant_id: str, request_id: str
    ) -> None:
        fake_session.queue_scalars([])
        result = await svc.scan_content(
            session=fake_session,
            tenant_id=tenant_id,
            content="这是一份普通的产品文档",
            resource_type="doc",
            resource_id="doc_3",
            request_id=request_id,
        )
        assert result["hits"] == []
        assert result["max_sensitivity"] == "L1"


class TestScanClassification:
    async def test_hit_creates_classification_for_real_resource(
        self, svc: DLPService, fake_session, tenant_id: str, request_id: str
    ) -> None:
        from foundation_dlp.domain.models import Classification

        rule = make_dlp_rule(
            tenant_id=tenant_id,
            rule_type="KEYWORD",
            pattern='["并购"]',
            min_sensitivity="L4",
        )
        fake_session.queue_scalars([rule])
        fake_session.queue_scalar(None)

        await svc.scan_content(
            session=fake_session,
            tenant_id=tenant_id,
            content="未公开并购方案",
            resource_type="document",
            resource_id="doc_merger",
            request_id=request_id,
        )

        labels = [obj for obj in fake_session.added if isinstance(obj, Classification)]
        assert len(labels) == 1
        assert labels[0].resource_type == "document"
        assert labels[0].resource_id == "doc_merger"
        assert labels[0].sensitivity == "L4"
        assert labels[0].auto_upgraded is True
        assert labels[0].tagged_by == "system:scanner"

    async def test_hit_only_upgrades_and_preserves_manual_metadata(
        self, svc: DLPService, fake_session, tenant_id: str, request_id: str
    ) -> None:
        existing = make_classification(
            tenant_id=tenant_id,
            resource_type="document",
            resource_id="doc_1",
            sensitivity="L2",
            tags=["manual"],
        )
        existing.reason = "owner classification"
        existing.tagged_by = "usr_owner"
        rule = make_dlp_rule(
            tenant_id=tenant_id,
            rule_type="KEYWORD",
            pattern='["核心算法"]',
            min_sensitivity="L5",
        )
        fake_session.queue_scalars([rule])
        fake_session.queue_scalar(existing)

        await svc.scan_content(
            session=fake_session,
            tenant_id=tenant_id,
            content="核心算法设计",
            resource_type="document",
            resource_id="doc_1",
            request_id=request_id,
        )

        assert existing.sensitivity == "L5"
        assert existing.auto_upgraded is True
        assert existing.downgradable is False
        assert existing.tags == ["manual"]
        assert existing.reason == "owner classification"
        assert existing.tagged_by == "usr_owner"

    async def test_lower_scan_hit_never_downgrades_existing_label(
        self, svc: DLPService, fake_session, tenant_id: str, request_id: str
    ) -> None:
        existing = make_classification(
            tenant_id=tenant_id,
            resource_type="document",
            resource_id="doc_1",
            sensitivity="L5",
            downgradable=False,
        )
        rule = make_dlp_rule(
            tenant_id=tenant_id,
            rule_type="KEYWORD",
            pattern='["手机号"]',
            min_sensitivity="L3",
        )
        fake_session.queue_scalars([rule])
        fake_session.queue_scalar(existing)

        await svc.scan_content(
            session=fake_session,
            tenant_id=tenant_id,
            content="包含手机号",
            resource_type="document",
            resource_id="doc_1",
            request_id=request_id,
        )

        assert existing.sensitivity == "L5"
        assert existing.downgradable is False

    async def test_new_label_never_falls_below_unclassified_default(
        self, svc: DLPService, fake_session, tenant_id: str, request_id: str
    ) -> None:
        from foundation_dlp.domain.models import Classification

        rule = make_dlp_rule(
            tenant_id=tenant_id,
            rule_type="KEYWORD",
            pattern='["邮箱"]',
            min_sensitivity="L2",
        )
        fake_session.queue_scalars([rule])
        fake_session.queue_scalar(None)

        await svc.scan_content(
            session=fake_session,
            tenant_id=tenant_id,
            content="包含邮箱",
            resource_type="document",
            resource_id="doc_email",
            request_id=request_id,
        )

        label = next(obj for obj in fake_session.added if isinstance(obj, Classification))
        assert label.sensitivity == "L3"

    async def test_shape_only_scan_does_not_persist_placeholder_label(
        self, svc: DLPService, fake_session, tenant_id: str, request_id: str
    ) -> None:
        from foundation_dlp.domain.models import Classification

        rule = make_dlp_rule(
            tenant_id=tenant_id,
            rule_type="KEYWORD",
            pattern='["身份证"]',
            min_sensitivity="L4",
        )
        fake_session.queue_scalars([rule])

        result = await svc.scan_content(
            session=fake_session,
            tenant_id=tenant_id,
            content="包含身份证",
            resource_type="text/plain",
            resource_id=None,
            request_id=request_id,
            persist_classification=False,
        )

        assert result["max_sensitivity"] == "L4"
        assert not [obj for obj in fake_session.added if isinstance(obj, Classification)]


def _default_rules() -> list:
    """Mirror of the built-in global rules seeded by migration 0002_dlp_default_rules.

    Built here (not via migration) so the scan logic can be unit-tested without a DB.
    """
    specs = [
        ("dlprule_pii_cn_idcard", "中国身份证", r"\b\d{17}[\dXx]\b", "L4"),
        ("dlprule_pii_cn_phone", "中国手机号", r"\b1[3-9]\d{9}\b", "L3"),
        ("dlprule_pii_bankcard", "银行卡号", r"\b\d{16,19}\b", "L4"),
        ("dlprule_pii_email", "邮箱", r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "L2"),
        ("dlprule_secret_aws_akid", "AWS Access Key", r"\bAKIA[0-9A-Z]{16}\b", "L4"),
        ("dlprule_secret_private_key", "私钥头", r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "L4"),
        ("dlprule_secret_api_key", "通用 API Key", r"(?i)\bapi[_-]?key\b\s*[:=]\s*\S+", "L3"),
    ]
    return [
        make_dlp_rule(
            rule_id=rid,
            tenant_id=None,
            name=name,
            rule_type="REGEX",
            pattern=pattern,
            min_sensitivity=sens,
        )
        for rid, name, pattern, sens in specs
    ]


class TestDefaultRulesScan:
    """Scan behavior against the built-in global DLP rules (action mapping included)."""

    async def test_idcard_quarantine(
        self, svc: DLPService, fake_session, tenant_id: str, request_id: str
    ) -> None:
        fake_session.queue_scalars(_default_rules())
        result = await svc.scan_content(
            session=fake_session,
            tenant_id=tenant_id,
            content="客户身份证 11010119900307691X 备案",
            resource_type="doc",
            resource_id="d1",
            request_id=request_id,
        )
        assert result["max_sensitivity"] == "L4"
        assert result["action"] == "QUARANTINE"

    async def test_email_only_scan_required(
        self, svc: DLPService, fake_session, tenant_id: str, request_id: str
    ) -> None:
        fake_session.queue_scalars(_default_rules())
        result = await svc.scan_content(
            session=fake_session,
            tenant_id=tenant_id,
            content="联系邮箱 alice@example.com 谢谢",
            resource_type="doc",
            resource_id="d2",
            request_id=request_id,
        )
        assert result["max_sensitivity"] == "L2"
        assert result["action"] == "SCAN_REQUIRED"

    async def test_aws_key_quarantine(
        self, svc: DLPService, fake_session, tenant_id: str, request_id: str
    ) -> None:
        fake_session.queue_scalars(_default_rules())
        result = await svc.scan_content(
            session=fake_session,
            tenant_id=tenant_id,
            content="export AWS key AKIAIOSFODNN7EXAMPLE here",
            resource_type="doc",
            resource_id="d3",
            request_id=request_id,
        )
        assert any(h["rule_id"] == "dlprule_secret_aws_akid" for h in result["hits"])
        assert result["max_sensitivity"] == "L4"
        assert result["action"] == "QUARANTINE"

    async def test_api_key_assignment_scan_required(
        self, svc: DLPService, fake_session, tenant_id: str, request_id: str
    ) -> None:
        fake_session.queue_scalars(_default_rules())
        result = await svc.scan_content(
            session=fake_session,
            tenant_id=tenant_id,
            content="config: api_key = sk-abc123def",
            resource_type="doc",
            resource_id="d4",
            request_id=request_id,
        )
        assert result["max_sensitivity"] == "L3"
        assert result["action"] == "SCAN_REQUIRED"

    async def test_clean_content_allow(
        self, svc: DLPService, fake_session, tenant_id: str, request_id: str
    ) -> None:
        fake_session.queue_scalars(_default_rules())
        result = await svc.scan_content(
            session=fake_session,
            tenant_id=tenant_id,
            content="这是一段关于产品路线图的普通描述",
            resource_type="doc",
            resource_id="d5",
            request_id=request_id,
        )
        assert result["hits"] == []
        assert result["max_sensitivity"] == "L1"
        assert result["action"] == "ALLOW"


class TestScanPersistence:
    """A hit-producing scan must persist a durable dlp_event row (not just the outbox)."""

    async def test_hit_persists_dlp_event_with_detail(
        self, svc: DLPService, fake_session, tenant_id: str, request_id: str
    ) -> None:
        import json as _json

        from foundation_dlp.domain.models import DLPEvent

        fake_session.queue_scalars(_default_rules())
        result = await svc.scan_content(
            session=fake_session,
            tenant_id=tenant_id,
            content="客户身份证 11010119900307691X 备案",
            resource_type="doc",
            resource_id="d1",
            user_id="usr_scanner",
            request_id=request_id,
        )

        events = [obj for obj in fake_session.added if isinstance(obj, DLPEvent)]
        assert len(events) == 1
        ev = events[0]
        assert ev.check_type == "SCAN"
        assert ev.decision == result["action"] == "QUARANTINE"
        assert ev.tenant_id == tenant_id
        assert ev.user_id == "usr_scanner"
        assert ev.resource_type == "doc"
        assert ev.resource_id == "d1"
        # detail is a JSON string carrying the matched rule(s).
        detail = _json.loads(ev.detail)
        assert detail["max_sensitivity"] == "L4"
        assert any(r["rule_id"] == "dlprule_pii_cn_idcard" for r in detail["rules"])

    async def test_clean_scan_persists_no_event(
        self, svc: DLPService, fake_session, tenant_id: str, request_id: str
    ) -> None:
        from foundation_dlp.domain.models import DLPEvent

        fake_session.queue_scalars(_default_rules())
        await svc.scan_content(
            session=fake_session,
            tenant_id=tenant_id,
            content="普通的产品路线图描述",
            resource_type="doc",
            resource_id="d2",
            request_id=request_id,
        )
        assert not [obj for obj in fake_session.added if isinstance(obj, DLPEvent)]


class TestGovernanceReads:
    """Service-layer queries backing the /core governance endpoints."""

    async def test_list_events_filters_and_orders(
        self, svc: DLPService, fake_session, tenant_id: str
    ) -> None:
        from foundation_dlp.domain.models import DLPEvent

        rows = [DLPEvent(id=3, tenant_id=tenant_id, check_type="SCAN", decision="QUARANTINE")]
        fake_session.queue_scalars(rows)
        out = await svc.list_events(fake_session, tenant_id=tenant_id, check_type="SCAN", limit=10)
        assert [e.id for e in out] == [3]

    async def test_stats_aggregates(self, svc: DLPService, fake_session, tenant_id: str) -> None:
        from datetime import UTC, datetime, timedelta

        fake_session.queue_execute([("ALLOW", 5), ("DENY", 2)])
        fake_session.queue_execute([("READ", 4), ("SCAN", 3)])
        fake_session.queue_execute([("L3", 6), ("L4", 1)])
        out = await svc.stats(
            fake_session, tenant_id=tenant_id, since=datetime.now(UTC) - timedelta(days=30)
        )
        assert out["by_decision"] == {"ALLOW": 5, "DENY": 2}
        assert out["by_check_type"] == {"READ": 4, "SCAN": 3}
        assert out["by_sensitivity"] == {"L3": 6, "L4": 1}
        assert out["total_events"] == 7

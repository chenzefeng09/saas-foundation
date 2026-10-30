"""Unit tests for DLP + Classification service."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy.dialects import postgresql

from foundation_dlp.domain.models import Classification, DLPEvent
from foundation_dlp.errors import (
    SENSITIVITY_IMMUTABLE_DOWNGRADE,
    VALIDATION_FAILED,
    FoundationError,
)
from foundation_dlp.services.dlp_service import DLPService
from foundation_dlp.services.pagination import (
    encode_cursor,
    parse_classification_id,
    parse_event_id,
)
from tests._factories import (
    make_classification,
    make_dlp_event,
    make_dlp_rule,
    newest_first_answer,
)


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

    async def test_verdict_only_scan_audits_resource_but_never_labels_it(
        self, svc: DLPService, fake_session, tenant_id: str, request_id: str
    ) -> None:
        # The path a non-management /core/scan caller takes (e.g. a sandboxed
        # worker's tool call): real resource identity for the audit trail, but
        # no classification row is created or raised.
        from foundation_dlp.domain.models import Classification, DLPEvent

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
            resource_type="tool_call",
            resource_id="Bash:toolu_1",
            request_id=request_id,
            persist_classification=False,
        )

        assert result["action"] == "QUARANTINE"
        assert not [obj for obj in fake_session.added if isinstance(obj, Classification)]
        event = next(obj for obj in fake_session.added if isinstance(obj, DLPEvent))
        assert event.check_type == "SCAN"
        assert event.resource_type == "tool_call"
        assert event.resource_id == "Bash:toolu_1"


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


_T0 = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
_TICK = timedelta(microseconds=1)
_EVENTS_ORDER_BY = "ORDER BY dlp.dlp_event.occurred_at DESC, dlp.dlp_event.id DESC"
_EVENTS_AFTER = "(dlp.dlp_event.occurred_at, dlp.dlp_event.id) < "
_LABELS_ORDER_BY = "ORDER BY dlp.classification.updated_at DESC, dlp.classification.id DESC"
_LABELS_AFTER = "(dlp.classification.updated_at, dlp.classification.id) < "


def _sql(stmt: Any) -> str:
    """Render a recorded SELECT as Postgres SQL, values inlined."""
    compiled = stmt.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True})
    return " ".join(str(compiled).split())


class TestGovernanceReads:
    """Service-layer queries backing the /core governance endpoints."""

    async def test_list_events_pages_through_every_event_once(
        self, svc: DLPService, fake_session, tenant_id: str
    ) -> None:
        # Events written in one transaction share its now(), and the sequence numbers
        # concurrent transactions out of time order: paging must neither skip nor repeat.
        events = [
            make_dlp_event(event_id=5, occurred_at=_T0),
            make_dlp_event(event_id=1, occurred_at=_T0 + _TICK),
            make_dlp_event(event_id=4, occurred_at=_T0 + _TICK),
            make_dlp_event(event_id=2, occurred_at=_T0 + _TICK),
            make_dlp_event(event_id=3, occurred_at=_T0 + 2 * _TICK),
        ]

        pages: list[list[DLPEvent]] = []
        cursor = None
        for _ in events:  # a cursor that never runs out fails below instead of looping
            fake_session.queue_scalars(newest_first_answer(
                events, cursor, 2, ts=lambda e: e.occurred_at, parse_id=parse_event_id,
            ))
            page, cursor = await svc.list_events(
                fake_session, tenant_id=tenant_id, check_type="SCAN", cursor=cursor, limit=2,
            )
            pages.append(page)
            if cursor is None:
                break

        assert cursor is None
        assert [[e.id for e in page] for page in pages] == [[3, 4], [2, 1], [5]]
        first, *later = (_sql(s) for s in fake_session.statements)
        assert "dlp.dlp_event.check_type = 'SCAN'" in first
        # LIMIT is one past the page: that row only tells whether another page follows.
        assert first.endswith(f"{_EVENTS_ORDER_BY} LIMIT 3")
        assert _EVENTS_AFTER not in first
        for previous, sql in zip(pages[:-1], later, strict=True):
            last = previous[-1]  # each page resumes right after the last event shown
            assert sql.endswith(f"{_EVENTS_ORDER_BY} LIMIT 3")
            assert f"{_EVENTS_AFTER}('{last.occurred_at}', {last.id})" in sql

    async def test_list_classifications_pages_through_every_label_once(
        self, svc: DLPService, fake_session, tenant_id: str
    ) -> None:
        # Labels written in one transaction share its now(); ids need not follow updated_at.
        labels = [
            make_classification(cls_id="cls_5", resource_id="doc_5", updated_at=_T0),
            make_classification(cls_id="cls_1", resource_id="doc_1", updated_at=_T0 + _TICK),
            make_classification(cls_id="cls_4", resource_id="doc_4", updated_at=_T0 + _TICK),
            make_classification(cls_id="cls_2", resource_id="doc_2", updated_at=_T0 + _TICK),
            make_classification(cls_id="cls_3", resource_id="doc_3", updated_at=_T0 + 2 * _TICK),
        ]

        pages: list[list[Classification]] = []
        cursor = None
        for _ in labels:  # a cursor that never runs out fails below instead of looping
            fake_session.queue_scalars(newest_first_answer(
                labels, cursor, 2, ts=lambda c: c.updated_at, parse_id=parse_classification_id,
            ))
            page, cursor = await svc.list_classifications(
                fake_session, tenant_id=tenant_id, sensitivity="L3", cursor=cursor, limit=2,
            )
            pages.append(page)
            if cursor is None:
                break

        assert cursor is None
        assert [[c.id for c in page] for page in pages] == [
            ["cls_3", "cls_4"], ["cls_2", "cls_1"], ["cls_5"],
        ]
        first, *later = (_sql(s) for s in fake_session.statements)
        assert "dlp.classification.sensitivity = 'L3'" in first
        # LIMIT is one past the page: that row only tells whether another page follows.
        assert first.endswith(f"{_LABELS_ORDER_BY} LIMIT 3")
        assert _LABELS_AFTER not in first
        for previous, sql in zip(pages[:-1], later, strict=True):
            last = previous[-1]  # each page resumes right after the last label shown
            assert sql.endswith(f"{_LABELS_ORDER_BY} LIMIT 3")
            assert f"{_LABELS_AFTER}('{last.updated_at}', '{last.id}')" in sql

    async def test_a_full_last_page_of_events_has_no_next_cursor(
        self, svc: DLPService, fake_session, tenant_id: str
    ) -> None:
        events = [make_dlp_event(event_id=n, occurred_at=_T0) for n in (1, 2)]
        fake_session.queue_scalars(newest_first_answer(
            events, None, 2, ts=lambda e: e.occurred_at, parse_id=parse_event_id,
        ))

        page, cursor = await svc.list_events(fake_session, tenant_id=tenant_id, limit=2)

        assert [e.id for e in page] == [2, 1]
        assert cursor is None  # the lookahead row decides, not len(page) == limit

    async def test_a_full_last_page_of_labels_has_no_next_cursor(
        self, svc: DLPService, fake_session, tenant_id: str
    ) -> None:
        labels = [
            make_classification(cls_id=f"cls_{n}", resource_id=f"doc_{n}", updated_at=_T0)
            for n in (1, 2)
        ]
        fake_session.queue_scalars(newest_first_answer(
            labels, None, 2, ts=lambda c: c.updated_at, parse_id=parse_classification_id,
        ))

        page, cursor = await svc.list_classifications(fake_session, tenant_id=tenant_id, limit=2)

        assert [c.id for c in page] == ["cls_2", "cls_1"]
        assert cursor is None  # the lookahead row decides, not len(page) == limit

    @pytest.mark.parametrize("cursor", [
        "2026-10-30T12:00:00+00:00",  # a bare timestamp: what next_before used to hold
        encode_cursor(_T0, "cls_01J0000000000000000000CLS1"),  # the label list's cursor
        encode_cursor(_T0, 2**63),  # past bigint: the driver would fail, not a 422
        "%%%",
    ])
    async def test_list_events_rejects_a_cursor_it_did_not_issue(
        self, svc: DLPService, fake_session, tenant_id: str, cursor: str
    ) -> None:
        with pytest.raises(FoundationError) as exc:
            await svc.list_events(fake_session, tenant_id=tenant_id, cursor=cursor)

        assert exc.value.error_code is VALIDATION_FAILED
        assert fake_session.statements == []

    @pytest.mark.parametrize("cursor", [
        "2026-10-30T12:00:00+00:00",  # a bare timestamp: what next_before used to hold
        encode_cursor(_T0, 7),  # the event list's cursor
        "%%%",
    ])
    async def test_list_classifications_rejects_a_cursor_it_did_not_issue(
        self, svc: DLPService, fake_session, tenant_id: str, cursor: str
    ) -> None:
        with pytest.raises(FoundationError) as exc:
            await svc.list_classifications(fake_session, tenant_id=tenant_id, cursor=cursor)

        assert exc.value.error_code is VALIDATION_FAILED
        assert fake_session.statements == []

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

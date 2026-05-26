"""Unit tests for DLP + Classification service."""

from __future__ import annotations
import pytest
from foundation_dlp.domain.models import Classification
from foundation_dlp.errors import CLEARANCE_INSUFFICIENT, SENSITIVITY_IMMUTABLE_DOWNGRADE, FoundationError
from foundation_dlp.services.dlp_service import DLPService

from tests._factories import make_classification, make_dlp_rule


@pytest.fixture
def svc() -> DLPService: return DLPService()


class TestClassification:
    async def test_tag_new_resource(self, svc: DLPService, fake_session, tenant_id: str, actor_id: str, request_id: str) -> None:
        fake_session.queue_scalar(None)  # no existing classification
        cls = await svc.tag_resource(session=fake_session, tenant_id=tenant_id,
            resource_type="document", resource_id="doc_1", sensitivity="L3",
            tags=["pii"], reason="has customer data", tagged_by=actor_id, request_id=request_id)
        assert cls.sensitivity == "L3"
        assert cls.resource_id == "doc_1"

    async def test_upgrade_allowed(self, svc: DLPService, fake_session, tenant_id: str, actor_id: str, request_id: str) -> None:
        existing = make_classification(tenant_id=tenant_id, resource_type="doc", resource_id="doc_1", sensitivity="L2")
        fake_session.queue_scalar(existing)
        cls = await svc.tag_resource(session=fake_session, tenant_id=tenant_id,
            resource_type="doc", resource_id="doc_1", sensitivity="L4",
            tags=[], reason="upgraded", tagged_by=actor_id, request_id=request_id)
        assert cls.sensitivity == "L4"

    async def test_downgrade_blocked(self, svc: DLPService, fake_session, tenant_id: str, actor_id: str, request_id: str) -> None:
        existing = make_classification(tenant_id=tenant_id, resource_type="doc", resource_id="doc_1", sensitivity="L4")
        fake_session.queue_scalar(existing)
        with pytest.raises(FoundationError) as exc:
            await svc.tag_resource(session=fake_session, tenant_id=tenant_id,
                resource_type="doc", resource_id="doc_1", sensitivity="L2",
                tags=[], reason="try downgrade", tagged_by=actor_id, request_id=request_id)
        assert exc.value.error_code is SENSITIVITY_IMMUTABLE_DOWNGRADE

    async def test_default_sensitivity_is_L2(self, svc: DLPService, fake_session, tenant_id: str) -> None:
        fake_session.queue_scalar(None)
        cls = await svc.get_sensitivity(session=fake_session, tenant_id=tenant_id,
            resource_type="doc", resource_id="new_doc")
        assert cls.sensitivity == "L2"


class TestAccessCheck:
    async def test_check_read_allowed(self, svc: DLPService, fake_session, tenant_id: str, actor_id: str, request_id: str) -> None:
        cls = make_classification(tenant_id=tenant_id, sensitivity="L2")
        fake_session.queue_scalar(cls)
        result = await svc.check_read(session=fake_session, tenant_id=tenant_id,
            user_id="usr_1", user_clearance="L3", resource_type="doc", resource_id="doc_1",
            request_id=request_id)
        assert result["allowed"] is True

    async def test_check_read_denied(self, svc: DLPService, fake_session, tenant_id: str, actor_id: str, request_id: str) -> None:
        cls = make_classification(tenant_id=tenant_id, sensitivity="L4")
        fake_session.queue_scalar(cls)
        result = await svc.check_read(session=fake_session, tenant_id=tenant_id,
            user_id="usr_1", user_clearance="L2", resource_type="doc", resource_id="doc_1",
            request_id=request_id)
        assert result["allowed"] is False

    async def test_check_download_L5_always_denied(self, svc: DLPService, fake_session, tenant_id: str, actor_id: str, request_id: str) -> None:
        cls = make_classification(tenant_id=tenant_id, sensitivity="L5")
        fake_session.queue_scalar(cls)
        result = await svc.check_download(session=fake_session, tenant_id=tenant_id,
            user_id="usr_1", user_clearance="L5", resource_type="doc", resource_id="top_secret",
            destination="laptop", request_id=request_id)
        assert result["allowed"] is False
        assert "L5" in str(result.get("reason", ""))


class TestContentScan:
    async def test_scan_with_keyword_rule(self, svc: DLPService, fake_session, tenant_id: str, request_id: str) -> None:
        import json
        rule = make_dlp_rule(tenant_id=tenant_id, rule_type="KEYWORD",
            pattern=json.dumps(["身份证", "银行卡"]), min_sensitivity="L3")
        fake_session.queue_scalars([rule])
        result = await svc.scan_content(session=fake_session, tenant_id=tenant_id,
            content="这是包含身份证号码的文档", resource_type="doc", resource_id="doc_1",
            request_id=request_id)
        assert len(result["hits"]) >= 1
        assert result["max_sensitivity"] == "L3"

    async def test_scan_with_regex_rule(self, svc: DLPService, fake_session, tenant_id: str, request_id: str) -> None:
        rule = make_dlp_rule(tenant_id=tenant_id, rule_type="REGEX",
            pattern=r"\b\d{6}(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b",
            min_sensitivity="L4")
        fake_session.queue_scalars([rule])
        result = await svc.scan_content(session=fake_session, tenant_id=tenant_id,
            content="身份证号 110101199001011234", resource_type="doc", resource_id="doc_2",
            request_id=request_id)
        assert result["max_sensitivity"] == "L4"

    async def test_scan_clean_content(self, svc: DLPService, fake_session, tenant_id: str, request_id: str) -> None:
        fake_session.queue_scalars([])
        result = await svc.scan_content(session=fake_session, tenant_id=tenant_id,
            content="这是一份普通的产品文档", resource_type="doc", resource_id="doc_3",
            request_id=request_id)
        assert result["hits"] == []
        assert result["max_sensitivity"] == "L1"

"""Unit tests for MaskingEngine and DataProtectionService."""

from __future__ import annotations
import pytest
from foundation_data_protection.services.masking_engine import MaskingEngine, PRESETS
from foundation_data_protection.services.data_protection_service import DataProtectionService
from foundation_data_protection.errors import FoundationError


class TestMaskingEngine:
    def setup_method(self):
        self.engine = MaskingEngine()

    def test_mask_phone(self):
        result = self.engine.mask("13812341234", "mask", keep_start=3, keep_end=4, pattern="****")
        assert result == "138****1234"

    def test_mask_truncate(self):
        result = self.engine.mask("110101199001011234", "truncate", keep=6)
        assert result == "110101"

    def test_mask_hash_deterministic(self):
        h1 = self.engine.mask("hello", "hash", purpose="test")
        h2 = self.engine.mask("hello", "hash", purpose="test")
        assert h1 == h2
        assert len(h1) == 32

    def test_mask_hash_different_purposes(self):
        h1 = self.engine.mask("hello", "hash", purpose="a")
        h2 = self.engine.mask("hello", "hash", purpose="b")
        assert h1 != h2

    def test_pseudonymize_deterministic(self):
        p1 = self.engine.mask("张三", "pseudonymize", purpose="name")
        p2 = self.engine.mask("张三", "pseudonymize", purpose="name")
        assert p1 == p2
        assert len(p1) == 16

    def test_suppress(self):
        result = self.engine.mask("anything", "suppress")
        assert result is None

    def test_passthrough(self):
        result = self.engine.mask("keep-me", "passthrough")
        assert result == "keep-me"

    def test_tokenize(self):
        t1 = self.engine.mask("secret", "tokenize")
        assert t1.startswith("tok_")

    def test_missing_method(self):
        with pytest.raises(ValueError, match="Unknown masking method"):
            self.engine.mask("x", "nonexistent")

    def test_mask_none_value(self):
        assert self.engine.mask(None, "mask") is None

    def test_mask_record(self):
        record = {"name": "张三", "phone": "13812341234", "id_card": "110101199001011234"}
        rules = {
            "name": {"method": "pseudonymize", "purpose": "person_name"},
            "phone": {"method": "mask", "keep_start": 3, "keep_end": 4, "pattern": "****"},
            "id_card": {"method": "truncate", "keep": 6},
        }
        result = self.engine.mask_record(record, rules)
        assert result["name"] != "张三"
        assert result["phone"] == "138****1234"
        assert result["id_card"] == "110101"

    def test_presets_exist(self):
        assert "phone" in PRESETS
        assert "id_card" in PRESETS
        assert "email" in PRESETS
        assert "person_name" in PRESETS


class TestCrossBorder:
    @pytest.fixture
    def svc(self):
        return DataProtectionService()

    async def test_cn_to_us_blocked_without_contract(self, svc, fake_session, tenant_id, request_id):
        result = await svc.check_cross_border(
            fake_session, tenant_id=tenant_id,
            data_country="CN", destination_country="US",
            data_type="personal_info", data_size_bytes=1024,
            has_standard_contract=False, has_safety_assessment=False,
            request_id=request_id)
        assert result["allowed"] is False
        assert result["decision"] == "BLOCKED"

    async def test_cn_to_us_allowed_with_contract(self, svc, fake_session, tenant_id, request_id):
        result = await svc.check_cross_border(
            fake_session, tenant_id=tenant_id,
            data_country="CN", destination_country="US",
            data_type="personal_info", data_size_bytes=1024,
            has_standard_contract=True, has_safety_assessment=True,
            request_id=request_id)
        assert result["allowed"] is True
        assert result["decision"] == "ALLOW"

    async def test_domestic_transfer_always_allowed(self, svc, fake_session, tenant_id, request_id):
        result = await svc.check_cross_border(
            fake_session, tenant_id=tenant_id,
            data_country="CN", destination_country="CN",
            data_type="personal_info", data_size_bytes=1024,
            has_standard_contract=False, has_safety_assessment=False,
            request_id=request_id)
        assert result["allowed"] is True


class TestDestructionApproval:
    @pytest.fixture
    def svc(self):
        return DataProtectionService()

    async def test_approve_requires_different_approver(self, svc, fake_session, tenant_id, request_id):
        from foundation_data_protection.domain.models import DataDestructionRequest
        req = DataDestructionRequest(
            id="ddr_test", tenant_id=tenant_id, resource_type="user_data",
            resource_ids=["res_1"], destruction_method="crypto_key_destroy",
            reason="gdpr deletion", requested_by="usr_requester",
            status="PENDING_APPROVAL")
        fake_session.put(req)

        with pytest.raises(FoundationError):
            await svc.approve_destruction(fake_session, tenant_id=tenant_id,
                request_id="ddr_test", approved_by="usr_requester")

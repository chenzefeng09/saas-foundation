"""Tests for Compliance service — ROPA, DPIA, DSAR, reports."""

import pytest

from foundation_compliance.services.compliance_service import ComplianceService
from foundation_compliance.domain.models import ROPARecord, DPIA, DSARRequest, ComplianceReport


class TestROPA:
    @pytest.fixture
    def svc(self):
        return ComplianceService()

    async def test_record_processing(self, svc, fake_session, tenant_id, request_id):
        record = await svc.record_processing(
            fake_session, tenant_id=tenant_id, service="identity",
            data_category="personal_info", purpose="user_authentication",
            legal_basis="consent", data_subjects=["employees"],
            recipients=["auth-service"], retention_days=365,
            cross_border=False, destination_countries=None,
            request_id=request_id,
        )
        assert isinstance(record, ROPARecord)
        assert record.id.startswith("ropa_")
        assert record.service == "identity"
        assert record.data_category == "personal_info"
        assert record.purpose == "user_authentication"
        assert record.legal_basis == "consent"
        assert "employees" in record.data_subjects
        assert record.retention_days == 365
        assert record.cross_border is False

    async def test_record_processing_cross_border(self, svc, fake_session, tenant_id, request_id):
        record = await svc.record_processing(
            fake_session, tenant_id=tenant_id, service="analytics",
            data_category="behavioral_data", purpose="product_improvement",
            legal_basis="legitimate_interest", data_subjects=["customers"],
            recipients=["analytics-provider"], retention_days=730,
            cross_border=True, destination_countries=["US", "SG"],
            request_id=request_id,
        )
        assert record.cross_border is True
        assert "US" in record.destination_countries
        assert "SG" in record.destination_countries

    async def test_list_ropa(self, svc, fake_session, tenant_id, request_id):
        # Create two records
        r1 = ROPARecord(
            id="ropa_1", tenant_id=tenant_id, service="svc1",
            data_category="cat1", purpose="p1", legal_basis="consent",
            data_subjects=[], recipients=[], retention_days=365,
            cross_border=False,
        )
        r2 = ROPARecord(
            id="ropa_2", tenant_id=tenant_id, service="svc2",
            data_category="cat2", purpose="p2", legal_basis="contract",
            data_subjects=[], recipients=[], retention_days=180,
            cross_border=False,
        )
        fake_session.queue_scalars([r1, r2])

        records = await svc.list_ropa(fake_session, tenant_id=tenant_id)
        assert len(records) == 2
        assert records[0].id in ("ropa_1", "ropa_2")


class TestDPIA:
    @pytest.fixture
    def svc(self):
        return ComplianceService()

    async def test_assess_dpia(self, svc, fake_session, tenant_id, request_id):
        dpia = await svc.assess_dpia(
            fake_session, tenant_id=tenant_id,
            project_name="AI Recommendation Engine",
            description="Processing user behavior for personalized recommendations",
            data_categories=["behavioral", "preferences"],
            risks=[{"risk": "profiling", "severity": "high"}],
            mitigations=[{"control": "opt-out", "status": "planned"}],
            assessed_by="dpo_001", request_id=request_id,
        )
        assert isinstance(dpia, DPIA)
        assert dpia.id.startswith("dpia_")
        assert dpia.project_name == "AI Recommendation Engine"
        assert dpia.conclusion == "ASSESSMENT_IN_PROGRESS"
        assert dpia.assessed_by == "dpo_001"
        assert len(dpia.risks) == 1
        assert dpia.risks[0]["severity"] == "high"

    async def test_complete_dpia(self, svc, fake_session, tenant_id, request_id):
        dpia = DPIA(
            id="dpia_pending", tenant_id=tenant_id,
            project_name="Test Project", description="Testing",
            data_categories=[], risks=[], mitigations=[],
            conclusion="ASSESSMENT_IN_PROGRESS", assessed_by="dpo_001",
        )
        fake_session.put(dpia)

        completed = await svc.complete_dpia(
            fake_session, tenant_id=tenant_id, dpia_id="dpia_pending",
            conclusion="APPROVED", residual_risks="Low risk after mitigations",
            approved_by="cco_001",
        )
        assert completed.conclusion == "APPROVED"
        assert completed.residual_risks == "Low risk after mitigations"
        assert completed.approved_by == "cco_001"
        assert completed.completed_at is not None

    async def test_complete_dpia_not_found(self, svc, fake_session, tenant_id, request_id):
        with pytest.raises(ValueError, match="not found"):
            await svc.complete_dpia(
                fake_session, tenant_id=tenant_id, dpia_id="nonexistent",
                conclusion="APPROVED", residual_risks="None",
                approved_by="cco_001",
            )

    async def test_complete_dpia_wrong_tenant(self, svc, fake_session, tenant_id, request_id):
        dpia = DPIA(
            id="dpia_other", tenant_id="tnt_OTHER",
            project_name="Other Project", description="Testing",
            data_categories=[], risks=[], mitigations=[],
            conclusion="ASSESSMENT_IN_PROGRESS", assessed_by="dpo_001",
        )
        fake_session.put(dpia)

        with pytest.raises(ValueError, match="not found"):
            await svc.complete_dpia(
                fake_session, tenant_id=tenant_id, dpia_id="dpia_other",
                conclusion="APPROVED", residual_risks="None",
                approved_by="cco_001",
            )


class TestDSAR:
    @pytest.fixture
    def svc(self):
        return ComplianceService()

    async def test_request_dsar(self, svc, fake_session, tenant_id, request_id):
        dsar = await svc.request_dsar(
            fake_session, tenant_id=tenant_id, user_id="usr_001",
            request_type="ERASURE", details="Request to delete all personal data",
            request_id=request_id,
        )
        assert isinstance(dsar, DSARRequest)
        assert dsar.id.startswith("dsar_")
        assert dsar.status == "RECEIVED"
        assert dsar.request_type == "ERASURE"
        assert dsar.sla_deadline is not None

    async def test_request_dsar_access(self, svc, fake_session, tenant_id, request_id):
        dsar = await svc.request_dsar(
            fake_session, tenant_id=tenant_id, user_id="usr_002",
            request_type="ACCESS", details="Request copy of all data",
            request_id=request_id,
        )
        assert dsar.request_type == "ACCESS"

    async def test_update_dsar_status(self, svc, fake_session, tenant_id, request_id):
        dsar = DSARRequest(
            id="dsar_open", tenant_id=tenant_id,
            user_id="usr_001", request_type="ERASURE",
            details="Delete all", status="RECEIVED",
            sla_deadline=None,
        )
        fake_session.put(dsar)

        updated = await svc.update_dsar_status(
            fake_session, tenant_id=tenant_id, dsar_id="dsar_open",
            status="IN_PROGRESS", response=None,
        )
        assert updated.status == "IN_PROGRESS"

    async def test_update_dsar_completed(self, svc, fake_session, tenant_id, request_id):
        dsar = DSARRequest(
            id="dsar_done", tenant_id=tenant_id,
            user_id="usr_001", request_type="ERASURE",
            details="Delete all", status="IN_PROGRESS",
            sla_deadline=None,
        )
        fake_session.put(dsar)

        updated = await svc.update_dsar_status(
            fake_session, tenant_id=tenant_id, dsar_id="dsar_done",
            status="COMPLETED", response="All data has been deleted",
        )
        assert updated.status == "COMPLETED"
        assert updated.response == "All data has been deleted"
        assert updated.completed_at is not None


class TestReports:
    @pytest.fixture
    def svc(self):
        return ComplianceService()

    async def test_generate_report_soc2(self, svc, fake_session, tenant_id, request_id):
        report = await svc.generate_report(
            fake_session, tenant_id=tenant_id, report_type="soc2_type2",
            compliance_modes=["soc2", "iso27001"],
            generated_by="admin", request_id=request_id,
        )
        assert isinstance(report, ComplianceReport)
        assert report.id.startswith("cpr_")
        assert report.report_type == "soc2_type2"
        assert "soc2" in report.compliance_modes
        sections = report.content_json.get("sections", [])
        assert len(sections) > 0
        # Should contain SOC2 sections
        section_names = [s["name"] for s in sections]
        assert "Security" in section_names

    async def test_generate_report_equal_protection(self, svc, fake_session, tenant_id, request_id):
        report = await svc.generate_report(
            fake_session, tenant_id=tenant_id, report_type="equal_protection_self_check",
            compliance_modes=["equal_protection_3"],
            generated_by="security_officer", request_id=request_id,
        )
        sections = report.content_json.get("sections", [])
        section_names = [s["name"] for s in sections]
        assert "安全通信网络" in section_names
        assert "安全区域边界" in section_names
        assert "安全计算环境" in section_names

    async def test_generate_report_multiple_modes(self, svc, fake_session, tenant_id, request_id):
        report = await svc.generate_report(
            fake_session, tenant_id=tenant_id, report_type="full_compliance",
            compliance_modes=["soc2", "iso27001", "equal_protection_3"],
            generated_by="admin", request_id=request_id,
        )
        sections = report.content_json.get("sections", [])
        assert len(sections) >= 10  # All 3 modes combined

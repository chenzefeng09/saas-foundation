"""Tests for PAMService."""

import pytest
from datetime import UTC, datetime, timedelta
from foundation_pam.services.pam_service import PAMService
from foundation_pam.domain.models import PAMElevationRequest, PAMSession


class TestPAM:
    @pytest.fixture
    def svc(self):
        return PAMService()

    async def test_request_elevation(self, svc, fake_session, tenant_id, request_id):
        req = await svc.request_elevation(
            fake_session, tenant_id=tenant_id, user_id="usr_1",
            reason="Need to destroy KEK for compliance", target_permissions=["crypto.kek.destroy"],
            duration_minutes=30, ticket_reference="INC-123", request_id=request_id)
        assert req.status == "PENDING"
        assert req.duration_minutes == 30
        assert req.id.startswith("pam_")

    async def test_request_invalid_duration(self, svc, fake_session, tenant_id, request_id):
        with pytest.raises(ValueError):
            await svc.request_elevation(fake_session, tenant_id=tenant_id, user_id="usr_1",
                reason="test", target_permissions=["read"], duration_minutes=1000,
                ticket_reference=None, request_id=request_id)

    async def test_approve_creates_session(self, svc, fake_session, tenant_id, request_id):
        req = PAMElevationRequest(
            id="pam_test", tenant_id=tenant_id, user_id="usr_requester",
            reason="test", target_permissions=["admin"], duration_minutes=60,
            status="PENDING", expires_at=datetime.now(UTC) + timedelta(hours=1))
        fake_session.put(req)

        result = await svc.approve(fake_session, tenant_id=tenant_id,
            request_id_str="pam_test", approver_id="usr_approver", reason="Approved")
        assert result.status == "APPROVED"

    async def test_approve_self_denied(self, svc, fake_session, tenant_id, request_id):
        req = PAMElevationRequest(
            id="pam_test", tenant_id=tenant_id, user_id="usr_1",
            reason="test", target_permissions=["admin"], duration_minutes=60,
            status="PENDING", expires_at=datetime.now(UTC) + timedelta(hours=1))
        fake_session.put(req)

        with pytest.raises(ValueError, match="four-eyes"):
            await svc.approve(fake_session, tenant_id=tenant_id,
                request_id_str="pam_test", approver_id="usr_1", reason=None)

    async def test_revoke_session(self, svc, fake_session, tenant_id, request_id):
        s = PAMSession(
            id="pams_test", tenant_id=tenant_id, elevation_request_id="pam_test",
            user_id="usr_1", approved_by="usr_approver", permissions=["admin"],
            started_at=datetime.now(UTC), expires_at=datetime.now(UTC) + timedelta(hours=1),
            is_active=True)
        fake_session.put(s)

        await svc.revoke(fake_session, tenant_id=tenant_id, session_id="pams_test",
            revoked_by="security_admin", reason="Security incident")
        assert s.is_active is False

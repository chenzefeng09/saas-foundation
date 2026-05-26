"""Unit tests for MembershipService."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from foundation_org.errors import (
    MEMBERSHIP_NOT_FOUND,
    ORG_UNIT_ARCHIVED,
    ORG_UNIT_NOT_FOUND,
    FoundationError,
)
from foundation_org.services.membership_service import MembershipService

from tests._factories import make_membership, make_org_unit, make_team


@pytest.fixture
def svc(audit_publisher: AsyncMock) -> MembershipService:
    return MembershipService(audit=audit_publisher)


class TestGet:
    async def test_get_found(
        self, svc: MembershipService, fake_session, tenant_id: str,
    ) -> None:
        m = make_membership(tenant_id=tenant_id)
        fake_session.put(m)

        result = await svc.get(fake_session, tenant_id=tenant_id, user_id=m.user_id)
        assert result.user_id == m.user_id

    async def test_get_not_found(
        self, svc: MembershipService, fake_session, tenant_id: str,
    ) -> None:
        with pytest.raises(FoundationError) as exc:
            await svc.get(fake_session, tenant_id=tenant_id, user_id="usr_nonexistent")
        assert exc.value.error_code is MEMBERSHIP_NOT_FOUND


class TestUpsert:
    async def test_upsert_new(
        self, svc: MembershipService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        ou = make_org_unit(tenant_id=tenant_id)
        fake_session.put(ou)

        result = await svc.upsert(
            fake_session, tenant_id=tenant_id, request_id=request_id, actor_id=actor_id,
            user_id="usr_new", primary_org_unit_id=ou.id,
            job_title="Engineer", employee_no="E001", join_date=None,
            manager_user_id=None, employment_kind="EMPLOYEE", metadata={},
        )
        assert result.user_id == "usr_new"
        assert result.primary_org_unit_id == ou.id

    async def test_upsert_invalid_ou(
        self, svc: MembershipService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        with pytest.raises(FoundationError) as exc:
            await svc.upsert(
                fake_session, tenant_id=tenant_id, request_id=request_id, actor_id=actor_id,
                user_id="usr_new", primary_org_unit_id="ou_nonexistent",
                job_title=None, employee_no=None, join_date=None,
                manager_user_id=None, employment_kind="EMPLOYEE", metadata={},
            )
        assert exc.value.error_code is ORG_UNIT_NOT_FOUND

    async def test_upsert_archived_ou(
        self, svc: MembershipService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        ou = make_org_unit(tenant_id=tenant_id, is_archived=True)
        fake_session.put(ou)

        with pytest.raises(FoundationError) as exc:
            await svc.upsert(
                fake_session, tenant_id=tenant_id, request_id=request_id, actor_id=actor_id,
                user_id="usr_new", primary_org_unit_id=ou.id,
                job_title=None, employee_no=None, join_date=None,
                manager_user_id=None, employment_kind="EMPLOYEE", metadata={},
            )
        assert exc.value.error_code is ORG_UNIT_ARCHIVED

    async def test_upsert_update_existing(
        self, svc: MembershipService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        ou = make_org_unit(tenant_id=tenant_id)
        existing = make_membership(tenant_id=tenant_id, user_id="usr_existing")
        fake_session.put(ou)
        fake_session.put(existing)

        result = await svc.upsert(
            fake_session, tenant_id=tenant_id, request_id=request_id, actor_id=actor_id,
            user_id="usr_existing", primary_org_unit_id=ou.id,
            job_title="Senior Engineer", employee_no="E001", join_date=None,
            manager_user_id=None, employment_kind="EMPLOYEE", metadata={},
        )
        assert result.job_title == "Senior Engineer"

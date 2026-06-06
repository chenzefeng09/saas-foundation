"""Unit tests for MembershipService."""

from __future__ import annotations

from datetime import date, datetime, UTC
from unittest.mock import AsyncMock

import pytest

from foundation_org.errors import (
    MEMBERSHIP_NOT_FOUND,
    ORG_UNIT_ARCHIVED,
    ORG_UNIT_NOT_FOUND,
    TEAM_NOT_FOUND,
    FoundationError,
)
from foundation_org.domain.models import UserOrgUnitSecondary
from foundation_org.services.membership_service import MembershipService

from tests._factories import make_membership, make_org_unit, make_team, make_team_membership


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


class TestTransfer:
    async def test_transfer_moves_primary_ou_and_replaces_teams(
        self, svc: MembershipService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        member = make_membership(tenant_id=tenant_id, primary_org_unit_id="ou_from")
        target_ou = make_org_unit(ou_id="ou_to", tenant_id=tenant_id)
        target_team = make_team(team_id="tm_target", tenant_id=tenant_id, org_unit_id=target_ou.id)
        previous_team = make_team_membership(tenant_id=tenant_id, user_id=member.user_id)
        returning_team = make_team_membership(
            tenant_id=tenant_id,
            user_id=member.user_id,
            team_id=target_team.id,
            left=True,
        )
        fake_session.put(member)
        fake_session.put(target_ou)
        fake_session.put(target_team)
        fake_session.put(returning_team)
        fake_session.queue_scalars([previous_team])

        result = await svc.transfer(
            fake_session,
            tenant_id=tenant_id,
            request_id=request_id,
            actor_id=actor_id,
            user_id=member.user_id,
            to_org_unit_id=target_ou.id,
            to_team_ids=[target_team.id],
            effective_date=date(2026, 1, 1),
            reason="rotation",
        )

        assert result.primary_org_unit_id == target_ou.id
        assert previous_team.left_at is not None
        assert returning_team.left_at is None
        assert returning_team.granted_by == actor_id

    async def test_transfer_rejects_team_in_different_ou(
        self, svc: MembershipService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        member = make_membership(tenant_id=tenant_id)
        target_ou = make_org_unit(ou_id="ou_to", tenant_id=tenant_id)
        wrong_team = make_team(team_id="tm_wrong", tenant_id=tenant_id, org_unit_id="ou_other")
        fake_session.put(member)
        fake_session.put(target_ou)
        fake_session.put(wrong_team)

        with pytest.raises(FoundationError) as exc:
            await svc.transfer(
                fake_session,
                tenant_id=tenant_id,
                request_id=request_id,
                actor_id=actor_id,
                user_id=member.user_id,
                to_org_unit_id=target_ou.id,
                to_team_ids=[wrong_team.id],
                effective_date=None,
                reason=None,
            )

        assert exc.value.error_code is TEAM_NOT_FOUND

    async def test_transfer_rejects_archived_team(
        self, svc: MembershipService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        member = make_membership(tenant_id=tenant_id)
        target_ou = make_org_unit(ou_id="ou_to", tenant_id=tenant_id)
        archived_team = make_team(
            team_id="tm_archived",
            tenant_id=tenant_id,
            org_unit_id=target_ou.id,
            is_archived=True,
        )
        fake_session.put(member)
        fake_session.put(target_ou)
        fake_session.put(archived_team)

        with pytest.raises(FoundationError) as exc:
            await svc.transfer(
                fake_session,
                tenant_id=tenant_id,
                request_id=request_id,
                actor_id=actor_id,
                user_id=member.user_id,
                to_org_unit_id=target_ou.id,
                to_team_ids=[archived_team.id],
                effective_date=None,
                reason=None,
            )

        assert exc.value.error_code is TEAM_NOT_FOUND


class TestSecondaryAssignments:
    async def test_list_secondary_returns_rows(
        self, svc: MembershipService, fake_session, tenant_id: str,
    ) -> None:
        row = UserOrgUnitSecondary(
            user_id="usr_01J0000000000000000000USR1",
            org_unit_id="ou_01J0000000000000000000OU01",
            valid_from=datetime.now(UTC),
            tenant_id=tenant_id,
            reason="TEMP_ASSIGN",
            valid_until=None,
            granted_by="usr_01J0000000000000000000ACT1",
        )
        fake_session.queue_scalars([row])

        rows = await svc.list_secondary(
            fake_session,
            tenant_id=tenant_id,
            user_id=row.user_id,
        )

        assert rows == [row]

    async def test_add_secondary_requires_active_ou_and_publishes(
        self, svc: MembershipService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        ou = make_org_unit(tenant_id=tenant_id)
        fake_session.put(ou)

        row = await svc.add_secondary(
            fake_session,
            tenant_id=tenant_id,
            request_id=request_id,
            actor_id=actor_id,
            user_id="usr_01J0000000000000000000USR1",
            org_unit_id=ou.id,
            reason="TEMP_ASSIGN",
            valid_until=None,
        )

        assert row.org_unit_id == ou.id
        assert row.granted_by == actor_id

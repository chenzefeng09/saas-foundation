"""Unit tests for OrgUnitService."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from foundation_org.errors import (
    ORG_UNIT_ARCHIVED,
    ORG_UNIT_CODE_CONFLICT,
    ORG_UNIT_DEPTH_EXCEEDED,
    ORG_UNIT_IMMUTABLE_CODE,
    ORG_UNIT_NOT_EMPTY,
    ORG_UNIT_NOT_FOUND,
    FoundationError,
)
from foundation_org.services.org_unit_service import OrgUnitService

from tests._factories import make_org_unit


@pytest.fixture
def svc(audit_publisher: AsyncMock) -> OrgUnitService:
    return OrgUnitService(audit=audit_publisher)


class TestGet:
    async def test_get_found(self, svc: OrgUnitService, fake_session, tenant_id: str) -> None:
        ou = make_org_unit(tenant_id=tenant_id)
        fake_session.put(ou)

        result = await svc.get(fake_session, tenant_id=tenant_id, ou_id=ou.id)
        assert result.id == ou.id

    async def test_get_not_found(self, svc: OrgUnitService, fake_session, tenant_id: str) -> None:
        with pytest.raises(FoundationError) as exc:
            await svc.get(fake_session, tenant_id=tenant_id, ou_id="ou_nonexistent")
        assert exc.value.error_code is ORG_UNIT_NOT_FOUND

    async def test_get_archived_excluded_by_default(
        self, svc: OrgUnitService, fake_session, tenant_id: str,
    ) -> None:
        ou = make_org_unit(tenant_id=tenant_id, is_archived=True)
        fake_session.put(ou)

        with pytest.raises(FoundationError) as exc:
            await svc.get(fake_session, tenant_id=tenant_id, ou_id=ou.id)
        assert exc.value.error_code is ORG_UNIT_NOT_FOUND

    async def test_get_archived_included(
        self, svc: OrgUnitService, fake_session, tenant_id: str,
    ) -> None:
        ou = make_org_unit(tenant_id=tenant_id, is_archived=True)
        fake_session.put(ou)

        result = await svc.get(fake_session, tenant_id=tenant_id, ou_id=ou.id, include_archived=True)
        assert result.id == ou.id

    async def test_get_deleted_excluded(
        self, svc: OrgUnitService, fake_session, tenant_id: str,
    ) -> None:
        ou = make_org_unit(tenant_id=tenant_id, deleted=True)
        fake_session.put(ou)

        with pytest.raises(FoundationError) as exc:
            await svc.get(fake_session, tenant_id=tenant_id, ou_id=ou.id, include_archived=True)
        assert exc.value.error_code is ORG_UNIT_NOT_FOUND


class TestCreate:
    async def test_create_root_ou(
        self, svc: OrgUnitService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        # No existing OU with same code under same parent
        fake_session.queue_scalar(None)

        result = await svc.create(
            fake_session, tenant_id=tenant_id, request_id=request_id, actor_id=actor_id,
            parent_id=None, code="engineering", name="Engineering", name_en=None,
            description=None, manager_user_id=None, kind="DEPARTMENT", sort_order=0, metadata={},
        )
        assert result.code == "engineering"
        assert result.name == "Engineering"
        assert result.depth == 0
        assert result.id.startswith("ou_")

    async def test_create_child_ou(
        self, svc: OrgUnitService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        parent = make_org_unit(ou_id="ou_parent", tenant_id=tenant_id, code="eng", depth=0)
        fake_session.put(parent)
        fake_session.queue_scalar(None)  # no code conflict

        result = await svc.create(
            fake_session, tenant_id=tenant_id, request_id=request_id, actor_id=actor_id,
            parent_id=parent.id, code="backend", name="Backend", name_en=None,
            description=None, manager_user_id=None, kind="DEPARTMENT", sort_order=1, metadata={},
        )
        assert result.parent_id == parent.id
        assert result.depth == 1

    async def test_create_code_conflict(
        self, svc: OrgUnitService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        existing = make_org_unit(tenant_id=tenant_id, code="engineering")
        fake_session.queue_scalar(existing)

        with pytest.raises(FoundationError) as exc:
            await svc.create(
                fake_session, tenant_id=tenant_id, request_id=request_id, actor_id=actor_id,
                parent_id=None, code="engineering", name="Engineering", name_en=None,
                description=None, manager_user_id=None, kind="DEPARTMENT", sort_order=0, metadata={},
            )
        assert exc.value.error_code is ORG_UNIT_CODE_CONFLICT

    async def test_create_parent_archived(
        self, svc: OrgUnitService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        parent = make_org_unit(ou_id="ou_parent", tenant_id=tenant_id, is_archived=True)
        fake_session.put(parent)

        with pytest.raises(FoundationError) as exc:
            await svc.create(
                fake_session, tenant_id=tenant_id, request_id=request_id, actor_id=actor_id,
                parent_id=parent.id, code="child", name="Child", name_en=None,
                description=None, manager_user_id=None, kind="DEPARTMENT", sort_order=0, metadata={},
            )
        assert exc.value.error_code is ORG_UNIT_ARCHIVED

    async def test_create_parent_not_found(
        self, svc: OrgUnitService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        with pytest.raises(FoundationError) as exc:
            await svc.create(
                fake_session, tenant_id=tenant_id, request_id=request_id, actor_id=actor_id,
                parent_id="ou_nonexistent", code="child", name="Child", name_en=None,
                description=None, manager_user_id=None, kind="DEPARTMENT", sort_order=0, metadata={},
            )
        assert exc.value.error_code is ORG_UNIT_NOT_FOUND


class TestUpdate:
    async def test_update_name(
        self, svc: OrgUnitService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        ou = make_org_unit(tenant_id=tenant_id)
        fake_session.put(ou)

        result = await svc.update(
            fake_session, tenant_id=tenant_id, request_id=request_id, actor_id=actor_id,
            ou_id=ou.id, patch={"name": "New Name"},
        )
        assert result.name == "New Name"

    async def test_update_code_rejected(
        self, svc: OrgUnitService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        ou = make_org_unit(tenant_id=tenant_id)
        fake_session.put(ou)

        with pytest.raises(FoundationError) as exc:
            await svc.update(
                fake_session, tenant_id=tenant_id, request_id=request_id, actor_id=actor_id,
                ou_id=ou.id, patch={"code": "new-code"},
            )
        assert exc.value.error_code is ORG_UNIT_IMMUTABLE_CODE


class TestArchive:
    async def test_archive_empty_ou(
        self, svc: OrgUnitService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        ou = make_org_unit(tenant_id=tenant_id)
        fake_session.put(ou)
        # No children, no teams, no members
        fake_session.queue_scalar(None)  # child check
        fake_session.queue_scalar(None)  # team check
        fake_session.queue_scalar(None)  # member check

        result = await svc.archive(
            fake_session, tenant_id=tenant_id, request_id=request_id,
            actor_id=actor_id, ou_id=ou.id, reason="Reorg",
        )
        assert result.is_archived is True

    async def test_archive_with_children(
        self, svc: OrgUnitService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        ou = make_org_unit(tenant_id=tenant_id)
        child = make_org_unit(ou_id="ou_child", tenant_id=tenant_id, parent_id=ou.id)
        fake_session.put(ou)
        fake_session.queue_scalar(child)  # has children

        with pytest.raises(FoundationError) as exc:
            await svc.archive(
                fake_session, tenant_id=tenant_id, request_id=request_id,
                actor_id=actor_id, ou_id=ou.id, reason="Reorg",
            )
        assert exc.value.error_code is ORG_UNIT_NOT_EMPTY


class TestDelete:
    async def test_delete_archived_ou(
        self, svc: OrgUnitService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        ou = make_org_unit(tenant_id=tenant_id, is_archived=True)
        fake_session.put(ou)

        await svc.delete(
            fake_session, tenant_id=tenant_id, request_id=request_id,
            actor_id=actor_id, ou_id=ou.id,
        )
        assert ou.deleted_at is not None

    async def test_delete_unarchived_raises(
        self, svc: OrgUnitService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        ou = make_org_unit(tenant_id=tenant_id, is_archived=False)
        fake_session.put(ou)

        with pytest.raises(FoundationError) as exc:
            await svc.delete(
                fake_session, tenant_id=tenant_id, request_id=request_id,
                actor_id=actor_id, ou_id=ou.id,
            )
        assert exc.value.error_code is ORG_UNIT_NOT_EMPTY

"""Unit tests for OrgUnitService."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest
from sqlalchemy.dialects import postgresql

from foundation_org.domain.models import OrgUnit
from foundation_org.errors import (
    ORG_UNIT_ARCHIVED,
    ORG_UNIT_CODE_CONFLICT,
    ORG_UNIT_CYCLE,
    ORG_UNIT_DEPTH_EXCEEDED,
    ORG_UNIT_IMMUTABLE_CODE,
    ORG_UNIT_NOT_EMPTY,
    ORG_UNIT_NOT_FOUND,
    FoundationError,
)
from foundation_org.services.org_unit_service import OrgUnitService

from tests._factories import make_membership, make_org_unit, make_team


@pytest.fixture
def svc(audit_publisher: AsyncMock) -> OrgUnitService:
    return OrgUnitService(audit=audit_publisher)


def _sql(stmt: Any) -> str:
    """Render a recorded SELECT as Postgres SQL, values inlined."""
    compiled = stmt.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True})
    return " ".join(str(compiled).split())


def _db_answer(units: list[OrgUnit], cursor: str | None, limit: int) -> list[OrgUnit]:
    """What ``WHERE id > :cursor ORDER BY id LIMIT :limit + 1`` returns from ``units``."""
    ordered = sorted(units, key=lambda u: u.id)
    return [u for u in ordered if cursor is None or u.id > cursor][: limit + 1]


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


class TestList:
    async def test_list_pages_through_every_org_unit_once(
        self, svc: OrgUnitService, fake_session, tenant_id: str,
    ) -> None:
        units = [
            make_org_unit(ou_id=f"ou_01J0000000000000000000OU0{i}", tenant_id=tenant_id)
            for i in range(1, 6)
        ]

        pages: list[list[OrgUnit]] = []
        cursor = None
        for _ in units:  # a cursor that never runs out fails below instead of looping
            fake_session.queue_scalars(_db_answer(units, cursor, limit=2))
            page, cursor = await svc.list(
                fake_session, tenant_id=tenant_id, cursor=cursor, limit=2,
            )
            pages.append(page)
            if cursor is None:
                break

        assert cursor is None
        assert pages == [units[0:2], units[2:4], units[4:5]]
        first, *later = (_sql(s) for s in fake_session.statements)
        assert "ORDER BY org.org_unit.id LIMIT 3" in first
        assert "org.org_unit.id >" not in first
        for previous, sql in zip(pages[:-1], later, strict=True):
            # Each page resumes right after the last unit the previous one showed.
            assert f"org.org_unit.id > '{previous[-1].id}' ORDER BY org.org_unit.id LIMIT 3" in sql


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

    async def test_update_no_changes_skips_audit(
        self, svc: OrgUnitService, fake_session, tenant_id: str, actor_id: str, request_id: str,
        audit_publisher: AsyncMock,
    ) -> None:
        ou = make_org_unit(tenant_id=tenant_id)
        fake_session.put(ou)

        result = await svc.update(
            fake_session,
            tenant_id=tenant_id,
            request_id=request_id,
            actor_id=actor_id,
            ou_id=ou.id,
            patch={"name": ou.name},
        )

        assert result is ou
        audit_publisher.publish.assert_not_awaited()


class TestMove:
    async def test_move_to_new_parent(
        self, svc: OrgUnitService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        ou = make_org_unit(
            ou_id="ou_child",
            tenant_id=tenant_id,
            parent_id=None,
            code="backend",
            path="backend",
            depth=0,
        )
        parent = make_org_unit(
            ou_id="ou_parent",
            tenant_id=tenant_id,
            code="engineering",
            path="engineering",
            depth=0,
        )
        fake_session.put(ou)
        fake_session.put(parent)
        fake_session.queue_scalar(ou.depth)  # descendants max depth
        fake_session.queue_scalar(None)  # no sibling conflict

        result = await svc.move(
            fake_session,
            tenant_id=tenant_id,
            request_id=request_id,
            actor_id=actor_id,
            ou_id=ou.id,
            new_parent_id=parent.id,
            reason="reorg",
        )

        assert result.parent_id == parent.id
        assert result.updated_by == actor_id

    async def test_move_to_same_parent_noops(
        self, svc: OrgUnitService, fake_session, tenant_id: str, actor_id: str, request_id: str,
        audit_publisher: AsyncMock,
    ) -> None:
        ou = make_org_unit(tenant_id=tenant_id, parent_id="ou_parent")
        fake_session.put(ou)

        result = await svc.move(
            fake_session,
            tenant_id=tenant_id,
            request_id=request_id,
            actor_id=actor_id,
            ou_id=ou.id,
            new_parent_id="ou_parent",
            reason=None,
        )

        assert result is ou
        audit_publisher.publish.assert_not_awaited()

    async def test_move_rejects_cycle(
        self, svc: OrgUnitService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        ou = make_org_unit(ou_id="ou_parent", tenant_id=tenant_id, path="root.parent")
        child = make_org_unit(
            ou_id="ou_child",
            tenant_id=tenant_id,
            parent_id=ou.id,
            path="root.parent.child",
        )
        fake_session.put(ou)
        fake_session.put(child)

        with pytest.raises(FoundationError) as exc:
            await svc.move(
                fake_session,
                tenant_id=tenant_id,
                request_id=request_id,
                actor_id=actor_id,
                ou_id=ou.id,
                new_parent_id=child.id,
                reason=None,
            )

        assert exc.value.error_code is ORG_UNIT_CYCLE

    async def test_move_rejects_depth_exceeded(
        self, svc: OrgUnitService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        ou = make_org_unit(ou_id="ou_child", tenant_id=tenant_id, path="child", depth=1)
        parent = make_org_unit(
            ou_id="ou_deep",
            tenant_id=tenant_id,
            code="deep",
            path="deep",
            depth=svc._settings.max_org_unit_depth,
        )
        fake_session.put(ou)
        fake_session.put(parent)
        fake_session.queue_scalar(ou.depth)

        with pytest.raises(FoundationError) as exc:
            await svc.move(
                fake_session,
                tenant_id=tenant_id,
                request_id=request_id,
                actor_id=actor_id,
                ou_id=ou.id,
                new_parent_id=parent.id,
                reason=None,
            )

        assert exc.value.error_code is ORG_UNIT_DEPTH_EXCEEDED


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

    async def test_archive_with_team(
        self, svc: OrgUnitService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        ou = make_org_unit(tenant_id=tenant_id)
        team = make_team(tenant_id=tenant_id, org_unit_id=ou.id)
        fake_session.put(ou)
        fake_session.queue_scalar(None)  # no children
        fake_session.queue_scalar(team)

        with pytest.raises(FoundationError) as exc:
            await svc.archive(
                fake_session,
                tenant_id=tenant_id,
                request_id=request_id,
                actor_id=actor_id,
                ou_id=ou.id,
                reason=None,
            )

        assert exc.value.error_code is ORG_UNIT_NOT_EMPTY

    async def test_archive_with_member(
        self, svc: OrgUnitService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        ou = make_org_unit(tenant_id=tenant_id)
        member = make_membership(tenant_id=tenant_id, primary_org_unit_id=ou.id)
        fake_session.put(ou)
        fake_session.queue_scalar(None)  # no children
        fake_session.queue_scalar(None)  # no teams
        fake_session.queue_scalar(member)

        with pytest.raises(FoundationError) as exc:
            await svc.archive(
                fake_session,
                tenant_id=tenant_id,
                request_id=request_id,
                actor_id=actor_id,
                ou_id=ou.id,
                reason=None,
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


class TestTreeReads:
    async def test_descendants_returns_rows(
        self, svc: OrgUnitService, fake_session, tenant_id: str,
    ) -> None:
        ou = make_org_unit(tenant_id=tenant_id, path="engineering")
        child = make_org_unit(
            ou_id="ou_child",
            tenant_id=tenant_id,
            parent_id=ou.id,
            path="engineering.backend",
        )
        fake_session.put(ou)
        fake_session.queue_scalars([child])

        rows = await svc.descendants(fake_session, tenant_id=tenant_id, ou_id=ou.id)

        assert rows == [child]

    async def test_ancestors_returns_rows(
        self, svc: OrgUnitService, fake_session, tenant_id: str,
    ) -> None:
        parent = make_org_unit(ou_id="ou_parent", tenant_id=tenant_id, path="engineering")
        child = make_org_unit(
            ou_id="ou_child",
            tenant_id=tenant_id,
            parent_id=parent.id,
            path="engineering.backend",
            depth=1,
        )
        fake_session.put(child)
        fake_session.queue_scalars([parent])

        rows = await svc.ancestors(fake_session, tenant_id=tenant_id, ou_id=child.id)

        assert rows == [parent]

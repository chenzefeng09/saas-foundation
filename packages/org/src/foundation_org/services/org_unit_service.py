"""Org-unit CRUD + move + archive + descendants/ancestors (org-v1 §6).

Postgres triggers handle `path` and `depth` computation on insert/update, so
this service mostly enforces business invariants and emits audit events.

For unit-testability we keep all SQL through the SQLAlchemy session and do
not call DB functions directly — `path` reads come back from the trigger-
populated column. Tests stub the session.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import ulid
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy_utils import Ltree  # type: ignore[import-untyped]

from foundation_org.adapters.audit_publisher import AuditPublisher
from foundation_org.config import get_settings
from foundation_org.domain.models import OrgUnit, OrgUnitHistory, Team, UserMembership
from sqlalchemy.exc import IntegrityError

from foundation_org.errors import (
    ORG_UNIT_ARCHIVED,
    ORG_UNIT_CODE_CONFLICT,
    ORG_UNIT_CYCLE,
    ORG_UNIT_DEPTH_EXCEEDED,
    ORG_UNIT_IMMUTABLE_CODE,
    ORG_UNIT_NAME_DUPLICATE,
    ORG_UNIT_NOT_EMPTY,
    ORG_UNIT_NOT_FOUND,
    FoundationError,
)
from foundation_org.observability import get_logger

log = get_logger(__name__)


def _new_ou_id() -> str:
    return f"ou_{ulid.new()!s}"


class OrgUnitService:
    def __init__(self, audit: AuditPublisher) -> None:
        self._audit = audit
        self._settings = get_settings()

    # ------------------------------------------------------------------ get
    async def get(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        ou_id: str,
        include_archived: bool = False,
    ) -> OrgUnit:
        ou = await session.get(OrgUnit, ou_id)
        if (
            ou is None
            or ou.tenant_id != tenant_id
            or ou.deleted_at is not None
            or (ou.is_archived and not include_archived)
        ):
            raise FoundationError(ORG_UNIT_NOT_FOUND, extra={"ou_id": ou_id})
        return ou

    # ------------------------------------------------------------------ list
    async def list(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        parent_id: str | None = None,
        include_archived: bool = False,
        cursor: str | None = None,
        limit: int = 50,
    ) -> tuple[list[OrgUnit], str | None]:
        stmt = select(OrgUnit).where(
            OrgUnit.tenant_id == tenant_id,
            OrgUnit.deleted_at.is_(None),
        )
        if parent_id is not None:
            stmt = stmt.where(OrgUnit.parent_id == parent_id)
        if not include_archived:
            stmt = stmt.where(OrgUnit.is_archived.is_(False))
        if cursor:
            stmt = stmt.where(OrgUnit.id > cursor)
        stmt = stmt.order_by(OrgUnit.id).limit(limit + 1)
        rows = list((await session.scalars(stmt)).all())
        page = rows[:limit]
        # The cursor is the last id *returned*: the next page selects id > cursor,
        # so handing out the (limit+1)-th id would silently skip that row.
        next_cursor = page[-1].id if len(rows) > limit else None
        return page, next_cursor

    # ------------------------------------------------------------------ create
    async def create(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        request_id: str,
        actor_id: str,
        parent_id: str | None,
        code: str | None,
        name: str,
        name_en: str | None,
        description: str | None,
        manager_user_id: str | None,
        kind: str,
        sort_order: int,
        metadata: dict[str, Any],
    ) -> OrgUnit:
        if code is None:
            code = f"ou_{ulid.new()!s}".lower()[:32]

        # Validate parent (if any) and depth budget.
        parent_depth = -1
        if parent_id is not None:
            parent = await session.get(OrgUnit, parent_id)
            if (
                parent is None
                or parent.tenant_id != tenant_id
                or parent.deleted_at is not None
            ):
                raise FoundationError(ORG_UNIT_NOT_FOUND, extra={"ou_id": parent_id})
            if parent.is_archived:
                raise FoundationError(ORG_UNIT_ARCHIVED, extra={"ou_id": parent_id})
            parent_depth = parent.depth
            if parent_depth + 1 > self._settings.max_org_unit_depth:
                raise FoundationError(
                    ORG_UNIT_DEPTH_EXCEEDED,
                    extra={"parent_depth": str(parent_depth)},
                )

        # Uniqueness on (tenant_id, parent_id, code).
        existing = await session.scalar(
            select(OrgUnit).where(
                OrgUnit.tenant_id == tenant_id,
                OrgUnit.parent_id.is_(parent_id) if parent_id is None else OrgUnit.parent_id == parent_id,
                OrgUnit.code == code,
                OrgUnit.deleted_at.is_(None),
            )
        )
        if existing is not None:
            raise FoundationError(
                ORG_UNIT_CODE_CONFLICT,
                extra={"code": code, "parent_id": parent_id or ""},
            )

        # path + depth are filled by the BEFORE INSERT trigger; we set
        # placeholders that satisfy NOT NULL pre-trigger (Postgres allows
        # writing arbitrary values; trigger overwrites).
        ou_id = _new_ou_id()
        ou = OrgUnit(
            id=ou_id,
            tenant_id=tenant_id,
            parent_id=parent_id,
            code=code,
            name=name,
            name_en=name_en,
            description=description,
            manager_user_id=manager_user_id,
            kind=kind,
            # LtreeType.bind_processor calls `value.path`, so this must be an
            # Ltree (not a raw str). The BEFORE INSERT trigger overwrites it;
            # we use the id (valid ltree label: [A-Za-z0-9_]) as placeholder
            # because `code` may contain hyphens which are invalid ltree labels.
            path=Ltree(ou_id),  # placeholder; trigger rewrites
            depth=parent_depth + 1,  # placeholder
            sort_order=sort_order,
            metadata_json=metadata,
            created_by=actor_id,
            updated_by=actor_id,
        )
        session.add(ou)
        try:
            await session.flush()
            # path + depth are computed by the BEFORE INSERT trigger; reload them so
            # the response reflects the real ltree path instead of the placeholder.
            await session.refresh(ou, attribute_names=["path", "depth", "updated_at"])
        except IntegrityError as exc:
            await session.rollback()
            if "uq_org_unit_parent_name" in str(exc):
                raise FoundationError(ORG_UNIT_NAME_DUPLICATE, extra={"name": name}) from exc
            raise

        await self._audit.publish(
            session,
            event_type="foundation.org.org_unit.created",
            tenant_id=tenant_id,
            aggregate_id=ou.id,
            payload={
                "ou_id": ou.id,
                "parent_id": parent_id,
                "code": code,
                "name": name,
                "kind": kind,
                "created_by": actor_id,
            },
            request_id=request_id,
        )
        return ou

    # ------------------------------------------------------------------ update
    async def update(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        request_id: str,
        actor_id: str,
        ou_id: str,
        patch: dict[str, Any],
    ) -> OrgUnit:
        if "code" in patch:
            raise FoundationError(ORG_UNIT_IMMUTABLE_CODE, extra={"ou_id": ou_id})

        ou = await self.get(session, tenant_id=tenant_id, ou_id=ou_id, include_archived=True)
        changed: list[str] = []
        for field in (
            "name", "name_en", "description", "manager_user_id",
            "sort_order", "metadata",
        ):
            if field in patch and patch[field] is not None:
                attr = "metadata_json" if field == "metadata" else field
                old = getattr(ou, attr)
                new = patch[field]
                if old != new:
                    setattr(ou, attr, new)
                    changed.append(field)
                    session.add(
                        OrgUnitHistory(
                            tenant_id=tenant_id,
                            org_unit_id=ou.id,
                            changed_by=actor_id,
                            field=field,
                            old_value=str(old) if old is not None else None,
                            new_value=str(new),
                        )
                    )

        if not changed:
            return ou

        ou.updated_by = actor_id
        try:
            await session.flush()
            await session.refresh(ou, attribute_names=["updated_at"])
        except IntegrityError as exc:
            await session.rollback()
            if "uq_org_unit_parent_name" in str(exc):
                raise FoundationError(
                    ORG_UNIT_NAME_DUPLICATE, extra={"name": patch.get("name", "")}
                ) from exc
            raise
        await self._audit.publish(
            session,
            event_type="foundation.org.org_unit.updated",
            tenant_id=tenant_id,
            aggregate_id=ou.id,
            payload={
                "ou_id": ou.id,
                "changed_fields": sorted(changed),
                "updated_by": actor_id,
            },
            request_id=request_id,
        )
        return ou

    # ------------------------------------------------------------------ move
    async def move(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        request_id: str,
        actor_id: str,
        ou_id: str,
        new_parent_id: str | None,
        reason: str | None,
    ) -> OrgUnit:
        ou = await self.get(session, tenant_id=tenant_id, ou_id=ou_id, include_archived=True)
        if ou.parent_id == new_parent_id:
            return ou

        new_parent: OrgUnit | None = None
        if new_parent_id is not None:
            new_parent = await session.get(OrgUnit, new_parent_id)
            if (
                new_parent is None
                or new_parent.tenant_id != tenant_id
                or new_parent.deleted_at is not None
            ):
                raise FoundationError(ORG_UNIT_NOT_FOUND, extra={"ou_id": new_parent_id})
            if new_parent.is_archived:
                raise FoundationError(ORG_UNIT_ARCHIVED, extra={"ou_id": new_parent_id})

            # Cycle check: new_parent must not be ou itself or any of its descendants.
            # The DB trigger also enforces this, but checking up-front gives a
            # clean error before round-tripping.
            if new_parent.id == ou.id:
                raise FoundationError(ORG_UNIT_CYCLE, extra={"ou_id": ou.id})
            if _is_descendant_path(new_parent_path=str(new_parent.path), ancestor_path=str(ou.path)):
                raise FoundationError(ORG_UNIT_CYCLE, extra={"ou_id": ou.id})

            # Depth budget
            descendants_max_depth = await session.scalar(
                select(func.max(OrgUnit.depth)).where(
                    OrgUnit.tenant_id == tenant_id,
                    OrgUnit.path.descendant_of(ou.path),  # type: ignore[attr-defined]
                    OrgUnit.deleted_at.is_(None),
                )
            )
            subtree_height = (descendants_max_depth or ou.depth) - ou.depth
            if new_parent.depth + 1 + subtree_height > self._settings.max_org_unit_depth:
                raise FoundationError(
                    ORG_UNIT_DEPTH_EXCEEDED,
                    extra={
                        "new_parent_depth": str(new_parent.depth),
                        "subtree_height": str(subtree_height),
                    },
                )

        # Uniqueness under new parent (same code under same parent forbidden).
        sibling = await session.scalar(
            select(OrgUnit).where(
                OrgUnit.tenant_id == tenant_id,
                OrgUnit.parent_id.is_(new_parent_id) if new_parent_id is None else OrgUnit.parent_id == new_parent_id,
                OrgUnit.code == ou.code,
                OrgUnit.id != ou.id,
                OrgUnit.deleted_at.is_(None),
            )
        )
        if sibling is not None:
            raise FoundationError(
                ORG_UNIT_CODE_CONFLICT,
                extra={"code": ou.code, "parent_id": new_parent_id or ""},
            )

        old_path = str(ou.path)
        session.add(
            OrgUnitHistory(
                tenant_id=tenant_id,
                org_unit_id=ou.id,
                changed_by=actor_id,
                field="parent_id",
                old_value=ou.parent_id,
                new_value=new_parent_id,
            )
        )
        ou.parent_id = new_parent_id
        ou.updated_by = actor_id
        # path + depth + descendant paths are recalculated by the AFTER UPDATE
        # trigger; refresh the local row so the post-condition reflects new state.
        await session.flush()
        await session.refresh(ou, attribute_names=["path", "depth", "updated_at"])

        await self._audit.publish(
            session,
            event_type="foundation.org.org_unit.moved",
            tenant_id=tenant_id,
            aggregate_id=ou.id,
            payload={
                "ou_id": ou.id,
                "old_path": old_path,
                "new_path": str(ou.path),
                "new_parent_id": new_parent_id,
                "reason": reason,
                "moved_by": actor_id,
            },
            request_id=request_id,
        )
        return ou

    # ------------------------------------------------------------------ archive
    async def archive(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        request_id: str,
        actor_id: str,
        ou_id: str,
        reason: str | None,
    ) -> OrgUnit:
        ou = await self.get(session, tenant_id=tenant_id, ou_id=ou_id)
        if ou.is_archived:
            return ou

        # Must be empty: no live children, no live teams, no live members.
        child = await session.scalar(
            select(OrgUnit).where(
                OrgUnit.tenant_id == tenant_id,
                OrgUnit.parent_id == ou.id,
                OrgUnit.deleted_at.is_(None),
                OrgUnit.is_archived.is_(False),
            ).limit(1)
        )
        if child is not None:
            raise FoundationError(ORG_UNIT_NOT_EMPTY, extra={"reason": "has_children"})

        team = await session.scalar(
            select(Team).where(
                Team.tenant_id == tenant_id,
                Team.org_unit_id == ou.id,
                Team.deleted_at.is_(None),
                Team.is_archived.is_(False),
            ).limit(1)
        )
        if team is not None:
            raise FoundationError(ORG_UNIT_NOT_EMPTY, extra={"reason": "has_teams"})

        member = await session.scalar(
            select(UserMembership).where(
                UserMembership.tenant_id == tenant_id,
                UserMembership.primary_org_unit_id == ou.id,
                UserMembership.leave_date.is_(None),
            ).limit(1)
        )
        if member is not None:
            raise FoundationError(ORG_UNIT_NOT_EMPTY, extra={"reason": "has_members"})

        ou.is_archived = True
        ou.updated_by = actor_id
        session.add(
            OrgUnitHistory(
                tenant_id=tenant_id,
                org_unit_id=ou.id,
                changed_by=actor_id,
                field="is_archived",
                old_value="false",
                new_value="true",
            )
        )
        await session.flush()
        await session.refresh(ou, attribute_names=["updated_at"])
        await self._audit.publish(
            session,
            event_type="foundation.org.org_unit.archived",
            tenant_id=tenant_id,
            aggregate_id=ou.id,
            payload={"ou_id": ou.id, "reason": reason, "archived_by": actor_id},
            request_id=request_id,
        )
        return ou

    # ------------------------------------------------------------------ delete
    async def delete(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        request_id: str,
        actor_id: str,
        ou_id: str,
    ) -> None:
        ou = await self.get(session, tenant_id=tenant_id, ou_id=ou_id, include_archived=True)
        if not ou.is_archived:
            raise FoundationError(
                ORG_UNIT_NOT_EMPTY,
                detail="Org unit must be archived before deletion.",
                extra={"reason": "not_archived"},
            )

        ou.deleted_at = datetime.now(UTC)
        ou.updated_by = actor_id
        await self._audit.publish(
            session,
            event_type="foundation.org.org_unit.deleted",
            tenant_id=tenant_id,
            aggregate_id=ou.id,
            payload={"ou_id": ou.id, "was_path": str(ou.path), "deleted_by": actor_id},
            request_id=request_id,
        )
        await session.flush()

    # ------------------------------------------------------------------ descendants/ancestors
    async def descendants(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        ou_id: str,
        include_archived: bool = False,
    ) -> list[OrgUnit]:
        ou = await self.get(session, tenant_id=tenant_id, ou_id=ou_id, include_archived=True)
        stmt = select(OrgUnit).where(
            OrgUnit.tenant_id == tenant_id,
            OrgUnit.path.descendant_of(ou.path),  # type: ignore[attr-defined]
            OrgUnit.id != ou.id,
            OrgUnit.deleted_at.is_(None),
        )
        if not include_archived:
            stmt = stmt.where(OrgUnit.is_archived.is_(False))
        stmt = stmt.order_by(OrgUnit.path)
        return list((await session.scalars(stmt)).all())

    async def ancestors(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        ou_id: str,
    ) -> list[OrgUnit]:
        ou = await self.get(session, tenant_id=tenant_id, ou_id=ou_id, include_archived=True)
        stmt = select(OrgUnit).where(
            OrgUnit.tenant_id == tenant_id,
            OrgUnit.path.ancestor_of(ou.path),  # type: ignore[attr-defined]
            OrgUnit.id != ou.id,
            OrgUnit.deleted_at.is_(None),
        ).order_by(OrgUnit.depth)
        return list((await session.scalars(stmt)).all())


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _is_descendant_path(*, new_parent_path: str, ancestor_path: str) -> bool:
    """Returns True if `new_parent_path` is `ancestor_path` or its descendant.

    ltree paths are dot-separated labels; "a.b" descends from "a".
    """
    if new_parent_path == ancestor_path:
        return True
    return new_parent_path.startswith(ancestor_path + ".")

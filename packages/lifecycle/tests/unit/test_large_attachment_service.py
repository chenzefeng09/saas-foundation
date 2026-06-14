"""Unit tests for LargeAttachmentService.

Covers the generalized subject allowlist (USER / TEAM / ORG_UNIT), the
back-compat ``user_*`` delegation onto the unified subject table, and the
union ``resolve`` (USER veto → TEAM → ORG_UNIT-with-ancestor-inheritance).

The org reverse-lookups in ``resolve`` are exercised through a network-free
``FakeOrgClient`` injected via the ``org_client`` parameter.
"""

from __future__ import annotations

import pytest

from foundation_lifecycle.domain.models import (
    SubjectLargeAttachmentAllow,
    TenantLargeAttachmentSetting,
)
from foundation_lifecycle.services.large_attachment_service import (
    LargeAttachmentService,
)


@pytest.fixture
def svc() -> LargeAttachmentService:
    return LargeAttachmentService()


class FakeOrgClient:
    """Network-free stand-in for ``adapters.org_client.OrgClient``.

    ``teams`` / ``org_units`` are the already-resolved id lists the real client
    would return (``org_units`` is expected to already include the ancestor
    chain, matching ``OrgClient.org_units_of``).
    """

    def __init__(
        self,
        *,
        teams: list[str] | None = None,
        org_units: list[str] | None = None,
    ) -> None:
        self._teams = teams or []
        self._org_units = org_units or []
        self.teams_calls: list[tuple[str, str]] = []
        self.org_units_calls: list[tuple[str, str]] = []

    async def teams_of(self, *, tenant_id: str, user_id: str) -> list[str]:
        self.teams_calls.append((tenant_id, user_id))
        return list(self._teams)

    async def org_units_of(self, *, tenant_id: str, user_id: str) -> list[str]:
        self.org_units_calls.append((tenant_id, user_id))
        return list(self._org_units)


# ---------------------------------------------------------------------------
# Tenant setting (unchanged behaviour)
# ---------------------------------------------------------------------------
class TestUpsertTenantSetting:
    async def test_creates_new_row_when_missing(
        self, svc: LargeAttachmentService, fake_session, tenant_id: str
    ) -> None:
        fake_session.queue_scalar(None)  # get_tenant_setting → no row

        row = await svc.upsert_tenant_setting(
            fake_session, tenant_id=tenant_id, enabled=True, actor="usr_admin"
        )

        assert row.id.startswith("tla_")
        assert row.tenant_id == tenant_id
        assert row.large_attachment_enabled is True
        assert row.updated_by == "usr_admin"
        assert fake_session.flush_calls == 1

    async def test_patches_existing_row(
        self, svc: LargeAttachmentService, fake_session, tenant_id: str
    ) -> None:
        existing = TenantLargeAttachmentSetting(
            id="tla_test",
            tenant_id=tenant_id,
            large_attachment_enabled=False,
            updated_by="usr_old",
        )
        fake_session.queue_scalar(existing)

        row = await svc.upsert_tenant_setting(
            fake_session, tenant_id=tenant_id, enabled=True, actor="usr_admin"
        )

        assert row is existing
        assert row.large_attachment_enabled is True
        assert row.updated_by == "usr_admin"


# ---------------------------------------------------------------------------
# Subject CRUD (USER / TEAM / ORG_UNIT)
# ---------------------------------------------------------------------------
class TestSubjectAllowCrud:
    @pytest.mark.parametrize(
        ("subject_type", "subject_id"),
        [
            ("USER", "usr_42"),
            ("TEAM", "tem_eng"),
            ("ORG_UNIT", "oun_eng_infra"),
        ],
    )
    async def test_create_round_trip(
        self,
        svc: LargeAttachmentService,
        fake_session,
        tenant_id: str,
        subject_type: str,
        subject_id: str,
    ) -> None:
        fake_session.queue_scalar(None)  # get_subject_allow → no row

        row = await svc.upsert_subject_allow(
            fake_session,
            tenant_id=tenant_id,
            subject_type=subject_type,
            subject_id=subject_id,
            allowed=True,
            actor="usr_admin",
        )

        assert row.id.startswith("las_")
        assert row.tenant_id == tenant_id
        assert row.subject_type == subject_type
        assert row.subject_id == subject_id
        assert row.allowed is True
        assert row.updated_by == "usr_admin"
        assert fake_session.flush_calls == 1
        assert row in fake_session.added

    async def test_patches_existing_subject_row(
        self, svc: LargeAttachmentService, fake_session, tenant_id: str
    ) -> None:
        existing = SubjectLargeAttachmentAllow(
            id="las_test",
            tenant_id=tenant_id,
            subject_type="TEAM",
            subject_id="tem_eng",
            allowed=True,
        )
        fake_session.queue_scalar(existing)

        row = await svc.upsert_subject_allow(
            fake_session,
            tenant_id=tenant_id,
            subject_type="TEAM",
            subject_id="tem_eng",
            allowed=False,
            actor="usr_admin",
        )

        assert row is existing
        assert row.allowed is False
        assert row.updated_by == "usr_admin"

    async def test_invalid_subject_type_raises(
        self, svc: LargeAttachmentService, fake_session, tenant_id: str
    ) -> None:
        with pytest.raises(ValueError, match="invalid subject_type"):
            await svc.upsert_subject_allow(
                fake_session,
                tenant_id=tenant_id,
                subject_type="ROLE",
                subject_id="rol_x",
                allowed=True,
                actor="usr_admin",
            )

    async def test_get_subject_allow(
        self, svc: LargeAttachmentService, fake_session, tenant_id: str
    ) -> None:
        existing = SubjectLargeAttachmentAllow(
            id="las_g",
            tenant_id=tenant_id,
            subject_type="ORG_UNIT",
            subject_id="oun_eng",
            allowed=True,
        )
        fake_session.queue_scalar(existing)

        out = await svc.get_subject_allow(
            fake_session,
            tenant_id=tenant_id,
            subject_type="ORG_UNIT",
            subject_id="oun_eng",
        )
        assert out is existing

    async def test_list_subject_allows(
        self, svc: LargeAttachmentService, fake_session, tenant_id: str
    ) -> None:
        rows = [
            SubjectLargeAttachmentAllow(
                id="las_a", tenant_id=tenant_id,
                subject_type="USER", subject_id="usr_a", allowed=True,
            ),
            SubjectLargeAttachmentAllow(
                id="las_b", tenant_id=tenant_id,
                subject_type="TEAM", subject_id="tem_b", allowed=False,
            ),
        ]
        fake_session.queue_scalars(rows)

        out = await svc.list_subject_allows(fake_session, tenant_id=tenant_id)
        assert len(out) == 2
        assert {r.subject_id for r in out} == {"usr_a", "tem_b"}

    async def test_delete_subject_allow(
        self, svc: LargeAttachmentService, fake_session, tenant_id: str
    ) -> None:
        existing = SubjectLargeAttachmentAllow(
            id="las_x", tenant_id=tenant_id,
            subject_type="TEAM", subject_id="tem_x", allowed=True,
        )
        fake_session.queue_scalar(existing)

        deleted = await svc.delete_subject_allow(
            fake_session, tenant_id=tenant_id,
            subject_type="TEAM", subject_id="tem_x",
        )
        assert deleted is True
        assert existing in fake_session.deleted

    async def test_delete_subject_allow_missing(
        self, svc: LargeAttachmentService, fake_session, tenant_id: str
    ) -> None:
        fake_session.queue_scalar(None)
        deleted = await svc.delete_subject_allow(
            fake_session, tenant_id=tenant_id,
            subject_type="TEAM", subject_id="tem_nope",
        )
        assert deleted is False
        assert fake_session.deleted == []


# ---------------------------------------------------------------------------
# Back-compat user_* delegation → subject table, legacy user JSON shape
# ---------------------------------------------------------------------------
class TestUserAllowDelegation:
    async def test_upsert_user_allow_writes_subject_user_row(
        self, svc: LargeAttachmentService, fake_session, tenant_id: str
    ) -> None:
        fake_session.queue_scalar(None)  # get_subject_allow(USER) → none

        row = await svc.upsert_user_allow(
            fake_session, tenant_id=tenant_id,
            user_id="usr_42", allowed=True, actor="usr_admin",
        )

        # Stored on the unified subject table as subject_type='USER'.
        assert isinstance(row, SubjectLargeAttachmentAllow)
        assert row.id.startswith("las_")
        assert row.subject_type == "USER"
        assert row.subject_id == "usr_42"
        assert row.allowed is True

        # ...but the legacy serializer still emits the user shape.
        out = LargeAttachmentService.serialize_allow(row)
        assert out["user_id"] == "usr_42"
        assert "subject_type" not in out

    async def test_get_user_allow_delegates(
        self, svc: LargeAttachmentService, fake_session, tenant_id: str
    ) -> None:
        existing = SubjectLargeAttachmentAllow(
            id="las_u", tenant_id=tenant_id,
            subject_type="USER", subject_id="usr_7", allowed=True,
        )
        fake_session.queue_scalar(existing)

        out = await svc.get_user_allow(
            fake_session, tenant_id=tenant_id, user_id="usr_7"
        )
        assert out is existing

    async def test_list_user_allows_returns_user_subjects(
        self, svc: LargeAttachmentService, fake_session, tenant_id: str
    ) -> None:
        rows = [
            SubjectLargeAttachmentAllow(
                id="las_a", tenant_id=tenant_id,
                subject_type="USER", subject_id="usr_a", allowed=True,
            ),
            SubjectLargeAttachmentAllow(
                id="las_b", tenant_id=tenant_id,
                subject_type="USER", subject_id="usr_b", allowed=False,
            ),
        ]
        fake_session.queue_scalars(rows)

        out = await svc.list_user_allows(fake_session, tenant_id=tenant_id)
        assert len(out) == 2
        # Serialized through the legacy path → user_id key.
        shapes = [LargeAttachmentService.serialize_allow(r) for r in out]
        assert {s["user_id"] for s in shapes} == {"usr_a", "usr_b"}

    async def test_delete_user_allow_delegates(
        self, svc: LargeAttachmentService, fake_session, tenant_id: str
    ) -> None:
        existing = SubjectLargeAttachmentAllow(
            id="las_d", tenant_id=tenant_id,
            subject_type="USER", subject_id="usr_x", allowed=True,
        )
        fake_session.queue_scalar(existing)

        deleted = await svc.delete_user_allow(
            fake_session, tenant_id=tenant_id, user_id="usr_x"
        )
        assert deleted is True
        assert existing in fake_session.deleted


# ---------------------------------------------------------------------------
# resolve() — union (tenant gate → USER veto → TEAM → ORG_UNIT inheritance)
# ---------------------------------------------------------------------------
def _setting(tenant_id: str, *, enabled: bool) -> TenantLargeAttachmentSetting:
    return TenantLargeAttachmentSetting(
        id="tla_1", tenant_id=tenant_id, large_attachment_enabled=enabled
    )


def _subject(
    tenant_id: str, subject_type: str, subject_id: str, *, allowed: bool
) -> SubjectLargeAttachmentAllow:
    return SubjectLargeAttachmentAllow(
        id=f"las_{subject_id}", tenant_id=tenant_id,
        subject_type=subject_type, subject_id=subject_id, allowed=allowed,
    )


class TestResolveUnion:
    async def test_tenant_off_denied(
        self, svc: LargeAttachmentService, fake_session, tenant_id: str
    ) -> None:
        fake_session.queue_scalar(_setting(tenant_id, enabled=False))
        org = FakeOrgClient(teams=["tem_eng"], org_units=["oun_eng"])

        out = await svc.resolve(
            fake_session, tenant_id=tenant_id, user_id="usr_1", org_client=org
        )
        assert out == {
            "allowed": False,
            "tenant_enabled": False,
            "user_allowed": False,
            "reason": "tenant_disabled",
        }
        # tenant gate short-circuits before any org call.
        assert org.teams_calls == []
        assert org.org_units_calls == []

    async def test_user_allowed_true(
        self, svc: LargeAttachmentService, fake_session, tenant_id: str
    ) -> None:
        fake_session.queue_scalar(_setting(tenant_id, enabled=True))
        fake_session.queue_scalar(
            _subject(tenant_id, "USER", "usr_1", allowed=True)
        )
        org = FakeOrgClient()

        out = await svc.resolve(
            fake_session, tenant_id=tenant_id, user_id="usr_1", org_client=org
        )
        assert out == {
            "allowed": True,
            "tenant_enabled": True,
            "user_allowed": True,
            "reason": "user",
        }
        # USER row authoritative → no org enrichment needed.
        assert org.teams_calls == []
        assert org.org_units_calls == []

    async def test_user_denied_vetoes_team_allow(
        self, svc: LargeAttachmentService, fake_session, tenant_id: str
    ) -> None:
        # tenant on, USER row allowed=false → veto even though team allows.
        fake_session.queue_scalar(_setting(tenant_id, enabled=True))
        fake_session.queue_scalar(
            _subject(tenant_id, "USER", "usr_1", allowed=False)
        )
        org = FakeOrgClient(teams=["tem_eng"], org_units=["oun_eng"])

        out = await svc.resolve(
            fake_session, tenant_id=tenant_id, user_id="usr_1", org_client=org
        )
        assert out == {
            "allowed": False,
            "tenant_enabled": True,
            "user_allowed": False,
            "reason": "user_denied",
        }
        # veto short-circuits before consulting teams/org-units.
        assert org.teams_calls == []
        assert org.org_units_calls == []

    async def test_team_allow_hit(
        self, svc: LargeAttachmentService, fake_session, tenant_id: str
    ) -> None:
        # tenant on, no USER row, user in tem_eng which is whitelisted.
        fake_session.queue_scalar(_setting(tenant_id, enabled=True))
        fake_session.queue_scalar(None)  # get USER row → none
        # team loop: tem_a not listed (None), tem_eng allowed=true.
        fake_session.queue_scalar(None)
        fake_session.queue_scalar(
            _subject(tenant_id, "TEAM", "tem_eng", allowed=True)
        )
        org = FakeOrgClient(teams=["tem_a", "tem_eng"], org_units=["oun_eng"])

        out = await svc.resolve(
            fake_session, tenant_id=tenant_id, user_id="usr_1", org_client=org
        )
        assert out == {
            "allowed": True,
            "tenant_enabled": True,
            "user_allowed": False,
            "reason": "team",
            "via": "tem_eng",
        }
        assert org.teams_calls == [(tenant_id, "usr_1")]
        # team hit short-circuits before org-unit enrichment.
        assert org.org_units_calls == []

    async def test_org_unit_allow_via_ancestor(
        self, svc: LargeAttachmentService, fake_session, tenant_id: str
    ) -> None:
        # No USER row, no team allows; user sits in oun_eng_infra whose ancestor
        # oun_eng is whitelisted (inheritance). org_units_of already returns the
        # ancestor chain: [oun_eng_infra, oun_eng].
        fake_session.queue_scalar(_setting(tenant_id, enabled=True))
        fake_session.queue_scalar(None)  # USER row → none
        # team loop: single team not listed.
        fake_session.queue_scalar(None)  # TEAM tem_eng → none
        # org-unit loop: oun_eng_infra not listed, oun_eng (ancestor) allowed.
        fake_session.queue_scalar(None)  # ORG_UNIT oun_eng_infra → none
        fake_session.queue_scalar(
            _subject(tenant_id, "ORG_UNIT", "oun_eng", allowed=True)
        )
        org = FakeOrgClient(
            teams=["tem_eng"], org_units=["oun_eng_infra", "oun_eng"]
        )

        out = await svc.resolve(
            fake_session, tenant_id=tenant_id, user_id="usr_1", org_client=org
        )
        assert out == {
            "allowed": True,
            "tenant_enabled": True,
            "user_allowed": False,
            "reason": "org_unit",
            "via": "oun_eng",
        }
        assert org.teams_calls == [(tenant_id, "usr_1")]
        assert org.org_units_calls == [(tenant_id, "usr_1")]

    async def test_not_listed(
        self, svc: LargeAttachmentService, fake_session, tenant_id: str
    ) -> None:
        # tenant on, nothing grants access anywhere.
        fake_session.queue_scalar(_setting(tenant_id, enabled=True))
        fake_session.queue_scalar(None)  # USER row → none
        fake_session.queue_scalar(None)  # TEAM tem_eng → none
        fake_session.queue_scalar(None)  # ORG_UNIT oun_eng → none
        org = FakeOrgClient(teams=["tem_eng"], org_units=["oun_eng"])

        out = await svc.resolve(
            fake_session, tenant_id=tenant_id, user_id="usr_1", org_client=org
        )
        assert out == {
            "allowed": False,
            "tenant_enabled": True,
            "user_allowed": False,
            "reason": "not_listed",
        }

    async def test_org_unreachable_degrades_to_not_listed(
        self, svc: LargeAttachmentService, fake_session, tenant_id: str
    ) -> None:
        # tenant on, no USER row; org returns nothing (degraded) → not_listed.
        fake_session.queue_scalar(_setting(tenant_id, enabled=True))
        fake_session.queue_scalar(None)  # USER row → none
        org = FakeOrgClient(teams=[], org_units=[])

        out = await svc.resolve(
            fake_session, tenant_id=tenant_id, user_id="usr_1", org_client=org
        )
        assert out["allowed"] is False
        assert out["reason"] == "not_listed"


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------
class TestSerialize:
    def test_serialize_setting_shape(self) -> None:
        from datetime import UTC, datetime

        row = TenantLargeAttachmentSetting(
            id="tla_x",
            tenant_id="tnt_01",
            large_attachment_enabled=True,
            updated_at=datetime(2026, 6, 12, tzinfo=UTC),
            updated_by="usr_admin",
        )
        out = LargeAttachmentService.serialize_setting(row)
        assert out == {
            "id": "tla_x",
            "tenant_id": "tnt_01",
            "large_attachment_enabled": True,
            "updated_at": "2026-06-12T00:00:00+00:00",
            "updated_by": "usr_admin",
        }

    def test_serialize_allow_user_shape(self) -> None:
        from datetime import UTC, datetime

        row = SubjectLargeAttachmentAllow(
            id="las_x",
            tenant_id="tnt_01",
            subject_type="USER",
            subject_id="usr_1",
            allowed=False,
            updated_at=datetime(2026, 6, 12, tzinfo=UTC),
            updated_by="usr_admin",
        )
        out = LargeAttachmentService.serialize_allow(row)
        assert out == {
            "id": "las_x",
            "tenant_id": "tnt_01",
            "user_id": "usr_1",
            "allowed": False,
            "updated_at": "2026-06-12T00:00:00+00:00",
            "updated_by": "usr_admin",
        }

    def test_serialize_subject_allow_shape(self) -> None:
        from datetime import UTC, datetime

        row = SubjectLargeAttachmentAllow(
            id="las_y",
            tenant_id="tnt_01",
            subject_type="ORG_UNIT",
            subject_id="oun_eng",
            allowed=True,
            updated_at=datetime(2026, 6, 12, tzinfo=UTC),
            updated_by="usr_admin",
        )
        out = LargeAttachmentService.serialize_subject_allow(row)
        assert out == {
            "id": "las_y",
            "tenant_id": "tnt_01",
            "subject_type": "ORG_UNIT",
            "subject_id": "oun_eng",
            "allowed": True,
            "updated_at": "2026-06-12T00:00:00+00:00",
            "updated_by": "usr_admin",
        }

"""Schema validation tests for org module."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from foundation_org.schemas.org_unit import (
    CreateOrgUnitRequest,
    OrgUnitRead,
    UpdateOrgUnitRequest,
)
from foundation_org.schemas.team import CreateTeamRequest, TeamRead
from foundation_org.schemas.membership import UpsertUserMembershipRequest


class TestOrgUnitSchema:
    def test_valid_create_request(self) -> None:
        req = CreateOrgUnitRequest(code="engineering", name="Engineering")
        assert req.code == "engineering"

    def test_invalid_code_pattern(self) -> None:
        with pytest.raises(ValidationError):
            CreateOrgUnitRequest(code="Invalid Code!", name="Engineering")

    def test_empty_name_rejected(self) -> None:
        with pytest.raises(ValidationError):
            CreateOrgUnitRequest(code="eng", name="")

    def test_update_request_no_code(self) -> None:
        """code is NOT in UpdateOrgUnitRequest (immutable)."""
        req = UpdateOrgUnitRequest(name="New Name")
        assert req.name == "New Name"
        assert not hasattr(req, "code")


class TestTeamSchema:
    def test_valid_create_request(self) -> None:
        req = CreateTeamRequest(
            code="backend",
            name="Backend Team",
            org_unit_id="ou_01J0000000000000000000OU01",
        )
        assert req.code == "backend"

    def test_invalid_team_code(self) -> None:
        with pytest.raises(ValidationError):
            CreateTeamRequest(
                code="INVALID",
                name="Team",
                org_unit_id="ou_01J0000000000000000000OU01",
            )


class TestMembershipSchema:
    def test_valid_upsert(self) -> None:
        req = UpsertUserMembershipRequest(
            primary_org_unit_id="ou_01J0000000000000000000OU01",
        )
        assert req.primary_org_unit_id.startswith("ou_")

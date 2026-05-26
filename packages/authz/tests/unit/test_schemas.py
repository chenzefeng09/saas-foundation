"""Pydantic schema validation tests."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from foundation_authz.schemas.binding import CreateBindingRequest
from foundation_authz.schemas.check import (
    BatchCheckRequest,
    CheckRequest,
    ListAccessibleIdsRequest,
)
from foundation_authz.schemas.role import CreateRoleRequest, UpdateRoleRequest


pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# CheckRequest
# ---------------------------------------------------------------------------

class TestCheckRequest:
    def test_minimal_request_ok(self) -> None:
        req = CheckRequest(
            user_id="usr_01J0000000000000000000USR1",
            action="billing.invoice.read",
            resource_type="invoice",
        )
        assert req.context == {}
        assert req.resource_id is None

    def test_rejects_bad_user_id_pattern(self) -> None:
        with pytest.raises(ValidationError):
            CheckRequest(
                user_id="not-a-ulid",
                action="x",
                resource_type="y",
            )

    def test_rejects_extra_fields(self) -> None:
        with pytest.raises(ValidationError):
            CheckRequest(
                user_id="usr_01J0000000000000000000USR1",
                action="x",
                resource_type="y",
                unknown="nope",
            )

    def test_rejects_empty_action(self) -> None:
        with pytest.raises(ValidationError):
            CheckRequest(
                user_id="usr_01J0000000000000000000USR1",
                action="",
                resource_type="y",
            )


class TestBatchCheckRequest:
    def test_max_batch_size(self) -> None:
        item = CheckRequest(
            user_id="usr_01J0000000000000000000USR1",
            action="x.y.z",
            resource_type="t",
        )
        # 100 OK
        BatchCheckRequest(checks=[item] * 100)
        # 101 rejected
        with pytest.raises(ValidationError):
            BatchCheckRequest(checks=[item] * 101)

    def test_rejects_empty_batch(self) -> None:
        with pytest.raises(ValidationError):
            BatchCheckRequest(checks=[])


class TestListAccessibleIdsRequest:
    def test_max_default(self) -> None:
        req = ListAccessibleIdsRequest(
            user_id="usr_01J0000000000000000000USR1",
            resource_type="invoice",
            action="read",
        )
        assert req.max == 10000

    def test_max_clamped_at_upper_bound(self) -> None:
        with pytest.raises(ValidationError):
            ListAccessibleIdsRequest(
                user_id="usr_01J0000000000000000000USR1",
                resource_type="t",
                action="a",
                max=100001,
            )

    def test_max_at_lower_bound(self) -> None:
        with pytest.raises(ValidationError):
            ListAccessibleIdsRequest(
                user_id="usr_01J0000000000000000000USR1",
                resource_type="t",
                action="a",
                max=0,
            )


# ---------------------------------------------------------------------------
# Role schemas
# ---------------------------------------------------------------------------

class TestCreateRoleRequest:
    @pytest.mark.parametrize("name", ["viewer", "billing_admin", "a", "x_1_2_3"])
    def test_valid_names(self, name: str) -> None:
        # name pattern requires length >=2 (`[a-z][a-z0-9_]{1,99}`); single-char "a"
        # should fail. Verify both branches explicitly.
        if len(name) < 2:
            with pytest.raises(ValidationError):
                CreateRoleRequest(name=name, display_name="X")
        else:
            CreateRoleRequest(name=name, display_name="X")

    @pytest.mark.parametrize(
        "bad",
        ["Viewer", "1viewer", "view-er", "", " viewer ", "viewer "],
    )
    def test_invalid_names_rejected(self, bad: str) -> None:
        with pytest.raises(ValidationError):
            CreateRoleRequest(name=bad, display_name="X")

    def test_display_name_required(self) -> None:
        with pytest.raises(ValidationError):
            CreateRoleRequest(name="viewer", display_name="")

    def test_extra_field_rejected(self) -> None:
        with pytest.raises(ValidationError):
            CreateRoleRequest(
                name="viewer",
                display_name="V",
                permissions=[],
                bogus="x",  # type: ignore[call-arg]
            )

    def test_permissions_defaults_to_empty_list(self) -> None:
        req = CreateRoleRequest(name="viewer", display_name="V")
        assert req.permissions == []


class TestUpdateRoleRequest:
    def test_all_optional(self) -> None:
        req = UpdateRoleRequest()
        assert req.display_name is None
        assert req.permissions is None

    def test_extra_field_rejected(self) -> None:
        with pytest.raises(ValidationError):
            UpdateRoleRequest(name="rename_attempt")  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# Binding schemas
# ---------------------------------------------------------------------------

class TestCreateBindingRequest:
    def test_minimal_request_ok(self) -> None:
        req = CreateBindingRequest(
            principal_kind="USER",
            principal_id="usr_01J0000000000000000000USR1",
            role_id="rol_01J0000000000000000000ROL1",
        )
        assert req.scope_kind == "TENANT"
        assert req.scope_id is None
        assert req.expires_at is None

    def test_rejects_bad_role_id(self) -> None:
        with pytest.raises(ValidationError):
            CreateBindingRequest(
                principal_kind="USER",
                principal_id="usr_01J0000000000000000000USR1",
                role_id="not-a-role-id",
            )

    def test_rejects_unknown_principal_kind(self) -> None:
        with pytest.raises(ValidationError):
            CreateBindingRequest(
                principal_kind="ROBOT",  # type: ignore[arg-type]
                principal_id="usr_01J0000000000000000000USR1",
                role_id="rol_01J0000000000000000000ROL1",
            )

    def test_grant_reason_max_length(self) -> None:
        with pytest.raises(ValidationError):
            CreateBindingRequest(
                principal_kind="USER",
                principal_id="usr_01J0000000000000000000USR1",
                role_id="rol_01J0000000000000000000ROL1",
                grant_reason="x" * 501,
            )

    def test_all_scope_kinds_accepted(self) -> None:
        for sk in ("TENANT", "ORG_UNIT", "TEAM", "RESOURCE", "GLOBAL_SYSTEM"):
            CreateBindingRequest(
                principal_kind="USER",
                principal_id="usr_01J0000000000000000000USR1",
                role_id="rol_01J0000000000000000000ROL1",
                scope_kind=sk,  # type: ignore[arg-type]
            )

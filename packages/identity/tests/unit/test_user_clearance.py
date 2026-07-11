"""Clearance schema/default invariants for the identity authority."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import BaseModel, ValidationError

from foundation_identity.api.v1.sessions import _extract_clearance
from foundation_identity.domain.models import User
from foundation_identity.schemas.session import MeResponse
from foundation_identity.schemas.user import InviteUserRequest, UpdateUserRequest, UserRead

_USER_ID = "usr_01J5DEVUSER000000000000002"
_TENANT_ID = "tnt_01J5DEV00000000000000000A1"


def _user_payload(clearance: object) -> dict[str, object]:
    now = datetime.now(UTC)
    return {
        "id": _USER_ID,
        "tenant_id": _TENANT_ID,
        "email": "employee@example.com",
        "display_name": "Employee",
        "status": "ACTIVE",
        "roles": ["USER"],
        "clearance": clearance,
        "mfa_enabled": False,
        "created_at": now,
        "updated_at": now,
    }


def test_invite_defaults_to_l3() -> None:
    body = InviteUserRequest(email="employee@example.com")
    assert body.clearance == "L3"


def test_update_omission_does_not_emit_default_into_merge_patch() -> None:
    body = UpdateUserRequest(display_name="New Name")
    assert body.clearance == "L3"
    assert body.model_dump(exclude_unset=True) == {"display_name": "New Name"}


@pytest.mark.parametrize("schema", [InviteUserRequest, UpdateUserRequest])
@pytest.mark.parametrize("clearance", ["L0", "L6", "l3", "3", None])
def test_write_schemas_strictly_reject_invalid_clearance(
    schema: type[BaseModel], clearance: object
) -> None:
    kwargs: dict[str, object] = {"clearance": clearance}
    if schema is InviteUserRequest:
        kwargs["email"] = "employee@example.com"
    with pytest.raises(ValidationError):
        schema(**kwargs)


@pytest.mark.parametrize("clearance", ["L1", "L2", "L3", "L4", "L5"])
def test_write_schemas_accept_all_supported_levels(clearance: str) -> None:
    assert InviteUserRequest(
        email="employee@example.com", clearance=clearance
    ).clearance == clearance
    assert UpdateUserRequest(clearance=clearance).model_dump(exclude_unset=True) == {
        "clearance": clearance
    }


def test_user_read_projects_legacy_null_as_l3() -> None:
    assert UserRead.model_validate(_user_payload(None)).clearance == "L3"


def test_user_model_and_me_response_default_to_l3() -> None:
    column = User.__table__.c.clearance
    assert column.nullable is False
    assert column.default is not None
    assert column.default.arg == "L3"
    assert _extract_clearance({}) == "L3"
    assert _extract_clearance({"clearance": "invalid"}) == "L3"
    assert MeResponse(
        user_id=_USER_ID,
        tenant_id=_TENANT_ID,
        email="employee@example.com",
        display_name="Employee",
        roles=[],
    ).clearance == "L3"

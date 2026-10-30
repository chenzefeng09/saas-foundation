"""A member's model preferences on behalf of a tenant admin (GDPR Art. 15 / 17).

The routes are called directly with a fake service: what matters here is the
actor gate and that every read / delete stays inside the caller's tenant.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from foundation_llm_gateway.api.v1.llm_gateway import (
    delete_member_preferences,
    list_member_preferences,
)
from foundation_llm_gateway.domain.base import FoundationContext
from foundation_llm_gateway.errors import PERMISSION_DENIED, FoundationError
from foundation_llm_gateway.services.llm_gateway_service import LLMGatewayService

TENANT = "tnt_01J5TEST00000000000000TNT1"
ADMIN_USER = "usr_01J5TEST00000000000000ADM1"
MEMBER = "usr_01J5TEST0000000000000USER2"


def _ctx(actor: str) -> FoundationContext:
    return FoundationContext(
        tenant_id=TENANT, user_id=ADMIN_USER, actor=actor, request_id="req_1",  # type: ignore[arg-type]
    )


def _row(purpose: str) -> SimpleNamespace:
    return SimpleNamespace(
        id=f"ump_{purpose}", tenant_id=TENANT, user_id=MEMBER, purpose=purpose,
        model_id="m", provider_id="p", created_at=None, updated_at=None,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("actor", ["USER", "SYSTEM"])
async def test_member_preferences_need_a_privileged_actor(actor: str) -> None:
    svc = MagicMock(spec=LLMGatewayService)
    for route in (list_member_preferences, delete_member_preferences):
        with pytest.raises(FoundationError) as err:
            await route(user_id=MEMBER, ctx=_ctx(actor), session=MagicMock(), svc=svc)
        assert err.value.error_code.code == PERMISSION_DENIED.code
    svc.list_user_preferences.assert_not_called()
    svc.delete_all_user_preferences.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("actor", ["ADMIN", "SERVICE"])
async def test_admin_lists_a_members_preferences_in_its_own_tenant(actor: str) -> None:
    svc = MagicMock(spec=LLMGatewayService)
    svc.list_user_preferences = AsyncMock(return_value=[_row("chat"), _row("title")])
    session = MagicMock()

    body = await list_member_preferences(user_id=MEMBER, ctx=_ctx(actor), session=session, svc=svc)

    assert [item["purpose"] for item in body["items"]] == ["chat", "title"]
    svc.list_user_preferences.assert_awaited_once_with(session, tenant_id=TENANT, user_id=MEMBER)


@pytest.mark.asyncio
async def test_admin_deletes_every_preference_of_a_member() -> None:
    svc = MagicMock(spec=LLMGatewayService)
    svc.delete_all_user_preferences = AsyncMock(return_value=2)
    session = MagicMock()

    body = await delete_member_preferences(
        user_id=MEMBER, ctx=_ctx("ADMIN"), session=session, svc=svc,
    )

    assert body == {"deleted": 2}
    svc.delete_all_user_preferences.assert_awaited_once_with(
        session, tenant_id=TENANT, user_id=MEMBER,
    )


@pytest.mark.asyncio
async def test_delete_all_user_preferences_scopes_the_statement() -> None:
    session = MagicMock()
    session.execute = AsyncMock(return_value=SimpleNamespace(rowcount=3))
    session.flush = AsyncMock()

    deleted = await LLMGatewayService().delete_all_user_preferences(
        session, tenant_id=TENANT, user_id=MEMBER,
    )

    assert deleted == 3
    statement = session.execute.await_args.args[0]
    sql = str(statement.compile(compile_kwargs={"literal_binds": True}))
    assert "DELETE FROM" in sql
    assert TENANT in sql and MEMBER in sql

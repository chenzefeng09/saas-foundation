"""``GET /org-units`` and ``GET /teams`` filter by ``filter.<field>`` (CONVENTIONS §2.5).

The bare ``parent_id`` / ``org_unit_id`` the routes used to take stay as
deprecated aliases, so callers written against them keep working.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest

from foundation_org.api import dependencies as deps
from foundation_org.domain.base import FoundationContext
from foundation_org.main import create_app

OU = "ou_01J9Z8Y7X6W5V4T3S2R1Q0P9N8"
OTHER_OU = "ou_01J9Z8Y7X6W5V4T3S2R1Q0P9N9"


class _RecordingListService:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def list(self, session: Any, **kwargs: Any) -> tuple[list[Any], str | None]:
        self.calls.append(kwargs)
        return [], None


@pytest.fixture
def svc() -> _RecordingListService:
    return _RecordingListService()


@pytest.fixture
async def client(svc: _RecordingListService) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app()

    async def _no_session() -> AsyncIterator[None]:
        yield None

    app.dependency_overrides[deps.current_context] = lambda: FoundationContext(
        tenant_id="tnt_01J9Z8Y7X6W5V4T3S2R1Q0P9N8",
        user_id="usr_01J9Z8Y7X6W5V4T3S2R1Q0P9N8",
        actor="USER",
        request_id="req_test",
    )
    app.dependency_overrides[deps.db_session] = _no_session
    app.dependency_overrides[deps.org_unit_service] = lambda: svc
    app.dependency_overrides[deps.team_service] = lambda: svc
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://org") as c:
        yield c


ROUTES = [
    pytest.param("/api/org/v1/org-units", "parent_id", id="org-units"),
    pytest.param("/api/org/v1/teams", "org_unit_id", id="teams"),
]


@pytest.mark.parametrize(("path", "field"), ROUTES)
@pytest.mark.parametrize(
    ("params", "expected"),
    [
        pytest.param({}, None, id="unfiltered"),
        pytest.param({"filter.{field}": OU}, OU, id="filter-name"),
        pytest.param({"{field}": OU}, OU, id="deprecated-alias"),
        pytest.param({"filter.{field}": OU, "{field}": OTHER_OU}, OU, id="filter-name-wins"),
    ],
)
async def test_list_filters_on_the_documented_name_and_the_alias(
    client: httpx.AsyncClient,
    svc: _RecordingListService,
    path: str,
    field: str,
    params: dict[str, str],
    expected: str | None,
) -> None:
    resp = await client.get(path, params={k.format(field=field): v for k, v in params.items()})

    assert resp.status_code == 200, resp.text
    assert [call[field] for call in svc.calls] == [expected]


@pytest.mark.parametrize(("path", "field"), ROUTES)
@pytest.mark.parametrize("name", ["filter.{field}", "{field}"])
async def test_list_rejects_a_malformed_id_under_either_name(
    client: httpx.AsyncClient, svc: _RecordingListService, path: str, field: str, name: str
) -> None:
    resp = await client.get(path, params={name.format(field=field): "not-an-ou"})

    assert resp.status_code == 422
    assert svc.calls == []


async def test_openapi_marks_the_bare_names_deprecated(client: httpx.AsyncClient) -> None:
    spec = (await client.get("/api/org/v1/openapi.json")).json()

    for path, field in (
        ("/api/org/v1/org-units", "parent_id"),
        ("/api/org/v1/teams", "org_unit_id"),
    ):
        params = {p["name"]: p for p in spec["paths"][path]["get"]["parameters"]}
        assert not params[f"filter.{field}"].get("deprecated", False)
        assert params[field]["deprecated"] is True

"""Cursor paging of the id-ordered lists: every row comes back exactly once.

Each list selects ``id > :cursor ORDER BY id LIMIT :limit + 1`` and returns the
first ``limit`` rows, so the next cursor must be the last id *returned*; the
id of the lookahead row would make the next page skip that row.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from httpx import AsyncClient
from sqlalchemy.dialects import postgresql

from foundation_identity.api.v1 import platform_admin
from foundation_identity.domain.models import User
from foundation_identity.services.user_service import UserService

_TENANT_ID = "tnt_01J5DEV00000000000000000A1"
_CREATED_AT = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# UserService.list_users
# ---------------------------------------------------------------------------


class _Scalars:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def all(self) -> list[Any]:
        return self._rows


class _QueuedSession:
    """Serves ``scalars`` from a queue and records each statement (never evaluates it)."""

    def __init__(self) -> None:
        self.statements: list[Any] = []
        self._results: list[list[Any]] = []

    def queue_scalars(self, rows: list[Any]) -> None:
        self._results.append(list(rows))

    async def scalars(self, stmt: Any) -> _Scalars:
        self.statements.append(stmt)
        return _Scalars(self._results.pop(0))


def _sql(stmt: Any) -> str:
    """Render a recorded SELECT as Postgres SQL, values inlined."""
    compiled = stmt.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True})
    return " ".join(str(compiled).split())


def _db_answer(users: list[User], cursor: str | None, limit: int) -> list[User]:
    """What ``WHERE id > :cursor ORDER BY id LIMIT :limit + 1`` returns from ``users``."""
    ordered = sorted(users, key=lambda u: u.id)
    return [u for u in ordered if cursor is None or u.id > cursor][: limit + 1]


async def test_list_users_pages_through_every_user_once() -> None:
    users = [
        User(
            id=f"usr_01J5PAGEUSER0000000000000{i}",
            tenant_id=_TENANT_ID,
            email=f"user{i}@example.com",
            status="ACTIVE",
        )
        for i in range(1, 6)
    ]
    session = _QueuedSession()
    svc = UserService(keycloak=AsyncMock(), audit=AsyncMock())

    pages: list[list[User]] = []
    cursor = None
    for _ in users:  # a cursor that never runs out fails below instead of looping
        session.queue_scalars(_db_answer(users, cursor, limit=2))
        page, cursor = await svc.list_users(
            session,  # type: ignore[arg-type]
            tenant_id=_TENANT_ID,
            cursor=cursor,
            limit=2,
        )
        pages.append(page)
        if cursor is None:
            break

    assert cursor is None
    assert pages == [users[0:2], users[2:4], users[4:5]]
    user_id = 'identity."user".id'  # "user" is reserved in Postgres, so it is quoted
    first, *later = (_sql(s) for s in session.statements)
    assert f"ORDER BY {user_id} LIMIT 3" in first
    assert f"{user_id} >" not in first
    for previous, sql in zip(pages[:-1], later, strict=True):
        # Each page resumes right after the last user the previous one showed.
        assert f"{user_id} > '{previous[-1].id}' ORDER BY {user_id} LIMIT 3" in sql


# ---------------------------------------------------------------------------
# GET /platform/tenants, GET /platform/users (raw SQL, tuple rows)
# ---------------------------------------------------------------------------


class _Rows:
    def __init__(self, rows: list[tuple[Any, ...]]) -> None:
        self._rows = rows

    def fetchall(self) -> list[tuple[Any, ...]]:
        return self._rows


class _PlatformDb:
    """Answers a platform list query the way Postgres would, from its bound params.

    Rows are tuples whose first column is ``id``: ``id > :cursor ORDER BY id
    LIMIT :limit``.  Each query is recorded so a test can check the SQL asked
    for exactly that.
    """

    def __init__(self, rows: list[tuple[Any, ...]]) -> None:
        self._rows = sorted(rows)
        self.queries: list[tuple[str, dict[str, Any]]] = []

    async def execute(self, stmt: Any, params: dict[str, Any]) -> _Rows:
        self.queries.append((" ".join(str(stmt).split()), dict(params)))
        cursor = params.get("cursor")
        hits = [r for r in self._rows if cursor is None or r[0] > cursor]
        return _Rows(hits[: params["limit"]])


@pytest.fixture
def platform_db(app: FastAPI, monkeypatch: pytest.MonkeyPatch) -> Any:
    def _install(rows: list[tuple[Any, ...]]) -> _PlatformDb:
        db = _PlatformDb(rows)

        @asynccontextmanager
        async def _scope(**_kwargs: Any) -> AsyncIterator[_PlatformDb]:
            yield db

        monkeypatch.setattr(platform_admin, "admin_session_scope", _scope)
        app.dependency_overrides[platform_admin.require_super_admin] = (
            lambda: "usr_01J5DEVUSER000000000000001"
        )
        return db

    return _install


async def _get_all_pages(
    client: AsyncClient, url: str, headers: dict[str, str], *, rows: int, limit: int,
) -> list[list[str]]:
    """Follow next_cursor from the first page to the last; the ids of each page."""
    pages: list[list[str]] = []
    params: dict[str, Any] = {"limit": limit}
    for _ in range(rows):  # a cursor that never runs out fails below instead of looping
        resp = await client.get(url, params=params, headers=headers)
        assert resp.status_code == 200, resp.text
        body = resp.json()
        pages.append([item["id"] for item in body["items"]])
        if body["next_cursor"] is None:
            return pages
        params["cursor"] = body["next_cursor"]
    raise AssertionError(f"next_cursor never ran out after {rows} pages")


def _assert_resumes_after_previous_page(db: _PlatformDb, pages: list[list[str]]) -> None:
    (first_sql, first_params), *later = db.queries
    assert "ORDER BY id LIMIT :limit" in first_sql
    assert "id > :cursor" not in first_sql
    assert first_params["limit"] == 3  # limit + 1: the lookahead row signals another page
    for previous, (sql, params) in zip(pages[:-1], later, strict=True):
        assert "id > :cursor" in sql
        assert "ORDER BY id LIMIT :limit" in sql
        assert params["cursor"] == previous[-1]  # right after the last row shown


async def test_list_tenants_pages_through_every_tenant_once(
    client: AsyncClient, tenant_headers: dict[str, str], platform_db: Any,
) -> None:
    ids = [f"tnt_01J5PAGETENANT00000000000{i}" for i in range(1, 6)]
    db = platform_db([(tid, f"Tenant {tid[-1]}", "FREE", "ACTIVE", _CREATED_AT) for tid in ids])

    pages = await _get_all_pages(
        client, "/api/identity/v1/platform/tenants", tenant_headers, rows=len(ids), limit=2,
    )

    assert pages == [ids[0:2], ids[2:4], ids[4:5]]
    _assert_resumes_after_previous_page(db, pages)


async def test_list_users_cross_tenant_pages_through_every_user_once(
    client: AsyncClient, tenant_headers: dict[str, str], platform_db: Any,
) -> None:
    ids = [f"usr_01J5PAGEUSER0000000000000{i}" for i in range(1, 6)]
    db = platform_db([
        (uid, _TENANT_ID, f"{uid}@example.com", None, "ACTIVE", _CREATED_AT) for uid in ids
    ])

    pages = await _get_all_pages(
        client, "/api/identity/v1/platform/users", tenant_headers, rows=len(ids), limit=2,
    )

    assert pages == [ids[0:2], ids[2:4], ids[4:5]]
    _assert_resumes_after_previous_page(db, pages)

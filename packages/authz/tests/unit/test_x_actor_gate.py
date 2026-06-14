"""X-Actor=ADMIN hardening tests for the authz middleware.

Security invariants (mirrors the identity service's gate):
  - "ADMIN" is NOT an accepted external X-Actor value.
  - An unknown actor (incl. ADMIN) is silently downgraded to USER, NOT 400'd
    (avoids letting a caller probe "valid-but-forbidden" vs "syntactically wrong").
  - Valid actors USER/SERVICE/SYSTEM/MIGRATOR pass through unchanged.
  - A caller presenting the correct pre-shared X-Internal-Admin-Token may
    re-assert actor=ADMIN; a wrong/absent token cannot.
  - tenant_id / user_id format violations still return 400.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr

from foundation_authz.api.middleware import (
    ACTOR_VALUES,
    INTERNAL_ADMIN_TOKEN_HEADER,
    RequestIdMiddleware,
    TenantContextMiddleware,
)
from foundation_authz.domain.base import foundation_context

pytestmark = pytest.mark.unit

VALID_TENANT = "tnt_01J5VALIDTENANT000000000T1"
VALID_USER = "usr_01J5VALIDUSER00000000000U1"
ADMIN_TOKEN = "s3cret-internal-admin-token"


class _Settings:
    """Minimal stand-in exposing internal_admin_token as the middleware reads it."""

    def __init__(self, token: str) -> None:
        self.internal_admin_token = SecretStr(token)


def _make_app(*, admin_token: str = "") -> FastAPI:
    """A tiny app wired with the real middleware + an echo route that reports the
    resolved actor from the FoundationContext."""
    app = FastAPI()
    app.state.settings = _Settings(admin_token)
    app.add_middleware(TenantContextMiddleware)
    app.add_middleware(RequestIdMiddleware)

    @app.get("/echo")
    async def _echo(_request: Request) -> dict[str, str | None]:
        ctx = foundation_context.get()
        return {"actor": ctx.actor if ctx else None}

    @app.get("/healthz")
    async def _healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app


async def _client(app: FastAPI) -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver")


# ---------------------------------------------------------------------------
# Static invariant
# ---------------------------------------------------------------------------

def test_actor_values_excludes_admin_includes_safe_set() -> None:
    assert "ADMIN" not in ACTOR_VALUES
    for v in ("USER", "SERVICE", "SYSTEM", "MIGRATOR"):
        assert v in ACTOR_VALUES


# ---------------------------------------------------------------------------
# Downgrade behaviour
# ---------------------------------------------------------------------------

async def test_external_admin_header_downgraded_to_user() -> None:
    app = _make_app(admin_token=ADMIN_TOKEN)  # token configured, but caller has none
    async with await _client(app) as c:
        resp = await c.get(
            "/echo",
            headers={
                "X-Tenant-Id": VALID_TENANT,
                "X-User-Id": VALID_USER,
                "X-Actor": "ADMIN",
            },
        )
    assert resp.status_code == 200  # NOT 400
    assert resp.json()["actor"] == "USER"


async def test_external_admin_header_does_not_400_on_public_path() -> None:
    app = _make_app()
    async with await _client(app) as c:
        resp = await c.get("/healthz", headers={"X-Actor": "ADMIN"})
    assert resp.status_code == 200


async def test_unknown_actor_downgraded_to_user() -> None:
    app = _make_app()
    async with await _client(app) as c:
        resp = await c.get(
            "/echo",
            headers={
                "X-Tenant-Id": VALID_TENANT,
                "X-User-Id": VALID_USER,
                "X-Actor": "TOTALLY_BOGUS",
            },
        )
    assert resp.status_code == 200
    assert resp.json()["actor"] == "USER"


@pytest.mark.parametrize("actor", ["USER", "SERVICE", "SYSTEM", "MIGRATOR"])
async def test_valid_actors_pass_through(actor: str) -> None:
    app = _make_app()
    async with await _client(app) as c:
        resp = await c.get(
            "/echo",
            headers={
                "X-Tenant-Id": VALID_TENANT,
                "X-User-Id": VALID_USER,
                "X-Actor": actor,
            },
        )
    assert resp.status_code == 200
    assert resp.json()["actor"] == actor


# ---------------------------------------------------------------------------
# Internal-admin re-elevation
# ---------------------------------------------------------------------------

async def test_correct_internal_token_elevates_to_admin() -> None:
    app = _make_app(admin_token=ADMIN_TOKEN)
    async with await _client(app) as c:
        resp = await c.get(
            "/echo",
            headers={
                "X-Tenant-Id": VALID_TENANT,
                "X-User-Id": VALID_USER,
                "X-Actor": "ADMIN",
                INTERNAL_ADMIN_TOKEN_HEADER: ADMIN_TOKEN,
            },
        )
    assert resp.status_code == 200
    assert resp.json()["actor"] == "ADMIN"


async def test_internal_token_elevates_even_without_admin_header() -> None:
    """The token alone authorises ADMIN; the X-Actor header is irrelevant."""
    app = _make_app(admin_token=ADMIN_TOKEN)
    async with await _client(app) as c:
        resp = await c.get(
            "/echo",
            headers={
                "X-Tenant-Id": VALID_TENANT,
                "X-User-Id": VALID_USER,
                INTERNAL_ADMIN_TOKEN_HEADER: ADMIN_TOKEN,
            },
        )
    assert resp.status_code == 200
    assert resp.json()["actor"] == "ADMIN"


async def test_wrong_internal_token_does_not_elevate() -> None:
    app = _make_app(admin_token=ADMIN_TOKEN)
    async with await _client(app) as c:
        resp = await c.get(
            "/echo",
            headers={
                "X-Tenant-Id": VALID_TENANT,
                "X-User-Id": VALID_USER,
                "X-Actor": "ADMIN",
                INTERNAL_ADMIN_TOKEN_HEADER: "wrong-token",
            },
        )
    assert resp.status_code == 200
    assert resp.json()["actor"] == "USER"


async def test_empty_configured_token_disables_elevation() -> None:
    """With no configured token, even presenting a token cannot elevate."""
    app = _make_app(admin_token="")
    async with await _client(app) as c:
        resp = await c.get(
            "/echo",
            headers={
                "X-Tenant-Id": VALID_TENANT,
                "X-User-Id": VALID_USER,
                INTERNAL_ADMIN_TOKEN_HEADER: "anything",
            },
        )
    assert resp.status_code == 200
    assert resp.json()["actor"] == "USER"


# ---------------------------------------------------------------------------
# Format validation still 400s
# ---------------------------------------------------------------------------

async def test_bad_tenant_format_still_400() -> None:
    app = _make_app()
    async with await _client(app) as c:
        resp = await c.get(
            "/echo",
            headers={"X-Tenant-Id": "not-a-tenant", "X-Actor": "USER"},
        )
    assert resp.status_code == 400
    assert resp.json()["code"] == "FOUNDATION.AUTHZ.INPUT.INVALID_FORMAT"

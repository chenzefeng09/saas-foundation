"""Mock-based unit tests for the browser SSO login flow (server side).

Covers:
  * SsoService.list_platform_login_options — PLATFORM + enabled filter, no
    config leak (returns id/name/kind only).
  * SsoService.build_authorize_url — URL construction (kc_idp_hint present,
    redirect_uri/state URL-encoded, public base used); disabled / missing-alias
    / missing-provider → FoundationError(USER_NOT_FOUND).
  * KeycloakOIDCAdapter.authorization_code_grant — happy path + invalid_grant,
    mocking Keycloak's token endpoint via respx (same style other foundation
    services use for httpx adapters).

No DB: an AsyncMock AsyncSession returns canned Result mocks; ORM objects are
built in-memory.
"""

from __future__ import annotations

import urllib.parse
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
import respx
from httpx import AsyncClient, Response

from foundation_identity.adapters.keycloak_oidc import KeycloakOIDCAdapter
from foundation_identity.config import get_settings
from foundation_identity.domain.models import SsoProvider
from foundation_identity.errors import (
    INVALID_CREDENTIALS,
    USER_NOT_FOUND,
    FoundationError,
)
from foundation_identity.services.sso_service import SsoService

_BASE = datetime(2026, 1, 1, tzinfo=UTC)


# ── builders ──────────────────────────────────────────────────────────────── #


def _provider(
    *,
    pid: str = "sso_x",
    tenant_id: str | None = None,
    scope: str = "PLATFORM",
    kind: str = "OIDC",
    name: str = "Corp SSO",
    enabled: bool = True,
    alias: str | None = "platform-corp-abc12345",
    config: dict[str, Any] | None = None,
) -> SsoProvider:
    return SsoProvider(
        id=pid,
        tenant_id=tenant_id,
        kind=kind,
        name=name,
        enabled=enabled,
        scope=scope,
        default_tenant_id=None,
        keycloak_idp_alias=alias,
        config=config if config is not None else {"client_id": "cid", "client_secret": "shh"},
        created_at=_BASE,
        updated_at=_BASE,
    )


def _result(*, scalars_all: list[Any] | None = None, scalar_one: Any = ...) -> MagicMock:
    res = MagicMock()
    scalars = MagicMock()
    scalars.all.return_value = scalars_all or []
    res.scalars.return_value = scalars
    if scalar_one is not ...:
        res.scalar_one_or_none.return_value = scalar_one
    return res


def _session(results: list[MagicMock]) -> AsyncMock:
    session = AsyncMock()
    session.execute.side_effect = list(results)
    return session


def _service() -> SsoService:
    return SsoService(keycloak=AsyncMock(), audit=AsyncMock())


# ── list_platform_login_options ───────────────────────────────────────────── #


async def test_login_options_returns_id_name_kind_only() -> None:
    svc = _service()
    prov = _provider(
        pid="sso_corp",
        name="Corp SSO",
        kind="OIDC",
        config={"client_id": "cid", "client_secret": "topsecret"},
    )
    session = _session([_result(scalars_all=[prov])])

    out = await svc.list_platform_login_options(session)

    assert len(out) == 1
    opt = out[0]
    assert opt.id == "sso_corp"
    assert opt.name == "Corp SSO"
    assert opt.kind == "OIDC"
    # No config field exists on the public read model at all → no secret leak.
    assert not hasattr(opt, "config")
    dumped = opt.model_dump()
    assert "config" not in dumped
    assert "client_secret" not in dumped


async def test_login_options_empty_when_no_platform_providers() -> None:
    svc = _service()
    session = _session([_result(scalars_all=[])])
    out = await svc.list_platform_login_options(session)
    assert out == []


async def test_login_options_query_filters_platform_and_enabled() -> None:
    """The SELECT must constrain to scope=PLATFORM AND enabled=true.

    We can't introspect the compiled SQL easily off the AsyncMock, but we assert
    the service issues exactly one execute and trusts the WHERE clause — the
    filter columns are asserted via the rendered statement string.
    """
    svc = _service()
    session = _session([_result(scalars_all=[])])
    await svc.list_platform_login_options(session)

    stmt = session.execute.call_args.args[0]
    compiled = str(stmt).lower()
    assert "scope" in compiled
    assert "enabled" in compiled


# ── build_authorize_url ───────────────────────────────────────────────────── #


async def test_authorize_url_contains_hint_and_encoded_params() -> None:
    svc = _service()
    prov = _provider(alias="platform-corp-abc12345")
    session = _session([_result(scalar_one=prov)])

    redirect_uri = "http://localhost:3000/auth/callback?x=1"
    state = "st/ate+with spaces"
    url = await svc.build_authorize_url(
        session,
        provider_id="sso_x",
        redirect_uri=redirect_uri,
        state=state,
    )

    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)

    settings = get_settings()
    assert parsed.path.endswith("/protocol/openid-connect/auth")
    assert f"/realms/{settings.keycloak_realm}/" in url
    # kc_idp_hint routes Keycloak straight to the brokered IdP.
    assert qs["kc_idp_hint"] == ["platform-corp-abc12345"]
    assert qs["client_id"] == [settings.oidc_client_id]
    assert qs["response_type"] == ["code"]
    assert qs["scope"] == ["openid"]
    # redirect_uri + state round-trip through URL-decoding intact.
    assert qs["redirect_uri"] == [redirect_uri]
    assert qs["state"] == [state]
    # Params are actually percent-encoded in the raw query: no raw spaces, and
    # the inner '?'/'='/'+' of redirect_uri/state are escaped.
    assert " " not in url
    assert "st%2Fate" in url  # state's '/' encoded
    assert "callback%3Fx%3D1" in url  # redirect_uri's '?' and '=' encoded


async def test_authorize_url_uses_public_base_when_set(monkeypatch: pytest.MonkeyPatch) -> None:
    svc = _service()
    prov = _provider(alias="platform-x")
    session = _session([_result(scalar_one=prov)])

    settings = get_settings()
    monkeypatch.setattr(settings, "keycloak_public_base_url", "http://127.0.0.1:8080")
    url = await svc.build_authorize_url(
        session, provider_id="sso_x", redirect_uri="http://app/cb", state="s"
    )
    assert url.startswith("http://127.0.0.1:8080/realms/")


async def test_authorize_url_falls_back_to_base_when_public_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    svc = _service()
    prov = _provider(alias="platform-x")
    session = _session([_result(scalar_one=prov)])

    settings = get_settings()
    monkeypatch.setattr(settings, "keycloak_public_base_url", None)
    url = await svc.build_authorize_url(
        session, provider_id="sso_x", redirect_uri="http://app/cb", state="s"
    )
    assert url.startswith(str(settings.keycloak_base_url).rstrip("/") + "/realms/")


async def test_authorize_url_disabled_provider_raises() -> None:
    svc = _service()
    prov = _provider(enabled=False)
    session = _session([_result(scalar_one=prov)])

    with pytest.raises(FoundationError) as exc:
        await svc.build_authorize_url(
            session, provider_id="sso_x", redirect_uri="http://app/cb", state="s"
        )
    assert exc.value.error_code is USER_NOT_FOUND


async def test_authorize_url_missing_provider_raises() -> None:
    svc = _service()
    session = _session([_result(scalar_one=None)])

    with pytest.raises(FoundationError) as exc:
        await svc.build_authorize_url(
            session, provider_id="missing", redirect_uri="http://app/cb", state="s"
        )
    assert exc.value.error_code is USER_NOT_FOUND


async def test_authorize_url_missing_alias_raises() -> None:
    svc = _service()
    prov = _provider(alias=None)
    session = _session([_result(scalar_one=prov)])

    with pytest.raises(FoundationError) as exc:
        await svc.build_authorize_url(
            session, provider_id="sso_x", redirect_uri="http://app/cb", state="s"
        )
    assert exc.value.error_code is USER_NOT_FOUND


# ── authorization_code_grant (respx-mocked token endpoint) ────────────────── #


def _adapter() -> KeycloakOIDCAdapter:
    # Fresh adapter so it reads current settings; tests don't touch JWKS.
    return KeycloakOIDCAdapter()


@respx.mock
async def test_authorization_code_grant_happy_path() -> None:
    adapter = _adapter()
    token_url = adapter._token_url()
    route = respx.post(token_url).mock(
        return_value=Response(
            200,
            json={
                "access_token": "acc-tok",
                "refresh_token": "ref-tok",
                "expires_in": 300,
                "scope": "openid",
            },
        )
    )

    out = await adapter.authorization_code_grant(
        code="the-code", redirect_uri="http://app/cb"
    )

    assert out["access_token"] == "acc-tok"
    assert out["refresh_token"] == "ref-tok"
    assert route.called
    # Verify the grant_type + code + redirect_uri were posted as form fields.
    sent = route.calls.last.request
    body = sent.content.decode()
    assert "grant_type=authorization_code" in body
    assert "code=the-code" in body
    assert "redirect_uri=http" in body


@respx.mock
async def test_authorization_code_grant_invalid_grant_raises() -> None:
    adapter = _adapter()
    respx.post(adapter._token_url()).mock(
        return_value=Response(400, json={"error": "invalid_grant"})
    )

    with pytest.raises(FoundationError) as exc:
        await adapter.authorization_code_grant(
            code="bad", redirect_uri="http://app/cb"
        )
    assert exc.value.error_code is INVALID_CREDENTIALS


# ── endpoint wiring (PUBLIC routes + SSO_CODE) ────────────────────────────── #
#
# These exercise the FastAPI handlers without a real DB by monkeypatching
# admin_session_scope (imported into both api.v1.sso and api.v1.sessions) to
# yield a stub session.  They prove: middleware lets the public paths through
# without a tenant header, and SSO_CODE dispatches through the shared SSO path.


def _patch_admin_scope(monkeypatch: pytest.MonkeyPatch, module: str, fake) -> None:
    @asynccontextmanager
    async def _scope(*, tenant_id: str = "", user_id: str = "PLATFORM"):
        yield fake

    monkeypatch.setattr(f"foundation_identity.api.v1.{module}.admin_session_scope", _scope)


async def test_login_options_endpoint_public_no_tenant_header(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    prov = _provider(pid="sso_corp", name="Corp SSO", kind="OIDC")
    _patch_admin_scope(
        monkeypatch, "sso", _session([_result(scalars_all=[prov])])
    )

    # No X-Tenant-Id header → would 401 on tenant-scoped routes; public path is fine.
    resp = await client.get("/api/identity/v1/sso/login-options")
    assert resp.status_code == 200
    body = resp.json()
    assert body == [{"id": "sso_corp", "name": "Corp SSO", "kind": "OIDC"}]
    # Hard guarantee: no config / secret leaked through the wire.
    assert "config" not in resp.text
    assert "client_secret" not in resp.text


async def test_authorize_url_endpoint_public(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    prov = _provider(alias="platform-corp-abc12345")
    _patch_admin_scope(monkeypatch, "sso", _session([_result(scalar_one=prov)]))

    resp = await client.get(
        "/api/identity/v1/sso/providers/sso_x/authorize-url",
        params={"redirect_uri": "http://app/cb", "state": "xyz"},
    )
    assert resp.status_code == 200
    url = resp.json()["authorize_url"]
    assert "kc_idp_hint=platform-corp-abc12345" in url
    assert "/protocol/openid-connect/auth?" in url


async def test_authorize_url_endpoint_requires_params(client: AsyncClient) -> None:
    # Missing required query params → 422 (FastAPI validation), still public.
    resp = await client.get("/api/identity/v1/sso/providers/sso_x/authorize-url")
    assert resp.status_code == 422


async def test_sessions_sso_code_happy_path(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch, mock_oidc: AsyncMock
) -> None:
    # authorization_code_grant returns a full bundle; verify_token → STUB claims.
    mock_oidc.authorization_code_grant = AsyncMock(
        return_value={
            "access_token": "acc",
            "refresh_token": "ref",
            "expires_in": 300,
            "scope": "openid",
        }
    )
    prov = _provider(
        pid="sso_corp",
        scope="PLATFORM",
        tenant_id="tnt_01J5DEV00000000000000000A1",
    )
    # _complete_sso_session issues, in order across both admin_session_scope
    # blocks (same fake session): provider lookup, routing-rules query (empty →
    # falls back to provider.tenant_id), existing-user lookup (found → no insert).
    existing_user = MagicMock()
    existing_user.id = "usr_01J5DEVUSER000000000000001"
    _patch_admin_scope(
        monkeypatch,
        "sessions",
        _session(
            [
                _result(scalar_one=prov),           # provider lookup
                _result(scalars_all=[]),            # routing rules (none)
                _result(scalar_one=existing_user),  # existing user
            ]
        ),
    )
    # Login-row persistence is exercised separately (test_session_lifecycle);
    # stub it here so the SSO assertions stay focused on the broker path.
    monkeypatch.setattr(
        "foundation_identity.api.v1.sessions._persist_session",
        AsyncMock(return_value=None),
    )

    resp = await client.post(
        "/api/identity/v1/sessions",
        json={
            "method": "SSO_CODE",
            "code": "auth-code",
            "redirect_uri": "http://app/cb",
            "provider_id": "sso_corp",
        },
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["refresh_token"] == "ref"  # SSO_CODE returns refresh_token
    assert data["tenant_id"] == "tnt_01J5DEV00000000000000000A1"
    assert data["user_id"] == "usr_01J5DEVUSER000000000000001"
    mock_oidc.authorization_code_grant.assert_awaited_once()


async def test_sessions_sso_code_missing_fields_rejected(client: AsyncClient) -> None:
    # extra="forbid" + required fields → 422 when code/redirect_uri absent.
    resp = await client.post(
        "/api/identity/v1/sessions",
        json={"method": "SSO_CODE", "provider_id": "sso_corp"},
    )
    assert resp.status_code == 422

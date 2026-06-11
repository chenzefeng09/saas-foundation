"""Mock-based unit tests for SsoService platform CRUD + login routing.

No DB: an AsyncMock ``AsyncSession`` is used whose ``execute`` returns a result
mock; ``SsoProvider`` / ``SsoRoutingRule`` ORM instances are built in-memory.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from foundation_identity.domain.models import SsoProvider, SsoRoutingRule
from foundation_identity.errors import (
    SSO_PROVIDER_ERROR,
    USER_NOT_FOUND,
    FoundationError,
)
from foundation_identity.schemas.sso import (
    CreatePlatformSsoProviderRequest,
    CreateSsoRoutingRuleRequest,
    UpdateSsoRoutingRuleRequest,
)
from foundation_identity.services.sso_service import SsoService

_BASE = datetime(2026, 1, 1, tzinfo=UTC)
_T_A = "tnt_01J5TESTAAAAAAAAAAAAAAAAAA"
_T_B = "tnt_01J5TESTBBBBBBBBBBBBBBBBBB"
_T_DEF = "tnt_01J5TESTDEFAULTAAAAAAAAAA"


# ── builders ──────────────────────────────────────────────────────────────── #


def _provider(
    *,
    pid: str = "sso_x",
    tenant_id: str | None = _T_A,
    default_tenant_id: str | None = None,
    scope: str = "TENANT",
    kind: str = "OIDC",
    name: str = "Acme IdP",
    enabled: bool = True,
    alias: str | None = "acme-alias",
    config: dict[str, Any] | None = None,
) -> SsoProvider:
    return SsoProvider(
        id=pid,
        tenant_id=tenant_id,
        kind=kind,
        name=name,
        enabled=enabled,
        scope=scope,
        default_tenant_id=default_tenant_id,
        keycloak_idp_alias=alias,
        config=config if config is not None else {"client_id": "cid", "client_secret": "shh"},
        created_at=_BASE,
        updated_at=_BASE,
    )


def _rule(
    *,
    rid: str = "ssor_x",
    provider_id: str = "sso_x",
    match_type: str = "EQUALS",
    match_attribute: str = "groups",
    match_value: str = "admins",
    target_tenant_id: str = _T_B,
    priority: int = 100,
    enabled: bool = True,
    default_role: str | None = None,
) -> SsoRoutingRule:
    return SsoRoutingRule(
        id=rid,
        provider_id=provider_id,
        priority=priority,
        match_attribute=match_attribute,
        match_type=match_type,
        match_value=match_value,
        target_tenant_id=target_tenant_id,
        default_role=default_role,
        enabled=enabled,
        created_at=_BASE,
        updated_at=_BASE,
    )


def _result(*, scalars_all: list[Any] | None = None, scalar_one: Any = ...) -> MagicMock:
    """Build a fake SQLAlchemy Result.

    ``result.scalars().all()`` → ``scalars_all``
    ``result.scalar_one_or_none()`` → ``scalar_one``
    """
    res = MagicMock()
    scalars = MagicMock()
    scalars.all.return_value = scalars_all or []
    res.scalars.return_value = scalars
    if scalar_one is not ...:
        res.scalar_one_or_none.return_value = scalar_one
    return res


def _session(results: list[MagicMock]) -> AsyncMock:
    """AsyncSession whose successive ``execute`` calls return ``results`` in order."""
    session = AsyncMock()
    session.execute.side_effect = list(results)
    session.flush = AsyncMock()
    session.add = MagicMock()
    session.delete = AsyncMock()
    return session


def _service() -> tuple[SsoService, AsyncMock, AsyncMock]:
    kc = AsyncMock()
    audit = AsyncMock()
    return SsoService(keycloak=kc, audit=audit), kc, audit


# ── resolve_tenant_for_login ──────────────────────────────────────────────── #


async def test_resolve_login_rule_match_wins() -> None:
    svc, _, _ = _service()
    prov = _provider(default_tenant_id=_T_DEF)
    rule = _rule(match_type="EQUALS", match_value="admins", target_tenant_id=_T_B,
                 default_role="member")
    session = _session([_result(scalars_all=[rule])])

    out = await svc.resolve_tenant_for_login(
        session, provider=prov, attributes={"groups": ["admins"]}, email=None
    )
    assert out == (_T_B, "member")


async def test_resolve_login_falls_back_to_default_tenant() -> None:
    svc, _, _ = _service()
    prov = _provider(tenant_id=_T_A, default_tenant_id=_T_DEF)
    session = _session([_result(scalars_all=[])])  # no rules

    out = await svc.resolve_tenant_for_login(
        session, provider=prov, attributes={}, email=None
    )
    assert out == (_T_DEF, None)


async def test_resolve_login_falls_back_to_tenant_id() -> None:
    svc, _, _ = _service()
    prov = _provider(tenant_id=_T_A, default_tenant_id=None)
    session = _session([_result(scalars_all=[])])

    out = await svc.resolve_tenant_for_login(
        session, provider=prov, attributes={}, email=None
    )
    assert out == (_T_A, None)


async def test_resolve_login_all_none_raises() -> None:
    svc, _, _ = _service()
    prov = _provider(tenant_id=None, default_tenant_id=None)
    session = _session([_result(scalars_all=[])])

    with pytest.raises(FoundationError) as exc:
        await svc.resolve_tenant_for_login(
            session, provider=prov, attributes={}, email=None
        )
    assert exc.value.error_code is SSO_PROVIDER_ERROR


# ── list_rules ────────────────────────────────────────────────────────────── #


async def test_list_rules_returns_rows() -> None:
    svc, _, _ = _service()
    prov = _provider()
    rules = [_rule(rid="ssor_1"), _rule(rid="ssor_2")]
    session = _session([
        _result(scalar_one=prov),          # _get_provider_platform
        _result(scalars_all=rules),        # list rules
    ])

    out = await svc.list_rules(session, "sso_x")
    assert [r.id for r in out] == ["ssor_1", "ssor_2"]


async def test_list_rules_provider_missing_raises() -> None:
    svc, _, _ = _service()
    session = _session([_result(scalar_one=None)])

    with pytest.raises(FoundationError) as exc:
        await svc.list_rules(session, "sso_missing")
    assert exc.value.error_code is USER_NOT_FOUND


# ── create_rule ───────────────────────────────────────────────────────────── #


async def test_create_rule_provider_exists() -> None:
    svc, _, audit = _service()
    prov = _provider(tenant_id=_T_A)
    session = _session([_result(scalar_one=prov)])

    body = CreateSsoRoutingRuleRequest(
        match_attribute="groups",
        match_type="EQUALS",
        match_value="admins",
        target_tenant_id=_T_B,
    )
    out = await svc.create_rule(
        session, request_id="req-1", provider_id="sso_x", body=body
    )
    assert out.provider_id == "sso_x"
    assert out.target_tenant_id == _T_B
    session.add.assert_called_once()
    session.flush.assert_awaited()
    audit.publish.assert_awaited_once()


async def test_create_rule_provider_missing_raises() -> None:
    svc, _, _ = _service()
    session = _session([_result(scalar_one=None)])

    body = CreateSsoRoutingRuleRequest(
        match_attribute="groups",
        match_type="EQUALS",
        match_value="admins",
        target_tenant_id=_T_B,
    )
    with pytest.raises(FoundationError) as exc:
        await svc.create_rule(
            session, request_id="req-1", provider_id="missing", body=body
        )
    assert exc.value.error_code is USER_NOT_FOUND
    session.add.assert_not_called()


# ── update_rule ───────────────────────────────────────────────────────────── #


async def test_update_rule_found() -> None:
    svc, _, audit = _service()
    prov = _provider(tenant_id=_T_A)
    rule = _rule(rid="ssor_1", priority=100, enabled=True)
    session = _session([
        _result(scalar_one=prov),    # _get_provider_platform
        _result(scalar_one=rule),    # select rule
    ])

    body = UpdateSsoRoutingRuleRequest(priority=5, enabled=False)
    out = await svc.update_rule(
        session, request_id="req-1", provider_id="sso_x",
        rule_id="ssor_1", body=body,
    )
    assert out.priority == 5
    assert out.enabled is False
    assert rule.priority == 5
    audit.publish.assert_awaited_once()


async def test_update_rule_not_found_raises() -> None:
    svc, _, _ = _service()
    prov = _provider()
    session = _session([
        _result(scalar_one=prov),
        _result(scalar_one=None),    # rule missing
    ])

    body = UpdateSsoRoutingRuleRequest(priority=5)
    with pytest.raises(FoundationError) as exc:
        await svc.update_rule(
            session, request_id="req-1", provider_id="sso_x",
            rule_id="missing", body=body,
        )
    assert exc.value.error_code is USER_NOT_FOUND


# ── delete_rule ───────────────────────────────────────────────────────────── #


async def test_delete_rule_found() -> None:
    svc, _, audit = _service()
    prov = _provider()
    rule = _rule(rid="ssor_1")
    session = _session([
        _result(scalar_one=prov),
        _result(scalar_one=rule),
    ])

    await svc.delete_rule(
        session, request_id="req-1", provider_id="sso_x", rule_id="ssor_1"
    )
    session.delete.assert_awaited_once_with(rule)
    session.flush.assert_awaited()
    audit.publish.assert_awaited_once()


async def test_delete_rule_not_found_raises() -> None:
    svc, _, _ = _service()
    prov = _provider()
    session = _session([
        _result(scalar_one=prov),
        _result(scalar_one=None),
    ])

    with pytest.raises(FoundationError) as exc:
        await svc.delete_rule(
            session, request_id="req-1", provider_id="sso_x", rule_id="missing"
        )
    assert exc.value.error_code is USER_NOT_FOUND
    session.delete.assert_not_called()


# ── list_providers_platform (redaction) ───────────────────────────────────── #


async def test_list_providers_platform_redacts_secret() -> None:
    svc, _, _ = _service()
    prov = _provider(config={"client_id": "cid", "client_secret": "topsecret"})
    session = _session([_result(scalars_all=[prov])])

    out = await svc.list_providers_platform(session)
    assert len(out) == 1
    assert out[0].config["client_secret"] == "••••••"
    assert out[0].config["client_id"] == "cid"


# ── create_provider_platform ──────────────────────────────────────────────── #


async def test_create_provider_platform_alias_prefix_and_redaction() -> None:
    svc, kc, audit = _service()
    session = _session([])  # no execute calls; only add/flush

    body = CreatePlatformSsoProviderRequest(
        kind="OIDC",
        name="Corp SSO",
        config={"client_id": "cid", "client_secret": "shh"},
        scope="PLATFORM",
    )
    out = await svc.create_provider_platform(
        session, request_id="req-1", body=body
    )

    # platform alias prefix + tenant_id NULL on the persisted ORM object
    added = session.add.call_args.args[0]
    assert added.keycloak_idp_alias.startswith("platform-")
    assert added.tenant_id is None
    assert added.scope == "PLATFORM"
    # secret redacted in the returned read model
    assert out.config["client_secret"] == "••••••"
    kc.upsert_identity_provider.assert_awaited_once()
    audit.publish.assert_awaited_once()


async def test_create_provider_platform_keycloak_failure_tolerated() -> None:
    svc, kc, _ = _service()
    kc.upsert_identity_provider.side_effect = FoundationError(
        SSO_PROVIDER_ERROR, detail="kc down"
    )
    session = _session([])

    body = CreatePlatformSsoProviderRequest(
        kind="OIDC",
        name="Corp SSO",
        config={"client_id": "cid"},
        scope="PLATFORM",
    )
    # Keycloak failure must be swallowed: creation still succeeds + persists.
    out = await svc.create_provider_platform(
        session, request_id="req-1", body=body
    )
    assert out.scope == "PLATFORM"
    session.add.assert_called_once()
    session.flush.assert_awaited()


async def test_create_provider_platform_tenant_scope() -> None:
    svc, kc, _ = _service()
    session = _session([])

    body = CreatePlatformSsoProviderRequest(
        kind="OIDC",
        name="Tenant SSO",
        config={"client_id": "cid"},
        scope="TENANT",
        tenant_id=_T_A,
        default_tenant_id=_T_DEF,
    )
    out = await svc.create_provider_platform(
        session, request_id="req-1", body=body
    )
    added = session.add.call_args.args[0]
    assert added.tenant_id == _T_A
    assert added.default_tenant_id == _T_DEF
    assert not added.keycloak_idp_alias.startswith("platform-")
    assert out.scope == "TENANT"


# ── set_provider_enabled / delete_provider (platform path: tenant_id=None) ─── #


async def test_set_provider_enabled_platform_path() -> None:
    svc, kc, audit = _service()
    prov = _provider(tenant_id=None, scope="PLATFORM", alias="platform-x")
    session = _session([_result(scalar_one=prov)])

    out = await svc.set_provider_enabled(
        session, tenant_id=None, request_id="req-1",
        provider_id="sso_x", enabled=False,
    )
    assert out.enabled is False
    assert prov.enabled is False
    kc.upsert_identity_provider.assert_awaited_once()
    audit.publish.assert_awaited_once()


async def test_set_provider_enabled_not_found_raises() -> None:
    svc, _, _ = _service()
    session = _session([_result(scalar_one=None)])

    with pytest.raises(FoundationError) as exc:
        await svc.set_provider_enabled(
            session, tenant_id=None, request_id="req-1",
            provider_id="missing", enabled=True,
        )
    assert exc.value.error_code is USER_NOT_FOUND


async def test_delete_provider_platform_path() -> None:
    svc, kc, audit = _service()
    prov = _provider(tenant_id=None, scope="PLATFORM", alias="platform-x")
    session = _session([_result(scalar_one=prov)])

    await svc.delete_provider(
        session, tenant_id=None, request_id="req-1", provider_id="sso_x"
    )
    kc._request.assert_awaited_once()
    session.delete.assert_awaited_once_with(prov)
    audit.publish.assert_awaited_once()


async def test_delete_provider_not_found_raises() -> None:
    svc, _, _ = _service()
    session = _session([_result(scalar_one=None)])

    with pytest.raises(FoundationError) as exc:
        await svc.delete_provider(
            session, tenant_id=None, request_id="req-1", provider_id="missing"
        )
    assert exc.value.error_code is USER_NOT_FOUND

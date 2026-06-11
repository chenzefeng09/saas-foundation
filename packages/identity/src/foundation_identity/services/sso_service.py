"""SSO (Single Sign-On) provider configuration service.

Responsibilities:
  * list_providers()        → all SSO providers for a tenant
  * create_provider()       → persist + Keycloak IdP sync (identity brokering)
  * update_provider()       → update config + Keycloak upsert
  * delete_provider()       → soft-delete (disable) + remove from Keycloak
  * list_social_providers() → static list of known social IdPs with per-tenant enable flag
  * get_login_url()         → build the Keycloak-hosted SSO initiation URL

Backend: Keycloak Identity Brokering (Admin API `/identity-provider/instances`).
For OIDC/SAML providers we map our config keys to Keycloak's IDP config payload.
For social providers (GOOGLE, GITHUB, …) we rely on pre-configured Keycloak social
broker clients — we only surface their enabled state and construct the login URL.

Keycloak SSO login URL pattern:
  {base}/realms/{realm}/broker/{alias}/login?client_id={client_id}&...
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

import ulid
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_identity.adapters.audit_publisher import AuditPublisher
from foundation_identity.adapters.keycloak_admin import KeycloakAdminAdapter
from foundation_identity.config import get_settings
from foundation_identity.domain.models import SsoProvider, SsoRoutingRule
from foundation_identity.errors import (
    SSO_PROVIDER_ERROR,
    USER_NOT_FOUND,
    FoundationError,
)
from foundation_identity.observability import get_logger
from foundation_identity.schemas.sso import (
    CreatePlatformSsoProviderRequest,
    CreateSsoProviderRequest,
    CreateSsoRoutingRuleRequest,
    SocialProviderRead,
    SsoLoginOptionRead,
    SsoProviderRead,
    SsoRoutingRuleRead,
    UpdateSsoRoutingRuleRequest,
)

log = get_logger(__name__)


def _new_id() -> str:
    return f"sso_{ulid.new()!s}"


def _new_rule_id() -> str:
    return f"ssor_{ulid.new()!s}"


# ── routing resolution (pure functions) ──────────────────────────────────── #


def resolve_routing(
    rules: list[SsoRoutingRule],
    attributes: dict[str, Any],
    email: str | None,
) -> tuple[str, str | None] | None:
    """Resolve (target_tenant_id, default_role) from routing rules.

    Pure function — no DB.  Rules are evaluated in (priority, created_at) order;
    the first match wins.  Disabled rules are skipped.

    Match semantics:
      * EMAIL_DOMAIN: ``match_value`` compared case-insensitively to the domain
        part of ``email`` (match_attribute ignored).
      * EQUALS:       ``attributes[match_attribute]`` equals ``match_value``
        (case-insensitive).  Value may be str or list[str] — any element matches.
      * CONTAINS:     ``match_value`` is a case-insensitive substring of the
        attribute value (str or any list element).
      * REGEX:        ``re.search(match_value, str(value))`` (any list element).
                      Invalid regexes are skipped defensively.
    """

    def _sort_key(r: SsoRoutingRule) -> tuple[int, Any]:
        # created_at may be None on freshly built (un-flushed) ORM objects in
        # tests; treat None as "earliest" so ordering is deterministic.
        return (r.priority, r.created_at or datetime.min)

    for rule in sorted(rules, key=_sort_key):
        if not rule.enabled:
            continue

        mt = rule.match_type
        mv = rule.match_value

        if mt == "EMAIL_DOMAIN":
            if not email or "@" not in email:
                continue
            domain = email.rsplit("@", 1)[1].lower()
            if domain == mv.lower():
                return (rule.target_tenant_id, rule.default_role)
            continue

        raw = attributes.get(rule.match_attribute)
        if raw is None:
            continue
        values = raw if isinstance(raw, list) else [raw]

        if mt == "EQUALS":
            for v in values:
                if str(v).lower() == mv.lower():
                    return (rule.target_tenant_id, rule.default_role)
        elif mt == "CONTAINS":
            for v in values:
                if mv.lower() in str(v).lower():
                    return (rule.target_tenant_id, rule.default_role)
        elif mt == "REGEX":
            try:
                pattern = re.compile(mv)
            except re.error:
                log.warning("sso.routing.invalid_regex", rule_id=rule.id)
                continue
            for v in values:
                if pattern.search(str(v)):
                    return (rule.target_tenant_id, rule.default_role)

    return None


# ── Keycloak IdP payload mapping ──────────────────────────────────────────── #

_KIND_TO_PROVIDER_ID: dict[str, str] = {
    "OIDC": "oidc",
    "SAML": "saml",
    "AD": "microsoft",  # Azure AD / Entra
    "LDAP": "ldap",
    "DINGTALK_ENTERPRISE": "oidc",  # DingTalk uses OIDC protocol
    "FEISHU_ENTERPRISE": "oidc",  # Feishu/Lark uses OIDC protocol
    "WECOM": "oidc",  # WeCom uses OAuth2/OIDC-like
}

# Known social provider aliases (pre-configured in Keycloak realm)
_SOCIAL_ALIASES: dict[str, str] = {
    "GOOGLE": "google",
    "GITHUB": "github",
    "MICROSOFT": "microsoft",
    "WECHAT": "wechat",
    "QQ": "qq",
    "DINGTALK_PERSONAL": "dingtalk",
    "FEISHU_PERSONAL": "feishu",
    "APPLE": "apple",
}


def _build_kc_config(kind: str, config: dict[str, Any]) -> dict[str, Any]:
    """Map our config dict to Keycloak IDP registration payload."""
    provider_id = _KIND_TO_PROVIDER_ID.get(kind, "oidc")
    base: dict[str, Any] = {
        "providerId": provider_id,
        "enabled": True,
        # Enterprise IdPs are authoritative for their users' email addresses —
        # tenant routing keys on the email domain, and distrusting it stalls
        # first-broker-login on a VERIFY_EMAIL action the user can't complete.
        "trustEmail": True,
        "storeToken": False,
        "addReadTokenRoleOnCreate": False,
        "firstBrokerLoginFlowAlias": "first broker login",
        "config": {},
    }

    if provider_id == "oidc":
        base["config"] = {
            "clientId": config.get("client_id", ""),
            "clientSecret": config.get("client_secret", ""),
            "authorizationUrl": config.get("authorization_url", ""),
            "tokenUrl": config.get("token_url", ""),
            "userInfoUrl": config.get("userinfo_url", ""),
            "issuer": config.get("issuer", ""),
            "defaultScope": config.get("scope", "openid email profile"),
            "validateSignature": "true",
            "useJwksUrl": "true",
            "jwksUrl": config.get("jwks_url", ""),
            "syncMode": "IMPORT",
        }
    elif provider_id == "saml":
        base["config"] = {
            "singleSignOnServiceUrl": config.get("sso_url", ""),
            "nameIDPolicyFormat": config.get(
                "name_id_format",
                "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
            ),
            "signatureAlgorithm": "RSA_SHA256",
            "xmlSigKeyInfoKeyNameTransformer": "KEY_ID",
            "syncMode": "IMPORT",
        }
        if "signing_certificate" in config:
            base["config"]["signingCertificate"] = config["signing_certificate"]

    # Pass through any extra keys the caller provided
    for k, v in config.items():
        if k not in base["config"]:
            base["config"][k] = v

    return base


_SENSITIVE_KEYS = frozenset({
    "client_secret", "bind_password", "app_secret", "secret",
})


def _redact_config(config: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of config with sensitive values masked."""
    return {
        k: "••••••" if k in _SENSITIVE_KEYS and v else v
        for k, v in config.items()
    }


class SsoService:
    """SSO provider CRUD + Keycloak IdP sync."""

    def __init__(
        self,
        keycloak: KeycloakAdminAdapter,
        audit: AuditPublisher,
    ) -> None:
        self._kc = keycloak
        self._audit = audit

    # ── list ─────────────────────────────────────────────────────────────── #

    async def list_providers(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
    ) -> list[SsoProviderRead]:
        """Return all SSO providers for the tenant."""
        result = await session.execute(
            select(SsoProvider).where(SsoProvider.tenant_id == tenant_id)
        )
        rows = result.scalars().all()
        out = []
        for r in rows:
            read = SsoProviderRead.model_validate(r)
            read.config = _redact_config(read.config)
            out.append(read)
        return out

    # ── create ────────────────────────────────────────────────────────────── #

    async def create_provider(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        request_id: str,
        body: CreateSsoProviderRequest,
    ) -> SsoProviderRead:
        """Create a new SSO provider, sync to Keycloak, persist in DB."""
        provider_id = _new_id()
        # Use tenant_id as part of the alias to prevent cross-tenant collision
        _uid_suffix = str(ulid.new())[:8]
        kc_alias = f"{tenant_id[:8]}-{body.name.lower().replace(' ', '-')[:20]}-{_uid_suffix}"

        kc_payload = _build_kc_config(body.kind, body.config)
        try:
            await self._kc.upsert_identity_provider(kc_alias, kc_payload)
        except FoundationError:
            # If Keycloak is unavailable, log + continue (eventual consistency)
            log.warning(
                "sso.keycloak_sync.failed",
                tenant_id=tenant_id,
                alias=kc_alias,
                request_id=request_id,
            )

        now = datetime.now(UTC)
        provider = SsoProvider(
            id=provider_id,
            tenant_id=tenant_id,
            kind=body.kind,
            name=body.name,
            enabled=True,
            keycloak_idp_alias=kc_alias,
            config=body.config,
            created_at=now,
            updated_at=now,
        )
        session.add(provider)
        await session.flush()

        await self._audit.publish(
            session,
            event_type="foundation.identity.sso.created",
            tenant_id=tenant_id,
            aggregate_id=provider_id,
            payload={"kind": body.kind, "name": body.name, "alias": kc_alias},
            request_id=request_id,
        )

        log.info(
            "sso.provider.created",
            tenant_id=tenant_id,
            provider_id=provider_id,
            kind=body.kind,
            request_id=request_id,
        )

        read = SsoProviderRead.model_validate(provider)
        read.config = _redact_config(read.config)
        return read

    # ── enable / disable ─────────────────────────────────────────────────── #

    async def set_provider_enabled(
        self,
        session: AsyncSession,
        *,
        tenant_id: str | None,
        request_id: str,
        provider_id: str,
        enabled: bool,
    ) -> SsoProviderRead:
        """Enable or disable an SSO provider.

        ``tenant_id=None`` skips the tenant filter (platform-admin callers).
        """
        conds = [SsoProvider.id == provider_id]
        if tenant_id is not None:
            conds.append(SsoProvider.tenant_id == tenant_id)
        result = await session.execute(select(SsoProvider).where(*conds))
        provider = result.scalar_one_or_none()
        if provider is None:
            raise FoundationError(USER_NOT_FOUND, detail="SSO provider not found")

        provider.enabled = enabled
        provider.updated_at = datetime.now(UTC)
        await session.flush()

        # Sync to Keycloak if alias is set
        if provider.keycloak_idp_alias:
            try:
                kc_payload = _build_kc_config(provider.kind, provider.config)
                kc_payload["enabled"] = enabled
                await self._kc.upsert_identity_provider(
                    provider.keycloak_idp_alias, kc_payload
                )
            except FoundationError:
                log.warning(
                    "sso.keycloak_sync.failed",
                    tenant_id=tenant_id,
                    provider_id=provider_id,
                    request_id=request_id,
                )

        await self._audit.publish(
            session,
            event_type="foundation.identity.sso.updated",
            tenant_id=tenant_id,
            aggregate_id=provider_id,
            payload={"enabled": enabled},
            request_id=request_id,
        )

        read = SsoProviderRead.model_validate(provider)
        read.config = _redact_config(read.config)
        return read

    # ── delete ────────────────────────────────────────────────────────────── #

    async def delete_provider(
        self,
        session: AsyncSession,
        *,
        tenant_id: str | None,
        request_id: str,
        provider_id: str,
    ) -> None:
        """Hard-delete an SSO provider from DB and Keycloak.

        ``tenant_id=None`` skips the tenant filter (platform-admin callers).
        """
        conds = [SsoProvider.id == provider_id]
        if tenant_id is not None:
            conds.append(SsoProvider.tenant_id == tenant_id)
        result = await session.execute(select(SsoProvider).where(*conds))
        provider = result.scalar_one_or_none()
        if provider is None:
            raise FoundationError(USER_NOT_FOUND, detail="SSO provider not found")

        # Remove from Keycloak
        if provider.keycloak_idp_alias:
            try:
                await self._kc._request(
                    "DELETE",
                    f"/identity-provider/instances/{provider.keycloak_idp_alias}",
                    expected=(204, 404),
                )
            except FoundationError:
                log.warning(
                    "sso.keycloak_delete.failed",
                    tenant_id=tenant_id,
                    provider_id=provider_id,
                    request_id=request_id,
                )

        await self._audit.publish(
            session,
            event_type="foundation.identity.sso.deleted",
            tenant_id=tenant_id,
            aggregate_id=provider_id,
            payload={"provider_id": provider_id, "kind": provider.kind},
            request_id=request_id,
        )

        await session.delete(provider)
        await session.flush()

    # ── login-time routing resolution ────────────────────────────────────── #

    async def resolve_tenant_for_login(
        self,
        session: AsyncSession,
        *,
        provider: SsoProvider,
        attributes: dict[str, Any],
        email: str | None,
    ) -> tuple[str, str | None]:
        """Resolve (tenant_id, default_role) for an SSO login.

        Strategy:
          1. Evaluate the provider's enabled routing rules via
             :func:`resolve_routing` (first match wins).
          2. Fall back to ``provider.default_tenant_id``.
          3. Fall back to ``provider.tenant_id``.
          4. If all None → raise SSO_PROVIDER_ERROR.
        """
        result = await session.execute(
            select(SsoRoutingRule)
            .where(
                SsoRoutingRule.provider_id == provider.id,
                SsoRoutingRule.enabled.is_(True),
            )
            .order_by(SsoRoutingRule.priority, SsoRoutingRule.created_at)
        )
        rules = list(result.scalars().all())

        match = resolve_routing(rules, attributes, email)
        if match is not None:
            return match

        if provider.default_tenant_id:
            return (provider.default_tenant_id, None)
        if provider.tenant_id:
            return (provider.tenant_id, None)

        raise FoundationError(
            SSO_PROVIDER_ERROR, detail="no tenant routing matched"
        )

    # ── platform provider CRUD ───────────────────────────────────────────── #

    async def list_providers_platform(
        self,
        session: AsyncSession,
    ) -> list[SsoProviderRead]:
        """List all SSO providers across all scopes (platform-admin)."""
        result = await session.execute(select(SsoProvider))
        rows = result.scalars().all()
        out = []
        for r in rows:
            read = SsoProviderRead.model_validate(r)
            read.config = _redact_config(read.config)
            out.append(read)
        return out

    async def create_provider_platform(
        self,
        session: AsyncSession,
        *,
        request_id: str,
        body: CreatePlatformSsoProviderRequest,
    ) -> SsoProviderRead:
        """Create a provider at PLATFORM or TENANT scope (platform-admin)."""
        provider_id = _new_id()
        _uid_suffix = str(ulid.new())[:8]
        slug = body.name.lower().replace(" ", "-")[:20]
        if body.scope == "PLATFORM":
            kc_alias = f"platform-{slug}-{_uid_suffix}"
            tenant_id: str | None = None
        else:
            kc_alias = f"{(body.tenant_id or '')[:8]}-{slug}-{_uid_suffix}"
            tenant_id = body.tenant_id

        kc_payload = _build_kc_config(body.kind, body.config)
        try:
            await self._kc.upsert_identity_provider(kc_alias, kc_payload)
        except FoundationError:
            log.warning(
                "sso.keycloak_sync.failed",
                alias=kc_alias,
                scope=body.scope,
                request_id=request_id,
            )

        now = datetime.now(UTC)
        provider = SsoProvider(
            id=provider_id,
            tenant_id=tenant_id,
            kind=body.kind,
            name=body.name,
            enabled=True,
            scope=body.scope,
            default_tenant_id=body.default_tenant_id,
            keycloak_idp_alias=kc_alias,
            config=body.config,
            created_at=now,
            updated_at=now,
        )
        session.add(provider)
        await session.flush()

        await self._audit.publish(
            session,
            event_type="foundation.identity.sso.created",
            tenant_id=tenant_id or "",
            aggregate_id=provider_id,
            payload={
                "kind": body.kind,
                "name": body.name,
                "alias": kc_alias,
                "scope": body.scope,
            },
            request_id=request_id,
        )

        log.info(
            "sso.provider.created_platform",
            provider_id=provider_id,
            kind=body.kind,
            scope=body.scope,
            request_id=request_id,
        )

        read = SsoProviderRead.model_validate(provider)
        read.config = _redact_config(read.config)
        return read

    # ── routing rule CRUD (platform-admin) ───────────────────────────────── #

    async def _get_provider_platform(
        self, session: AsyncSession, provider_id: str
    ) -> SsoProvider:
        result = await session.execute(
            select(SsoProvider).where(SsoProvider.id == provider_id)
        )
        provider = result.scalar_one_or_none()
        if provider is None:
            raise FoundationError(USER_NOT_FOUND, detail="SSO provider not found")
        return provider

    async def list_rules(
        self, session: AsyncSession, provider_id: str
    ) -> list[SsoRoutingRuleRead]:
        """List routing rules for a provider, ordered by priority."""
        await self._get_provider_platform(session, provider_id)
        result = await session.execute(
            select(SsoRoutingRule)
            .where(SsoRoutingRule.provider_id == provider_id)
            .order_by(SsoRoutingRule.priority, SsoRoutingRule.created_at)
        )
        return [
            SsoRoutingRuleRead.model_validate(r) for r in result.scalars().all()
        ]

    async def create_rule(
        self,
        session: AsyncSession,
        *,
        request_id: str,
        provider_id: str,
        body: CreateSsoRoutingRuleRequest,
    ) -> SsoRoutingRuleRead:
        """Create a routing rule for a provider."""
        provider = await self._get_provider_platform(session, provider_id)

        now = datetime.now(UTC)
        rule = SsoRoutingRule(
            id=_new_rule_id(),
            provider_id=provider_id,
            priority=body.priority,
            match_attribute=body.match_attribute,
            match_type=body.match_type,
            match_value=body.match_value,
            target_tenant_id=body.target_tenant_id,
            default_role=body.default_role,
            enabled=body.enabled,
            created_at=now,
            updated_at=now,
        )
        session.add(rule)
        await session.flush()

        await self._audit.publish(
            session,
            event_type="foundation.identity.sso.updated",
            tenant_id=provider.tenant_id or "",
            aggregate_id=provider_id,
            payload={"routing_rule": rule.id, "action": "created"},
            request_id=request_id,
        )
        return SsoRoutingRuleRead.model_validate(rule)

    async def update_rule(
        self,
        session: AsyncSession,
        *,
        request_id: str,
        provider_id: str,
        rule_id: str,
        body: UpdateSsoRoutingRuleRequest,
    ) -> SsoRoutingRuleRead:
        """Update a routing rule (partial)."""
        provider = await self._get_provider_platform(session, provider_id)
        result = await session.execute(
            select(SsoRoutingRule).where(
                SsoRoutingRule.id == rule_id,
                SsoRoutingRule.provider_id == provider_id,
            )
        )
        rule = result.scalar_one_or_none()
        if rule is None:
            raise FoundationError(USER_NOT_FOUND, detail="Routing rule not found")

        patch = body.model_dump(exclude_unset=True)
        for field, value in patch.items():
            setattr(rule, field, value)
        rule.updated_at = datetime.now(UTC)
        await session.flush()

        await self._audit.publish(
            session,
            event_type="foundation.identity.sso.updated",
            tenant_id=provider.tenant_id or "",
            aggregate_id=provider_id,
            payload={
                "routing_rule": rule.id,
                "action": "updated",
                "changed_fields": sorted(patch.keys()),
            },
            request_id=request_id,
        )
        return SsoRoutingRuleRead.model_validate(rule)

    async def delete_rule(
        self,
        session: AsyncSession,
        *,
        request_id: str,
        provider_id: str,
        rule_id: str,
    ) -> None:
        """Delete a routing rule."""
        provider = await self._get_provider_platform(session, provider_id)
        result = await session.execute(
            select(SsoRoutingRule).where(
                SsoRoutingRule.id == rule_id,
                SsoRoutingRule.provider_id == provider_id,
            )
        )
        rule = result.scalar_one_or_none()
        if rule is None:
            raise FoundationError(USER_NOT_FOUND, detail="Routing rule not found")

        await self._audit.publish(
            session,
            event_type="foundation.identity.sso.updated",
            tenant_id=provider.tenant_id or "",
            aggregate_id=provider_id,
            payload={"routing_rule": rule_id, "action": "deleted"},
            request_id=request_id,
        )
        await session.delete(rule)
        await session.flush()

    # ── public browser-login helpers ─────────────────────────────────────── #

    async def list_platform_login_options(
        self,
        session: AsyncSession,
    ) -> list[SsoLoginOptionRead]:
        """Return enabled PLATFORM-scoped providers for the public login page.

        PUBLIC endpoint helper: returns ONLY ``id`` / ``name`` / ``kind`` for
        providers with ``scope='PLATFORM' AND enabled=true``.  NEVER exposes
        config (which may carry secret refs) or tenant-scoped providers.
        """
        result = await session.execute(
            select(SsoProvider).where(
                SsoProvider.scope == "PLATFORM",
                SsoProvider.enabled.is_(True),
            )
        )
        rows = result.scalars().all()
        return [
            SsoLoginOptionRead(id=r.id, name=r.name, kind=r.kind)  # type: ignore[arg-type]
            for r in rows
        ]

    async def build_authorize_url(
        self,
        session: AsyncSession,
        *,
        provider_id: str,
        redirect_uri: str,
        state: str,
    ) -> str:
        """Build the browser-facing Keycloak authorize URL for an SSO provider.

        PUBLIC endpoint helper.  Validates the provider exists, is enabled, and
        carries a ``keycloak_idp_alias`` (so Keycloak can route the broker login
        via ``kc_idp_hint``).  The returned URL points at the *browser-facing*
        Keycloak base (``keycloak_public_base_url`` → falls back to
        ``keycloak_base_url``), since the end user's browser follows it.
        """
        import urllib.parse

        result = await session.execute(
            select(SsoProvider).where(SsoProvider.id == provider_id)
        )
        provider = result.scalar_one_or_none()
        if provider is None or not provider.enabled:
            raise FoundationError(
                USER_NOT_FOUND, detail="SSO provider not found or disabled"
            )
        if not provider.keycloak_idp_alias:
            raise FoundationError(
                USER_NOT_FOUND,
                detail="SSO provider has no Keycloak IdP alias configured",
            )

        settings = get_settings()
        public_base = (
            settings.keycloak_public_base_url or str(settings.keycloak_base_url)
        ).rstrip("/")
        realm = settings.keycloak_realm

        query = urllib.parse.urlencode(
            {
                "client_id": settings.oidc_client_id,
                "response_type": "code",
                "scope": "openid",
                "redirect_uri": redirect_uri,
                "state": state,
                "kc_idp_hint": provider.keycloak_idp_alias,
            }
        )
        return (
            f"{public_base}/realms/{realm}"
            f"/protocol/openid-connect/auth?{query}"
        )

    # ── social providers ─────────────────────────────────────────────────── #

    async def list_social_providers(
        self,
        *,
        tenant_id: str,
    ) -> list[SocialProviderRead]:
        """Return all known social providers with their login URLs.

        Social providers are realm-global in Keycloak; we surface them as
        a static catalogue with tenant-specific login URLs.
        """
        settings = get_settings()
        base = str(settings.keycloak_base_url).rstrip("/")
        realm = settings.keycloak_realm

        providers: list[SocialProviderRead] = []
        for kind, alias in _SOCIAL_ALIASES.items():
            login_url = (
                f"{base}/realms/{realm}/broker/{alias}/login"
                f"?client_id={settings.keycloak_admin_client_id}"
            )
            providers.append(
                SocialProviderRead(
                    provider=kind,  # type: ignore[arg-type]
                    enabled=True,  # Assume all configured; production: query KC
                    login_url=login_url,
                )
            )
        return providers

    # ── SSO login URL ─────────────────────────────────────────────────────── #

    def get_login_url(
        self,
        *,
        provider_id_or_alias: str,
        redirect_uri: str | None = None,
    ) -> str:
        """Build the Keycloak SSO initiation URL for a given IDP alias."""
        settings = get_settings()
        base = str(settings.keycloak_base_url).rstrip("/")
        realm = settings.keycloak_realm
        url = f"{base}/realms/{realm}/broker/{provider_id_or_alias}/login"
        if redirect_uri:
            import urllib.parse

            url += f"?redirect_uri={urllib.parse.quote(redirect_uri)}"
        return url

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

from datetime import UTC, datetime
from typing import Any

import ulid
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_identity.adapters.audit_publisher import AuditPublisher
from foundation_identity.adapters.keycloak_admin import KeycloakAdminAdapter
from foundation_identity.config import get_settings
from foundation_identity.domain.models import SsoProvider
from foundation_identity.errors import (
    SSO_PROVIDER_ERROR,
    USER_NOT_FOUND,
    FoundationError,
)
from foundation_identity.observability import get_logger
from foundation_identity.schemas.sso import (
    CreateSsoProviderRequest,
    SocialProviderRead,
    SsoProviderRead,
)

log = get_logger(__name__)


def _new_id() -> str:
    return f"sso_{ulid.new()!s}"


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
        "trustEmail": False,
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
        return [SsoProviderRead.model_validate(r) for r in rows]

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

        return SsoProviderRead.model_validate(provider)

    # ── enable / disable ─────────────────────────────────────────────────── #

    async def set_provider_enabled(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        request_id: str,
        provider_id: str,
        enabled: bool,
    ) -> SsoProviderRead:
        """Enable or disable an SSO provider."""
        result = await session.execute(
            select(SsoProvider).where(
                SsoProvider.tenant_id == tenant_id,
                SsoProvider.id == provider_id,
            )
        )
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

        return SsoProviderRead.model_validate(provider)

    # ── delete ────────────────────────────────────────────────────────────── #

    async def delete_provider(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        request_id: str,
        provider_id: str,
    ) -> None:
        """Hard-delete an SSO provider from DB and Keycloak."""
        result = await session.execute(
            select(SsoProvider).where(
                SsoProvider.tenant_id == tenant_id,
                SsoProvider.id == provider_id,
            )
        )
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

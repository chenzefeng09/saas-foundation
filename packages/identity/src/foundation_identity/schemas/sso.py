"""SSO + Social provider schemas."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, model_validator

SsoKind = Literal[
    "OIDC", "SAML", "AD", "LDAP", "DINGTALK_ENTERPRISE", "FEISHU_ENTERPRISE", "WECOM"
]
SsoScope = Literal["TENANT", "PLATFORM"]
SsoMatchType = Literal["EMAIL_DOMAIN", "EQUALS", "CONTAINS", "REGEX"]
SocialKind = Literal[
    "GOOGLE",
    "GITHUB",
    "MICROSOFT",
    "WECHAT",
    "QQ",
    "DINGTALK_PERSONAL",
    "FEISHU_PERSONAL",
    "APPLE",
]


class SsoProviderRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    kind: SsoKind
    name: str
    enabled: bool
    config: dict[str, Any]
    created_at: datetime
    scope: SsoScope = "TENANT"
    tenant_id: str | None = None
    default_tenant_id: str | None = None


class CreateSsoProviderRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: SsoKind
    name: str
    config: dict[str, Any]


class CreatePlatformSsoProviderRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: SsoKind
    name: str
    config: dict[str, Any]
    scope: SsoScope = "PLATFORM"
    tenant_id: str | None = None
    default_tenant_id: str | None = None

    @model_validator(mode="after")
    def _check_tenant_scope(self) -> "CreatePlatformSsoProviderRequest":
        if self.scope == "TENANT" and not self.tenant_id:
            raise ValueError("tenant_id is required when scope=TENANT")
        return self


class SsoRoutingRuleRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    provider_id: str
    priority: int
    match_attribute: str
    match_type: SsoMatchType
    match_value: str
    target_tenant_id: str
    default_role: str | None = None
    enabled: bool
    created_at: datetime


class CreateSsoRoutingRuleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    priority: int = 100
    match_attribute: str
    match_type: SsoMatchType
    match_value: str
    target_tenant_id: str
    default_role: str | None = None
    enabled: bool = True

    @model_validator(mode="after")
    def _validate_regex(self) -> "CreateSsoRoutingRuleRequest":
        if self.match_type == "REGEX":
            try:
                re.compile(self.match_value)
            except re.error as exc:
                raise ValueError(f"Invalid regex in match_value: {exc}") from exc
        return self


class UpdateSsoRoutingRuleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    priority: int | None = None
    match_attribute: str | None = None
    match_type: SsoMatchType | None = None
    match_value: str | None = None
    target_tenant_id: str | None = None
    default_role: str | None = None
    enabled: bool | None = None

    @model_validator(mode="after")
    def _validate_regex(self) -> "UpdateSsoRoutingRuleRequest":
        if self.match_type == "REGEX" and self.match_value is not None:
            try:
                re.compile(self.match_value)
            except re.error as exc:
                raise ValueError(f"Invalid regex in match_value: {exc}") from exc
        return self


class SocialProviderRead(BaseModel):
    provider: SocialKind
    enabled: bool
    login_url: str | None = None


class SsoLoginOptionRead(BaseModel):
    """Minimal, PUBLIC-safe view of a platform SSO provider for the login page.

    Deliberately omits ``config`` (may carry secret refs) and tenant routing —
    callers are unauthenticated, so only the IdP id / display name / kind are
    surfaced.
    """

    id: str
    name: str
    kind: SsoKind


class SsoAuthorizeUrlRead(BaseModel):
    """Wraps the browser-facing Keycloak authorize URL."""

    authorize_url: str

"""SSO + Social provider schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

SsoKind = Literal[
    "OIDC", "SAML", "AD", "LDAP", "DINGTALK_ENTERPRISE", "FEISHU_ENTERPRISE", "WECOM"
]
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


class CreateSsoProviderRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: SsoKind
    name: str
    config: dict[str, Any]


class SocialProviderRead(BaseModel):
    provider: SocialKind
    enabled: bool
    login_url: str | None = None

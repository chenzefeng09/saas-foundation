"""Session schemas — align with contracts/openapi/identity.yaml."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, SecretStr, field_validator
from pydantic.types import StringConstraints

# Loose email pattern that allows special-use TLDs like .local (used in dev)
# while still requiring a basic user@host.tld structure.
_LOOSE_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class EmailPasswordCredential(BaseModel):
    model_config = ConfigDict(extra="forbid")

    method: Literal["EMAIL_PASSWORD"]
    email: str
    password: SecretStr
    device_id: str | None = None

    @field_validator("email")
    @classmethod
    def _validate_email(cls, v: str) -> str:
        """Accept any syntactically plausible email, including .local/.test TLDs.

        Pydantic's built-in EmailStr uses email-validator which rejects RFC-6761
        reserved TLDs (.local, .test, .example, …).  Since the foundation stack
        uses .local addresses in dev/test, we fall back to a permissive regex
        that still catches obvious typos (missing @, missing dot, whitespace).
        """
        if not _LOOSE_EMAIL_RE.match(v):
            raise ValueError(f"Invalid email address: {v!r}")
        return v.lower()


class OidcCredential(BaseModel):
    model_config = ConfigDict(extra="forbid")

    method: Literal["OIDC"]
    provider: Annotated[str, StringConstraints(min_length=1, max_length=100)]
    code: str
    redirect_uri: str


class SamlCredential(BaseModel):
    model_config = ConfigDict(extra="forbid")

    method: Literal["SAML"]
    provider: str
    saml_response: str


CreateSessionRequest = EmailPasswordCredential | OidcCredential | SamlCredential


class SessionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str = Field(pattern=r"^sess_[0-9A-Z]{26}$")
    user_id: str = Field(pattern=r"^usr_[0-9A-Z]{26}$")
    tenant_id: str = Field(pattern=r"^tnt_[0-9A-Z]{26}$")
    access_token: str
    refresh_token: str
    token_type: Literal["BEARER"] = "BEARER"
    expires_at: datetime
    issued_at: datetime
    scopes: list[str] = Field(default_factory=list)
    device_id: str | None = None


# --------------------------------------------------------------------------- #
# Service-account tokens (short-lived, scope-limited)
#
# Issued by the Identity service to *services* (not end users) that need to
# call other foundation services on behalf of a tenant — e.g. the
# agent-platform scheduler spawns an OpenHands container and must give that
# container a token to call back into foundation.audit / foundation.llm-gateway.
#
# Properties enforced by this contract:
#   * tenant_id mandatory — token is bound to a single tenant
#   * ttl_seconds capped at 86_400 (24h); shorter is encouraged
#   * scopes is a closed allowlist drawn from the foundation scope catalogue
#   * audience identifies the *consumer service* expected to verify the token
#
# Spawn time recommendation: TTL = min(sandbox_timeout, 1h).
# --------------------------------------------------------------------------- #


class ServiceAccountTokenRequest(BaseModel):
    """Request a short-lived service-account token bound to one tenant."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: Annotated[str, Field(pattern=r"^tnt_[0-9A-Z]{26}$")]
    subject: Annotated[
        str,
        StringConstraints(min_length=3, max_length=128, pattern=r"^[a-z0-9._:-]+$"),
    ]
    """Caller-chosen identifier of the *workload* the token represents.

    Examples: ``agent-scheduler:run_01J5XYZ…``, ``etl-worker:job-42``.  Goes
    into the JWT ``sub`` claim and audit logs so revocation / forensic
    queries can trace which container received the token.
    """
    scopes: Annotated[list[str], Field(min_length=1, max_length=32)]
    """Subset of foundation scopes the token may exercise.

    Identity validates each scope against the catalogue at
    ``docs/CONVENTIONS.md §4 — Scope Catalogue`` and rejects unknown ones.
    """
    audience: Annotated[
        str,
        StringConstraints(min_length=1, max_length=64, pattern=r"^[a-z0-9-]+$"),
    ] = "foundation"
    """Target service name; downstream services MUST verify ``aud`` matches."""

    ttl_seconds: Annotated[int, Field(ge=60, le=86_400)] = 3_600


class ServiceAccountTokenResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    access_token: str
    token_type: Literal["BEARER"] = "BEARER"
    expires_at: datetime
    issued_at: datetime
    tenant_id: str = Field(pattern=r"^tnt_[0-9A-Z]{26}$")
    subject: str
    scopes: list[str]
    audience: str
    jti: str = Field(
        pattern=r"^jti_[0-9A-Z]{26}$",
        description="Unique token id; pass to revoke endpoint to invalidate.",
    )


class MeResponse(BaseModel):
    """Resolves the caller's identity from the supplied bearer token.

    Business-layer BFFs call this on every page-load to re-hydrate the user
    profile from the foundation-issued OIDC access token, avoiding the trap
    of storing identity data client-side where it can be forged.
    """

    model_config = ConfigDict(from_attributes=True)

    user_id: str = Field(pattern=r"^usr_[0-9A-Z]{26}$")
    tenant_id: str = Field(pattern=r"^tnt_[0-9A-Z]{26}$")
    # Use str instead of EmailStr to allow dev .local addresses.
    email: str
    display_name: str
    roles: list[str] = Field(default_factory=list)
    mfa_enabled: bool = False
    locale: str = "zh-CN"

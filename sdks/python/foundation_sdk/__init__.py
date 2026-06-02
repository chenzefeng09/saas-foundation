"""Foundation SDK — Python client for SaaS Foundation services.

Usage:
    from foundation_sdk import FoundationClient

    client = FoundationClient.from_env()
    with client:
        # Identity
        user = client.identity.get_user("usr_123")

        # Crypto
        envelope = client.crypto.encrypt("my-secret", kek_label="default")

        # Billing
        quota = client.billing.check_quota(dimension="user_seats")
"""

from __future__ import annotations

from ._context import FoundationContext, current_context, tenant_context
from ._signing import (
    CookieSigner,
    CookieSignerSettings,
    SignatureExpiredError,
    SignatureInvalid,
)
from .client import FoundationClient, FoundationClientSettings

__version__ = "0.1.0"
__all__ = [
    "FoundationClient",
    "FoundationClientSettings",
    "FoundationContext",
    "current_context",
    "tenant_context",
    "CookieSigner",
    "CookieSignerSettings",
    "SignatureInvalid",
    "SignatureExpiredError",
]

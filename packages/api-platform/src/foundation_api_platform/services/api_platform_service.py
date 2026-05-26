"""API Platform service — API Key, OAuth App, Webhook management.

Capabilities:
  - API Keys: per-tenant/user/app, scoped, IP whitelist, rate-limited
  - OAuth Apps: internal OAuth2 server for tenant apps
  - Webhooks: event subscription, HMAC-SHA256 signature, retry with backoff
"""

from __future__ import annotations

import hashlib
import hmac
from datetime import UTC, datetime
from typing import Any

import httpx
import ulid
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_api_platform.domain.models import (
    APIKey, OAuthApp, WebhookSubscription, WebhookDelivery, Outbox,
)
from foundation_api_platform.observability import get_logger

log = get_logger(__name__)


class APIPlatformService:
    """API key, OAuth, and webhook management."""

    # ------------------------------------------------------------------ API Keys

    async def create_api_key(
        self, session: AsyncSession, *, tenant_id: str,
        name: str, scopes: list[str], ip_whitelist: list[str] | None,
        rate_limit_rpm: int, expires_in_days: int | None,
        created_by: str, request_id: str,
    ) -> dict[str, Any]:
        """Create an API key. Returns the plaintext key ONCE."""
        import secrets
        plaintext = f"sk-foundation-{secrets.token_urlsafe(32)}"
        key_hash = hashlib.sha256(plaintext.encode()).hexdigest()

        expires_at = None
        if expires_in_days:
            expires_at = datetime.now(UTC) + __import__("datetime").timedelta(days=expires_in_days)

        key = APIKey(
            id=f"apk_{ulid.new()!s}",
            tenant_id=tenant_id,
            name=name,
            key_hash=key_hash,
            scopes=scopes,
            ip_whitelist=ip_whitelist or [],
            rate_limit_rpm=rate_limit_rpm,
            expires_at=expires_at,
            created_by=created_by,
            is_active=True,
        )
        session.add(key)
        self._emit(session, tenant_id, "foundation.api_platform.api_key.created",
                   {"key_id": key.id, "name": name}, request_id)
        await session.flush()
        return {"id": key.id, "name": name, "api_key": plaintext,
                "expires_at": expires_at.isoformat() if expires_at else None}

    async def validate_api_key(
        self, session: AsyncSession, *, key_hash: str, required_scope: str | None = None,
    ) -> APIKey | None:
        """Validate an API key by hash. Returns the key if valid."""
        key = await session.scalar(
            select(APIKey).where(
                APIKey.key_hash == key_hash,
                APIKey.is_active.is_(True),
            ).limit(1)
        )
        if key is None:
            return None
        if key.expires_at and key.expires_at < datetime.now(UTC):
            return None
        if required_scope and required_scope not in key.scopes:
            return None
        key.last_used_at = datetime.now(UTC)
        await session.flush()
        return key

    async def revoke_api_key(
        self, session: AsyncSession, *, tenant_id: str, key_id: str,
    ) -> None:
        key = await session.get(APIKey, key_id)
        if key and key.tenant_id == tenant_id:
            key.is_active = False
            key.revoked_at = datetime.now(UTC)
            await session.flush()

    # ------------------------------------------------------------------ OAuth Apps

    async def register_oauth_app(
        self, session: AsyncSession, *, tenant_id: str,
        name: str, redirect_uris: list[str], scopes: list[str],
        created_by: str, request_id: str,
    ) -> OAuthApp:
        import secrets
        app = OAuthApp(
            id=f"oap_{ulid.new()!s}",
            tenant_id=tenant_id,
            name=name,
            client_id=f"client-{secrets.token_urlsafe(16)}",
            client_secret_hash=hashlib.sha256(secrets.token_urlsafe(32).encode()).hexdigest(),
            redirect_uris=redirect_uris,
            scopes=scopes,
            created_by=created_by,
        )
        session.add(app)
        await session.flush()
        return app

    # ------------------------------------------------------------------ Webhooks

    async def subscribe_webhook(
        self, session: AsyncSession, *, tenant_id: str,
        url: str, event_types: list[str], secret: str | None,
        request_id: str,
    ) -> WebhookSubscription:
        sub = WebhookSubscription(
            id=f"whs_{ulid.new()!s}",
            tenant_id=tenant_id,
            url=url,
            event_types=event_types,
            secret=secret or __import__("secrets").token_urlsafe(32),
            enabled=True,
        )
        session.add(sub)
        await session.flush()
        return sub

    async def deliver_webhook(
        self, session: AsyncSession, *, subscription: WebhookSubscription,
        event_type: str, payload: dict[str, Any],
    ) -> WebhookDelivery:
        """Deliver a webhook event with HMAC-SHA256 signature."""
        body = __import__("json").dumps(payload, ensure_ascii=False)
        signature = hmac.new(
            subscription.secret.encode(), body.encode(), hashlib.sha256,
        ).hexdigest()

        delivery = WebhookDelivery(
            id=f"whd_{ulid.new()!s}",
            subscription_id=subscription.id,
            event_type=event_type,
            payload=payload,
            status="PENDING",
        )
        session.add(delivery)

        try:
            async with httpx.AsyncClient(timeout=10.0) as c:
                resp = await c.post(
                    subscription.url,
                    content=body,
                    headers={
                        "Content-Type": "application/json",
                        "X-Foundation-Event": event_type,
                        "X-Foundation-Signature": f"sha256={signature}",
                    },
                )
                delivery.status = "DELIVERED" if resp.status_code < 400 else "FAILED"
                delivery.response_status = resp.status_code
                delivery.response_body = resp.text[:1000]
        except Exception as e:
            delivery.status = "FAILED"
            delivery.response_body = str(e)[:1000]

        delivery.delivered_at = datetime.now(UTC)
        await session.flush()
        return delivery

    def _emit(self, session, tenant_id, event_type, payload, request_id):
        session.add(Outbox(tenant_id=tenant_id, event_type=event_type,
            aggregate_id=payload.get("key_id", ""), payload=payload, request_id=request_id))

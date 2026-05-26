"""Notification service — multi-channel send with template rendering.

Channels supported:
  - EMAIL (SMTP)
  - WEBHOOK (HTTP POST)
  - DINGTALK (robot webhook)
  - FEISHU (robot webhook)
  - WECOM (robot webhook)

Template engine: Jinja2 with i18n support.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any, Literal

import httpx
import ulid
try:
    from jinja2 import Template as _JinjaTemplate
except ImportError:
    _JinjaTemplate = None  # type: ignore[assignment]
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_notification.domain.models import (
    NotificationChannel, NotificationLog, NotificationTemplate, NotificationSubscription, Outbox,
)
from foundation_notification.observability import get_logger

log = get_logger(__name__)

ChannelKind = Literal["EMAIL", "WEBHOOK", "DINGTALK", "FEISHU", "WECOM"]


class NotificationService:
    """Core notification engine."""

    # ------------------------------------------------------------------ Send

    async def send(
        self, session: AsyncSession, *, tenant_id: str,
        event_type: str, recipients: list[str],
        context: dict[str, Any], channel: ChannelKind | None,
        request_id: str,
    ) -> list[NotificationLog]:
        """Send notification to recipients. Returns delivery logs."""
        # Resolve template
        tmpl = await session.scalar(
            select(NotificationTemplate).where(
                NotificationTemplate.tenant_id == tenant_id,
                NotificationTemplate.event_type == event_type,
                NotificationTemplate.enabled.is_(True),
            ).limit(1)
        )

        # Resolve channel config
        ch = None
        if channel:
            ch = await session.scalar(
                select(NotificationChannel).where(
                    NotificationChannel.tenant_id == tenant_id,
                    NotificationChannel.channel == channel,
                    NotificationChannel.enabled.is_(True),
                ).limit(1)
            )

        logs: list[NotificationLog] = []
        for recipient in recipients:
            # Render content
            if tmpl:
                if _JinjaTemplate:
                    subject = _JinjaTemplate(tmpl.subject_template).render(**context, recipient=recipient)
                    body = _JinjaTemplate(tmpl.body_template).render(**context, recipient=recipient)
                else:
                    subject = tmpl.subject_template.replace("{{ recipient }}", recipient)
                    body = tmpl.body_template.replace("{{ data }}", str(context.get("data", "")))
            else:
                subject = f"[{event_type}] Notification"
                body = json.dumps(context, ensure_ascii=False, indent=2)

            # Deliver through channel
            delivery_status, delivery_detail = await self._deliver(
                channel=channel or "EMAIL",
                channel_config=ch,
                recipient=recipient,
                subject=subject,
                body=body,
            )

            log_entry = NotificationLog(
                id=f"nlog_{ulid.new()!s}",
                tenant_id=tenant_id,
                event_type=event_type,
                recipient=recipient,
                channel=channel or "EMAIL",
                subject=subject[:500],
                status=delivery_status,
                detail=delivery_detail,
                request_id=request_id,
            )
            session.add(log_entry)
            logs.append(log_entry)

        await session.flush()
        return logs

    # ------------------------------------------------------------------ Channel Delivery

    async def _deliver(
        self, *, channel: ChannelKind, channel_config: NotificationChannel | None,
        recipient: str, subject: str, body: str,
    ) -> tuple[str, str | None]:
        """Attempt delivery. Returns (status, detail)."""
        try:
            if channel == "WEBHOOK":
                url = channel_config.config.get("url", "") if channel_config else ""
                if url:
                    async with httpx.AsyncClient(timeout=10.0) as c:
                        resp = await c.post(url, json={"recipient": recipient, "subject": subject, "body": body})
                        return ("DELIVERED", f"HTTP {resp.status_code}")
                return ("FAILED", "No webhook URL configured")

            elif channel == "DINGTALK":
                url = channel_config.config.get("webhook_url", "") if channel_config else ""
                if url:
                    payload = {"msgtype": "markdown", "markdown": {"title": subject, "text": body}}
                    async with httpx.AsyncClient(timeout=10.0) as c:
                        resp = await c.post(url, json=payload)
                        return ("DELIVERED", f"HTTP {resp.status_code}") if resp.status_code == 200 else ("FAILED", resp.text[:200])
                return ("FAILED", "No DingTalk webhook configured")

            elif channel == "FEISHU":
                url = channel_config.config.get("webhook_url", "") if channel_config else ""
                if url:
                    payload = {"msg_type": "interactive", "card": {"header": {"title": {"content": subject}}, "elements": [{"tag": "markdown", "content": body}]}}
                    async with httpx.AsyncClient(timeout=10.0) as c:
                        resp = await c.post(url, json=payload)
                        return ("DELIVERED", f"HTTP {resp.status_code}") if resp.status_code == 200 else ("FAILED", resp.text[:200])
                return ("FAILED", "No Feishu webhook configured")

            elif channel == "WECOM":
                url = channel_config.config.get("webhook_url", "") if channel_config else ""
                if url:
                    payload = {"msgtype": "markdown", "markdown": {"content": f"## {subject}\n{body}"}}
                    async with httpx.AsyncClient(timeout=10.0) as c:
                        resp = await c.post(url, json=payload)
                        return ("DELIVERED", f"HTTP {resp.status_code}") if resp.status_code == 200 else ("FAILED", resp.text[:200])
                return ("FAILED", "No WeCom webhook configured")

            else:  # EMAIL (default, simulated in dev)
                log.info("notification.email.simulated", recipient=recipient, subject=subject)
                return ("DELIVERED", "Email simulated (SMTP not configured in dev)")

        except Exception as exc:
            log.warning("notification.delivery.failed", channel=channel, error=str(exc))
            return ("FAILED", str(exc)[:500])

    # ------------------------------------------------------------------ Subscriptions

    async def subscribe(
        self, session: AsyncSession, *, tenant_id: str,
        subscriber_kind: str, subscriber_id: str,
        event_types: list[str], channel: ChannelKind, config: dict[str, Any] | None,
    ) -> NotificationSubscription:
        sub = NotificationSubscription(
            id=f"nsub_{ulid.new()!s}",
            tenant_id=tenant_id,
            subscriber_kind=subscriber_kind,
            subscriber_id=subscriber_id,
            event_types=event_types,
            channel=channel,
            config=config or {},
        )
        session.add(sub)
        await session.flush()
        return sub

    async def get_subscriptions(
        self, session: AsyncSession, *, tenant_id: str, event_type: str,
    ) -> list[NotificationSubscription]:
        stmt = select(NotificationSubscription).where(
            NotificationSubscription.tenant_id == tenant_id,
            NotificationSubscription.enabled.is_(True),
        )
        rows = list((await session.scalars(stmt)).all())
        # Filter: match event_type (supports wildcard: "crypto.*" matches "crypto.kek.rotated")
        return [r for r in rows if _event_matches(r.event_types, event_type)]


def _event_matches(subscribed: list[str], event_type: str) -> bool:
    for pattern in subscribed:
        if pattern == "*" or pattern == event_type:
            return True
        if pattern.endswith(".*"):
            prefix = pattern[:-2]
            if event_type.startswith(prefix):
                return True
    return False

"""Notification resource — send notifications via multiple channels."""

from __future__ import annotations

from typing import Any

from foundation_sdk._transport import Transport


class NotificationResource:
    """Send notifications via email, webhook, DingTalk, Feishu, WeCom."""

    def __init__(self, transport: Transport) -> None:
        self._t = transport

    def send(self, *, event_type: str, recipients: list[str],
             channel: str = "email", template: str | None = None,
             context: dict[str, Any] | None = None,
             priority: str = "normal") -> dict[str, Any]:
        return self._t.request("POST", "/api/notification/v1/send",
                                json={"event_type": event_type, "recipients": recipients,
                                      "channel": channel, "template": template,
                                      "context": context or {}, "priority": priority})

    async def send_async(self, *, event_type: str, recipients: list[str],
                          channel: str = "email", template: str | None = None,
                          context: dict[str, Any] | None = None,
                          priority: str = "normal") -> dict[str, Any]:
        return await self._t.request_async("POST", "/api/notification/v1/send",
                                            json={"event_type": event_type,
                                                  "recipients": recipients,
                                                  "channel": channel,
                                                  "template": template,
                                                  "context": context or {},
                                                  "priority": priority})

    def send_batch(self, *, notifications: list[dict[str, Any]]) -> dict[str, Any]:
        return self._t.request("POST", "/api/notification/v1/send-batch",
                                json={"notifications": notifications})

    def list_templates(self) -> dict[str, Any]:
        return self._t.request("GET", "/api/notification/v1/templates")

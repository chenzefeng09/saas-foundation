"""Notification API endpoints — send, batch, templates."""
from __future__ import annotations
from typing import Any
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from foundation_notification.api.dependencies import (
    current_context, current_request_id, db_session, notification_service,
)
from foundation_notification.domain.base import FoundationContext
from foundation_notification.services.notification_service import NotificationService

router = APIRouter()


class SendRequest(BaseModel):
    event_type: str
    recipients: list[str]
    channel: str = "email"
    template: str | None = None
    context: dict[str, Any] = {}
    priority: str = "normal"


class SendBatchRequest(BaseModel):
    notifications: list[dict[str, Any]]


@router.post("/send", tags=["notification"])
async def send(
    body: SendRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: NotificationService = Depends(notification_service),
    request_id: str = Depends(current_request_id),
) -> dict[str, Any]:
    logs = await svc.send(
        session, tenant_id=ctx.tenant_id,
        event_type=body.event_type, recipients=body.recipients,
        context=body.context, channel=body.channel.upper(),  # type: ignore[arg-type]
        request_id=request_id,
    )
    return {
        "queued": len(logs),
        "logs": [{"id": lg.id, "recipient": lg.recipient, "status": lg.status, "channel": lg.channel} for lg in logs],
    }


@router.post("/send-batch", tags=["notification"])
async def send_batch(
    body: SendBatchRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: NotificationService = Depends(notification_service),
    request_id: str = Depends(current_request_id),
) -> dict[str, Any]:
    total_logs = []
    for notif in body.notifications:
        logs = await svc.send(
            session, tenant_id=ctx.tenant_id,
            event_type=notif.get("event_type", ""),
            recipients=notif.get("recipients", []),
            context=notif.get("context", {}),
            channel=(notif.get("channel", "EMAIL")).upper(),  # type: ignore[arg-type]
            request_id=request_id,
        )
        total_logs.extend(logs)
    return {"queued": len(total_logs)}


@router.get("/templates", tags=["notification"])
async def list_templates(
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
) -> dict[str, Any]:
    from sqlalchemy import select
    from foundation_notification.domain.models import NotificationTemplate
    rows = list((await session.scalars(
        select(NotificationTemplate).where(
            NotificationTemplate.tenant_id == ctx.tenant_id,
            NotificationTemplate.enabled.is_(True),
        )
    )).all())
    return {"items": [
        {"id": r.id, "event_type": r.event_type, "locale": r.locale,
         "subject_template": r.subject_template, "enabled": r.enabled}
        for r in rows
    ]}

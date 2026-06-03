"""Billing API endpoints — plans, subscriptions, quota, invoices."""
from __future__ import annotations
from typing import Any
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from foundation_billing.api.dependencies import (
    billing_service, current_context, current_request_id, db_session,
)
from foundation_billing.domain.base import FoundationContext
from foundation_billing.services.billing_service import BillingService

router = APIRouter()


# ---------- Plans ----------

class CreatePlanRequest(BaseModel):
    name: str
    tier: str
    quotas: dict[str, int]
    price_monthly_usd: float


@router.get("/plans", tags=["billing"])
async def list_plans(
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
) -> dict[str, Any]:
    from sqlalchemy import select
    from foundation_billing.domain.models import SubscriptionPlan
    rows = list((await session.scalars(select(SubscriptionPlan).where(SubscriptionPlan.active.is_(True)))).all())
    return {"items": [{"id": r.id, "name": r.name, "tier": r.tier, "quotas": r.quotas, "price_monthly_usd": r.price_monthly_usd} for r in rows]}


@router.post("/plans", status_code=201, tags=["billing"])
async def create_plan(
    body: CreatePlanRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: BillingService = Depends(billing_service),
    request_id: str = Depends(current_request_id),
) -> dict[str, Any]:
    plan = await svc.create_plan(
        session, name=body.name, tier=body.tier,
        quotas=body.quotas, price_monthly_usd=body.price_monthly_usd,
        request_id=request_id,
    )
    return {"id": plan.id, "name": plan.name, "tier": plan.tier, "quotas": plan.quotas, "price_monthly_usd": plan.price_monthly_usd}


# ---------- Subscriptions ----------

class SubscribeRequest(BaseModel):
    plan_id: str
    mode: str = "private"


@router.post("/subscriptions", status_code=201, tags=["billing"])
async def subscribe(
    body: SubscribeRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: BillingService = Depends(billing_service),
    request_id: str = Depends(current_request_id),
) -> dict[str, Any]:
    sub = await svc.subscribe_tenant(
        session, tenant_id=ctx.tenant_id,
        plan_id=body.plan_id, mode=body.mode,
        request_id=request_id,
    )
    return {"id": sub.id, "tenant_id": sub.tenant_id, "plan_id": sub.plan_id, "mode": sub.mode, "status": sub.status}


@router.get("/subscriptions/current", tags=["billing"])
async def get_subscription(
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
) -> dict[str, Any]:
    from sqlalchemy import select
    from foundation_billing.domain.models import TenantSubscription
    sub = await session.scalar(
        select(TenantSubscription).where(
            TenantSubscription.tenant_id == ctx.tenant_id,
            TenantSubscription.status == "ACTIVE",
        ).limit(1)
    )
    if sub is None:
        return {"status": "NO_SUBSCRIPTION", "tenant_id": ctx.tenant_id}
    return {"id": sub.id, "tenant_id": sub.tenant_id, "plan_id": sub.plan_id, "mode": sub.mode, "status": sub.status}


# ---------- Quota ----------

class QuotaCheckRequest(BaseModel):
    dimension: str
    requested: int = 1


class RecordUsageRequest(BaseModel):
    dimension: str
    amount: float
    description: str = ""


@router.post("/quota/check", tags=["billing"])
async def check_quota(
    body: QuotaCheckRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: BillingService = Depends(billing_service),
) -> dict[str, Any]:
    return await svc.check_quota(
        session, tenant_id=ctx.tenant_id,
        dimension=body.dimension, requested=body.requested,  # type: ignore[arg-type]
    )


@router.post("/quota/usage", tags=["billing"])
async def record_usage(
    body: RecordUsageRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: BillingService = Depends(billing_service),
    request_id: str = Depends(current_request_id),
) -> dict[str, Any]:
    usage = await svc.record_usage(
        session, tenant_id=ctx.tenant_id,
        dimension=body.dimension, amount=body.amount,  # type: ignore[arg-type]
        request_id=request_id,
    )
    return {"id": usage.id, "dimension": usage.dimension, "current_value": usage.current_value}


# ---------- Invoices ----------

class GenerateInvoiceRequest(BaseModel):
    items: list[dict[str, Any]]
    due_days: int = 30


@router.post("/invoices", status_code=201, tags=["billing"])
async def generate_invoice(
    body: GenerateInvoiceRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: BillingService = Depends(billing_service),
    request_id: str = Depends(current_request_id),
) -> dict[str, Any]:
    inv = await svc.generate_invoice(
        session, tenant_id=ctx.tenant_id,
        items=body.items, due_days=body.due_days,
        request_id=request_id,
    )
    return {"id": inv.id, "invoice_number": inv.invoice_number, "total_amount": inv.total_amount, "currency": inv.currency, "status": inv.status}


@router.get("/invoices", tags=["billing"])
async def list_invoices(
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
) -> dict[str, Any]:
    from sqlalchemy import select
    from foundation_billing.domain.models import Invoice
    rows = list((await session.scalars(select(Invoice).where(Invoice.tenant_id == ctx.tenant_id).order_by(Invoice.created_at.desc()))).all())
    return {"items": [{"id": r.id, "invoice_number": r.invoice_number, "total_amount": r.total_amount, "status": r.status} for r in rows]}

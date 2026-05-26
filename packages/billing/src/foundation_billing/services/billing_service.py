"""Billing service — dual-mode: private deployment (quota + invoice) + SaaS (Stripe subscriptions).

Capabilities:
  - Quota management: user seats, storage, agent sessions, LLM tokens, API calls
  - Usage tracking: per-tenant, per-dimension metering
  - Quota enforcement: soft/hard limits with circuit-breaker
  - Invoice generation: PDF/Excel for private deployment
  - Subscription management: tier changes, proration (SaaS mode)
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

import ulid
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_billing.domain.models import (
    SubscriptionPlan, TenantSubscription, QuotaUsage, Invoice, Outbox,
)
from foundation_billing.observability import get_logger

log = get_logger(__name__)

QuotaDimension = Literal["user_seats", "storage_gb", "agent_sessions", "llm_tokens", "api_calls"]


class BillingService:
    """Dual-mode billing (private deployment + SaaS)."""

    # ------------------------------------------------------------------ Plans

    async def create_plan(
        self, session: AsyncSession, *, name: str, tier: str,
        quotas: dict[str, int], price_monthly_usd: float,
        request_id: str,
    ) -> SubscriptionPlan:
        plan = SubscriptionPlan(
            id=f"pln_{ulid.new()!s}",
            name=name,
            tier=tier,
            quotas=quotas,
            price_monthly_usd=price_monthly_usd,
            active=True,
        )
        session.add(plan)
        await session.flush()
        return plan

    # ------------------------------------------------------------------ Subscriptions

    async def subscribe_tenant(
        self, session: AsyncSession, *, tenant_id: str,
        plan_id: str, mode: str, request_id: str,
    ) -> TenantSubscription:
        plan = await session.get(SubscriptionPlan, plan_id)
        if plan is None:
            raise ValueError(f"Plan {plan_id} not found")

        sub = TenantSubscription(
            id=f"sub_{ulid.new()!s}",
            tenant_id=tenant_id,
            plan_id=plan_id,
            mode=mode,
            status="ACTIVE",
            current_period_start=datetime.now(UTC),
            current_period_end=datetime.now(UTC).replace(day=1),
        )
        session.add(sub)
        await session.flush()
        return sub

    # ------------------------------------------------------------------ Quota

    async def check_quota(
        self, session: AsyncSession, *, tenant_id: str,
        dimension: QuotaDimension, requested: int = 1,
    ) -> dict[str, Any]:
        """Check if tenant has remaining quota. Returns {allowed, remaining, limit}."""
        sub = await session.scalar(
            select(TenantSubscription).where(
                TenantSubscription.tenant_id == tenant_id,
                TenantSubscription.status == "ACTIVE",
            ).limit(1)
        )
        if sub is None:
            # No subscription → free tier defaults
            free_tier: dict[str, int] = {
                "user_seats": 5, "storage_gb": 1,
                "agent_sessions": 10, "llm_tokens": 1_000_000, "api_calls": 1000,
            }
            limit = free_tier.get(dimension, 100)
        else:
            plan = await session.get(SubscriptionPlan, sub.plan_id)
            limit = (plan.quotas or {}).get(dimension, 100) if plan else 100

        # Count current usage
        usage = await session.scalar(
            select(QuotaUsage).where(
                QuotaUsage.tenant_id == tenant_id,
                QuotaUsage.dimension == dimension,
            ).limit(1)
        )
        current = usage.current_value if usage else 0

        allowed = (current + requested) <= limit
        return {
            "allowed": allowed,
            "current": current,
            "limit": limit,
            "remaining": max(0, limit - current),
            "dimension": dimension,
        }

    async def record_usage(
        self, session: AsyncSession, *, tenant_id: str,
        dimension: QuotaDimension, amount: float,
        request_id: str,
    ) -> QuotaUsage:
        usage = await session.scalar(
            select(QuotaUsage).where(
                QuotaUsage.tenant_id == tenant_id,
                QuotaUsage.dimension == dimension,
            ).limit(1)
        )
        if usage:
            usage.current_value += amount
            usage.last_updated = datetime.now(UTC)
        else:
            usage = QuotaUsage(
                id=f"qus_{ulid.new()!s}",
                tenant_id=tenant_id,
                dimension=dimension,
                current_value=amount,
            )
            session.add(usage)
        await session.flush()
        return usage

    # ------------------------------------------------------------------ Invoices

    async def generate_invoice(
        self, session: AsyncSession, *, tenant_id: str,
        items: list[dict[str, Any]], due_days: int = 30,
        request_id: str,
    ) -> Invoice:
        total = sum(item.get("amount", 0) for item in items)
        invoice = Invoice(
            id=f"inv_{ulid.new()!s}",
            tenant_id=tenant_id,
            invoice_number=f"INV-{datetime.now(UTC).strftime('%Y%m')}-{ulid.new()!s}",
            items=items,
            total_amount=total,
            currency="CNY",
            status="DRAFT",
            due_date=datetime.now(UTC).replace(hour=0) + __import__("datetime").timedelta(days=due_days),
        )
        session.add(invoice)
        self._emit(session, tenant_id, "foundation.billing.invoice.generated",
                   {"invoice_id": invoice.id, "total": total}, request_id)
        await session.flush()
        return invoice

    def _emit(self, session, tenant_id, event_type, payload, request_id):
        session.add(Outbox(tenant_id=tenant_id, event_type=event_type,
            aggregate_id=payload.get("invoice_id", ""), payload=payload, request_id=request_id))

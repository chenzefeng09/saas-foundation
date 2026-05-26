"""Tests for Billing service — plans, subscriptions, quota, invoices."""

import pytest

from foundation_billing.services.billing_service import BillingService
from foundation_billing.domain.models import SubscriptionPlan, TenantSubscription, QuotaUsage, Invoice


class TestPlans:
    @pytest.fixture
    def svc(self):
        return BillingService()

    async def test_create_plan(self, svc, fake_session, request_id):
        plan = await svc.create_plan(
            fake_session, name="Pro Plan", tier="pro",
            quotas={"user_seats": 50, "storage_gb": 100, "llm_tokens": 10_000_000},
            price_monthly_usd=99.0,
            request_id=request_id,
        )
        assert isinstance(plan, SubscriptionPlan)
        assert plan.id.startswith("pln_")
        assert plan.name == "Pro Plan"
        assert plan.tier == "pro"
        assert plan.quotas["user_seats"] == 50
        assert plan.price_monthly_usd == 99.0
        assert plan.active is True

    async def test_create_plan_free_tier(self, svc, fake_session, request_id):
        plan = await svc.create_plan(
            fake_session, name="Free", tier="free",
            quotas={"user_seats": 5, "storage_gb": 1},
            price_monthly_usd=0.0,
            request_id=request_id,
        )
        assert plan.price_monthly_usd == 0.0
        assert plan.quotas["user_seats"] == 5


class TestSubscriptions:
    @pytest.fixture
    def svc(self):
        return BillingService()

    async def test_subscribe_tenant(self, svc, fake_session, tenant_id, request_id):
        # Create plan first
        plan = SubscriptionPlan(
            id="pln_pro", name="Pro", tier="pro",
            quotas={"user_seats": 50}, price_monthly_usd=99.0, active=True,
        )
        fake_session.put(plan)

        sub = await svc.subscribe_tenant(
            fake_session, tenant_id=tenant_id, plan_id="pln_pro",
            mode="private", request_id=request_id,
        )
        assert isinstance(sub, TenantSubscription)
        assert sub.id.startswith("sub_")
        assert sub.tenant_id == tenant_id
        assert sub.plan_id == "pln_pro"
        assert sub.mode == "private"
        assert sub.status == "ACTIVE"
        assert sub.current_period_start is not None

    async def test_subscribe_tenant_invalid_plan(self, svc, fake_session, tenant_id, request_id):
        with pytest.raises(ValueError, match="Plan nonexistent not found"):
            await svc.subscribe_tenant(
                fake_session, tenant_id=tenant_id, plan_id="nonexistent",
                mode="private", request_id=request_id,
            )


class TestQuota:
    @pytest.fixture
    def svc(self):
        return BillingService()

    async def test_check_quota_free_tier(self, svc, fake_session, tenant_id, request_id):
        """No subscription → free tier defaults apply."""
        fake_session.queue_scalar(None)  # No subscription
        fake_session.queue_scalar(None)  # No existing usage

        result = await svc.check_quota(
            fake_session, tenant_id=tenant_id, dimension="user_seats",
        )
        assert result["allowed"] is True
        assert result["limit"] == 5  # Free tier default
        assert result["current"] == 0
        assert result["remaining"] == 5

    async def test_check_quota_free_tier_llm_tokens(self, svc, fake_session, tenant_id, request_id):
        fake_session.queue_scalar(None)  # No subscription
        fake_session.queue_scalar(None)  # No usage

        result = await svc.check_quota(
            fake_session, tenant_id=tenant_id, dimension="llm_tokens",
        )
        assert result["limit"] == 1_000_000

    async def test_check_quota_exceeded(self, svc, fake_session, tenant_id, request_id):
        """When current usage is at limit, should deny."""
        usage = QuotaUsage(
            id="qus_1", tenant_id=tenant_id,
            dimension="user_seats", current_value=5,
        )
        fake_session.queue_scalar(None)  # No subscription → free tier (limit 5)
        fake_session.queue_scalar(usage)  # Current usage = 5

        result = await svc.check_quota(
            fake_session, tenant_id=tenant_id, dimension="user_seats", requested=1,
        )
        assert result["allowed"] is False
        assert result["remaining"] == 0

    async def test_check_quota_with_subscription(self, svc, fake_session, tenant_id, request_id):
        plan = SubscriptionPlan(
            id="pln_ent", name="Enterprise", tier="enterprise",
            quotas={"user_seats": 500}, price_monthly_usd=999.0, active=True,
        )
        sub = TenantSubscription(
            id="sub_1", tenant_id=tenant_id, plan_id="pln_ent",
            mode="saas", status="ACTIVE",
            current_period_start=None, current_period_end=None,
        )
        fake_session.queue_scalar(sub)   # Active subscription
        fake_session.put(plan)           # Plan accessible via get()
        fake_session.queue_scalar(None)  # No existing usage

        result = await svc.check_quota(
            fake_session, tenant_id=tenant_id, dimension="user_seats",
        )
        assert result["limit"] == 500
        assert result["allowed"] is True

    async def test_record_usage_new(self, svc, fake_session, tenant_id, request_id):
        fake_session.queue_scalar(None)  # No existing usage

        usage = await svc.record_usage(
            fake_session, tenant_id=tenant_id,
            dimension="llm_tokens", amount=50000, request_id=request_id,
        )
        assert isinstance(usage, QuotaUsage)
        assert usage.dimension == "llm_tokens"
        assert usage.current_value == 50000

    async def test_record_usage_accumulate(self, svc, fake_session, tenant_id, request_id):
        existing = QuotaUsage(
            id="qus_existing", tenant_id=tenant_id,
            dimension="llm_tokens", current_value=100000,
        )
        fake_session.queue_scalar(existing)

        usage = await svc.record_usage(
            fake_session, tenant_id=tenant_id,
            dimension="llm_tokens", amount=25000, request_id=request_id,
        )
        assert usage.current_value == 125000  # Accumulated


class TestInvoices:
    @pytest.fixture
    def svc(self):
        return BillingService()

    async def test_generate_invoice(self, svc, fake_session, tenant_id, request_id):
        items = [
            {"description": "User seats (50)", "amount": 500.00},
            {"description": "LLM tokens (1M)", "amount": 150.00},
        ]
        invoice = await svc.generate_invoice(
            fake_session, tenant_id=tenant_id,
            items=items, due_days=30, request_id=request_id,
        )
        assert isinstance(invoice, Invoice)
        assert invoice.id.startswith("inv_")
        assert invoice.invoice_number.startswith("INV-")
        assert invoice.total_amount == 650.00
        assert invoice.currency == "CNY"
        assert invoice.status == "DRAFT"
        assert invoice.due_date is not None

    async def test_generate_invoice_zero_amount(self, svc, fake_session, tenant_id, request_id):
        invoice = await svc.generate_invoice(
            fake_session, tenant_id=tenant_id,
            items=[], due_days=30, request_id=request_id,
        )
        assert invoice.total_amount == 0.0

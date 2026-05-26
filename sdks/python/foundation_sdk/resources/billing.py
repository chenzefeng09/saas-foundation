"""Billing resource — plans, subscriptions, quota checks, invoices."""

from __future__ import annotations

from typing import Any

from foundation_sdk._transport import Transport


class BillingResource:
    """Dual-mode billing (private deployment + SaaS)."""

    def __init__(self, transport: Transport) -> None:
        self._t = transport

    # --- Plans ---

    def list_plans(self) -> dict[str, Any]:
        return self._t.request("GET", "/api/billing/v1/plans")

    def create_plan(self, *, name: str, tier: str, quotas: dict[str, int],
                     price_monthly_usd: float) -> dict[str, Any]:
        return self._t.request("POST", "/api/billing/v1/plans",
                                json={"name": name, "tier": tier, "quotas": quotas,
                                      "price_monthly_usd": price_monthly_usd})

    # --- Subscriptions ---

    def subscribe(self, *, plan_id: str, mode: str = "private") -> dict[str, Any]:
        return self._t.request("POST", "/api/billing/v1/subscriptions",
                                json={"plan_id": plan_id, "mode": mode})

    def get_subscription(self) -> dict[str, Any]:
        return self._t.request("GET", "/api/billing/v1/subscriptions/current")

    # --- Quota ---

    def check_quota(self, *, dimension: str, requested: int = 1) -> dict[str, Any]:
        return self._t.request("POST", "/api/billing/v1/quota/check",
                                json={"dimension": dimension, "requested": requested})

    async def check_quota_async(self, *, dimension: str, requested: int = 1) -> dict[str, Any]:
        return await self._t.request_async("POST", "/api/billing/v1/quota/check",
                                            json={"dimension": dimension, "requested": requested})

    def record_usage(self, *, dimension: str, amount: float, description: str = "") -> dict[str, Any]:
        return self._t.request("POST", "/api/billing/v1/quota/usage",
                                json={"dimension": dimension, "amount": amount,
                                      "description": description})

    # --- Invoices ---

    def generate_invoice(self, *, items: list[dict[str, Any]],
                          due_days: int = 30) -> dict[str, Any]:
        return self._t.request("POST", "/api/billing/v1/invoices",
                                json={"items": items, "due_days": due_days})

    def list_invoices(self) -> dict[str, Any]:
        return self._t.request("GET", "/api/billing/v1/invoices")

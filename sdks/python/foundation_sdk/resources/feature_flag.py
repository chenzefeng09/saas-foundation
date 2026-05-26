"""Feature Flag resource — Unleash-compatible feature flag evaluation."""

from __future__ import annotations

from typing import Any

from foundation_sdk._transport import Transport


class FeatureFlagResource:
    """Evaluate feature flags with tenant/user context."""

    def __init__(self, transport: Transport) -> None:
        self._t = transport

    def is_enabled(self, flag: str) -> dict[str, Any]:
        return self._t.request("POST", "/api/feature-flag/v1/evaluate",
                                json={"flag": flag})

    async def is_enabled_async(self, flag: str) -> dict[str, Any]:
        return await self._t.request_async("POST", "/api/feature-flag/v1/evaluate",
                                            json={"flag": flag})

    def evaluate_batch(self, flags: list[str]) -> dict[str, Any]:
        return self._t.request("POST", "/api/feature-flag/v1/evaluate-batch",
                                json={"flags": flags})

    def list_flags(self) -> dict[str, Any]:
        return self._t.request("GET", "/api/feature-flag/v1/flags")

    def set_flag(self, *, flag: str, enabled: bool,
                  rollout_percentage: int = 100,
                  tenant_whitelist: list[str] | None = None) -> dict[str, Any]:
        return self._t.request("PUT", f"/api/feature-flag/v1/flags/{flag}",
                                json={"enabled": enabled,
                                      "rollout_percentage": rollout_percentage,
                                      "tenant_whitelist": tenant_whitelist or []})

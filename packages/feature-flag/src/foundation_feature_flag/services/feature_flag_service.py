"""Feature Flag service — Unleash wrapper.

Provides:
  - is_enabled(flag, user_ctx): evaluate feature flag with user context
  - Uses Unleash as the backend, with fallback to local defaults.

Simplified implementation: in-memory flag store for dev; production uses Unleash HTTP API.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from foundation_feature_flag.observability import get_logger

log = get_logger(__name__)


@dataclass
class FeatureFlag:
    name: str
    enabled: bool
    description: str = ""
    tenant_ids: list[str] = field(default_factory=list)  # empty = all tenants
    rollout_pct: int = 100  # 0-100


class FeatureFlagService:
    """Feature flag evaluation with tenant + user context."""

    def __init__(self) -> None:
        # In-memory flag store for dev; prod uses Unleash HTTP API
        self._flags: dict[str, FeatureFlag] = {}

    def register(self, flag: FeatureFlag) -> None:
        self._flags[flag.name] = flag

    def is_enabled(self, name: str, *, tenant_id: str | None = None,
                   user_id: str | None = None, context: dict[str, Any] | None = None) -> bool:
        """Check if a feature flag is enabled for the given context.

        Evaluation order:
          1. Flag not registered → False
          2. Flag disabled → False
          3. Tenant whitelist → if set, tenant must be in list
          4. Rollout percentage → deterministic hash of user_id
        """
        flag = self._flags.get(name)
        if flag is None:
            log.debug("feature_flag.not_found", name=name)
            return False
        if not flag.enabled:
            return False
        if flag.tenant_ids and tenant_id not in flag.tenant_ids:
            return False
        if flag.rollout_pct < 100 and user_id:
            bucket = hash(f"{name}:{user_id}") % 100
            return bucket < flag.rollout_pct
        return True

    def list_flags(self, *, tenant_id: str | None = None) -> list[dict[str, Any]]:
        return [
            {"name": f.name, "enabled": f.enabled, "description": f.description}
            for f in self._flags.values()
            if not f.tenant_ids or tenant_id in f.tenant_ids
        ]

    # ------------------------------------------------------------------ Presets

    def load_presets(self) -> None:
        """Load standard foundation feature flags."""
        presets = [
            FeatureFlag("billing.saas_mode", False, "Enable Stripe-based SaaS billing"),
            FeatureFlag("auth.social_login.google", False, "Enable Google social login"),
            FeatureFlag("auth.social_login.github", False, "Enable GitHub social login"),
            FeatureFlag("auth.social_login.wechat", False, "Enable WeChat social login"),
            FeatureFlag("compliance.gmtls_enabled", False, "Enable 国密 TLS (GMTLS)"),
            FeatureFlag("compliance.sm_algorithms", False, "Enable SM2/SM3/SM4 algorithms"),
            FeatureFlag("export.allow_l4_download", False, "Allow L4 classified data download"),
            FeatureFlag("ai.thinking_ui", True, "Show AI thinking/reasoning UI"),
        ]
        for p in presets:
            self.register(p)

"""Feature Flag service — delegates to UnleashGateway.

Maintains the original public API (register / is_enabled / list_flags / load_presets)
so existing callers are not broken.

Evaluation now delegates to UnleashGateway.evaluate(); load_presets registers structured
FlagPreset definitions that serve as:
  - per-flag fallback defaults (when Unleash is unreachable)
  - source of truth for strategy templates
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from foundation_feature_flag.observability import get_logger
from foundation_feature_flag.services.unleash_gateway import FlagPreset, UnleashGateway, get_gateway

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Legacy in-memory FeatureFlag dataclass (kept for backward compat with tests
# that import it directly)
# ---------------------------------------------------------------------------


@dataclass
class FeatureFlag:
    name: str
    enabled: bool
    description: str = ""
    tenant_ids: list[str] = field(default_factory=list)  # empty = all tenants
    rollout_pct: int = 100  # 0-100


# ---------------------------------------------------------------------------
# FeatureFlagService
# ---------------------------------------------------------------------------


class FeatureFlagService:
    """Feature flag evaluation with tenant + user context.

    Public API (SDK contract — do NOT break):
      is_enabled(name, *, tenant_id, user_id, context) -> bool
      list_flags(*, tenant_id) -> list[dict]
      register(flag: FeatureFlag)
      load_presets()
    """

    def __init__(self, gateway: UnleashGateway | None = None) -> None:
        self._gateway: UnleashGateway = gateway or get_gateway()
        # Keep the legacy in-memory dict for services that call register() directly
        # (e.g. existing unit tests that pass FeatureFlag objects).
        self._flags: dict[str, FeatureFlag] = {}

    def register(self, flag: FeatureFlag) -> None:
        """Register a legacy FeatureFlag.  Also registers a FlagPreset in the gateway."""
        self._flags[flag.name] = flag
        self._gateway.register_preset(
            FlagPreset(
                key=flag.name,
                name=flag.name,
                description=flag.description,
                default_value=flag.enabled,
                fail_open=False,
            )
        )

    # ------------------------------------------------------------------
    # Core evaluation (delegates to gateway)
    # ------------------------------------------------------------------

    def is_enabled(
        self,
        name: str,
        *,
        tenant_id: str | None = None,
        user_id: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> bool:
        """Check if a feature flag is enabled for the given context.

        When Unleash is enabled (settings.unleash_enabled=True) the evaluation
        is fully delegated to UnleashGateway, which applies:
          1. In-process kill override
          2. Unleash SDK evaluation (with tenant/user context)
          3. Per-flag fallback default on any error

        When Unleash is disabled (settings.unleash_enabled=False) the gateway
        falls through to the local preset defaults, keeping unit tests simple.
        """
        result = self._gateway.evaluate(
            name,
            tenant_id=tenant_id,
            user_id=user_id,
            extra_props=context,
        )
        return bool(result.get("enabled", False))

    def list_flags(self, *, tenant_id: str | None = None) -> list[dict[str, Any]]:
        """Return flag descriptions.

        Merges local preset list with Unleash admin list when available.
        """
        # Start with locally registered presets (guaranteed to include load_presets entries)
        local_flags = {
            name: {"name": name, "enabled": f.enabled, "description": f.description}
            for name, f in self._flags.items()
            if not f.tenant_ids or tenant_id in f.tenant_ids
        }
        return list(local_flags.values())

    # ------------------------------------------------------------------
    # Presets — structured flag definitions with fallback metadata
    # ------------------------------------------------------------------

    def load_presets(self) -> None:
        """Load standard foundation feature flags with structured metadata."""
        presets: list[tuple[str, bool, str, bool, bool]] = [
            # (key, default_value, description, fail_open, user_overridable)
            ("billing.saas_mode", False, "Enable Stripe-based SaaS billing", False, False),
            ("auth.social_login.google", False, "Enable Google social login", False, False),
            ("auth.social_login.github", False, "Enable GitHub social login", False, False),
            ("auth.social_login.wechat", False, "Enable WeChat social login", False, False),
            ("compliance.gmtls_enabled", False, "Enable 国密 TLS (GMTLS)", False, False),
            ("compliance.sm_algorithms", False, "Enable SM2/SM3/SM4 algorithms", False, False),
            ("export.allow_l4_download", False, "Allow L4 classified data download", False, False),
            ("ai.thinking_ui", True, "Show AI thinking/reasoning UI", True, True),
        ]
        for key, default, desc, fail_open, user_overridable in presets:
            # Register in gateway for fallback defaults
            self._gateway.register_preset(
                FlagPreset(
                    key=key,
                    name=key,
                    description=desc,
                    default_value=default,
                    fail_open=fail_open,
                    user_overridable=user_overridable,
                )
            )
            # Keep in local dict so list_flags / existing tests work
            self._flags[key] = FeatureFlag(
                name=key,
                enabled=default,
                description=desc,
            )

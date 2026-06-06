"""Unleash gateway — wraps UnleashClient (server-side SDK) + Admin REST API.

Design decisions:
- Single singleton UnleashClient that polls Unleash in the background.
- All business-layer knowledge is isolated here; callers never import UnleashClient.
- unleash_enabled=False → short-circuits to local preset defaults (unit-test friendly).
- In-process kill override set (_killed) takes precedence over Unleash eval so that
  a kill-switch command takes effect *immediately* without waiting for the next refresh.
- Fallback priority: killed > unleash eval > per-flag default_value / fail_open / fail_open_flags.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any

import httpx

from foundation_feature_flag.config import get_settings
from foundation_feature_flag.observability import get_logger

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

EvalResult = dict[str, Any]  # {enabled, variant, reason}


@dataclass
class FlagPreset:
    """Local preset definition for a flag — used as fallback source of truth."""

    key: str
    name: str
    description: str = ""
    default_value: bool = False
    fail_open: bool = False


# ---------------------------------------------------------------------------
# UnleashGateway
# ---------------------------------------------------------------------------


class UnleashGateway:
    """Thin abstraction over Unleash Python SDK + Admin REST API.

    Lifecycle:
      await gateway.initialize()   # call in lifespan startup
      gateway.destroy()            # call in lifespan shutdown
    """

    def __init__(self) -> None:
        self._settings = get_settings()
        self._client: Any | None = None  # UnleashClient | None
        self._presets: dict[str, FlagPreset] = {}
        # In-process kill override — takes effect immediately, bypass Unleash refresh delay.
        self._killed: set[str] = set()
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Preset registration (called by FeatureFlagService.load_presets)
    # ------------------------------------------------------------------

    def register_preset(self, preset: FlagPreset) -> None:
        self._presets[preset.key] = preset

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def initialize(self) -> None:
        """Initialize Unleash client (blocking until first cache fetch)."""
        s = self._settings
        if not s.unleash_enabled:
            log.info("unleash_gateway.disabled", reason="unleash_enabled=False")
            return

        try:
            from UnleashClient import UnleashClient  # type: ignore[import]

            # UnleashClient appends /client/features to url, so we must include /api
            # e.g. http://unleash:4242/api → http://unleash:4242/api/client/features
            base_url = s.unleash_url.rstrip("/")
            if not base_url.endswith("/api"):
                base_url = base_url + "/api"

            self._client = UnleashClient(
                url=base_url,
                app_name=s.unleash_app_name,
                custom_headers={"Authorization": s.unleash_api_token},
                refresh_interval=s.unleash_refresh_interval,
                metrics_interval=s.unleash_metrics_interval,
                verbose_log_level=40,  # ERROR only
            )
            self._client.initialize_client(fetch_toggles=True)
            log.info("unleash_gateway.initialized", url=s.unleash_url, app=s.unleash_app_name)
        except Exception as exc:
            log.warning("unleash_gateway.init_failed", error=str(exc))
            # Don't raise — service starts in degraded mode, fallback to presets
            self._client = None

    def destroy(self) -> None:
        if self._client is not None:
            try:
                self._client.destroy()
            except Exception as exc:
                log.warning("unleash_gateway.destroy_failed", error=str(exc))
            finally:
                self._client = None

    # ------------------------------------------------------------------
    # Core evaluation
    # ------------------------------------------------------------------

    def _fallback_result(self, flag: str, *, reason: str = "fallback_default") -> EvalResult:
        """Return safe default from preset or global fail-open config."""
        s = self._settings
        if flag in s.unleash_fail_open_flags:
            return {"enabled": True, "variant": None, "reason": "fail_open_config"}
        preset = self._presets.get(flag)
        if preset is not None:
            return {"enabled": preset.default_value or preset.fail_open, "variant": None, "reason": reason}
        return {"enabled": False, "variant": None, "reason": reason}

    def evaluate(
        self,
        flag: str,
        *,
        tenant_id: str | None = None,
        user_id: str | None = None,
        extra_props: dict[str, Any] | None = None,
    ) -> EvalResult:
        """Evaluate a feature flag for the given context.

        Evaluation order:
          1. In-process kill override → disabled immediately
          2. unleash_enabled=False → local preset default
          3. UnleashClient not available (init failed) → local preset default
          4. UnleashClient.is_enabled with tenant/user context → unleash_eval
          5. Exception during eval → fallback_default
        """
        # 1. Kill override — immediate, no Unleash round-trip
        with self._lock:
            if flag in self._killed:
                return {"enabled": False, "variant": None, "reason": "killed"}

        # 2. Unleash disabled (dev / test with no Unleash)
        if not self._settings.unleash_enabled:
            return self._fallback_result(flag, reason="unleash_disabled")

        # 3. Client not available
        if self._client is None:
            return self._fallback_result(flag, reason="fallback_default")

        # 4. Unleash evaluation with context
        try:
            ctx: dict[str, Any] = {}
            if user_id:
                ctx["userId"] = user_id
            props: dict[str, str] = {}
            if tenant_id:
                props["tenantId"] = tenant_id
            if extra_props:
                props.update({k: str(v) for k, v in extra_props.items()})
            if props:
                ctx["properties"] = props

            # fallback_function: return preset default_value when Unleash has no toggle
            preset = self._presets.get(flag)
            preset_default = (preset.default_value or preset.fail_open) if preset else False

            enabled = self._client.is_enabled(
                flag,
                ctx if ctx else None,
                fallback_function=lambda f, c: preset_default,
            )

            # Variant (A/B)
            variant: str | None = None
            try:
                v = self._client.get_variant(flag, ctx if ctx else None)
                if v and v.get("name") and v["name"] != "disabled":
                    variant = v["name"]
            except Exception:
                pass

            return {"enabled": bool(enabled), "variant": variant, "reason": "unleash_eval"}

        except Exception as exc:
            log.warning("unleash_gateway.eval_failed", flag=flag, error=str(exc))
            return self._fallback_result(flag)

    def evaluate_batch(
        self,
        flags: list[str],
        *,
        tenant_id: str | None = None,
        user_id: str | None = None,
        extra_props: dict[str, Any] | None = None,
    ) -> dict[str, EvalResult]:
        return {
            f: self.evaluate(f, tenant_id=tenant_id, user_id=user_id, extra_props=extra_props)
            for f in flags
        }

    # ------------------------------------------------------------------
    # In-process kill override (immediate effect)
    # ------------------------------------------------------------------

    def kill(self, flag: str) -> None:
        """Force-disable a flag in-process immediately."""
        with self._lock:
            self._killed.add(flag)
        log.warning("unleash_gateway.killed", flag=flag)

    def restore(self, flag: str) -> None:
        """Remove in-process kill override; resume normal Unleash evaluation."""
        with self._lock:
            self._killed.discard(flag)
        log.info("unleash_gateway.restored", flag=flag)

    def is_killed(self, flag: str) -> bool:
        with self._lock:
            return flag in self._killed

    # ------------------------------------------------------------------
    # Admin REST API — Unleash flag management (uses admin_token)
    # ------------------------------------------------------------------

    def _admin_headers(self) -> dict[str, str]:
        return {
            "Authorization": self._settings.unleash_admin_token,
            "Content-Type": "application/json",
        }

    def _admin_base(self) -> str:
        return self._settings.unleash_url.rstrip("/")

    def admin_list(self) -> list[dict[str, Any]]:
        """List all feature toggles from Unleash Admin API."""
        if not self._settings.unleash_enabled:
            return []
        try:
            with httpx.Client(timeout=10) as client:
                resp = client.get(
                    f"{self._admin_base()}/api/admin/features",
                    headers=self._admin_headers(),
                )
                resp.raise_for_status()
                return resp.json().get("features", [])
        except Exception as exc:
            log.warning("unleash_gateway.admin_list_failed", error=str(exc))
            return []

    def admin_upsert_flag(
        self,
        *,
        flag_key: str,
        name: str | None = None,
        description: str | None = None,
        enabled: bool | None = None,
        strategies: list[dict[str, Any]] | None = None,
    ) -> bool:
        """Create or update a feature toggle via Unleash Admin API.

        Returns True on success.
        """
        if not self._settings.unleash_enabled:
            return False
        base = self._admin_base()
        headers = self._admin_headers()
        # Default strategy if none provided
        if strategies is None:
            strategies = [{"name": "default", "constraints": [], "parameters": {}}]

        try:
            with httpx.Client(timeout=10) as client:
                # Try to get existing toggle
                get_resp = client.get(
                    f"{base}/api/admin/features/{flag_key}", headers=headers
                )
                if get_resp.status_code == 404:
                    # Create new toggle
                    payload: dict[str, Any] = {
                        "name": flag_key,
                        "description": description or "",
                        "type": "release",
                        "enabled": False,  # Create disabled; enable separately
                        "strategies": strategies,
                    }
                    create_resp = client.post(
                        f"{base}/api/admin/features",
                        headers=headers,
                        json=payload,
                    )
                    create_resp.raise_for_status()
                    log.info("unleash_gateway.admin_created", flag=flag_key)
                else:
                    get_resp.raise_for_status()
                    # Update description/name if changed
                    existing = get_resp.json()
                    update_payload: dict[str, Any] = {
                        "name": flag_key,
                        "description": description or existing.get("description", ""),
                        "type": existing.get("type", "release"),
                        "enabled": existing.get("enabled", False),
                        "strategies": strategies or existing.get("strategies", []),
                    }
                    put_resp = client.put(
                        f"{base}/api/admin/features/{flag_key}",
                        headers=headers,
                        json=update_payload,
                    )
                    put_resp.raise_for_status()
                    log.info("unleash_gateway.admin_updated", flag=flag_key)

                # Set enabled state
                if enabled is not None:
                    toggle_action = "enable" if enabled else "disable"
                    # In Unleash v5+ API the endpoint is per-environment
                    # Try the simpler toggle endpoint first
                    toggle_resp = client.post(
                        f"{base}/api/admin/features/{flag_key}/{toggle_action}",
                        headers=headers,
                    )
                    if toggle_resp.status_code not in (200, 204):
                        # Unleash v5+ uses environment-scoped endpoints
                        toggle_resp2 = client.post(
                            f"{base}/api/admin/projects/default/features/{flag_key}/environments/development/{toggle_action}",
                            headers=headers,
                        )
                        if toggle_resp2.status_code not in (200, 204):
                            log.warning(
                                "unleash_gateway.toggle_failed",
                                flag=flag_key,
                                action=toggle_action,
                                status=toggle_resp2.status_code,
                            )

                return True
        except Exception as exc:
            log.warning("unleash_gateway.admin_upsert_failed", flag=flag_key, error=str(exc))
            return False

    def admin_set_kill_switch(self, flag: str, killed: bool) -> bool:
        """Disable/enable a flag via Unleash Admin API (persists across restarts).

        This is called AFTER the in-process kill override so the flag is also
        disabled in Unleash for other instances/restarts.
        """
        if not self._settings.unleash_enabled:
            return False
        return self.admin_upsert_flag(flag_key=flag, enabled=not killed)


# ---------------------------------------------------------------------------
# Module-level singleton (accessed via get_gateway())
# ---------------------------------------------------------------------------

_gateway: UnleashGateway | None = None


def get_gateway() -> UnleashGateway:
    global _gateway
    if _gateway is None:
        _gateway = UnleashGateway()
    return _gateway

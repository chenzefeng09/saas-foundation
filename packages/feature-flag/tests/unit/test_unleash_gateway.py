"""Unit tests for UnleashGateway and FeatureFlagService + API endpoints.

All tests run without a real Unleash server:
  - unleash_enabled=False path → short-circuits to local preset defaults
  - Kill override → immediate effect
  - Fallback on eval failure
  - Endpoint contract: body accepts {flag} and {flag_key}
  - Batch evaluate
  - Kill-switch endpoint
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from foundation_feature_flag.api.exception_handlers import install_exception_handlers
from foundation_feature_flag.api.middleware import TenantContextMiddleware
from foundation_feature_flag.api.v1.evaluate import router as evaluate_router
from foundation_feature_flag.api.v1.flags import router as flags_router
from foundation_feature_flag.services.feature_flag_service import FeatureFlagService
from foundation_feature_flag.services.unleash_gateway import FlagPreset, UnleashGateway


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def make_gateway(*, unleash_enabled: bool = False) -> UnleashGateway:
    """Create a gateway with unleash_enabled=False for unit tests (no Unleash server)."""
    gw = UnleashGateway.__new__(UnleashGateway)
    import threading

    gw._settings = MagicMock()
    gw._settings.unleash_enabled = unleash_enabled
    gw._settings.unleash_url = "http://localhost:4242"
    gw._settings.unleash_api_token = "test-token"
    gw._settings.unleash_admin_token = "test-admin-token"
    gw._settings.unleash_app_name = "test"
    gw._settings.unleash_refresh_interval = 15
    gw._settings.unleash_metrics_interval = 60
    gw._settings.unleash_fail_open_flags = ["ai.thinking_ui"]
    gw._client = None
    gw._presets = {}
    gw._killed = set()
    gw._lock = threading.Lock()
    return gw


def make_service_with_gateway(gw: UnleashGateway) -> FeatureFlagService:
    svc = FeatureFlagService(gateway=gw)
    svc.load_presets()
    return svc


def make_test_app(gw: UnleashGateway, svc: FeatureFlagService) -> FastAPI:
    """Create a minimal FastAPI app with the evaluate and flags routers."""
    app = FastAPI()
    app.add_middleware(TenantContextMiddleware)
    install_exception_handlers(app)
    app.state.unleash_gateway = gw
    app.state.feature_flag_service = svc
    app.include_router(evaluate_router)
    app.include_router(flags_router)
    return app


ADMIN_HEADERS = {
    "X-Tenant-Id": "tnt_01J0000000000000000000TNT1",
    "X-Actor": "ADMIN",
    "X-User-Id": "usr_admin",
}


# ---------------------------------------------------------------------------
# UnleashGateway unit tests
# ---------------------------------------------------------------------------


class TestUnleashGatewayLocal:
    """Test gateway when unleash_enabled=False (local preset fallback)."""

    def setup_method(self):
        self.gw = make_gateway(unleash_enabled=False)
        self.gw.register_preset(FlagPreset("billing.saas_mode", "Billing", default_value=False))
        self.gw.register_preset(FlagPreset("ai.thinking_ui", "AI Thinking", default_value=True))
        self.gw.register_preset(
            FlagPreset("ai.fail_open_flag", "Fail-open", default_value=False, fail_open=True)
        )

    def test_unleash_disabled_returns_preset_default_false(self):
        result = self.gw.evaluate("billing.saas_mode")
        assert result["enabled"] is False
        assert result["reason"] == "unleash_disabled"

    def test_unleash_disabled_returns_preset_default_true(self):
        result = self.gw.evaluate("ai.thinking_ui")
        assert result["enabled"] is True
        # ai.thinking_ui is in unleash_fail_open_flags — reason will be fail_open_config
        assert result["reason"] in ("unleash_disabled", "fail_open_config")

    def test_unknown_flag_returns_false_on_disabled(self):
        result = self.gw.evaluate("unknown.flag")
        assert result["enabled"] is False

    def test_fail_open_preset_returns_true(self):
        result = self.gw.evaluate("ai.fail_open_flag")
        assert result["enabled"] is True

    def test_fail_open_config_overrides(self):
        """unleash_fail_open_flags in settings returns true regardless of preset."""
        result = self.gw.evaluate("ai.thinking_ui")
        # ai.thinking_ui is in fail_open_flags mock setting AND has preset default=True
        # since unleash_disabled it returns from fallback_result which checks fail_open_flags first
        # but reason is unleash_disabled (preset lookup branch) — both acceptable
        assert result["enabled"] is True


class TestUnleashGatewayKillOverride:
    """Kill override is immediate and independent of Unleash state."""

    def setup_method(self):
        self.gw = make_gateway(unleash_enabled=False)
        self.gw.register_preset(FlagPreset("some.flag", "Some flag", default_value=True))

    def test_kill_disables_immediately(self):
        result_before = self.gw.evaluate("some.flag")
        assert result_before["enabled"] is True

        self.gw.kill("some.flag")
        result_after = self.gw.evaluate("some.flag")
        assert result_after["enabled"] is False
        assert result_after["reason"] == "killed"

    def test_restore_re_enables(self):
        self.gw.kill("some.flag")
        self.gw.restore("some.flag")
        result = self.gw.evaluate("some.flag")
        # After restore, evaluation goes to local preset (unleash_disabled)
        assert result["enabled"] is True
        assert result["reason"] != "killed"

    def test_kill_takes_precedence_over_unleash(self):
        """Even if we had a live Unleash returning True, kill must override."""
        # Simulate a live client returning True
        self.gw._settings.unleash_enabled = True
        mock_client = MagicMock()
        mock_client.is_enabled.return_value = True
        mock_client.get_variant.return_value = {"name": "disabled"}
        self.gw._client = mock_client

        self.gw.kill("some.flag")
        result = self.gw.evaluate("some.flag")
        # Kill check happens BEFORE client.is_enabled call
        assert result["enabled"] is False
        assert result["reason"] == "killed"
        mock_client.is_enabled.assert_not_called()

    def test_is_killed_reflects_state(self):
        assert self.gw.is_killed("some.flag") is False
        self.gw.kill("some.flag")
        assert self.gw.is_killed("some.flag") is True
        self.gw.restore("some.flag")
        assert self.gw.is_killed("some.flag") is False


class TestUnleashGatewayUnleashEnabled:
    """Test gateway when Unleash client is available."""

    def setup_method(self):
        self.gw = make_gateway(unleash_enabled=True)
        self.gw.register_preset(FlagPreset("billing.saas_mode", "Billing", default_value=False))
        # Inject a mock UnleashClient
        self.mock_client = MagicMock()
        self.gw._client = self.mock_client

    def test_delegates_to_unleash_when_enabled(self):
        self.mock_client.is_enabled.return_value = True
        self.mock_client.get_variant.return_value = {"name": "disabled"}
        result = self.gw.evaluate("billing.saas_mode", tenant_id="tnt_123", user_id="usr_456")
        assert result["enabled"] is True
        assert result["reason"] == "unleash_eval"
        # Verify context was passed
        call_args = self.mock_client.is_enabled.call_args
        assert call_args[0][0] == "billing.saas_mode"
        ctx_arg = call_args[0][1]
        assert ctx_arg is not None
        assert ctx_arg.get("userId") == "usr_456"
        assert ctx_arg["properties"]["tenantId"] == "tnt_123"

    def test_fallback_on_unleash_exception(self):
        self.mock_client.is_enabled.side_effect = RuntimeError("Unleash down")
        result = self.gw.evaluate("billing.saas_mode")
        assert result["enabled"] is False
        assert result["reason"] == "fallback_default"

    def test_variant_populated(self):
        self.mock_client.is_enabled.return_value = True
        self.mock_client.get_variant.return_value = {"name": "variant-a", "enabled": True}
        result = self.gw.evaluate("billing.saas_mode")
        assert result["variant"] == "variant-a"


class TestBatchEvaluate:
    def test_batch_returns_all_flags(self):
        gw = make_gateway(unleash_enabled=False)
        gw.register_preset(FlagPreset("flag.a", "A", default_value=True))
        gw.register_preset(FlagPreset("flag.b", "B", default_value=False))
        results = gw.evaluate_batch(["flag.a", "flag.b"])
        assert results["flag.a"]["enabled"] is True
        assert results["flag.b"]["enabled"] is False

    def test_batch_empty(self):
        gw = make_gateway(unleash_enabled=False)
        results = gw.evaluate_batch([])
        assert results == {}


# ---------------------------------------------------------------------------
# FeatureFlagService delegation tests
# ---------------------------------------------------------------------------


class TestFeatureFlagServiceDelegation:
    def setup_method(self):
        self.gw = make_gateway(unleash_enabled=False)
        self.svc = make_service_with_gateway(self.gw)

    def test_is_enabled_delegates_to_gateway(self):
        # billing.saas_mode has default False
        assert self.svc.is_enabled("billing.saas_mode") is False

    def test_is_enabled_ai_thinking_ui_true_by_default(self):
        assert self.svc.is_enabled("ai.thinking_ui") is True

    def test_kill_switch_via_gateway_affects_service(self):
        assert self.svc.is_enabled("ai.thinking_ui") is True
        self.gw.kill("ai.thinking_ui")
        assert self.svc.is_enabled("ai.thinking_ui") is False

    def test_list_flags_returns_all_presets(self):
        flags = self.svc.list_flags()
        keys = {f["name"] for f in flags}
        assert "billing.saas_mode" in keys
        assert "ai.thinking_ui" in keys
        assert len(flags) >= 8

    def test_flag_not_found_returns_false(self):
        assert self.svc.is_enabled("does.not.exist") is False

    def test_disabled_flag_returns_false(self):
        assert self.svc.is_enabled("compliance.gmtls_enabled") is False


# ---------------------------------------------------------------------------
# API endpoint tests (TestClient, no DB)
# ---------------------------------------------------------------------------


class TestEvaluateEndpoint:
    def setup_method(self):
        self.gw = make_gateway(unleash_enabled=False)
        self.svc = make_service_with_gateway(self.gw)
        self.app = make_test_app(self.gw, self.svc)
        self.client = TestClient(self.app)

    def test_evaluate_with_flag_field(self):
        resp = self.client.post("/evaluate", json={"flag": "ai.thinking_ui"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["enabled"] is True
        assert "reason" in data

    def test_evaluate_with_flag_key_field(self):
        """flag_key is the spec alias — must also work."""
        resp = self.client.post("/evaluate", json={"flag_key": "billing.saas_mode"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["enabled"] is False

    def test_evaluate_unknown_flag_returns_false(self):
        resp = self.client.post("/evaluate", json={"flag": "no.such.flag"})
        assert resp.status_code == 200
        assert resp.json()["enabled"] is False

    def test_evaluate_missing_flag_returns_422(self):
        resp = self.client.post("/evaluate", json={"context": {}})
        assert resp.status_code == 422

    def test_evaluate_with_context(self):
        resp = self.client.post(
            "/evaluate",
            json={"flag": "billing.saas_mode", "context": {"tier": "PRO"}},
        )
        assert resp.status_code == 200

    def test_evaluate_kill_switch_immediate(self):
        # Before kill
        resp = self.client.post("/evaluate", json={"flag": "ai.thinking_ui"})
        assert resp.json()["enabled"] is True

        # Apply kill in-process
        self.gw.kill("ai.thinking_ui")

        # After kill — must return False immediately
        resp = self.client.post("/evaluate", json={"flag": "ai.thinking_ui"})
        assert resp.json()["enabled"] is False
        assert resp.json()["reason"] == "killed"


class TestEvaluateBatchEndpoint:
    def setup_method(self):
        self.gw = make_gateway(unleash_enabled=False)
        self.svc = make_service_with_gateway(self.gw)
        self.app = make_test_app(self.gw, self.svc)
        self.client = TestClient(self.app)

    def test_batch_evaluate(self):
        resp = self.client.post(
            "/evaluate-batch",
            json={"flags": ["billing.saas_mode", "ai.thinking_ui"]},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "results" in data
        assert data["results"]["billing.saas_mode"]["enabled"] is False
        assert data["results"]["ai.thinking_ui"]["enabled"] is True

    def test_batch_empty_list(self):
        resp = self.client.post("/evaluate-batch", json={"flags": []})
        assert resp.status_code == 200
        assert resp.json()["results"] == {}


class TestListFlagsEndpoint:
    def setup_method(self):
        self.gw = make_gateway(unleash_enabled=False)
        self.svc = make_service_with_gateway(self.gw)
        self.app = make_test_app(self.gw, self.svc)
        self.client = TestClient(self.app)

    def test_list_flags_fallback_no_db(self):
        """When DB is unavailable, list_flags falls back to in-memory presets."""
        resp = self.client.get("/flags")
        # Will attempt DB session_scope and fail; falls back to svc.list_flags()
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) >= 8
        keys = {item["key"] for item in data}
        assert "billing.saas_mode" in keys
        assert "ai.thinking_ui" in keys

    def test_kill_switch_reflected_in_list(self):
        self.gw.kill("billing.saas_mode")
        resp = self.client.get("/flags")
        assert resp.status_code == 200
        data = resp.json()
        flag = next((f for f in data if f["key"] == "billing.saas_mode"), None)
        assert flag is not None
        assert flag["kill_switch_active"] is True


class TestKillSwitchEndpoint:
    def setup_method(self):
        self.gw = make_gateway(unleash_enabled=False)
        self.svc = make_service_with_gateway(self.gw)
        self.app = make_test_app(self.gw, self.svc)
        self.client = TestClient(self.app)

    def test_kill_switch_disables_flag_immediately(self):
        # Verify flag is enabled before kill
        assert self.svc.is_enabled("ai.thinking_ui") is True

        # Call kill-switch endpoint
        resp = self.client.post(
            "/flags/ai.thinking_ui/kill-switch",
            json={"reason": "P0 incident — immediate kill"},
            headers=ADMIN_HEADERS,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["killed"] is True
        assert data["flag"] == "ai.thinking_ui"
        assert "timestamp" in data

        # Flag must be disabled immediately via in-process override
        assert self.gw.is_killed("ai.thinking_ui") is True
        assert self.svc.is_enabled("ai.thinking_ui") is False

    def test_kill_switch_requires_admin_actor(self):
        resp = self.client.post(
            "/flags/ai.thinking_ui/kill-switch",
            json={"reason": "P0 incident — immediate kill"},
            headers={"X-Tenant-Id": ADMIN_HEADERS["X-Tenant-Id"], "X-Actor": "USER"},
        )
        assert resp.status_code == 403
        assert resp.json()["code"] == "FOUNDATION.FEATURE_FLAG.AUTHZ.ACCESS_DENIED"
        assert self.gw.is_killed("ai.thinking_ui") is False

    def test_kill_switch_requires_reason(self):
        resp = self.client.post(
            "/flags/ai.thinking_ui/kill-switch",
            json={},  # missing reason
            headers=ADMIN_HEADERS,
        )
        assert resp.status_code == 422

    def test_kill_switch_reason_too_short(self):
        resp = self.client.post(
            "/flags/billing.saas_mode/kill-switch",
            json={"reason": "bad"},  # < 5 chars
            headers=ADMIN_HEADERS,
        )
        assert resp.status_code == 422


class TestSetFlagEndpoint:
    def setup_method(self):
        self.gw = make_gateway(unleash_enabled=False)
        self.svc = make_service_with_gateway(self.gw)
        self.app = make_test_app(self.gw, self.svc)
        self.client = TestClient(self.app)

    def test_set_flag_returns_flag_view(self):
        resp = self.client.put(
            "/flags/billing.saas_mode",
            json={"enabled": True, "rollout_percentage": 100},
            headers=ADMIN_HEADERS,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["key"] == "billing.saas_mode"
        assert data["enabled"] is True

    def test_set_flag_sdk_contract_fields(self):
        """SDK set_flag sends {enabled, rollout_percentage, tenant_whitelist}."""
        resp = self.client.put(
            "/flags/some.flag",
            json={
                "enabled": True,
                "rollout_percentage": 50,
                "tenant_whitelist": ["tnt_aaa", "tnt_bbb"],
            },
            headers=ADMIN_HEADERS,
        )
        assert resp.status_code == 200
        assert resp.json()["enabled"] is True

    def test_set_flag_requires_admin_actor(self):
        resp = self.client.put(
            "/flags/some.flag",
            json={"enabled": True, "rollout_percentage": 100},
            headers={"X-Tenant-Id": ADMIN_HEADERS["X-Tenant-Id"], "X-Actor": "USER"},
        )
        assert resp.status_code == 403
        assert resp.json()["code"] == "FOUNDATION.FEATURE_FLAG.AUTHZ.ACCESS_DENIED"


class TestFallbackBehavior:
    """Test the fallback / degraded mode when Unleash is unreachable."""

    def test_fallback_fail_open_flag(self):
        """fail_open=True in preset → enabled=True even on Unleash error."""
        gw = make_gateway(unleash_enabled=True)
        gw.register_preset(
            FlagPreset("some.critical_flag", "Critical", default_value=False, fail_open=True)
        )
        # Client raises an exception simulating Unleash unreachable
        mock_client = MagicMock()
        mock_client.is_enabled.side_effect = ConnectionError("Unleash unreachable")
        gw._client = mock_client

        result = gw.evaluate("some.critical_flag")
        assert result["enabled"] is True
        assert result["reason"] == "fallback_default"

    def test_fallback_non_fail_open_flag_returns_false(self):
        """fail_open=False → safe default is False on error."""
        gw = make_gateway(unleash_enabled=True)
        gw.register_preset(
            FlagPreset("export.allow_l4_download", "Export", default_value=False, fail_open=False)
        )
        mock_client = MagicMock()
        mock_client.is_enabled.side_effect = ConnectionError("Unleash unreachable")
        gw._client = mock_client

        result = gw.evaluate("export.allow_l4_download")
        assert result["enabled"] is False
        assert result["reason"] == "fallback_default"

    def test_fail_open_config_flag(self):
        """unleash_fail_open_flags from config → always True."""
        gw = make_gateway(unleash_enabled=True)
        # ai.thinking_ui is in fail_open_flags in our mock settings
        mock_client = MagicMock()
        mock_client.is_enabled.side_effect = ConnectionError("Unleash unreachable")
        gw._client = mock_client

        result = gw.evaluate("ai.thinking_ui")
        assert result["enabled"] is True
        assert result["reason"] == "fail_open_config"

    def test_no_client_falls_back(self):
        """When _client is None (init failed), use preset defaults."""
        gw = make_gateway(unleash_enabled=True)
        gw.register_preset(FlagPreset("billing.saas_mode", "B", default_value=False))
        assert gw._client is None  # no client

        result = gw.evaluate("billing.saas_mode")
        assert result["enabled"] is False
        assert result["reason"] == "fallback_default"

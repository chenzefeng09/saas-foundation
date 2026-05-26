"""Tests for FeatureFlagService."""

import pytest
from foundation_feature_flag.services.feature_flag_service import FeatureFlagService, FeatureFlag


class TestFeatureFlag:
    def setup_method(self):
        self.svc = FeatureFlagService()
        self.svc.load_presets()

    def test_flag_not_found_returns_false(self):
        assert self.svc.is_enabled("nonexistent") is False

    def test_disabled_flag_returns_false(self):
        assert self.svc.is_enabled("billing.saas_mode") is False

    def test_enabled_flag_returns_true(self):
        assert self.svc.is_enabled("ai.thinking_ui") is True

    def test_tenant_whitelist_blocks(self):
        self.svc.register(FeatureFlag("premium_feature", True, tenant_ids=["tnt_vip"]))
        assert self.svc.is_enabled("premium_feature", tenant_id="tnt_regular") is False
        assert self.svc.is_enabled("premium_feature", tenant_id="tnt_vip") is True

    def test_rollout_percentage(self):
        self.svc.register(FeatureFlag("beta", True, rollout_pct=50))
        # Deterministic: same user always gets same result
        r1 = self.svc.is_enabled("beta", user_id="usr_a")
        r2 = self.svc.is_enabled("beta", user_id="usr_a")
        assert r1 == r2

    def test_list_flags(self):
        flags = self.svc.list_flags()
        assert len(flags) >= 8

    def test_gmtls_flag_disabled_by_default(self):
        assert self.svc.is_enabled("compliance.gmtls_enabled") is False

    def test_sm_algorithms_disabled_by_default(self):
        assert self.svc.is_enabled("compliance.sm_algorithms") is False

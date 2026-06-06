"""Migration checks for tenant RLS coverage.

These tests do not replace the live Postgres fuzz tests.  They execute Alembic
upgrade functions with a fake ``op`` object and assert the actual generated DDL
contains ENABLE/FORCE RLS and tenant policies.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any


ROOT = Path(__file__).resolve().parents[2]


class _FakeOp:
    def __init__(self) -> None:
        self.executed: list[str] = []

    def execute(self, sql: str) -> None:
        self.executed.append(sql)

    def create_table(self, *args: Any, **kwargs: Any) -> None:
        return None

    def create_index(self, *args: Any, **kwargs: Any) -> None:
        return None


def _load_migration(path: str) -> ModuleType:
    full_path = ROOT / path
    spec = importlib.util.spec_from_file_location("migration_under_test", full_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _migration_ddl(path: str) -> list[str]:
    module = _load_migration(
        path
    )
    fake_op = _FakeOp()
    module.op = fake_op
    module.upgrade()
    return fake_op.executed


def _assert_tenant_table_rls(schema: str, tables: tuple[str, ...], ddl: list[str]) -> None:
    for table in tables:
        assert f'ALTER TABLE {schema}."{table}" ENABLE ROW LEVEL SECURITY' in ddl
        assert f'ALTER TABLE {schema}."{table}" FORCE ROW LEVEL SECURITY' in ddl
        for operation in ("SELECT", "INSERT", "UPDATE", "DELETE"):
            assert any(
                f'CREATE POLICY tenant_{operation.lower()} ON {schema}."{table}" '
                f"FOR {operation} TO app_user, app_admin" in statement
                for statement in ddl
            )
    for operation in ("SELECT", "INSERT", "UPDATE", "DELETE"):
        assert any(f"FOR {operation} TO app_user, app_admin" in stmt for stmt in ddl)
    assert any(f"CREATE POLICY admin_all ON {schema}." in stmt for stmt in ddl)


def _assert_outbox_rls(schema: str, table: str, ddl: list[str]) -> None:
    assert (
        f"ALTER TABLE {schema}.{table} "
        "ENABLE ROW LEVEL SECURITY"
    ) in ddl
    assert (
        f"ALTER TABLE {schema}.{table} "
        "FORCE ROW LEVEL SECURITY"
    ) in ddl
    assert any("CREATE POLICY outbox_tenant_insert" in stmt for stmt in ddl)
    assert any("CREATE POLICY outbox_tenant_select" in stmt for stmt in ddl)
    assert any("CREATE POLICY outbox_system_all" in stmt for stmt in ddl)


def _assert_platform_table_rls(schema: str, tables: tuple[str, ...], ddl: list[str]) -> None:
    for table in tables:
        assert f"ALTER TABLE {schema}.{table} ENABLE ROW LEVEL SECURITY" in ddl
        assert f"ALTER TABLE {schema}.{table} FORCE ROW LEVEL SECURITY" in ddl
        assert any(
            f"CREATE POLICY platform_all ON {schema}.{table}" in statement
            and "current_setting('app.actor', true) IN ('ADMIN', 'SYSTEM', 'SERVICE')" in statement
            for statement in ddl
        )
        assert any(
            f"CREATE POLICY platform_observability_select ON {schema}.{table}" in statement
            for statement in ddl
        )


def test_llm_gateway_initial_migration_enables_tenant_rls() -> None:
    ddl = _migration_ddl(
        "packages/llm-gateway/migrations/versions/"
        "2026_06_03_0001-0001_init_llm_gateway.py"
    )
    _assert_tenant_table_rls(
        "llm_gateway",
        ("llm_provider", "llm_tenant_key", "llm_usage_record"),
        ddl,
    )


def test_llm_gateway_outbox_has_rls_policies() -> None:
    ddl = _migration_ddl(
        "packages/llm-gateway/migrations/versions/"
        "2026_06_03_0001-0001_init_llm_gateway.py"
    )
    _assert_outbox_rls("llm_gateway", "llm_gateway_event_outbox", ddl)


def test_billing_initial_migration_enables_tenant_rls() -> None:
    ddl = _migration_ddl(
        "packages/billing/migrations/versions/2026_06_03_0001-0001_init_billing.py"
    )
    _assert_tenant_table_rls(
        "billing",
        ("tenant_subscription", "quota_usage", "invoice"),
        ddl,
    )


def test_billing_outbox_has_rls_policies() -> None:
    ddl = _migration_ddl(
        "packages/billing/migrations/versions/2026_06_03_0001-0001_init_billing.py"
    )
    _assert_outbox_rls("billing", "billing_event_outbox", ddl)


def test_api_platform_initial_migration_enables_tenant_rls() -> None:
    ddl = _migration_ddl(
        "packages/api-platform/migrations/versions/"
        "2026_06_03_0001-0001_init_api_platform.py"
    )
    _assert_tenant_table_rls(
        "api_platform",
        ("api_key", "oauth_app", "webhook_subscription"),
        ddl,
    )


def test_api_platform_outbox_has_rls_policies() -> None:
    ddl = _migration_ddl(
        "packages/api-platform/migrations/versions/"
        "2026_06_03_0001-0001_init_api_platform.py"
    )
    _assert_outbox_rls("api_platform", "api_platform_event_outbox", ddl)


def test_search_initial_migration_enables_tenant_rls() -> None:
    ddl = _migration_ddl(
        "packages/search/migrations/versions/2026_06_03_0001-0001_init_search.py"
    )
    _assert_tenant_table_rls(
        "search",
        ("search_index", "search_query_log"),
        ddl,
    )


def test_search_outbox_has_rls_policies() -> None:
    ddl = _migration_ddl(
        "packages/search/migrations/versions/2026_06_03_0001-0001_init_search.py"
    )
    _assert_outbox_rls("search", "search_event_outbox", ddl)


def test_dlp_initial_migration_enables_tenant_rls() -> None:
    ddl = _migration_ddl(
        "packages/dlp/migrations/versions/2026_06_03_0001-0001_init_dlp.py"
    )
    _assert_tenant_table_rls(
        "dlp",
        ("classification", "dlp_rule", "dlp_event"),
        ddl,
    )


def test_dlp_rule_allows_global_read_only() -> None:
    ddl = _migration_ddl(
        "packages/dlp/migrations/versions/2026_06_03_0001-0001_init_dlp.py"
    )
    assert any(
        'CREATE POLICY tenant_select ON dlp."dlp_rule" '
        "FOR SELECT TO app_user, app_admin "
        "USING (tenant_id IS NULL OR tenant_id = current_setting('app.tenant_id', true))"
        in statement
        for statement in ddl
    )
    assert any(
        'CREATE POLICY tenant_insert ON dlp."dlp_rule" '
        "FOR INSERT TO app_user, app_admin "
        "WITH CHECK (tenant_id = current_setting('app.tenant_id', true))"
        in statement
        for statement in ddl
    )


def test_dlp_outbox_has_rls_policies() -> None:
    ddl = _migration_ddl(
        "packages/dlp/migrations/versions/2026_06_03_0001-0001_init_dlp.py"
    )
    _assert_outbox_rls("dlp", "dlp_event_outbox", ddl)


def test_data_protection_initial_migration_enables_tenant_rls() -> None:
    ddl = _migration_ddl(
        "packages/data-protection/migrations/versions/"
        "2026_06_03_0001-0001_init_data_protection.py"
    )
    _assert_tenant_table_rls(
        "data_protection",
        ("cross_border_transfer", "data_destruction_request", "consent_record"),
        ddl,
    )


def test_data_protection_outbox_has_rls_policies() -> None:
    ddl = _migration_ddl(
        "packages/data-protection/migrations/versions/"
        "2026_06_03_0001-0001_init_data_protection.py"
    )
    _assert_outbox_rls("data_protection", "dp_event_outbox", ddl)


def test_compliance_initial_migration_enables_tenant_rls() -> None:
    ddl = _migration_ddl(
        "packages/compliance/migrations/versions/2026_06_03_0001-0001_init_compliance.py"
    )
    _assert_tenant_table_rls(
        "compliance",
        ("ropa_record", "dpia", "dsar_request", "compliance_report"),
        ddl,
    )


def test_compliance_outbox_has_rls_policies() -> None:
    ddl = _migration_ddl(
        "packages/compliance/migrations/versions/2026_06_03_0001-0001_init_compliance.py"
    )
    _assert_outbox_rls("compliance", "compliance_event_outbox", ddl)


def test_notification_initial_migration_enables_tenant_rls() -> None:
    ddl = _migration_ddl(
        "packages/notification/migrations/versions/"
        "2026_06_03_0001-0001_init_notification.py"
    )
    _assert_tenant_table_rls(
        "notification",
        (
            "notification_template",
            "notification_channel",
            "notification_subscription",
            "notification_log",
        ),
        ddl,
    )


def test_notification_outbox_has_rls_policies() -> None:
    ddl = _migration_ddl(
        "packages/notification/migrations/versions/"
        "2026_06_03_0001-0001_init_notification.py"
    )
    _assert_outbox_rls("notification", "notification_event_outbox", ddl)


def test_pam_initial_migration_enables_tenant_rls() -> None:
    ddl = _migration_ddl(
        "packages/pam/migrations/versions/2026_06_03_0001-0001_init_pam.py"
    )
    _assert_tenant_table_rls(
        "pam",
        ("pam_elevation_request", "pam_session"),
        ddl,
    )


def test_pam_outbox_has_rls_policies() -> None:
    ddl = _migration_ddl(
        "packages/pam/migrations/versions/2026_06_03_0001-0001_init_pam.py"
    )
    _assert_outbox_rls("pam", "pam_event_outbox", ddl)


def test_feature_flag_initial_migration_protects_global_tables() -> None:
    ddl = _migration_ddl(
        "packages/feature-flag/migrations/versions/"
        "2026_06_05_0001-0001_init_feature_flag.py"
    )
    assert 'ALTER TABLE feature_flag."flag" ENABLE ROW LEVEL SECURITY' in ddl
    assert 'ALTER TABLE feature_flag."flag" FORCE ROW LEVEL SECURITY' in ddl
    assert any(
        'CREATE POLICY flag_read ON feature_flag."flag" '
        "FOR SELECT TO app_user, app_admin, app_observability USING (true)"
        in statement
        for statement in ddl
    )
    assert any(
        'CREATE POLICY flag_admin_write ON feature_flag."flag" '
        "FOR ALL TO app_user, app_admin "
        "USING (current_setting('app.actor', true) = 'ADMIN') "
        "WITH CHECK (current_setting('app.actor', true) = 'ADMIN')"
        in statement
        for statement in ddl
    )
    assert 'ALTER TABLE feature_flag."kill_switch_log" ENABLE ROW LEVEL SECURITY' in ddl
    assert 'ALTER TABLE feature_flag."kill_switch_log" FORCE ROW LEVEL SECURITY' in ddl
    assert any("CREATE POLICY kill_switch_admin_all" in statement for statement in ddl)
    assert any("CREATE POLICY kill_switch_system_select" in statement for statement in ddl)


def test_security_ops_initial_migration_enables_platform_rls_policies() -> None:
    ddl = _migration_ddl(
        "packages/security-ops/migrations/versions/"
        "2026_06_05_0001-0001_init_security_ops.py"
    )
    _assert_platform_table_rls(
        "security_ops",
        (
            "scan_run",
            "vulnerability",
            "incident",
            "sbom_record",
            "sbom_watch",
            "license_finding",
            "drill",
            "security_ops_event_outbox",
        ),
        ddl,
    )

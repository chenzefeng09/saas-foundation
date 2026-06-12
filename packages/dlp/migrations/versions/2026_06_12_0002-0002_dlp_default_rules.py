"""seed default global dlp rules

Revision ID: 0002_dlp_default_rules
Revises: 0001_dlp_init
Create Date: 2026-06-12 00:00:00 UTC
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0002_dlp_default_rules"
down_revision: str | None = "0001_dlp_init"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


# Built-in global rules (tenant_id NULL). Inserted via raw SQL with op.execute so
# the migration role (table owner) bypasses the dlp_rule INSERT RLS policy that
# would otherwise reject NULL-tenant rows. ids are stable (<=30 chars) so downgrade
# can delete them precisely.
#
# Each tuple: (id, name, pattern, min_sensitivity, description)
_DEFAULT_RULES: list[tuple[str, str, str, str, str]] = [
    ("dlprule_pii_cn_idcard", "中国身份证", r"\b\d{17}[\dXx]\b", "L4", "18 位身份证号"),
    ("dlprule_pii_cn_phone", "中国手机号", r"\b1[3-9]\d{9}\b", "L3", "手机号"),
    ("dlprule_pii_bankcard", "银行卡号", r"\b\d{16,19}\b", "L4", "银行卡/借记卡号"),
    (
        "dlprule_pii_email",
        "邮箱",
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        "L2",
        "邮箱地址",
    ),
    (
        "dlprule_secret_aws_akid",
        "AWS Access Key",
        r"\bAKIA[0-9A-Z]{16}\b",
        "L4",
        "AWS Access Key ID",
    ),
    (
        "dlprule_secret_private_key",
        "私钥头",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
        "L4",
        "PEM 私钥",
    ),
    (
        "dlprule_secret_api_key",
        "通用 API Key",
        r"(?i)\bapi[_-]?key\b\s*[:=]\s*\S+",
        "L3",
        "通用 API key 赋值",
    ),
]


def _sql_quote(value: str) -> str:
    """Escape a Python string for embedding in a single-quoted PostgreSQL literal.

    PostgreSQL treats backslashes as literal characters in standard string literals,
    so only the single-quote needs doubling.
    """
    return "'" + value.replace("'", "''") + "'"


def upgrade() -> None:
    columns = (
        "id, tenant_id, name, rule_type, pattern, "
        "min_sensitivity, description, enabled, created_by"
    )
    for rule_id, name, pattern, min_sensitivity, description in _DEFAULT_RULES:
        values = (
            f"{_sql_quote(rule_id)}, NULL, {_sql_quote(name)}, 'REGEX', "
            f"{_sql_quote(pattern)}, {_sql_quote(min_sensitivity)}, "
            f"{_sql_quote(description)}, true, 'system'"
        )
        # S608 suppressed: all interpolated values are quote-escaped literals from
        # the hardcoded _DEFAULT_RULES constant, never user input.
        stmt = f"INSERT INTO dlp.dlp_rule ({columns}) VALUES ({values}) ON CONFLICT (id) DO NOTHING"  # noqa: S608
        op.execute(stmt)


def downgrade() -> None:
    ids = ", ".join(_sql_quote(rule[0]) for rule in _DEFAULT_RULES)
    # S608 suppressed: ids are quote-escaped literals from the hardcoded constant.
    op.execute(f"DELETE FROM dlp.dlp_rule WHERE id IN ({ids})")  # noqa: S608

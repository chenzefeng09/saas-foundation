"""add CHECK constraints for ropa_record.legal_basis and dsar_request.request_type

Normalizes any pre-existing lowercase values to the canonical UPPER_CASE
vocabulary, then enforces it with CHECK constraints. Mirrors the LegalBasis /
DsarRequestType enums in foundation_compliance.domain.enums.

Revision ID: 0002_compliance_enum_checks
Revises: 0001_compliance_init
Create Date: 2026-06-12 00:00:00 UTC
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_compliance_enum_checks"
down_revision: str | None = "0001_compliance_init"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# NOTE: keep these literal whitelists in sync with THREE places:
#   1. foundation_compliance.domain.enums.LegalBasis / DsarRequestType
#   2. the IN-list CHECK constraints created below
#   3. this migration's UPPER()+mapping normalization
# Alembic migrations are frozen snapshots, so we intentionally inline the
# literals here rather than importing the enums (which may drift later).
LEGAL_BASIS_VALUES = (
    "CONSENT", "CONTRACT", "LEGAL_OBLIGATION", "VITAL_INTEREST",
    "PUBLIC_TASK", "LEGITIMATE_INTEREST",
    "PIPL_CONSENT", "PIPL_SEPARATE_CONSENT", "PIPL_CONTRACT",
    "PIPL_HR_MANAGEMENT", "PIPL_LEGAL_DUTY", "PIPL_PUBLIC_HEALTH",
    "PIPL_PUBLIC_INTEREST", "PIPL_PUBLIC_DATA",
)
DSAR_REQUEST_TYPE_VALUES = (
    "ACCESS", "RECTIFICATION", "ERASURE", "RESTRICTION",
    "PORTABILITY", "OBJECTION", "AUTOMATED_DECISION",
)

# Explicit mapping for known Chinese / non-UPPER aliases that UPPER() cannot
# normalize. Only high-confidence synonyms — anything ambiguous is left to the
# residual check below so it fails loudly rather than being silently rewritten.
# Keys are matched after the UPPER() pass, against the trimmed raw value.
LEGAL_BASIS_ALIAS_MAP: dict[str, str] = {
    "合同履行": "PIPL_CONTRACT",
    "履行合同": "PIPL_CONTRACT",
    "同意": "PIPL_CONSENT",
    "知情同意": "PIPL_CONSENT",
    "单独同意": "PIPL_SEPARATE_CONSENT",
}
DSAR_REQUEST_TYPE_ALIAS_MAP: dict[str, str] = {}

LEGAL_BASIS_CK = "ropa_record_legal_basis_check"
DSAR_TYPE_CK = "dsar_request_request_type_check"


def _in_list(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{v}'" for v in values)


def _normalize_column(
    bind: sa.engine.Connection,
    *,
    table: str,
    column: str,
    allowed: tuple[str, ...],
    alias_map: dict[str, str],
) -> None:
    """Best-effort normalization of a constrained column before a CHECK is added.

    Steps:
      1. UPPER() pass — folds lowercase English aliases ('consent' -> 'CONSENT').
      2. Explicit alias map — handles known Chinese / free-text synonyms that
         UPPER() cannot touch ('合同履行' -> 'PIPL_CONTRACT').
      3. Residual guard — any value still outside the whitelist is NOT silently
         rewritten to a placeholder (that would mask dirty data). Instead the
         migration fails with the offending DISTINCT values listed, so ops can
         clean them manually before re-running.
    """
    qualified = f"compliance.{table}"

    # 1. UPPER() normalization.
    bind.execute(
        sa.text(
            f"UPDATE {qualified} SET {column} = UPPER({column}) "  # noqa: S608 - fixed identifiers
            f"WHERE {column} <> UPPER({column})"
        )
    )

    # 2. Explicit alias mapping (matched on the trimmed raw value).
    for raw, canonical in alias_map.items():
        bind.execute(
            sa.text(
                f"UPDATE {qualified} SET {column} = :canonical "  # noqa: S608 - fixed identifiers
                f"WHERE TRIM({column}) = :raw"
            ),
            {"canonical": canonical, "raw": raw},
        )

    # 3. Residual guard — fail loudly, never coerce to a placeholder.
    rows = bind.execute(
        sa.text(
            f"SELECT DISTINCT {column} FROM {qualified} "  # noqa: S608 - fixed identifiers
            f"WHERE {column} NOT IN ({_in_list(allowed)})"
        )
    ).fetchall()
    bad_values = sorted(r[0] for r in rows)
    if bad_values:
        raise RuntimeError(
            f"无法自动规范化 compliance.{table}.{column} 中的以下值"
            f" (请先人工清洗后重跑迁移): {bad_values}"
        )


def upgrade() -> None:
    bind = op.get_bind()

    _normalize_column(
        bind,
        table="ropa_record",
        column="legal_basis",
        allowed=LEGAL_BASIS_VALUES,
        alias_map=LEGAL_BASIS_ALIAS_MAP,
    )
    _normalize_column(
        bind,
        table="dsar_request",
        column="request_type",
        allowed=DSAR_REQUEST_TYPE_VALUES,
        alias_map=DSAR_REQUEST_TYPE_ALIAS_MAP,
    )

    op.create_check_constraint(
        LEGAL_BASIS_CK,
        "ropa_record",
        f"legal_basis IN ({_in_list(LEGAL_BASIS_VALUES)})",
        schema="compliance",
    )
    op.create_check_constraint(
        DSAR_TYPE_CK,
        "dsar_request",
        f"request_type IN ({_in_list(DSAR_REQUEST_TYPE_VALUES)})",
        schema="compliance",
    )


def downgrade() -> None:
    op.drop_constraint(DSAR_TYPE_CK, "dsar_request", schema="compliance", type_="check")
    op.drop_constraint(LEGAL_BASIS_CK, "ropa_record", schema="compliance", type_="check")

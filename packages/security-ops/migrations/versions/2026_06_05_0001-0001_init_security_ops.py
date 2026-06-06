"""init security_ops schema

Revision ID: 0001_security_ops_init
Revises:
Create Date: 2026-06-05 00:00:00 UTC
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_security_ops_init"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS security_ops")

    # ── scan_run ──────────────────────────────────────────────────────────────
    op.create_table(
        "scan_run",
        sa.Column("id", sa.String(40), primary_key=True),
        sa.Column("type", sa.String(20), nullable=False),
        sa.Column("tool", sa.String(50), nullable=False),
        sa.Column("target", sa.String(500), nullable=False),
        sa.Column("commit_sha", sa.String(64)),
        sa.Column("pipeline_id", sa.String(100)),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("sarif_s3_key", sa.String(500)),
        sa.Column(
            "findings_count",
            postgresql.JSONB(),
            nullable=False,
            server_default="{}",
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        schema="security_ops",
    )
    op.create_index(
        "idx_scan_run_type_status",
        "scan_run",
        ["type", "status"],
        schema="security_ops",
    )

    # ── vulnerability ─────────────────────────────────────────────────────────
    op.create_table(
        "vulnerability",
        sa.Column("id", sa.String(40), primary_key=True),
        sa.Column("source", sa.String(30), nullable=False),
        sa.Column("source_ref", sa.String(200)),
        sa.Column("cve_id", sa.String(30)),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("severity", sa.String(10), nullable=False),
        sa.Column("cvss_score", sa.Numeric(3, 1)),
        sa.Column("package_affected", sa.String(200)),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("found_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("due_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("assignee", sa.String(200)),
        sa.Column("fix_pr_url", sa.String(500)),
        sa.Column("closed_at", sa.DateTime(timezone=True)),
        sa.Column("exception_id", sa.String(40)),
        sa.Column("risk_acceptance_id", sa.String(40)),
        sa.Column("notes_md", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        schema="security_ops",
    )
    op.create_index(
        "idx_vuln_severity_status",
        "vulnerability",
        ["severity", "status"],
        schema="security_ops",
    )
    # Partial index for open vulns — cannot use op.create_index with postgresql_where portably
    op.execute(
        "CREATE INDEX idx_vuln_status_due ON security_ops.vulnerability (status, due_at) "
        "WHERE status NOT IN ('CLOSED','RISK_ACCEPTED','EXEMPTED')"
    )

    # ── incident ──────────────────────────────────────────────────────────────
    op.create_table(
        "incident",
        sa.Column("id", sa.String(40), primary_key=True),
        sa.Column("severity", sa.String(10), nullable=False),
        sa.Column("category", sa.String(30), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reported_by", sa.String(200), nullable=False),
        sa.Column("ic", sa.String(200)),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("containment_at", sa.DateTime(timezone=True)),
        sa.Column("resolved_at", sa.DateTime(timezone=True)),
        sa.Column("root_cause", sa.Text()),
        sa.Column("pir_s3_key", sa.String(500)),
        sa.Column("customers_notified", sa.Boolean()),
        sa.Column("regulators_notified", sa.Boolean()),
        sa.Column("affected_tenants", postgresql.ARRAY(sa.String())),
        sa.Column("audit_event_ids", postgresql.ARRAY(sa.String())),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        schema="security_ops",
    )
    op.create_index(
        "idx_incident_status",
        "incident",
        ["status", "severity"],
        schema="security_ops",
    )

    # ── sbom_record ───────────────────────────────────────────────────────────
    op.create_table(
        "sbom_record",
        sa.Column("id", sa.String(40), primary_key=True),
        sa.Column("image_ref", sa.String(500), nullable=False),
        sa.Column("format", sa.String(20), nullable=False, server_default="CycloneDX"),
        sa.Column("sbom_s3_key", sa.String(500)),
        sa.Column("attestation_digest", sa.String(200)),
        sa.Column("component_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("generator_tool", sa.String(50), nullable=False, server_default="syft"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        schema="security_ops",
    )
    op.create_index("idx_sbom_image_ref", "sbom_record", ["image_ref"], schema="security_ops")

    # ── sbom_watch ────────────────────────────────────────────────────────────
    op.create_table(
        "sbom_watch",
        sa.Column("id", sa.String(40), primary_key=True),
        sa.Column("image_ref", sa.String(500), nullable=False, unique=True),
        sa.Column("registered_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_scanned_at", sa.DateTime(timezone=True)),
        sa.Column("notify", postgresql.ARRAY(sa.String())),
        sa.Column("new_cves_count", sa.Integer(), nullable=False, server_default="0"),
        schema="security_ops",
    )

    # ── license_finding ───────────────────────────────────────────────────────
    op.create_table(
        "license_finding",
        sa.Column("id", sa.String(40), primary_key=True),
        sa.Column("scan_run_id", sa.String(40), nullable=False),
        sa.Column("package_name", sa.String(200), nullable=False),
        sa.Column("package_version", sa.String(100)),
        sa.Column("license_spdx", sa.String(100), nullable=False),
        sa.Column("verdict", sa.String(20), nullable=False),
        sa.Column("exception_id", sa.String(40)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        schema="security_ops",
    )
    op.create_index(
        "idx_license_scan_run",
        "license_finding",
        ["scan_run_id"],
        schema="security_ops",
    )

    # ── drill ─────────────────────────────────────────────────────────────────
    op.create_table(
        "drill",
        sa.Column("id", sa.String(40), primary_key=True),
        sa.Column("kind", sa.String(30), nullable=False),
        sa.Column("scheduled_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("pir_s3_key", sa.String(500)),
        sa.Column("participants", postgresql.ARRAY(sa.String())),
        sa.Column("scenario_runbook", sa.String(500)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        schema="security_ops",
    )

    # ── outbox ────────────────────────────────────────────────────────────────
    op.create_table(
        "security_ops_event_outbox",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.String(30)),
        sa.Column("event_type", sa.String(200), nullable=False),
        sa.Column("aggregate_id", sa.String(64)),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        sa.Column("request_id", sa.String(64)),
        sa.Column("occurred_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        schema="security_ops",
    )

    # ── RLS ───────────────────────────────────────────────────────────────────
    for table in (
        "scan_run",
        "vulnerability",
        "incident",
        "sbom_record",
        "sbom_watch",
        "license_finding",
        "drill",
        "security_ops_event_outbox",
    ):
        op.execute(f"ALTER TABLE security_ops.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE security_ops.{table} FORCE ROW LEVEL SECURITY")

    # ── Grants ────────────────────────────────────────────────────────────────
    op.execute(
        "GRANT USAGE ON SCHEMA security_ops TO app_user, app_admin, app_observability"
    )
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE "
        "ON ALL TABLES IN SCHEMA security_ops TO app_user, app_admin"
    )
    op.execute(
        "GRANT SELECT ON ALL TABLES IN SCHEMA security_ops TO app_observability"
    )


def downgrade() -> None:
    op.execute("DROP SCHEMA IF EXISTS security_ops CASCADE")

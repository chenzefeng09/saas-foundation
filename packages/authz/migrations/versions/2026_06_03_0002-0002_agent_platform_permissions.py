"""agent-platform permission catalog

Revision ID: 0002_agent_platform_permissions
Revises: 0001_authz_init
Create Date: 2026-06-03 00:00:00 UTC

Inserts all agent-platform permission definitions into
authz.permission_definition (global catalog; no RLS).

Actions catalogued
------------------
session: read, create, update, delete
session.message: read, create, delete
session.attachment: read, create
run: create, read, cancel
sandbox: read, stop
skill: read, create, update, delete
document: read, create, update, search
mcp_server: read, create, update, delete
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_agent_platform_permissions"
down_revision: str | None = "0001_authz_init"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# ---------------------------------------------------------------------------
# Canonical permission list
# id convention: "<service>.<resource_type>.<action>" or "<service>.<action>"
# service = first dot-segment of the full action string.
# ---------------------------------------------------------------------------
_PERMISSIONS = [
    # ── session ────────────────────────────────────────────────────────────
    {
        "id": "session.read",
        "service": "session",
        "resource_type": "session",
        "action": "read",
        "description": "List or retrieve sessions for the current tenant.",
    },
    {
        "id": "session.create",
        "service": "session",
        "resource_type": "session",
        "action": "create",
        "description": "Create a new session.",
    },
    {
        "id": "session.update",
        "service": "session",
        "resource_type": "session",
        "action": "update",
        "description": "Update session metadata or title.",
    },
    {
        "id": "session.delete",
        "service": "session",
        "resource_type": "session",
        "action": "delete",
        "description": "Delete a session and its associated data.",
    },
    # ── session.message ────────────────────────────────────────────────────
    {
        "id": "session.message.read",
        "service": "session",
        "resource_type": "session.message",
        "action": "read",
        "description": "List or stream messages in a session.",
    },
    {
        "id": "session.message.create",
        "service": "session",
        "resource_type": "session.message",
        "action": "create",
        "description": "Post a new message to a session.",
    },
    {
        "id": "session.message.delete",
        "service": "session",
        "resource_type": "session.message",
        "action": "delete",
        "description": "Delete (rewind/truncate) messages in a session.",
    },
    # ── session.attachment ─────────────────────────────────────────────────
    {
        "id": "session.attachment.read",
        "service": "session",
        "resource_type": "session.attachment",
        "action": "read",
        "description": "List or download session attachments.",
    },
    {
        "id": "session.attachment.create",
        "service": "session",
        "resource_type": "session.attachment",
        "action": "create",
        "description": "Upload a file attachment to a session.",
    },
    # ── run ────────────────────────────────────────────────────────────────
    {
        "id": "run.create",
        "service": "run",
        "resource_type": "run",
        "action": "create",
        "description": "Spawn a new agent run / sandbox container.",
    },
    {
        "id": "run.read",
        "service": "run",
        "resource_type": "run",
        "action": "read",
        "description": "Read run status and results.",
    },
    {
        "id": "run.cancel",
        "service": "run",
        "resource_type": "run",
        "action": "cancel",
        "description": "Cancel a running or pending agent run.",
    },
    # ── sandbox ────────────────────────────────────────────────────────────
    {
        "id": "sandbox.read",
        "service": "sandbox",
        "resource_type": "sandbox",
        "action": "read",
        "description": "List sandbox containers for the current tenant.",
    },
    {
        "id": "sandbox.stop",
        "service": "sandbox",
        "resource_type": "sandbox",
        "action": "stop",
        "description": "Stop a running sandbox container.",
    },
    # ── skill ──────────────────────────────────────────────────────────────
    {
        "id": "skill.read",
        "service": "skill",
        "resource_type": "skill",
        "action": "read",
        "description": "List or retrieve skills and versions.",
    },
    {
        "id": "skill.create",
        "service": "skill",
        "resource_type": "skill",
        "action": "create",
        "description": "Create a new skill record.",
    },
    {
        "id": "skill.update",
        "service": "skill",
        "resource_type": "skill",
        "action": "update",
        "description": "Upload a new skill version or update skill metadata.",
    },
    {
        "id": "skill.delete",
        "service": "skill",
        "resource_type": "skill",
        "action": "delete",
        "description": "Delete a skill version.",
    },
    # ── document ───────────────────────────────────────────────────────────
    {
        "id": "document.read",
        "service": "document",
        "resource_type": "document",
        "action": "read",
        "description": "List or retrieve knowledge-base documents.",
    },
    {
        "id": "document.create",
        "service": "document",
        "resource_type": "document",
        "action": "create",
        "description": "Upload a new document to the knowledge base.",
    },
    {
        "id": "document.update",
        "service": "document",
        "resource_type": "document",
        "action": "update",
        "description": "Trigger ingest / re-embed an existing document.",
    },
    {
        "id": "document.search",
        "service": "document",
        "resource_type": "document",
        "action": "search",
        "description": "Semantic search over ingested document chunks.",
    },
    {
        "id": "document.delete",
        "service": "document",
        "resource_type": "document",
        "action": "delete",
        "description": "Delete a knowledge-base document and its chunks.",
    },
    # ── mcp_server ─────────────────────────────────────────────────────────
    {
        "id": "mcp_server.read",
        "service": "mcp_server",
        "resource_type": "mcp_server",
        "action": "read",
        "description": "List or retrieve registered MCP servers.",
    },
    {
        "id": "mcp_server.create",
        "service": "mcp_server",
        "resource_type": "mcp_server",
        "action": "create",
        "description": "Register a new MCP server.",
    },
    {
        "id": "mcp_server.update",
        "service": "mcp_server",
        "resource_type": "mcp_server",
        "action": "update",
        "description": "Update an existing MCP server configuration.",
    },
    {
        "id": "mcp_server.delete",
        "service": "mcp_server",
        "resource_type": "mcp_server",
        "action": "delete",
        "description": "Delete a registered MCP server.",
    },
    # ── platform (cross-tenant admin) ─────────────────────────────────────────
    # Covered by super_admin's permissions=["*"] wildcard.
    # Listed explicitly so the permission catalogue is complete.
    {
        "id": "platform.admin",
        "service": "platform",
        "resource_type": "platform",
        "action": "admin",
        "description": (
            "Full cross-tenant platform administration access. "
            "Only super_admin role (permissions=[\"*\"]) should have this. "
            "Never grant to tenant-level roles."
        ),
    },
]


def upgrade() -> None:
    perm_table = sa.table(
        "permission_definition",
        sa.column("id", sa.String),
        sa.column("service", sa.String),
        sa.column("resource_type", sa.String),
        sa.column("action", sa.String),
        sa.column("description", sa.Text),
        sa.column("risk_level", sa.String),
        sa.column("requires_mfa", sa.Boolean),
        sa.column("requires_4eyes", sa.Boolean),
        sa.column("requires_pam_jit", sa.Boolean),
        sa.column("requires_business_hours", sa.Boolean),
        sa.column("is_system", sa.Boolean),
        schema="authz",
    )

    rows = [
        {
            "id": p["id"],
            "service": p["service"],
            "resource_type": p["resource_type"],
            "action": p["action"],
            "description": p["description"],
            "risk_level": "LOW",
            "requires_mfa": False,
            "requires_4eyes": False,
            "requires_pam_jit": False,
            "requires_business_hours": False,
            "is_system": True,
        }
        for p in _PERMISSIONS
    ]

    # Idempotent: skip rows whose id is already present.
    op.execute(
        perm_table.insert().prefix_with("OR IGNORE")
        if _is_sqlite()
        else sa.text(  # nosemgrep: avoid-sqlalchemy-text  # DDL migration; all values are module-level constants, no user input
            "INSERT INTO authz.permission_definition "
            "(id, service, resource_type, action, description, risk_level, "
            " requires_mfa, requires_4eyes, requires_pam_jit, requires_business_hours, is_system) "
            "VALUES "
            + ", ".join(
                f"('{r['id']}', '{r['service']}', '{r['resource_type']}', '{r['action']}', "
                f"'{r['description']}', 'LOW', false, false, false, false, true)"
                for r in rows
            )
            + " ON CONFLICT (id) DO NOTHING"
        )
    )


def _is_sqlite() -> bool:
    """Detect SQLite (used in unit tests) to switch to OR IGNORE syntax."""
    try:
        bind = op.get_bind()
        return bind.dialect.name == "sqlite"
    except Exception:  # noqa: BLE001
        return False


def downgrade() -> None:
    ids = ", ".join(f"'{p['id']}'" for p in _PERMISSIONS)
    op.execute(
        sa.text(f"DELETE FROM authz.permission_definition WHERE id IN ({ids})")  # nosemgrep: avoid-sqlalchemy-text  # DDL migration; ids are module-level permission id constants, no user input
    )

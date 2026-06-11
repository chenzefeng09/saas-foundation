"""Add admin_all policy to identity.outbox.

Every other identity table carries an ``admin_all`` policy
(``app.actor = 'ADMIN'`` via admin_session_scope); outbox was the lone
exception.  Without it, platform-scoped audit events (tenant_id NULL,
published under the admin engine) fail on ``INSERT … RETURNING``:
PostgreSQL applies the SELECT policies to rows returned by RETURNING,
and ``outbox_tenant_select`` only matches exact-tenant rows.

Revision ID: 0003_outbox_admin_policy
Revises: 0002_platform_sso
"""

from __future__ import annotations

from alembic import op

revision = "0003_outbox_admin_policy"
down_revision = "0002_platform_sso"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        'CREATE POLICY admin_all ON identity."outbox" '
        "FOR ALL TO app_admin "
        "USING (current_setting('app.actor', true) = 'ADMIN') "
        "WITH CHECK (current_setting('app.actor', true) = 'ADMIN')"
    )


def downgrade() -> None:
    op.execute('DROP POLICY admin_all ON identity."outbox"')

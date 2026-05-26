-- =============================================================================
-- 创建 tenant.tenant 元数据表（其他所有租户表的外键目标）
-- =============================================================================

\c foundation

CREATE TABLE IF NOT EXISTS tenant.tenant (
    id         TEXT PRIMARY KEY CHECK (id ~ '^tnt_[0-9A-Z]{26}$'),
    name       TEXT NOT NULL,
    tier       TEXT NOT NULL DEFAULT 'FREE'
               CHECK (tier IN ('FREE', 'PRO', 'BUSINESS', 'ENTERPRISE', 'DEDICATED')),
    status     TEXT NOT NULL DEFAULT 'ACTIVE'
               CHECK (status IN ('ACTIVE', 'SUSPENDED', 'TERMINATING', 'TERMINATED')),
    compliance_modes TEXT[] NOT NULL DEFAULT ARRAY['pipl']::TEXT[],
    data_residency   TEXT NOT NULL DEFAULT 'cn-only',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Seed dev 租户
INSERT INTO tenant.tenant (id, name, tier) VALUES
    ('tnt_01J5DEV0000000000000000AA', 'Dev Tenant A', 'PRO'),
    ('tnt_01J5DEV0000000000000000BB', 'Dev Tenant B', 'PRO')
ON CONFLICT (id) DO NOTHING;

SELECT id, name, tier FROM tenant.tenant;

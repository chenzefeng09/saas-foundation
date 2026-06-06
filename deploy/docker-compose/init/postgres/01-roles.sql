-- =============================================================================
-- 初始化 saas-foundation 标准角色
-- 此脚本在 Postgres 容器首次启动时由 docker-entrypoint-initdb.d 自动执行
-- 详见 docs/multi-tenancy.md §3
-- =============================================================================

\set app_user_password    `echo $APP_USER_PASSWORD`
\set app_admin_password   `echo $APP_ADMIN_PASSWORD`
\set app_migrator_password `echo $APP_MIGRATOR_PASSWORD`
\set app_obs_password     `echo $APP_OBSERVABILITY_PASSWORD`

-- app_user: 业务运行时主力，受 RLS 约束
CREATE ROLE app_user LOGIN PASSWORD :'app_user_password' NOBYPASSRLS NOSUPERUSER NOCREATEDB NOCREATEROLE;

-- app_admin: 管理控制台，受 RLS 约束但走 admin policy
CREATE ROLE app_admin LOGIN PASSWORD :'app_admin_password' NOBYPASSRLS NOSUPERUSER NOCREATEDB NOCREATEROLE;

-- app_migrator: 迁移专用，BYPASSRLS（仅 CI 使用）
CREATE ROLE app_migrator LOGIN PASSWORD :'app_migrator_password' BYPASSRLS NOSUPERUSER CREATEDB NOCREATEROLE;

-- app_observability: 只读，看全平台
CREATE ROLE app_observability LOGIN PASSWORD :'app_obs_password' NOBYPASSRLS NOSUPERUSER NOCREATEDB NOCREATEROLE;

-- 平台 schema（无 RLS，只允许 admin/migrator 写）
CREATE SCHEMA IF NOT EXISTS platform AUTHORIZATION app_migrator;
CREATE SCHEMA IF NOT EXISTS tenant AUTHORIZATION app_migrator;

GRANT USAGE ON SCHEMA platform, tenant TO app_user, app_admin, app_observability;
GRANT SELECT ON ALL TABLES IN SCHEMA platform TO app_user, app_observability;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA tenant TO app_admin;
GRANT SELECT ON ALL TABLES IN SCHEMA tenant TO app_user, app_observability;

-- 为每个 service 预创建 schema（service 的 alembic 后续接管）
CREATE SCHEMA IF NOT EXISTS identity AUTHORIZATION app_migrator;
CREATE SCHEMA IF NOT EXISTS authz    AUTHORIZATION app_migrator;
CREATE SCHEMA IF NOT EXISTS org      AUTHORIZATION app_migrator;
CREATE SCHEMA IF NOT EXISTS billing  AUTHORIZATION app_migrator;
CREATE SCHEMA IF NOT EXISTS audit    AUTHORIZATION app_migrator;
CREATE SCHEMA IF NOT EXISTS lifecycle AUTHORIZATION app_migrator;

CREATE SCHEMA IF NOT EXISTS crypto       AUTHORIZATION app_migrator;
CREATE SCHEMA IF NOT EXISTS feature_flag AUTHORIZATION app_migrator;
CREATE SCHEMA IF NOT EXISTS search       AUTHORIZATION app_migrator;
CREATE SCHEMA IF NOT EXISTS llm_gateway  AUTHORIZATION app_migrator;

GRANT USAGE ON SCHEMA identity, authz, org, billing, audit, lifecycle, crypto, feature_flag, search, llm_gateway
    TO app_user, app_admin, app_observability;

ALTER DEFAULT PRIVILEGES FOR ROLE app_migrator IN SCHEMA identity, authz, org, billing, audit, lifecycle, crypto, feature_flag, search, llm_gateway
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_user, app_admin;
ALTER DEFAULT PRIVILEGES FOR ROLE app_migrator IN SCHEMA identity, authz, org, billing, audit, lifecycle, crypto, feature_flag, search, llm_gateway
    GRANT SELECT ON TABLES TO app_observability;
ALTER DEFAULT PRIVILEGES FOR ROLE app_migrator IN SCHEMA identity, authz, org, billing, audit, lifecycle, crypto, feature_flag, search, llm_gateway
    GRANT USAGE ON SEQUENCES TO app_user, app_admin;

-- Keycloak 自己的数据库
CREATE DATABASE keycloak OWNER app_migrator;
GRANT ALL PRIVILEGES ON DATABASE keycloak TO app_migrator;

-- Unleash 自己的数据库
CREATE DATABASE unleash OWNER app_migrator;
GRANT ALL PRIVILEGES ON DATABASE unleash TO app_migrator;

-- 输出确认
SELECT rolname, rolbypassrls, rolsuper FROM pg_roles
WHERE rolname LIKE 'app_%' ORDER BY rolname;

-- alembic 迁移需 CREATE 权限（即使 schema 已存在）
GRANT CREATE ON DATABASE foundation TO app_migrator;

-- Note: GRANT REFERENCES ON tenant.tenant is done in 02-tenant-table.sql after the table is created.

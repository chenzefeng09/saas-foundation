# 多租户与 Postgres RLS 基线

> 配套 [CONVENTIONS.md](./CONVENTIONS.md) §3、§8。所有 service、所有 package 必须遵守。违反此基线的 schema / 代码不予合并。
>
> 这是底座**最容易引发越权事故**的一份契约，所有改动需 ≥2 架构师 sign-off + ADR 记录。

---

## 0. TL;DR — 一页速查

```
租户隔离的三道墙（顺序就是失效时的回退顺序）：
  1️⃣ 网关层 — JWT 提取 tenant_id 强制注入 X-Tenant-Id（业务无法绕过）
  2️⃣ 应用层 — DB 连接 acquire 时 SET LOCAL app.tenant_id（事务内有效）
  3️⃣ 数据层 — Postgres RLS policy 强制过滤（FORCE ROW LEVEL SECURITY）

所有租户表（强制）：
  - 含 tenant_id TEXT NOT NULL 列（指向 tenant.id）
  - 启用 RLS + FORCE RLS
  - 至少 1 个以 tenant_id 为前导列的复合索引
  - 至少 4 个 policy：tenant_select / tenant_insert / tenant_update / tenant_delete

PgBouncer 必须用 transaction 或 session 模式（statement 模式禁用）。

DB 角色（强制）：
  - app_user        — 应用走的角色，受 RLS 约束
  - app_admin       — 管理控制台走的角色，FORCE RLS 仍生效，多一组 admin policy
  - app_migrator    — Alembic 迁移专用，BYPASSRLS（仅它有）
  - app_observability — 监控/审计只读，自定义只读 policy
  禁止业务代码用 superuser 或 BYPASSRLS 角色连接。
```

---

## 1. 设计目标与威胁模型

### 1.1 目标
- **强默认隔离**：业务代码忘写 `WHERE tenant_id=...` 也不会越权
- **不可绕过**：即使应用层有 SQL 注入，最坏只能拿到当前租户数据
- **可证明**：RLS 是数据库强制行为，可作为合规审计证据
- **可观察**：所有越权尝试可被审计捕获
- **性能可接受**：千万行级表读写不超过应用层 WHERE 过滤 5%

### 1.2 威胁模型（对应缓解）
| 威胁 | 缓解 |
|---|---|
| 业务代码漏写 `WHERE tenant_id` | RLS policy 强制过滤 |
| SQL 注入 | RLS + 参数化查询 + 最小权限角色 |
| 业务代码错传 `tenant_id` 参数到 SDK | SDK 不接受该参数（CONVENTIONS §3.3） |
| DB 连接从池里复用，前一请求的会话状态污染 | `SET LOCAL` + 事务边界 + 连接归还前 RESET |
| 应用层用 superuser 连库导致 RLS 失效 | 不允许 superuser 连接；CI 静态扫描 |
| 表 owner 默认绕过 RLS | `ALTER TABLE ... FORCE ROW LEVEL SECURITY` |
| 迁移角色把数据搬错租户 | 迁移专用 `app_migrator` 角色 + 审批流程 |
| 跨租户合法操作（计费汇总等）走错租户 | SDK `as_tenant()` 显式声明 + 审计强制 |
| 连接池非 transaction/session 模式导致 SET LOCAL 失效 | PgBouncer 模式硬约束 + 启动健康检查 |

---

## 2. 租户上下文如何到达 RLS

```
JWT (tenant_id claim)
    │
    ▼
API Gateway 注入 X-Tenant-Id header（覆盖客户端任何值）
    │
    ▼
Service middleware 把 X-Tenant-Id 写入 contextvars (FoundationContext)
    │
    ▼
DB session 工厂 acquire 连接时执行：
    BEGIN;
    SET LOCAL app.tenant_id = '<tenant_id>';
    SET LOCAL app.user_id   = '<user_id>';
    SET LOCAL app.actor     = 'USER';  -- 或 'SYSTEM' / 'MIGRATOR' / 'ADMIN'
    │
    ▼
ORM/SQL 执行 — Postgres RLS policy 读取 current_setting('app.tenant_id') 过滤
    │
    ▼
COMMIT / ROLLBACK 后 SET LOCAL 自动失效
    │
    ▼
连接归还池前 RESET ALL（防御性保护，详见 §4）
```

**关键**：业务层代码**永远不写** `SET LOCAL`。这是数据库适配器层的责任。业务层代码出现 `SET LOCAL` 视为 bug。

---

## 3. Postgres 角色与权限模型

### 3.1 角色定义

| 角色 | LOGIN | BYPASSRLS | 用途 | 谁能用 |
|---|---|---|---|---|
| `foundation_superuser` | ✅ | ✅ | 仅限 DBA 手动救场 | 人 |
| `app_migrator` | ✅ | ✅ | Alembic schema 迁移、数据搬运 | CI 迁移 job |
| `app_user` | ✅ | ❌ | **业务运行时主力**，受 RLS 约束 | 所有 service runtime |
| `app_admin` | ✅ | ❌ | 管理控制台 / SRE 操作；FORCE RLS 仍生效，但走 admin policy | admin-console service |
| `app_observability` | ✅ | ❌ | 审计 / 监控 / 报表只读；自定义只读 policy | audit / metrics exporter |

### 3.2 创建脚本（每个 service 启动前由 operator 跑一次）

```sql
-- 一次性创建（幂等）
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_user') THEN
        CREATE ROLE app_user LOGIN PASSWORD :'app_user_password' NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_admin') THEN
        CREATE ROLE app_admin LOGIN PASSWORD :'app_admin_password' NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_migrator') THEN
        CREATE ROLE app_migrator LOGIN PASSWORD :'app_migrator_password' BYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_observability') THEN
        CREATE ROLE app_observability LOGIN PASSWORD :'app_observability_password' NOBYPASSRLS;
    END IF;
END$$;

-- 表级权限（按 service schema 重复）
GRANT USAGE ON SCHEMA identity TO app_user, app_admin, app_observability;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA identity TO app_user, app_admin;
GRANT SELECT ON ALL TABLES IN SCHEMA identity TO app_observability;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA identity TO app_user, app_admin;

ALTER DEFAULT PRIVILEGES IN SCHEMA identity
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_user, app_admin;
ALTER DEFAULT PRIVILEGES IN SCHEMA identity
    GRANT SELECT ON TABLES TO app_observability;
```

### 3.3 禁令
- ❌ 业务 service runtime 连接**禁止**用 `app_migrator`、`foundation_superuser`
- ❌ 任何 `GRANT BYPASSRLS` 给 `app_user` / `app_admin` 的 PR 拒绝合并
- ❌ 在 production 数据库直连用 `psql` 跑 DML 必须用 `app_admin` 并显式开启事务

CI 检查：扫描 helm values / k8s secret 引用，禁止 service 配 `app_migrator` 凭据；扫描代码禁止出现 `BYPASSRLS`。

---

## 4. PgBouncer 配置约束

底座 medium/large profile 强制走 PgBouncer。**配置错了 RLS 就废了。**

### 4.1 必选参数

```ini
[pgbouncer]
pool_mode = transaction          ; 不允许 statement；session 也可但浪费连接
server_reset_query =             ; 留空！transaction mode 自动 reset，不要叠加
server_reset_query_always = 0
ignore_startup_parameters = extra_float_digits,application_name
max_client_conn = 5000
default_pool_size = 50           ; 按 service 后端调
reserve_pool_size = 10
reserve_pool_timeout = 3
server_lifetime = 3600
server_idle_timeout = 600
query_wait_timeout = 30
```

### 4.2 为什么必须 transaction 模式
- `SET LOCAL` 的语义是"事务内有效"，每次事务结束自动释放
- transaction 模式下连接归还到池前，事务必须已 COMMIT/ROLLBACK → 状态干净
- statement 模式下每个 statement 之间会换连接，`SET LOCAL` 失效 → **会读到其他租户数据**

### 4.3 为什么 `server_reset_query` 留空
- transaction 模式下 PgBouncer 自动管理事务边界，不需要 DISCARD ALL
- 加 DISCARD ALL 会**强制断开 prepared statement、临时表、会话锁**，性能掉一截
- 如果误用 session 模式，必须改成 `server_reset_query = DISCARD ALL` 防泄漏

### 4.4 应用层防御性双保险
即使 PgBouncer 配置正确，应用层 ORM 仍要：
- 每次 acquire 后**显式开 transaction + SET LOCAL**
- 事务结束（提交或回滚）**再归还连接**
- 检测连接异常时 `DISCARD ALL` 后再归还

### 4.5 启动健康检查（service 启动时跑一次）
```python
# foundation_common.db.health
async def verify_pgbouncer_mode(pool) -> None:
    """If we're behind PgBouncer, refuse to start unless mode is transaction/session."""
    async with pool.acquire() as conn:
        mode = await conn.fetchval("SHOW pool_mode")
        if mode == "statement":
            raise RuntimeError(
                "PgBouncer pool_mode=statement is unsafe for RLS. "
                "Set pool_mode=transaction in pgbouncer.ini."
            )
```

---

## 5. 数据库适配器层契约

每个 service 的 `adapters/db.py` 必须提供 `session_for_request()`，使用方式：

```python
# adapters/db.py
from contextlib import asynccontextmanager
from foundation_common.context import current_context

@asynccontextmanager
async def session_for_request():
    """Acquire DB session bound to current tenant context.

    Caller MUST use as async context manager. SET LOCAL is applied inside
    a transaction, released on commit/rollback. Never share session across
    contexts.
    """
    ctx = current_context()  # raises if no context
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                "SELECT set_config('app.tenant_id', $1, true),"
                "       set_config('app.user_id', $2, true),"
                "       set_config('app.actor', $3, true)",
                ctx.tenant_id,
                ctx.user_id or "",
                "USER",  # or SYSTEM / MIGRATOR / ADMIN
            )
            yield conn
```

> 用 `set_config(name, value, is_local=true)` 替代 `SET LOCAL`，因为参数化更安全 + 一次设多个。`is_local=true` 等价于 `SET LOCAL`。

### 5.1 system / cross-tenant 场景

```python
@asynccontextmanager
async def session_as_system():
    """For platform-level workers (billing rollups, compliance scans).

    Uses app_admin role + sets actor=SYSTEM. Audited.
    """
    # emit audit event before acquiring
    ...
    async with admin_pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                "SELECT set_config('app.tenant_id', '', true),"
                "       set_config('app.actor', 'SYSTEM', true)"
            )
            yield conn
```

### 5.2 禁令
- ❌ 业务代码出现裸 `pool.acquire()`
- ❌ 业务代码出现 `SET LOCAL` / `set_config('app.*', ...)`
- ❌ 业务代码出现 `DISCARD ALL`

CI 用 Semgrep 规则扫描。

---

## 6. Schema 约定

### 6.1 强制列

每张租户表必须含：

```sql
tenant_id   TEXT        NOT NULL,
id          TEXT        NOT NULL PRIMARY KEY,  -- '<type>_<ULID>'
created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
deleted_at  TIMESTAMPTZ,                       -- 软删除标记
created_by  TEXT,                              -- user_id 或 'SYSTEM'
updated_by  TEXT,
FOREIGN KEY (tenant_id) REFERENCES tenant.tenant(id) ON DELETE RESTRICT
```

外键策略 `ON DELETE RESTRICT`：硬删租户必须先迁/销毁数据（详见 lifecycle）。

### 6.2 索引

**强制规则**：所有租户表至少 1 个**以 tenant_id 为前导列**的复合索引。

理由：RLS policy 翻译成 `WHERE tenant_id = current_setting(...)`，前导列对应不上索引时全表扫描，千万行表性能崩坏。

```sql
-- 推荐基线索引
CREATE INDEX user_tenant_id_idx        ON identity.user (tenant_id);
CREATE UNIQUE INDEX user_tenant_email_idx
    ON identity.user (tenant_id, email) WHERE deleted_at IS NULL;
CREATE INDEX user_tenant_created_idx   ON identity.user (tenant_id, created_at DESC);
```

唯一约束**必须**带 `tenant_id`：不同租户的同名 email 可共存。

### 6.3 表命名

- schema 名 = service 名：`identity`、`authz`、`org`、`billing`、...
- 表名单数小写：`user`、`role`、`role_binding`
- 关联表：`<a>_<b>`，例 `user_role`、`team_member`

### 6.4 不带 tenant_id 的表（少数白名单）

仅以下表允许无 `tenant_id`（即"平台级表"）：
- `tenant.tenant` 本身（租户元数据）
- `platform.feature_flag_definition`（功能开关定义；启用关系另立 `tenant_feature_flag` 带 tenant_id）
- `platform.compliance_mode`（合规模式注册表）
- `platform.error_code`（错误码注册表）
- 第三方组件自管表（Keycloak / Unleash / OPA bundles）

平台级表**不启用 RLS**，但只允许 `app_admin` / `app_migrator` 写，`app_user` 只读。

新增"无 tenant_id 表"必须走 ADR 评审。

---

## 7. RLS Policy 标准模板

### 7.1 启用 RLS

```sql
ALTER TABLE identity.user ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.user FORCE ROW LEVEL SECURITY;  -- 关键：表 owner 也受约束
```

`FORCE ROW LEVEL SECURITY` 缺失是常见漏洞——默认表 owner 绕过 RLS，意味着任何用 owner 角色的连接都能看全租户数据。

### 7.2 标准四 policy 模板

```sql
-- 1) SELECT：只能看自己租户的非删数据
CREATE POLICY user_tenant_select ON identity.user
    FOR SELECT TO app_user
    USING (
        tenant_id = current_setting('app.tenant_id', true)
        AND (deleted_at IS NULL OR current_setting('app.show_deleted', true) = 'true')
    );

-- 2) INSERT：插入时 tenant_id 必须等于当前会话
CREATE POLICY user_tenant_insert ON identity.user
    FOR INSERT TO app_user
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

-- 3) UPDATE：USING 限制能改谁；WITH CHECK 限制改完后 tenant_id 不能跨租户
CREATE POLICY user_tenant_update ON identity.user
    FOR UPDATE TO app_user
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

-- 4) DELETE：限制能删谁
CREATE POLICY user_tenant_delete ON identity.user
    FOR DELETE TO app_user
    USING (tenant_id = current_setting('app.tenant_id', true));
```

要点：
- `current_setting(name, true)`：第二个参数 `true` 表示"缺失时返回 NULL 而非报错"。配合 USING 表达式 `tenant_id = NULL`（永远 false）保证未设置会话变量时**默认拒绝**，而不是"看不到 RLS 限制 = 全开放"
- UPDATE 必须同时给 USING + WITH CHECK，否则可能允许"读到我自己的行，但改成别人的 tenant_id"

### 7.3 admin policy

`app_admin` 走管理控制台，需要看全平台或跨租户视图，但仍受 RLS 约束（保护边界），用单独 policy：

```sql
CREATE POLICY user_admin_select ON identity.user
    FOR SELECT TO app_admin
    USING (
        -- admin 必须显式指定 tenant_id 或 'ALL'
        current_setting('app.tenant_id', true) = '*ALL*'
        OR tenant_id = current_setting('app.tenant_id', true)
    );

-- INSERT/UPDATE/DELETE 不放开；管理后台对租户数据的修改也必须切到该租户上下文
```

`app.tenant_id = '*ALL*'` 是 admin 专属约定值，业务 service 不允许使用。

### 7.4 observability policy

```sql
CREATE POLICY user_observability_select ON identity.user
    FOR SELECT TO app_observability
    USING (true);  -- 只读，看全平台
```

但 `app_observability` 角色本身在 `GRANT` 阶段就只有 SELECT，不需 INSERT/UPDATE/DELETE policy。

### 7.5 Policy 命名规范

```
<table>_<persona>_<verb>
```

- `<table>`：表短名
- `<persona>`：`tenant` / `admin` / `observability` / `migrator`
- `<verb>`：`select` / `insert` / `update` / `delete` / `all`

例：`role_binding_tenant_select`、`order_admin_update`。

### 7.6 Policy 生成器

为避免手写遗漏，提供 `foundation_common.db.rls` 模板：

```python
from foundation_common.db.rls import standard_tenant_policies

# Alembic migration
def upgrade():
    op.execute(standard_tenant_policies("identity.user"))
```

生成的 SQL 包含完整四 policy + admin policy + FORCE RLS。

---

## 8. Alembic 迁移规范

### 8.1 角色
- 迁移用 `app_migrator`（BYPASSRLS）连接
- CI/CD pipeline 才能用迁移凭据；开发本地用 docker-compose 内的本地实例

### 8.2 模板

```python
# alembic/versions/20260522_0001_create_user.py
"""create identity.user table

Revision ID: 0001
"""
from alembic import op
import sqlalchemy as sa
from foundation_common.db.rls import standard_tenant_policies

revision = "0001"
down_revision = None

def upgrade():
    op.execute("CREATE SCHEMA IF NOT EXISTS identity")
    op.create_table(
        "user",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("tenant_id", sa.Text, sa.ForeignKey("tenant.tenant.id"), nullable=False),
        sa.Column("email", sa.Text, nullable=False),
        sa.Column("status", sa.Text, nullable=False, server_default="ACTIVE"),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True),
                  server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True),
                  server_default=sa.func.now(), nullable=False),
        sa.Column("deleted_at", sa.TIMESTAMP(timezone=True)),
        sa.Column("created_by", sa.Text),
        sa.Column("updated_by", sa.Text),
        schema="identity",
    )

    # Indexes — tenant_id leading
    op.create_index("user_tenant_id_idx", "user", ["tenant_id"], schema="identity")
    op.create_index(
        "user_tenant_email_idx",
        "user",
        ["tenant_id", "email"],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL"),
        schema="identity",
    )

    # RLS + standard policies
    op.execute(standard_tenant_policies("identity.user"))

def downgrade():
    op.drop_table("user", schema="identity")
```

### 8.3 CI 校验

CI 在 migration PR 上跑：
1. `alembic upgrade head` 跑通
2. **RLS 强制扫描**：对所有迁移完后的表跑：
   ```sql
   SELECT n.nspname AS schema, c.relname AS table, c.relrowsecurity, c.relforcerowsecurity
   FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
   WHERE c.relkind='r' AND n.nspname NOT IN ('pg_catalog','information_schema','tenant','platform');
   ```
   任何 `relrowsecurity=false` 或 `relforcerowsecurity=false` 的表，**除白名单外**，CI 失败
3. **tenant_id 索引扫描**：对所有 RLS 表检查至少一个索引以 tenant_id 为第一列，否则失败
4. **Policy 完整性扫描**：每张 RLS 表必须有 select/insert/update/delete 各至少 1 个 policy

---

## 9. 性能

### 9.1 经验值（参考 PlanetScale / pganalyze 公开基准）
- 50M 行表 / 10k 租户 / 复合索引齐全：policy 评估均值 **0.3ms**
- `SET LOCAL` 调用：<0.1ms
- 500 并发连接对比应用层 WHERE：**无可测降级**
- 缺索引时：单查询从 ms 级退化到 s 级，**两个数量级差距**

**结论**：RLS 性能问题 99% 是缺索引，不是 RLS 本身。

### 9.2 性能检查清单
- [ ] 每张 RLS 表至少 1 个 tenant_id 前导索引
- [ ] 热点查询的过滤条件全部走索引（`EXPLAIN` 看 Index Scan，不是 Seq Scan）
- [ ] 大表（>10M 行）按 `tenant_id` HASH partition（postgres native partition）
- [ ] 高 QPS 表（>1k/s 写）建议 partial index：`WHERE deleted_at IS NULL`
- [ ] 跨租户聚合用 `app_observability` 物化视图 + 定时刷新

### 9.3 大租户 vs 小租户
- 1 万小租户共享同表 → 表行数大但每租户行数少；索引高效
- 1 个大租户占 90% 数据 → 索引选择性下降；考虑大租户独立 schema（SaaS Business 套餐）或独立 db（Enterprise 套餐）。详见 §11

---

## 10. 测试约束

### 10.1 单元测试
- 所有 service 测试**禁止裸跑** DB 查询
- 用 `with tenant_context("tnt_test_a")` 包裹
- pytest fixture `with_tenant` 强制提供

### 10.2 RLS 越权 fuzz 测试（强制）

每个 service 的 `tests/security/` 必须含：

```python
# tests/security/test_rls_isolation.py
import pytest
from foundation_common.context import tenant_context

@pytest.mark.parametrize("attempt", range(1000))
async def test_cross_tenant_read_blocked(attempt, db, seed_two_tenants):
    """Random fuzz: under tenant A context, never see tenant B's rows."""
    tenant_a, tenant_b = seed_two_tenants
    with tenant_context(tenant_a.id):
        rows = await db.fetch("SELECT id, tenant_id FROM identity.user")
        assert all(r["tenant_id"] == tenant_a.id for r in rows), \
            f"Cross-tenant leak in attempt {attempt}"
```

CI 跑 1000 次（参数化），全过才能合并。

### 10.3 PgBouncer 模式测试
- CI integration 起一份 PgBouncer，启动健康检查跑通才能继续

### 10.4 越权审计测试
- 测试构造跨租户访问（不走 SDK，绕过 RLS 走 admin 角色），验证审计 pipeline 正确捕获 + 告警触发

---

## 11. SaaS 隔离三档与 RLS 关系

| 套餐 | 隔离模式 | RLS 角色 | 备注 |
|---|---|---|---|
| Free / Pro | **Shared**：所有租户同库同表 | RLS 是唯一隔离手段 | 千个小租户共享一套基础设施 |
| Business | **Schema-per-tenant**：每租户独立 schema，schema 内表仍带 tenant_id + RLS | RLS 是双保险 | search_path 按租户切；schema 名 `tenant_<tenant_id>` |
| Enterprise | **Database-per-tenant**：每租户独立 db | RLS 仍保留但收益小 | 物理隔离主导 |
| Dedicated | 独立 K8s 集群 / 独立 db | RLS 仍保留 | 客户专属部署 |

**RLS 在每档都开启**，因为：
- 多一层防御不损失什么（性能可忽略）
- 套餐升级迁移期数据可能同时存在于多模式，RLS 是兜底
- 合规审计需要"无论部署形态，租户隔离都不依赖应用代码"

### 11.1 BFF 路由

```python
# foundation_common.routing.tenant_router
def resolve_dsn(tenant: Tenant) -> str:
    if tenant.tier == "FREE" or tenant.tier == "PRO":
        return SHARED_DSN
    if tenant.tier == "BUSINESS":
        # Same DB, switch search_path
        return f"{SHARED_DSN}?options=-csearch_path=tenant_{tenant.id},identity,public"
    if tenant.tier == "ENTERPRISE":
        return tenant.dedicated_dsn  # provisioned per tenant
    raise ValueError(f"Unknown tier: {tenant.tier}")
```

### 11.2 套餐迁移

升级 Pro → Business 时：
1. 创建 `tenant_<tenant_id>` schema + 表结构
2. 双写期：新写两边、读源（旧 shared 表）
3. 校验一致性：对每张表 row count + 抽样 hash 比对
4. 切流：读切到新 schema
5. 停旧写 → 一致性最终校验 → 删除旧表中该租户行（带 Legal Hold 检查）

详细工具放 `packages/lifecycle`（A-M2）。

---

## 12. 跨服务调用与 RLS

### 12.1 服务调服务
- service A 调 service B 时，**传播 X-Tenant-Id header**
- service B 的 middleware 读 header → 写 contextvars → DB session SET LOCAL
- 整个调用链上租户上下文一致

### 12.2 事件消费
- 事件 payload 强制带 `tenant_id`（CONVENTIONS §9）
- 消费者从 payload 提取 tenant_id → `tenant_context(tenant_id)` 包裹处理
- 测试覆盖：消费时**没读 payload tenant_id** 的 bug 会触发"无 context"运行时错误

### 12.3 异步任务
- Celery / arq / dramatiq 任务参数必须含 `tenant_id`
- task 入口 boilerplate 自动 push context（封装在 `foundation_common.tasks`）

---

## 13. 监控与告警

### 13.1 必备 metric
- `foundation_db_rls_policy_violations_total{table,tenant_id}` — 任何写操作触发 RLS 拒绝时 +1（应当永远为 0）
- `foundation_db_no_tenant_context_total{service}` — service 尝试访问 DB 但无 context 的次数（应当永远为 0）
- `foundation_db_pgbouncer_mode{mode}` — 启动时报告，非 transaction/session 触发告警

### 13.2 PagerDuty 告警
- RLS policy violation > 0 / 5min → **P0**
- "no tenant context" > 0 / 5min → **P0**
- PgBouncer 模式异常 → **P0**

---

## 14. 应急预案

### 14.1 怀疑跨租户泄露
1. 立即冻结目标 service：将 deployment 缩到 0
2. 拉取 audit log 过去 N 小时内 `tenant_id` mismatch 事件
3. 用 `app_observability` 跨租户聚合验证嫌疑数据
4. 通知合规 / 法务 / 受影响租户（按 PIPL/GDPR 时限 §IR）
5. Root cause: 通常是 PgBouncer 模式 / context 丢失 / 业务代码绕 SDK
6. 修复 → 验证 → 渐进恢复

### 14.2 RLS policy 写错全局拒绝
- 立即用 `foundation_superuser` 临时降级该 policy（保留版本号）
- 走 hotfix 流程修 policy
- 部署后恢复 + 复盘 ADR

---

## 15. 不在本基线范围（后续 ADR 决策）

- **业务层多租户缓存**（Redis key 前缀策略）→ 进 `caching.md`
- **审计日志的多租户隔离**（ClickHouse partition by tenant_id）→ 进 `audit-pipeline.md`（A-M2）
- **跨集群联邦租户**（一个租户跨多机房）→ 暂不支持，v2 再议
- **MinIO/S3 对象存储多租户 bucket 策略** → 进 `storage.md`

---

## 16. 检查清单（PR self-review）

新增/修改租户表的 PR 必须自查：

- [ ] 表有 `tenant_id` 列且 NOT NULL
- [ ] 外键引用 `tenant.tenant(id)`
- [ ] 至少 1 个以 tenant_id 为前导列的索引
- [ ] 唯一约束都带 tenant_id（不同租户可重）
- [ ] 启用了 `ROW LEVEL SECURITY` 且 `FORCE`
- [ ] 至少 4 个 policy（select/insert/update/delete）覆盖 `app_user`
- [ ] 必要时含 admin policy / observability policy
- [ ] 使用 `standard_tenant_policies()` 生成器（不要手写）
- [ ] Migration 用 `app_migrator` 跑通
- [ ] 添加 RLS fuzz 测试用例
- [ ] 文档 / ER 图更新

---

## 附录 A：常用 SQL 速查

```sql
-- 当前会话租户
SELECT current_setting('app.tenant_id', true);

-- 看某表是否启用 RLS
SELECT relrowsecurity, relforcerowsecurity FROM pg_class
WHERE oid = 'identity.user'::regclass;

-- 看某表所有 policy
SELECT polname, polcmd, polroles::regrole[], pg_get_expr(polqual, polrelid) AS using_expr
FROM pg_policy WHERE polrelid = 'identity.user'::regclass;

-- 临时切到 admin tenant 看全平台
SET LOCAL app.tenant_id = '*ALL*';  -- 仅 app_admin 角色生效

-- 重置会话变量
RESET app.tenant_id;
```

---

## 附录 B：参考资料

- [Postgres Row Level Security Footguns — Bytebase](https://www.bytebase.com/blog/postgres-row-level-security-footguns/)
- [Using Postgres RLS in Rails — pganalyze](https://pganalyze.com/blog/postgres-row-level-security-ruby-rails)
- [PgBouncer features](https://www.pgbouncer.org/features.html)
- [Multi-tenant data isolation with PostgreSQL RLS — AWS](https://aws.amazon.com/blogs/database/multi-tenant-data-isolation-with-postgresql-row-level-security/)
- [RLS at scale — The Nile](https://www.thenile.dev/blog/multi-tenant-rls)
- [RLS sounds great until it isn't — PlanetScale](https://planetscale.com/blog/rls-sounds-great-until-it-isnt)

---

## 附录 C：变更记录

| 日期 | 版本 | 变更 |
|---|---|---|
| 2026-05-22 | 0.1.0 | 初版（P0 #2） |

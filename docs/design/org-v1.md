# Org Service — 设计文档 v0.1

> P1 #6 产出。覆盖 A-M1 范围。配套：
> - [CONVENTIONS.md](../CONVENTIONS.md)
> - [errors.md](../errors.md)
> - [multi-tenancy.md](../multi-tenancy.md)
> - [identity-v1.md](./identity-v1.md)
> - [authz-v1.md](./authz-v1.md)

---

## 1. Context

`org-service` 是底座**组织结构的事实源（system of record）**。所有"谁在哪个部门 / 哪个团队 / 上下级是谁"的查询都来这里。它要解决三个核心问题：

1. **四层模型**：`Tenant → Org Unit → Team → User` 怎么落到 schema 上，既支持深度嵌套又保证查询性能
2. **批量入职 / 调动 / 离职**：每天可能几百人变动，要原子化、可审计、可撤销
3. **跨服务事件契约**：identity/authz/billing/search 都要消费 org 变更，schema 要稳

### 关键技术决定（已定型）

| 维度 | 决定 | 理由 |
|---|---|---|
| 存储策略 | **邻接表（主）+ ltree 路径列（冗余）** | 邻接表写简单、ltree 让"取后代/祖先/同级"O(log n)；既能 RLS 又能 GiST 索引 |
| 模型层数 | **Tenant → Org Unit (可嵌套 N 层) → Team → User** | 与 Microsoft/Google 一致；OU 是部门，Team 是项目组；User 可在多 Team |
| Workspace 概念 | **后置到业务层**（不在底座） | 业务自定义"项目空间"，绑 team；底座不强加 |
| 命名空间 | `org_unit.path` 全租户唯一（含 tenant_id 前缀） | 避免跨租户路径冲突；RLS + path 双重防越权 |
| 跨 OU 操作权限 | 走 `authz-service` ABAC：祖先链上有权限即可 | 不在 org 内自建权限模型 |
| 移动子树 | 改 parent_id + 自动重算 ltree path（trigger） | 邻接表改一行 + DB 函数批量更新 path |
| 批量导入 | CSV / SCIM Group / 钉钉通讯录拉取 | identity-service 反向适配器把外部信号转 org SDK |
| 软删除 | OU 软删 → 30 天后硬删；非空 OU 不可删 | 强制先迁移成员 |
| 历史版本 | 关键字段（path/parent_id/manager_id）写 `org_unit_history` 表 | 审计 + 时点还原 |

---

## 2. 模型与术语

### 2.1 四层

```
Tenant (租户)
  └── Org Unit (部门 / BU，可任意嵌套)
        └── Org Unit (子部门)
              └── Team (团队，叶子)
                    └── User (成员)
```

| 概念 | 含义 | 关系 |
|---|---|---|
| **Tenant** | 客户公司 | 1 个客户 1 个 tenant |
| **Org Unit (OU)** | 部门 / BU / 事业群，可嵌套 | 1 tenant N OU；OU 嵌套 DAG（实际只允许树） |
| **Team** | 团队 / 项目组，**OU 的叶子下挂** | 1 OU N team；team 不能嵌套 |
| **User** | 个人 | 1 user 主属 1 OU；可加入 N team；可临时借调到其他 OU |

### 2.2 关键关系

- `user.primary_org_unit_id`：主属部门（唯一）
- `user_team_membership`：user ↔ team N:N
- `user_org_unit_secondary`：user ↔ OU N:N（借调 / 兼任，可带时间窗）
- `org_unit.manager_user_id`：部门负责人
- `team.lead_user_id`：团队 leader
- `org_unit.parent_id`：上级 OU（NULL = 一级部门）
- `org_unit.path`：ltree 路径，例 `tnt_01J5DEV0000000000000000A.engineering.platform.foundation`

### 2.3 与其他 service 边界

| Service | 来 org 取什么 |
|---|---|
| **identity** | 用户的主属 OU + 部门负责人（首次激活时用） |
| **authz** | scope = ORG_UNIT/TEAM 时 ABAC 拿祖先链做权限判定 |
| **billing** | 席位计数按 OU 维度报表；OU/Team 改名时通知账单 |
| **search** | OpenSearch 索引：OU 树 + user 关联，权限过滤 |
| **notification** | "通知整个 OU"路由展开 |
| **compliance** | DSAR 时 org 提供"该用户曾在哪些 OU"历史 |

org **不消费** identity 的"用户档案 PII"（手机/邮箱）——这些归 identity。

---

## 3. 数据模型

### 3.1 表清单

| 表 | 用途 | RLS |
|---|---|---|
| `org.org_unit` | 部门 | ✅ |
| `org.org_unit_history` | OU 关键字段变更历史 | ✅ |
| `org.team` | 团队 | ✅ |
| `org.user_membership` | user 主属 OU（1:1 与 identity.user 关联） | ✅ |
| `org.user_team_membership` | user ↔ team N:N | ✅ |
| `org.user_org_unit_secondary` | user ↔ OU 兼任 / 借调 N:N（带时间窗） | ✅ |
| `org.import_job` | 批量导入任务记录 | ✅ |
| `org.import_job_item` | 导入逐行结果 | ✅ |
| `org.org_event_outbox` | 事件投递保证（outbox 模式） | ✅ |

### 3.2 `org.org_unit`（核心表）

```sql
CREATE EXTENSION IF NOT EXISTS ltree;

CREATE TABLE org.org_unit (
    id              TEXT PRIMARY KEY CHECK (id ~ '^ou_[0-9A-Z]{26}$'),
    tenant_id       TEXT NOT NULL REFERENCES tenant.tenant(id),
    parent_id       TEXT REFERENCES org.org_unit(id),       -- NULL = 一级
    -- 业务字段
    code            TEXT NOT NULL,                          -- 'engineering' / 'r-and-d-cn'
    name            TEXT NOT NULL,                          -- '研发部'
    name_en         TEXT,                                   -- 国际化（可选）
    description     TEXT,
    manager_user_id TEXT,                                   -- → identity.user.id（异步软关联）
    kind            TEXT NOT NULL DEFAULT 'DEPARTMENT'
                    CHECK (kind IN ('BU','DEPARTMENT','CENTER','OFFICE','VIRTUAL')),
    -- 派生：通过 trigger 维护
    path            LTREE NOT NULL,                         -- 含 tenant_id 前缀
    depth           SMALLINT NOT NULL,                      -- 0 = 一级
    sort_order      INT NOT NULL DEFAULT 0,                 -- 同级排序
    -- 元
    is_archived     BOOLEAN NOT NULL DEFAULT false,
    metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at      TIMESTAMPTZ,
    created_by      TEXT,
    updated_by      TEXT,
    -- 约束
    CHECK (depth <= 12),                                    -- 最深 13 层（够用）
    CHECK (parent_id IS NULL OR parent_id != id),           -- 自引用禁止
    UNIQUE (tenant_id, parent_id, code)                     -- 同一父下 code 唯一
);

-- 索引
CREATE INDEX ou_tenant_id_idx    ON org.org_unit (tenant_id);
CREATE INDEX ou_parent_idx       ON org.org_unit (tenant_id, parent_id);
CREATE INDEX ou_path_gist        ON org.org_unit USING GIST (path);   -- 祖先/后代 O(log n)
CREATE INDEX ou_path_btree       ON org.org_unit USING BTREE (path);  -- 精确匹配
CREATE INDEX ou_manager_idx      ON org.org_unit (manager_user_id) WHERE manager_user_id IS NOT NULL;
CREATE UNIQUE INDEX ou_tenant_path_idx
    ON org.org_unit (tenant_id, path) WHERE deleted_at IS NULL;

-- RLS
ALTER TABLE org.org_unit ENABLE ROW LEVEL SECURITY;
ALTER TABLE org.org_unit FORCE ROW LEVEL SECURITY;
-- 4 个 standard policy（详见 multi-tenancy.md）
```

### 3.3 path 自动维护

`path` 列由 trigger 在 insert/update parent_id 时自动重算：

```sql
CREATE OR REPLACE FUNCTION org.compute_org_unit_path() RETURNS TRIGGER AS $$
DECLARE
    parent_path LTREE;
    parent_depth SMALLINT;
BEGIN
    IF NEW.parent_id IS NULL THEN
        NEW.path  := text2ltree(NEW.tenant_id || '.' || NEW.code);
        NEW.depth := 0;
    ELSE
        SELECT path, depth INTO parent_path, parent_depth
            FROM org.org_unit WHERE id = NEW.parent_id;
        IF parent_path IS NULL THEN
            RAISE EXCEPTION 'Parent % not found', NEW.parent_id;
        END IF;
        NEW.path  := parent_path || text2ltree(NEW.code);
        NEW.depth := parent_depth + 1;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER org_unit_path_compute
    BEFORE INSERT OR UPDATE OF parent_id, code ON org.org_unit
    FOR EACH ROW EXECUTE FUNCTION org.compute_org_unit_path();
```

**移动子树（改 parent_id）后**，所有后代的 path 也要重算。这通过 statement-level 后置 trigger 完成：

```sql
CREATE OR REPLACE FUNCTION org.reparent_org_unit_subtree() RETURNS TRIGGER AS $$
DECLARE
    old_path LTREE := OLD.path;
    new_path LTREE := NEW.path;
BEGIN
    IF old_path = new_path THEN RETURN NEW; END IF;
    UPDATE org.org_unit
        SET path = new_path || subpath(path, nlevel(old_path)),
            depth = nlevel(new_path) + (nlevel(path) - nlevel(old_path))
        WHERE path <@ old_path AND id != NEW.id;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER org_unit_reparent
    AFTER UPDATE OF parent_id ON org.org_unit
    FOR EACH ROW WHEN (OLD.parent_id IS DISTINCT FROM NEW.parent_id)
    EXECUTE FUNCTION org.reparent_org_unit_subtree();
```

**性能**：千万节点级仍 O(后代数)；超大子树移动建议走异步 job（详见 §9）。

**防环**：trigger 在 update parent_id 时检查 `NEW.parent_id` 不在 OLD path 内：

```sql
CREATE OR REPLACE FUNCTION org.prevent_cycle() RETURNS TRIGGER AS $$
BEGIN
    IF NEW.parent_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM org.org_unit
        WHERE id = NEW.parent_id AND path <@ OLD.path
    ) THEN
        RAISE EXCEPTION 'Cycle detected: cannot make % child of its descendant', NEW.id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER org_unit_no_cycle BEFORE UPDATE OF parent_id ON org.org_unit
    FOR EACH ROW EXECUTE FUNCTION org.prevent_cycle();
```

### 3.4 `org.team`

```sql
CREATE TABLE org.team (
    id              TEXT PRIMARY KEY CHECK (id ~ '^tm_[0-9A-Z]{26}$'),
    tenant_id       TEXT NOT NULL REFERENCES tenant.tenant(id),
    org_unit_id     TEXT NOT NULL REFERENCES org.org_unit(id),  -- 必属一个 OU
    code            TEXT NOT NULL,
    name            TEXT NOT NULL,
    description     TEXT,
    lead_user_id    TEXT,                                       -- → identity.user.id
    kind            TEXT NOT NULL DEFAULT 'PROJECT'
                    CHECK (kind IN ('PROJECT','SQUAD','GUILD','VIRTUAL')),
    is_archived     BOOLEAN NOT NULL DEFAULT false,
    metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at      TIMESTAMPTZ,
    created_by      TEXT,
    updated_by      TEXT,
    UNIQUE (tenant_id, org_unit_id, code)
);

CREATE INDEX team_tenant_idx        ON org.team (tenant_id);
CREATE INDEX team_ou_idx            ON org.team (tenant_id, org_unit_id);
CREATE INDEX team_lead_idx          ON org.team (lead_user_id) WHERE lead_user_id IS NOT NULL;
-- RLS 同上
```

### 3.5 `org.user_membership`（主属）

```sql
CREATE TABLE org.user_membership (
    user_id            TEXT PRIMARY KEY,                       -- = identity.user.id
    tenant_id          TEXT NOT NULL REFERENCES tenant.tenant(id),
    primary_org_unit_id TEXT NOT NULL REFERENCES org.org_unit(id),
    job_title          TEXT,
    employee_no        TEXT,
    join_date          DATE NOT NULL DEFAULT current_date,
    leave_date         DATE,                                    -- 离职日期
    manager_user_id    TEXT,                                    -- 直接上级
    employment_kind    TEXT NOT NULL DEFAULT 'EMPLOYEE'
                       CHECK (employment_kind IN ('EMPLOYEE','CONTRACTOR','INTERN','EXTERNAL')),
    metadata           JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by         TEXT
);

CREATE INDEX um_tenant_idx          ON org.user_membership (tenant_id);
CREATE INDEX um_primary_ou_idx      ON org.user_membership (tenant_id, primary_org_unit_id);
CREATE INDEX um_manager_idx         ON org.user_membership (manager_user_id) WHERE manager_user_id IS NOT NULL;
CREATE UNIQUE INDEX um_tenant_emp_idx
    ON org.user_membership (tenant_id, employee_no) WHERE employee_no IS NOT NULL;
```

### 3.6 `org.user_team_membership` 与 `org.user_org_unit_secondary`

```sql
CREATE TABLE org.user_team_membership (
    user_id    TEXT NOT NULL,
    team_id    TEXT NOT NULL REFERENCES org.team(id),
    tenant_id  TEXT NOT NULL REFERENCES tenant.tenant(id),
    role_in_team TEXT NOT NULL DEFAULT 'MEMBER'
                CHECK (role_in_team IN ('MEMBER','LEAD','OBSERVER')),
    joined_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    left_at    TIMESTAMPTZ,
    PRIMARY KEY (user_id, team_id)
);
CREATE INDEX utm_team_idx ON org.user_team_membership (tenant_id, team_id) WHERE left_at IS NULL;

CREATE TABLE org.user_org_unit_secondary (
    user_id       TEXT NOT NULL,
    org_unit_id   TEXT NOT NULL REFERENCES org.org_unit(id),
    tenant_id     TEXT NOT NULL REFERENCES tenant.tenant(id),
    reason        TEXT NOT NULL DEFAULT 'TEMP_ASSIGN'
                  CHECK (reason IN ('TEMP_ASSIGN','DOTTED_LINE','CROSS_TEAM')),
    valid_from    TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_until   TIMESTAMPTZ,                                 -- NULL = 长期
    granted_by    TEXT NOT NULL,
    PRIMARY KEY (user_id, org_unit_id, valid_from)
);
CREATE INDEX uos_ou_idx ON org.user_org_unit_secondary (tenant_id, org_unit_id)
    WHERE valid_until IS NULL OR valid_until > now();
```

### 3.7 `org.org_unit_history`（审计 + 时点还原）

```sql
CREATE TABLE org.org_unit_history (
    id           BIGSERIAL PRIMARY KEY,
    tenant_id    TEXT NOT NULL,
    org_unit_id  TEXT NOT NULL,
    changed_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    changed_by   TEXT NOT NULL,
    field        TEXT NOT NULL,                                 -- 'parent_id' / 'name' / 'manager_user_id' / 'archived'
    old_value    TEXT,
    new_value    TEXT,
    audit_event_id TEXT NOT NULL
);
CREATE INDEX ouh_ou_time_idx ON org.org_unit_history (tenant_id, org_unit_id, changed_at DESC);
```

由 trigger 在 update 时自动写入；team / user_membership 同款 history 表。

### 3.8 `org.org_event_outbox`（事务性事件）

org 改动 + 事件发送必须原子。outbox 模式：

```sql
CREATE TABLE org.org_event_outbox (
    id          BIGSERIAL PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    event_type  TEXT NOT NULL,                                  -- 'foundation.org.user.moved'
    payload     JSONB NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_at TIMESTAMPTZ,                                   -- 由 worker 标记
    attempts    INT NOT NULL DEFAULT 0,
    last_error  TEXT
);
CREATE INDEX outbox_pending_idx ON org.org_event_outbox (id) WHERE published_at IS NULL;
```

worker 周期 LISTEN/NOTIFY 或 polling 把未发布事件推到 Redis Streams / NATS。

---

## 4. 关键查询模式

| 场景 | SQL（用 ltree） | 复杂度 |
|---|---|---|
| 列出某 OU 全部后代 | `WHERE path <@ '<ou_path>'` | O(log n) GiST |
| 列出某 OU 直接子级 | `WHERE parent_id = '<ou_id>'` | O(log n) btree |
| 取某 OU 全部祖先 | `WHERE path @> '<ou_path>'` | O(log n) GiST |
| 取兄弟节点 | `WHERE subpath(path, 0, -1) = subpath('<ou_path>', 0, -1)` | O(log n) |
| 整个租户树（前端展示） | `WHERE tenant_id = $1 ORDER BY path` | 全租户表扫描，结果加缓存 |
| 用户能访问的 OU 树 | join `user_membership` + `user_org_unit_secondary` + RLS | 需 service 层组合 |
| 移动 OU 子树 | `UPDATE org_unit SET parent_id = $new` + trigger | O(后代数) |
| 某 OU 下所有 user | `JOIN org_unit ON user_membership.primary_ou_id = ou.id WHERE ou.path <@ $1` | O(后代数 × user 数) |

性能基线（参考 [pganalyze cybertec ltree benchmark](https://www.cybertec-postgresql.com/en/postgresql-speeding-up-recursive-queries-and-hierarchic-data/)）：
- 100 万 OU + 1000 万 user：
  - 取某 OU 全部后代 P99 < 5ms
  - 移动 100 节点子树 < 50ms
  - 整个租户树（1 万 OU）P99 < 100ms

---

## 5. API 表面

完整 OpenAPI 在 `contracts/openapi/org.yaml`。端点清单：

### 5.1 Org Unit

| 端点 | 方法 | 权限 |
|---|---|---|
| `/org-units` | GET | `org.org_unit.list` |
| `/org-units/tree` | GET | `org.org_unit.list`（完整树，前端展示） |
| `/org-units` | POST | `org.org_unit.create` |
| `/org-units/{id}` | GET / PATCH / DELETE | `org.org_unit.{read|update|delete}` |
| `/org-units/{id}/move` | POST | `org.org_unit.move`（改 parent_id） |
| `/org-units/{id}/archive` | POST | `org.org_unit.archive` |
| `/org-units/{id}/descendants` | GET | `org.org_unit.list` |
| `/org-units/{id}/ancestors` | GET | `org.org_unit.list` |
| `/org-units/{id}/members` | GET | `org.org_unit.list_members` |
| `/org-units/{id}/teams` | GET | `org.org_unit.list_teams` |
| `/org-units/{id}/history` | GET | `org.org_unit.read_history` |

### 5.2 Team

| 端点 | 方法 | 权限 |
|---|---|---|
| `/teams` | GET / POST | `org.team.{list|create}` |
| `/teams/{id}` | GET / PATCH / DELETE | `org.team.*` |
| `/teams/{id}/members` | GET / POST / DELETE | `org.team.manage_members` |

### 5.3 User Membership

| 端点 | 方法 | 权限 |
|---|---|---|
| `/users/{user_id}/membership` | GET | bearer + (self or `org.user_membership.read`) |
| `/users/{user_id}/membership` | PUT | `org.user_membership.update` |
| `/users/{user_id}/transfer` | POST | `org.user_membership.transfer`（换部门） |
| `/users/{user_id}/secondary-org-units` | GET / POST / DELETE | `org.user_secondary.*` |
| `/users/{user_id}/teams` | GET | bearer |

### 5.4 批量导入

| 端点 | 方法 | 权限 |
|---|---|---|
| `/import-jobs` | POST | `org.import.create`（multipart/form-data CSV） |
| `/import-jobs/{id}` | GET | `org.import.read` |
| `/import-jobs/{id}/items` | GET | `org.import.read` |
| `/import-jobs/{id}/cancel` | POST | `org.import.cancel` |
| `/import-jobs/{id}/rollback` | POST | `org.import.rollback` |

### 5.5 内部端点

| 端点 | 方法 | 用途 |
|---|---|---|
| `/internal/scim-group-sync` | POST | identity-service SCIM 处理 Group → 转 OU/Team |
| `/internal/dingtalk-org-sync` | POST | identity-service 钉钉适配器 |

---

## 6. 关键操作的语义

### 6.1 创建 OU
```
POST /org-units
{ "parent_id": "ou_...", "code": "platform", "name": "平台中心", "kind": "DEPARTMENT" }
```
- 校验：tenant 一致；code 在同父下唯一；depth ≤ 12；parent 未 archived
- 写表 + trigger 算 path
- 发事件 `foundation.org.org_unit.created`

### 6.2 移动 OU（业务上"部门调整"）
```
POST /org-units/{id}/move
{ "new_parent_id": "ou_...", "preserve_managers": true }
```
- 校验：不能移到自己后代；新父未 archived；权限要求 src+dst 都有 `move` 权限
- 写表 + trigger 算 path（连同所有后代）
- 发事件 `foundation.org.org_unit.moved`（payload 含 `old_path` / `new_path` / `descendants_count`）
- **重要**：移动后 authz scope=ORG_UNIT 的 role binding 自动跟随（按 path 解释，不是按 id）

### 6.3 归档 OU
- 软标记 `is_archived = true`
- 拒绝条件：非空（有 user 或 team）→ 422 `FOUNDATION.ORG.STATE.NOT_EMPTY`
- 强制归档需先把成员迁走（前端引导"批量调动"）

### 6.4 删除 OU
- 必须先归档 + 空 + 满足 retention
- 软删 30 天后 lifecycle 硬删
- 历史 + 审计永久保留

### 6.5 调动用户
```
POST /users/{user_id}/transfer
{ "to_org_unit_id": "ou_...", "to_team_ids": ["tm_...", "tm_..."], "effective_date": "2026-06-01", "reason": "promotion" }
```
- 原子事务：写 user_membership + user_team_membership + history + outbox event
- 发事件 `foundation.org.user.transferred`
- authz / billing / search 异步消费

### 6.6 跨 OU 操作权限（OPA ABAC）

业务调 authz 时 input 携带：
```json
{
  "user": { "primary_org_unit_path": "tnt_X.engineering.platform" },
  "resource": { "org_unit_path": "tnt_X.engineering.platform.foundation" }
}
```

Rego 规则示例：
```rego
package foundation.authz

# 祖先 OU 上的管理员可管理后代
ancestor_admin_allowed if {
    some grant in input.user.role_grants
    grant.role == "org_unit_admin"
    startswith(input.resource.org_unit_path, grant.scope.id)
}
```

---

## 7. 批量导入

### 7.1 输入格式

**CSV 标准**（首版）：
```csv
employee_no,email,name,org_unit_path,team_codes,manager_email,job_title,join_date
E001,alice@x.com,Alice,engineering.platform,foundation,bob@x.com,Engineer,2026-06-01
E002,bob@x.com,Bob,engineering.platform,foundation;authn,,Senior Engineer,2024-01-01
```

**SCIM Group**（由 identity-service 转发）：
```json
{ "displayName": "engineering.platform.foundation", "members": [...] }
```
- displayName 用 `.` 分隔表示 OU 路径
- 不存在的 OU 自动按层级创建（needs `org.org_unit.create` 权限）

**钉钉通讯录**：identity 适配器拉取后转 SCIM 风格调内部端点

### 7.2 流程

```
[upload CSV/SCIM]
   ↓
[parse + validate]  ── 行级错误立刻反馈
   ↓
[dry-run]           ── 显示将创建/更新/调动多少行
   ↓ confirm
[execute in batches (size=100)]
   ↓
[outbox events]
   ↓
[summary report]    ── 成功/失败/跳过统计
```

### 7.3 关键设计

- **幂等**：以 `(tenant_id, employee_no)` 或 `(tenant_id, email)` 为 dedup key
- **事务边界**：每 batch 一个事务，避免大事务长锁
- **失败隔离**：单行失败不阻塞其他行；写 `import_job_item` 标 status=FAILED + error
- **回滚**：导入后 30 分钟内可一键回滚（撤销变更）；超时只能逐行人工修
- **审计**：每条变更进 `org_unit_history` + audit-service

### 7.4 反向：导出
- `GET /export?format=csv` 触发异步导出任务，下载链接通过通知中心送达
- 导出走 `app_observability` 角色 + DLP 检查（分级 ≥ L3 的字段如手机/身份证默认脱敏，要原始数据走 PAM JIT）

---

## 8. 事件契约

### 8.1 发出

| 事件 | payload 关键字段 | consumer |
|---|---|---|
| `foundation.org.org_unit.created` | id, parent_id, path, name | authz, search |
| `foundation.org.org_unit.updated` | id, changed_fields | search, audit |
| `foundation.org.org_unit.moved` | id, old_path, new_path, descendants_count | authz, search, billing |
| `foundation.org.org_unit.archived` | id | authz |
| `foundation.org.org_unit.deleted` | id, was_path | lifecycle (硬删后调 data-protection) |
| `foundation.org.team.created` | id, org_unit_id | authz, search |
| `foundation.org.team.updated/deleted` | … | … |
| `foundation.org.user.joined` | user_id, primary_org_unit_id | billing (席位 +1), authz, search |
| `foundation.org.user.transferred` | user_id, from_ou, to_ou, effective_date | authz (撤旧角色 / 默认无新角色), notification |
| `foundation.org.user.left` | user_id, leave_date | identity (freeze), billing (-1), authz |
| `foundation.org.user.secondary_assigned` / `_revoked` | user_id, org_unit_id | authz |
| `foundation.org.import.completed` | job_id, summary | notification |

### 8.2 消费

| 事件 | 行为 |
|---|---|
| `foundation.identity.user.activated` | 若有 invite 时携带 OU 信息 → 写 user_membership |
| `foundation.identity.user.deactivated` | 标 user_membership.leave_date；保留行 |
| `foundation.tenant.created` | 自动建 "默认部门" + "默认团队"（让后续用户至少有归属） |
| `foundation.compliance.mode_changed` | 重新评估"字段脱敏 / DSAR 时点导出"规则 |

---

## 9. 性能与扩展

### 9.1 缓存

- 整租户树（< 10k 节点）走 Redis cache key `org:tree:{tenant_id}`，TTL 60s
- 失效触发：任何 OU 写操作 → `DEL org:tree:{tenant_id}` + pubsub
- 业务 service 自管 cache：通过 SDK `org_client.subscribe_tree_invalidate(handler)`

### 9.2 大子树移动

> 10 万节点的子树移动是真实风险。

- 同步路径：阈值 < 1000 节点，trigger 直接做
- 异步路径：> 1000 节点 → 排 job
  - 加 OU 标 `migrating=true` 拒新写
  - 批量 1000 / batch + checkpoint
  - 完成后清标 + 发事件
- 期间 RLS / 查询继续工作（旧 path 临时可见，最终一致 < 5 min）

### 9.3 RLS 与 ltree 配合

- RLS policy 仍用 `tenant_id = current_setting('app.tenant_id')`（多租户基线）
- ltree path 已含 tenant_id 前缀，双重保护
- "用户可见的 OU 子集"由 authz `list_accessible_ids(action=org.org_unit.read, type=org_unit)` 提供

### 9.4 反范式（如有必要）

- 大租户场景下 `user_membership` 行数 = user 数量；查 "某 OU 后代下所有 user" 走两层 join 仍 ok
- 如果发现 P99 > 100ms，加物化视图 `org.mv_ou_user_count`，每 5 min 刷新

---

## 10. 部署形态差异

| 维度 | small | medium | large |
|---|---|---|---|
| 副本 | 1 | 3 HPA | 5-10 HPA |
| 缓存 | 进程 LRU | + Redis | + Redis 集群 |
| 导入并发 | 1 job | 5 job | 20 job |
| 大子树移动阈值 | 500 同步 | 1000 同步 | 5000 同步 |

---

## 11. 关键技术风险

| 风险 | 缓解 |
|---|---|
| ltree GiST 索引深度限制（理论 ~64 层；实际 path 字符长度有限） | depth ≤ 12 + 每段 code 命名长度 ≤ 32 char，足够 |
| trigger 在大批量 reparent 时锁表慢 | 分 batch；超阈值走异步 job |
| 移动 OU 导致 authz scope 权限大变 | scope 按 path 解释；移动事件强制审计 + 自动通知受影响管理员 |
| 钉钉通讯录推送字段不规范 | 适配器层硬校验 + 不规范行进 import_job_item.FAILED |
| 跨租户 OU id 撞车 | path 含 tenant_id 前缀 + 双重 RLS |
| 软删的 OU 仍出现在 SCIM 同步 | SCIM endpoint 过滤 `deleted_at IS NULL` |
| 外部系统（钉钉）改 OU 结构后我们的 ltree 一致性 | 增量 diff + 冲突自动告警，人工裁决 |
| OU 大量重命名导致 path 漂移 | code 不可改（只能改 display name）；要改 code → 走 move + 旧 code 保留 30 天 alias |

---

## 12. 合规模式联动

| 模式 | 影响 |
|---|---|
| `pipl` | OU member 列表中默认脱敏 user PII（mobile/邮箱前缀） |
| `equal_protection_3` | OU 调整必经审批 + 双人签 |
| `equal_protection_4` | OU 树查询审计写 WORM；超 24h 未访问的 OU 数据走 cold storage |
| `finance_jrt0071` | 跨 BU 转账操作需四眼 + 部门 path 校验 |
| `hipaa` | OU 访问审计含访问理由 |

---

## 13. 测试策略

### 13.1 单元（≥85%）
- ltree path 计算 / 防环 / 重算后代
- OU 移动语义（同级、跨层、跨树根）
- import CSV 解析 / dedup / 错误隔离

### 13.2 集成
- 起 Postgres + 跑 trigger，10k OU 树构建 / 移动 / 删除往返
- 移动 1k 节点子树 < 50ms
- 全树查询 1万 OU < 100ms

### 13.3 fuzz
- 跨租户：用户在 A 租户读 B 租户的 OU path（构造 path 包含 tnt_B 前缀） → RLS 必拒
- 防环：随机构造 100 个 reparent 操作，含 50 个故意成环，全部拒绝

### 13.4 import 安全
- CSV 注入：employee_no 含 SQL 注入 payload → 拒绝
- CSV 巨型文件（100MB） → 分块 + 内存上限
- 钉钉 webhook 重放 → 拒绝

### 13.5 性能
- 1M OU + 10M user 场景：列后代 P99 < 5ms / 移动 100 节点 < 50ms

---

## 14. 待解决问题

| # | 问题 | 决策机制 | 截止 |
|---|---|---|---|
| Q1 | 是否支持矩阵式组织（多上级）？ | 当前不支持（树）；用 secondary_org_unit 替代；客户驱动再 v1.1 评 ReBAC | A-M3 |
| Q2 | OU code 是否允许中文 / Unicode？ | ltree label 限 ASCII；中文走 `name`，code 用拼音或英文缩写 | 已定 |
| Q3 | Workspace（业务层）如何引用 OU/Team？ | 业务表外键 `org_unit_id` / `team_id` + 同步事件失效缓存 | A-M3 |
| Q4 | 经理变更是否触发权限重算？ | 是；发事件 authz 重新评估"上级链上的管理权" | 已定 |
| Q5 | 大租户（1M+ OU）是否需分库？ | 当前 single Postgres 足；100k+ OU 时评估 schema-per-tenant | v1.2 |
| Q6 | 历史表保留多久？ | 跟随合规模式（默认 1 年；金融 7 年） | A-M4 |
| Q7 | 是否提供"组织架构图"导出 PNG/SVG？ | 业务层做；底座只暴露 JSON 数据 | 已定 |
| Q8 | 钉钉/飞书 OU 推过来时 code 不规范怎么办？ | 适配器自动 sanitize（去空格/特殊字符），冲突走 review queue | A-M3 |
| Q9 | OU 移动期间正在跑的 authz check 怎么处理？ | path 短暂双写；OPA 输入用 NEW path；旧 path 兼容 5 min | A-M3 |
| Q10 | secondary_org_unit_assignment 是否走审批？ | 是；管理员申请 → 上级 OU 管理员审批；走通知中心 + audit | A-M4 |

---

## 15. 验证标准（M1 出口）

- [ ] OpenAPI `contracts/openapi/org.yaml` spectral lint 通过
- [ ] 单元 / 集成测试 ≥85% 覆盖
- [ ] ltree trigger 在 10k OU 移动 1k 节点子树 < 50ms
- [ ] 全树查询 1 万 OU P99 < 100ms
- [ ] 防环 trigger 通过 100 次随机 fuzz
- [ ] RLS 跨租户访问 fuzz 1000 次 0 越权
- [ ] CSV import 1 万行端到端跑通 + 错误行隔离
- [ ] outbox event 投递保证：杀进程后重启自动续投
- [ ] 三档 helm profile 都能跑

---

## 16. 参考资料

- [Postgres ltree 官方文档](https://www.postgresql.org/docs/current/ltree.html)
- [Modeling Hierarchical Tree Data in PostgreSQL](https://leonardqmarcq.com/posts/modeling-hierarchical-tree-data)
- [Hierarchical models in PostgreSQL — Ackee](https://www.ackee.agency/blog/hierarchical-models-in-postgresql)
- [Speeding up recursive queries — CYBERTEC](https://www.cybertec-postgresql.com/en/postgresql-speeding-up-recursive-queries-and-hierarchic-data/)
- [Hacker News 讨论：Postgres tree 选型](https://news.ycombinator.com/item?id=27631765)

---

## 17. 变更记录

| 日期 | 版本 | 变更 |
|---|---|---|
| 2026-05-22 | 0.1.0 | 初版（P1 #6） |

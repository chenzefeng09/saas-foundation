# SCIM 2.0 Server + 钉钉单向同步详细设计 v1

> 底座作为 SCIM 2.0 **服务端**，对接 Azure AD / Okta / 钉钉企业版的「主数据 → 底座」推送 / 拉取同步。
> 钉钉非标准 SCIM，需要**反向适配层**把钉钉的 OAPI 翻译成 SCIM 调用。
>
> **关系到 identity-v1**：本文档是 identity-v1 §9（外部目录同步）的**详细展开**，不是独立设计。
> 表结构以 identity-v1 §3.1 `identity.scim_external_ref` 为准；本文档新增的 `identity.idp_config` / `identity.sync_task` / `identity.sync_anomaly` 是补充，**不重复**建外部 ID 映射表。

| 字段 | 值 |
|---|---|
| 状态 | Draft v1 |
| Owner | Identity 后端 |
| 实施 milestone | A-M3（钉钉单向）/ A-M4（Okta + AD 通用 SCIM）|
| 相关文档 | identity-v1 / org-v1 / notification |

## 0. TL;DR

- **标准 SCIM 2.0 server**：暴露 `/scim/v2/Users` `/scim/v2/Groups` 等端点（RFC 7643/7644）
- **认证**：bearer token 模式（per-tenant per-IdP token）+ 可选 mTLS
- **钉钉适配**：底座**反向**调钉钉 OAPI 拉取员工/部门/角色 → 翻译成 SCIM 操作 → 本地处理（钉钉不主动 push）
- **同步模式**：周期增量（5min）+ webhook 触发即时（钉钉「通讯录变更」事件） + 手工全量重同步
- **冲突解决**：source-of-truth = 外部 IdP；本地编辑被覆盖；冲突字段记日志
- **离职 SLA**：HR 系统终止 → 5 分钟内底座禁用 + Keycloak revoke session
- **审计 + 通知**：每次同步差异、错误、冲突全审计；安全管理员订阅异常事件

## 1. Context

- 私有化客户痛点：每加入员工要分别在 HR 系统 + 钉钉 + 底座 + 各业务系统建账号；管理成本高
- 合规要求：离职信号必须 ≤ 1 小时同步到所有系统（PIPL + 等保）
- 钉钉是国内私有化客户最常用的目录源（飞书次之）；钉钉**没有官方 SCIM**，需要适配
- Azure AD / Okta 海外 SaaS 客户标准 SCIM，工作量主要在合规与边界

## 2. SCIM Server 设计（标准）

### 2.1 端点

| Method | Path | RFC 7644 | 说明 |
|---|---|---|---|
| GET    | `/scim/v2/ServiceProviderConfig` | §4 | 暴露支持能力 |
| GET    | `/scim/v2/Schemas` | §4 | User/Group/Custom schema |
| GET    | `/scim/v2/ResourceTypes` | §4 | 资源类型 |
| GET    | `/scim/v2/Users` | §3.4 | 列表（filter + paging） |
| POST   | `/scim/v2/Users` | §3.3 | 创建 |
| GET    | `/scim/v2/Users/{id}` | §3.4.1 | 详情 |
| PUT    | `/scim/v2/Users/{id}` | §3.5.1 | 替换 |
| PATCH  | `/scim/v2/Users/{id}` | §3.5.2 | 局部更新（推荐）|
| DELETE | `/scim/v2/Users/{id}` | §3.6 | 软删除（status=deactivated）|
| GET    | `/scim/v2/Groups` | §3.4 | 组列表（映射 team） |
| POST   | `/scim/v2/Groups` | §3.3 | 创建组 |
| ...    | ... | ... | ... |
| POST   | `/scim/v2/Bulk` | §3.7 | 批量操作（最多 100 op） |

### 2.2 认证

```http
GET /scim/v2/Users
Authorization: Bearer <SCIM_TOKEN>
X-Tenant-ID: tnt_a
```

每个 IdP 一个 token，绑定到一个 tenant + scope：
```sql
CREATE TABLE identity.scim_token (
  tenant_id        TEXT NOT NULL,
  token_id         TEXT NOT NULL,
  idp_type         TEXT NOT NULL,         -- 'azure_ad'/'okta'/'dingtalk_adapter'/'custom'
  token_hash       TEXT NOT NULL,         -- bcrypt
  scopes           TEXT[] NOT NULL,       -- ['users:read','users:write','groups:read'...]
  ip_whitelist     INET[],
  expires_at       TIMESTAMPTZ,
  last_used_at     TIMESTAMPTZ,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, token_id)
);
```

每次请求 audit；高敏 op 强制 IP whitelist + mTLS。

### 2.3 User schema 映射

底座 User → SCIM:

```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "id": "usr_01J7ABC",
  "externalId": "ad-userid-12345",        // IdP 侧 ID
  "userName": "alice@tenant-a.com",
  "name": {
    "givenName": "Alice",
    "familyName": "Liu",
    "formatted": "Alice Liu"
  },
  "emails": [
    {"value": "alice@tenant-a.com", "type": "work", "primary": true}
  ],
  "phoneNumbers": [
    {"value": "+86-13800001234", "type": "mobile"}
  ],
  "active": true,                          // false = 禁用
  "groups": [                              // 自动从 group_membership 拼
    {"value": "tem_01J7DEF", "display": "Engineering Team"}
  ],
  "enterprise": {                          // §4.3 extension
    "employeeNumber": "E001",
    "department": "R&D",
    "manager": {"value": "usr_xxx"}
  },
  "meta": {
    "resourceType": "User",
    "created": "...",
    "lastModified": "...",
    "location": "/scim/v2/Users/usr_01J7ABC",
    "version": "W/\"v2\""                  // ETag for optimistic concurrency
  }
}
```

### 2.4 Group ↔ Team 映射

底座 4 层模型（详见 org-v1）：`tenant > org_unit > team > user`。
SCIM Group → 仅映射 **team**（最细粒度）。
- OU 层不暴露为 SCIM Group（IdP 一般也没这个概念）
- 多层级用户隶属：用户的 `groups` 反映直接所属 team；OU 关系通过 `enterprise.department` 单字段暴露

### 2.5 PATCH 语义（最常用）

```http
PATCH /scim/v2/Users/usr_01J7ABC
Content-Type: application/scim+json

{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [
    {"op": "replace", "path": "active", "value": false},
    {"op": "replace", "path": "name.familyName", "value": "Wang"},
    {"op": "add", "path": "groups", "value": [{"value": "tem_new"}]},
    {"op": "remove", "path": "groups[value eq \"tem_old\"]"}
  ]
}
```

实现要点：
- path expression parser（RFC 7644 §3.5.2.1）
- value filter（`groups[value eq "x"]`）
- atomic：所有 op 一个事务，失败全回滚

### 2.6 filter 表达式

支持 `eq / ne / co / sw / ew / pr / gt / ge / lt / le / and / or / not`。
实现：用 `parsimonious`（PEG parser）→ AST → SQLAlchemy filter。

例：`?filter=userName eq "alice@..." and emails.type eq "work"`

## 3. 钉钉单向同步（核心）

### 3.1 总体流程

```
钉钉企业版                            底座
─────────────                       ─────────────
通讯录变更事件 ──webhook──────────→  dingtalk-callback-handler
                                          ↓
                                    trigger 增量同步任务
                                          ↓
                                    sync-worker
                                          ↓
                                    钉钉 OAPI ←─pull─── department/list, user/list
                                          ↓
                                    映射：钉钉 user → SCIM User
                                          ↓
                                    SCIM PATCH 本地（POST/PATCH/DELETE）
                                          ↓
                                    审计 + 通知差异
```

### 3.2 钉钉对象 → SCIM 映射

钉钉 User 字段（部分）：
```
userid, name, mobile, email, orgEmail, department[], position, jobnumber, hiredDate, leaderInDept[], active, avatar, telephone, workPlace, ...
```

映射规则：

| 钉钉字段 | SCIM 字段 | 备注 |
|---|---|---|
| userid | externalId | 钉钉内部 ID |
| name | name.formatted + familyName/givenName 推断 | 中文姓名拆分难，保留 formatted |
| mobile | phoneNumbers[type=mobile] | |
| orgEmail | emails[type=work, primary=true] | 优先用企业邮箱 |
| email | emails[type=work] | 若无 orgEmail |
| department[] | groups[] | 多部门 → 多 team；自动建 team |
| position | enterprise.title | |
| jobnumber | enterprise.employeeNumber | |
| hiredDate | enterprise.hireDate (custom ext) | |
| leaderInDept[] | enterprise.manager (取 dept 主管) | 多 dept 取主部门 |
| active | active | |
| avatar | photos[type=photo] | |

### 3.3 钉钉部门 → SCIM Group 映射

钉钉部门是树形（与底座 org_unit 类似）；但底座 SCIM 只暴露 team 粒度，怎么办？

**策略**：钉钉**叶子部门**（无子部门的） → 底座 team；非叶子部门 → 底座 org_unit。

- 部门同步：钉钉部门树 → 底座 org_unit + team 树（leaf 部门 = team）
- 用户：直接挂到对应 team
- 多部门用户：挂多个 team（钉钉支持）

**注意**：钉钉中途把叶子部门加子部门 → 该部门从 team 变 org_unit。需迁移：
- 该 team 下的用户 → 新建一个「<部门名>-default」team 接管
- 审计 + 通知管理员

### 3.4 通讯录变更回调

钉钉 webhook 事件：
- `user_add_org` / `user_modify_org` / `user_leave_org`
- `org_dept_create` / `org_dept_modify` / `org_dept_remove`
- `label_user_change`（角色标签）

handler 收到 → 写 `dingtalk.sync_task` 表 → worker pick → 调钉钉 OAPI 拉详细数据 → 映射 → SCIM 内部 PATCH。

### 3.5 增量同步策略

- 主路径：webhook（实时）
- 兜底：每 5 分钟全量 diff（防 webhook 丢失）
  - 拉钉钉 user/list 全部 → vs 本地 → 差异 batch SCIM PATCH
  - 1k 员工租户全量 ≈ 30 秒
- 每日 02:00 全量重同步（防长期漂移）

### 3.6 离职 SLA

钉钉 user.active=false → 立即触发：
1. SCIM PATCH active=false （本地用户禁用）
2. 调 identity-service emergency_freeze（revoke all sessions + tokens）
3. notification 给安全管理员 + 用户 manager
4. audit

5 分钟 SLA 守卫：监控钉钉 active 字段变化与底座 disabled_at 时间差，>5min 告警。

## 4. 数据模型

```sql
-- IdP 配置（每租户每 IdP）
CREATE TABLE identity.idp_config (
  tenant_id        TEXT NOT NULL,
  idp_id           TEXT NOT NULL,
  type             TEXT NOT NULL,           -- 'scim_generic'/'dingtalk'/'feishu'/'azure_ad'/'okta'
  enabled          BOOLEAN NOT NULL DEFAULT TRUE,
  config_enc       BYTEA NOT NULL,          -- crypto.encrypt(JSON：钉钉 corp_id/agent_id/app_secret)
  sync_direction   TEXT NOT NULL,           -- 'inbound_only' / 'bidirectional'(v1.1)
  sync_interval_sec INT NOT NULL DEFAULT 300,
  last_sync_at     TIMESTAMPTZ,
  last_sync_status TEXT,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, idp_id)
);

-- 同步任务（钉钉 webhook / 周期 / 手工触发）
CREATE TABLE identity.sync_task (
  tenant_id        TEXT NOT NULL,
  task_id          TEXT NOT NULL,
  idp_id           TEXT NOT NULL,
  trigger          TEXT NOT NULL,           -- 'webhook'/'cron'/'manual_full'
  trigger_payload  JSONB,
  status           TEXT NOT NULL,           -- 'queued'/'running'/'done'/'failed'/'partial'
  total_ops        INT,
  succeed_ops      INT,
  failed_ops       INT,
  error_log        JSONB,
  started_at       TIMESTAMPTZ,
  finished_at      TIMESTAMPTZ,
  PRIMARY KEY (tenant_id, task_id)
);
CREATE INDEX idx_sync_pending ON identity.sync_task(status, started_at) WHERE status='queued';

-- 外部 ID 映射 → 复用 identity-v1 §3.1 的 identity.scim_external_ref（不在本文档重新建表）
-- 若 identity-v1 字段不够，本文档驱动扩展（向 identity-v1 §3.1 提 ADR 加字段）：
--   - idp_id (TEXT)           — 区分多 IdP 来源
--   - external_type (TEXT)    — 'user'/'group'/'department'
--   - first_synced_at         — 首次同步时间
-- 主键改为 (tenant_id, idp_id, external_type, external_id) 复合主键

-- 同步冲突 / 异常日志
CREATE TABLE identity.sync_anomaly (
  tenant_id        TEXT NOT NULL,
  anomaly_id       TEXT NOT NULL,
  task_id          TEXT NOT NULL,
  type             TEXT NOT NULL,           -- 'field_conflict'/'unmapped_field'/'orphan_user'/'duplicate_email'
  details          JSONB NOT NULL,
  resolved         BOOLEAN NOT NULL DEFAULT FALSE,
  resolved_by      TEXT,
  resolved_at      TIMESTAMPTZ,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, anomaly_id)
);
```

## 5. 冲突解决

| 场景 | 策略 |
|---|---|
| IdP 与本地同字段不同值 | IdP 胜（source of truth）；本地修改被覆盖 + 写 anomaly 记录 |
| 本地新增的字段（IdP 没有） | 保留（IdP 不管的字段不影响） |
| IdP 删除用户但本地有 active session | 立即 force logout；user.deactivated_at 标记 |
| 同邮箱被 IdP 关联到两个 externalId | 拒绝同步第二个，写 anomaly；管理员人工解决 |
| 部门移动（用户从 A 部门到 B 部门） | 自动 remove from team_A + add to team_B |
| 部门名重名 | externalId 优先；显示名加 `(部门 path)` 区分 |

## 6. 错误码

| code | HTTP | 说明 |
|---|---|---|
| `FOUNDATION.SCIM.AUTH.INVALID_TOKEN` | 401 | bearer token 错或过期 |
| `FOUNDATION.SCIM.RESOURCE.NOT_FOUND` | 404 | 标 SCIM error `404` |
| `FOUNDATION.SCIM.SCHEMA.INVALID` | 400 | 字段格式错 |
| `FOUNDATION.SCIM.UNIQUENESS_VIOLATION` | 409 | userName 重复 |
| `FOUNDATION.SCIM.FILTER.UNSUPPORTED` | 400 | 不支持的 filter |
| `FOUNDATION.SCIM.MUTABILITY` | 400 | 修改 immutable 字段（如 id） |
| `FOUNDATION.SCIM.SENSITIVE_OP.MFA_REQUIRED` | 403 | 删除全员等敏感 op 需 step-up |
| `FOUNDATION.DINGTALK.OAPI.RATE_LIMITED` | 429 | 钉钉 API 限流 |
| `FOUNDATION.DINGTALK.WEBHOOK.INVALID_SIGN` | 401 | webhook 签名错 |

SCIM 错误响应格式遵守 RFC 7644 §3.12：
```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
  "detail": "User already exists",
  "scimType": "uniqueness",
  "status": "409"
}
```

## 7. 集成

| 模块 | 集成 |
|---|---|
| **identity** | SCIM 操作落到 identity 的 user/group 表；session revoke 走 identity SDK |
| **org** | team / org_unit 同步 |
| **authz** | role 同步（用户角色绑定）|
| **audit** | 每次 SCIM op 入审计 |
| **notification** | 异常（冲突、孤儿、SLA 违反）告警 |
| **crypto** | IdP config (app_secret) 加密存储 |

## 8. 部署形态

| 形态 | SCIM server | 钉钉 worker | webhook ingress |
|---|---|---|---|
| small | 1 实例 | 1 实例 | 不暴露 webhook（仅 cron） |
| medium | 3 实例 HA | 3 实例 | 公网 ingress + mTLS |
| large | 5-20（HPA） | 10+（KEDA） | + WAF + DDoS |

## 9. 性能与容量

| 指标 | 目标 |
|---|---|
| SCIM GET Users (page=100) | < 200ms |
| SCIM PATCH User | < 100ms |
| Bulk 100 ops | < 2s |
| 钉钉全量同步 1k 员工 | < 30s |
| 钉钉 webhook → 本地生效 | < 5s p95 |
| 离职 SLA | < 5min |

## 10. 待解决问题

| # | 问题 | 决策 |
|---|---|---|
| 1 | 钉钉 access_token 7200s 过期 | token-refresh worker 提前 600s 刷新；分布式锁防并发刷 |
| 2 | 钉钉部门同步死循环（A 改 B，B 改 A） | 单向同步避免；webhook → 同步 → 不回写钉钉 |
| 3 | 中文姓名拆分 | v1 不拆，全放 formatted；v1.1 接百家姓库 |
| 4 | 钉钉 OAPI 限流（200 QPS） | 全局 token bucket；大租户分批；夜间窗口跑全量 |
| 5 | 用户已在多租户下 | SCIM 是 per-tenant scoped，同 email 在不同租户独立 user |
| 6 | 删除用户与 lifecycle Legal Hold 冲突 | active=false（禁用）但不 hard delete；hold 解除后清 |
| 7 | 飞书 / 企业微信适配 | 共享 SCIM 适配框架；按需做 |
| 8 | bidirectional 同步（本地修改回写 IdP） | v1 不做；v1.1 评估 |
| 9 | Azure AD provisioning 行为差异 | 跑微软 SCIM compliance test suite 确保兼容 |
| 10 | 钉钉「外部联系人」/ 「企业服务号」 | v1 不同步；只同步「企业员工」 |

## 11. 验证标准（A-M3 出口）

| # | 验证 | 通过 |
|---|---|---|
| 1 | RFC 7643/7644 标准合规 | 跑微软 SCIM Compliance Test + Okta SCIM Test |
| 2 | 钉钉单向 e2e | 钉钉建用户 → 5s 内底座可登录 |
| 3 | 钉钉部门同步 | 树结构 1:1 还原（叶子=team，非叶子=org_unit） |
| 4 | 离职 SLA | 钉钉禁用 → 5min 内底座失效 + session revoke |
| 5 | 冲突场景 | 同邮箱二次同步、字段冲突、部门移动等 5 场景人工 case 通过 |
| 6 | webhook 验签 | 篡改 sign 拒绝；timestamp 5min 防重放 |
| 7 | 全量重同步 | 手工触发；1k 员工 < 30s |
| 8 | PATCH path expression | filter 解析所有 RFC 例子通过 |
| 9 | 审计 | 每次 op + 异常落 audit；可按 idp_id 检索 |
| 10 | 多 IdP 共存 | 同租户同时启用钉钉 + Azure AD；不互相影响 |
| 11 | 性能 | 1000 webhook/min 稳定处理 |
| 12 | 安全 | token 加密 + IP whitelist + mTLS 选项 |

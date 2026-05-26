# Authz Service — 设计文档 v0.1

> P0 #5 产出。覆盖 A-M1 范围。配套：
> - [CONVENTIONS.md](../CONVENTIONS.md)
> - [errors.md](../errors.md)
> - [multi-tenancy.md](../multi-tenancy.md)
> - [identity-v1.md](./identity-v1.md)

---

## 1. Context（为什么做）

`authz-service` 是底座所有 service 共享的**唯一授权决策点**（PDP，Policy Decision Point）。其他 service 是策略执行点（PEP），通过 `foundation_authz` SDK 调 `check()` 来判定"这个用户能不能做这个动作"。

### 关键技术决定（已定型）

| 维度 | 决定 | 理由 |
|---|---|---|
| 模型 | **RBAC（90% 场景）+ OPA(ABAC)（10% 复杂场景）双轨** | 大多数权限是简单 role→permission 映射；少数需要"工作时间/部门/敏感度"复合判定 |
| OPA 部署 | **sidecar 模式 + 中心 bundle 服务** | 业务 pod 内 localhost 调 OPA → 亚毫秒延迟；bundle 由 authz-service 集中分发 + 灰度 |
| RBAC 存储 | **Postgres `authz.*`**，RLS 隔离 | 数据层一致；与其他 service 同库 |
| 决策缓存 | **每 service 进程内 LRU + Redis 二级** | RBAC 检查 ~99% 命中本地；TTL 60s + 失效事件主动 invalidate |
| OPA 数据源 | **bundle 拉模式**（authz-service push 到 OCI registry / S3） | 不用 push API；OPA 自带 polling + ETag 增量 |
| Bundle 灰度 | **shadow → canary → 全量** 三阶段 + kill switch | 策略写错可能全局拒绝/全局放行，必须有 dry-run 与瞬时回滚 |
| 列资源能力 | 提供 `list_accessible_ids()` SDK，**OPA 不擅长**所以走 RBAC 反向索引 | OPA 列举 N 个资源要 N 次 check；用 SQL 反向查 role_binding 表 |
| ReBAC（关系型授权） | **v1 不上**；为 v1.2 预留接口 | 目前业务无"文档共享给好友的好友"这类深层关系需求 |
| 审计 | 每次 check 走 OPA decision log，关键拒绝写 audit-service | 决策可追溯是合规硬要求 |

### 与 RLS 的分工（重要）

| 层 | 做什么 | 何时生效 |
|---|---|---|
| **API 层（authz check）** | 业务动作粒度："能不能调这个端点 / 能不能改这个字段 / 能不能下载这个文件" | 调用前 |
| **数据层（RLS）** | 行粒度兜底："就算应用层漏检，也只能看到自己租户的数据" | DB 查询时 |

**两者必须同时启用**。authz 是"主动拒绝"，RLS 是"被动兜底"。

---

## 2. 职责边界

### authz-service 负责
- 角色 / 权限 / 角色绑定的 CRUD（RBAC 主体）
- OPA bundle 编译 + 分发（含灰度）+ kill switch
- 决策接口：`check(user, action, resource)` / `batch_check()` / `list_accessible_ids()` / `who_can(action, resource)`
- 决策日志聚合（OPA decision log → 本地表 + 转 audit）
- 内置角色模板（platform_super_admin / tenant_admin / member / readonly / billing_admin / security_auditor / api_user / ...）
- 权限注册表（package 启动时注册自己暴露的 permission key）
- 策略测试沙盒（管理员控制台试跑策略）

### authz-service 不负责
- 用户身份认证 → `identity-service`
- 数据库行级隔离 → Postgres RLS（multi-tenancy.md）
- 资源数据本身（哪个用户在哪个部门等） → 由调用方在 `check()` input 里提供，或 authz 通过 SDK 反查 `org-service`
- 特权账号管理 / JIT 提权 → `pam-service`（authz 提供基础角色判定，pam 做时间窗 + 审批）
- 合规策略本身定义 → `compliance-service` 推策略给 authz

### 与其他 service 的交互

```
┌──────────────────────────────────────────────────────┐
│ Other Services (PEPs)                                │
│  identity / org / billing / search / api-platform / ... │
└────────────┬─────────────────────────────────────────┘
             │ foundation_authz SDK
             │   ↳ check(user, action, resource, context)
             │   ↳ 进程内 LRU cache（hit 99%）
             ▼
       ┌──────────────────────────────┐
       │ Sidecar OPA (localhost:8181) │
       │  ↳ 加载本服务关心的 bundle    │
       │  ↳ ~0.3ms 决策延迟           │
       │  ↳ decision log → stdout      │
       └────────┬─────────────────────┘
                │ bundle 拉取（30s polling + ETag）
                ▼
       ┌──────────────────────────────┐
       │ authz-service (PAP/PDP-mgmt) │
       │  ↳ Bundle 编译 + 灰度        │
       │  ↳ RBAC CRUD + Postgres      │
       │  ↳ decision log 聚合 → audit │
       └─┬─────┬──────────────┬───────┘
         │     │              │
         ▼     ▼              ▼
    Postgres  OCI/S3        audit
    (RBAC)    (Bundles)
                ▲
                │ pull
                │
       ┌──────────────────────┐
       │ Sidecar OPAs in fleet│
       └──────────────────────┘
```

---

## 3. RBAC 数据模型

### 3.1 概念

- **Permission**（权限）：原子动作，命名 `<service>.<resource>.<action>`，例 `billing.invoice.read` / `identity.user.freeze`
- **Role**（角色）：permission 集合，可继承（DAG，禁环）
- **RoleBinding**（角色绑定）：把 role 授给 principal（user / team / org_unit / api_key）on scope
- **Scope**（作用域）：`tenant` / `org_unit:<id>` / `team:<id>` / `resource:<type>:<id>` / `*`
- **Permission package**：service 启动时声明自己暴露的全部 permission，authz 维护注册表

### 3.2 表清单

| 表 | 用途 | RLS | 备注 |
|---|---|---|---|
| `authz.permission_definition` | service 注册的 permission 元 | ❌ 平台级 | 仅 migrator/admin 可写；user 只读 |
| `authz.role` | 角色定义 | ✅ | tenant 可自建；带 `is_system` 标记区分内置 |
| `authz.role_permission` | 角色↔权限 | ✅ | many-to-many |
| `authz.role_inherit` | 角色继承（DAG） | ✅ | 防环约束 |
| `authz.role_binding` | 主体↔角色↔作用域 | ✅ | 核心查询热点 |
| `authz.opa_bundle_release` | 已发布 bundle 版本 | ❌ 平台级 | 包含 SHA、签名、灰度状态 |
| `authz.opa_policy_source` | OPA Rego 源代码 | ✅ | 平台预置策略 is_system=true |
| `authz.decision_log` | 决策日志（30 天 ClickHouse mirror） | ✅ | 写 Postgres 热 + 转 audit/ClickHouse |
| `authz.kill_switch` | 紧急关闭某 policy | ✅ | 命中时 OPA 直接 fallback 到默认行为 |

### 3.3 `authz.permission_definition`

```sql
CREATE TABLE authz.permission_definition (
    id            TEXT PRIMARY KEY,                       -- "billing.invoice.read"
    service       TEXT NOT NULL,                          -- "billing"
    resource_type TEXT NOT NULL,                          -- "invoice"
    action        TEXT NOT NULL,                          -- "read"
    description   TEXT NOT NULL,
    risk_level    TEXT NOT NULL DEFAULT 'LOW'
                  CHECK (risk_level IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    requires_mfa  BOOLEAN NOT NULL DEFAULT false,         -- HIGH/CRITICAL 默认 true
    requires_4eyes BOOLEAN NOT NULL DEFAULT false,        -- CRITICAL 默认 true
    requires_pam_jit BOOLEAN NOT NULL DEFAULT false,
    is_system     BOOLEAN NOT NULL DEFAULT true,          -- 平台预置 vs 自定义
    deprecated_at TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX permission_service_idx ON authz.permission_definition (service);
```

权限注册示例（service 启动时）：

```python
# packages/billing/src/foundation_billing/permissions.py
from foundation_authz import permission

PERMISSIONS = [
    permission("billing.invoice.read",  risk="LOW"),
    permission("billing.invoice.create", risk="MEDIUM"),
    permission("billing.invoice.void", risk="HIGH", requires_mfa=True),
    permission("billing.subscription.cancel", risk="CRITICAL",
               requires_mfa=True, requires_4eyes=True),
]
```

每个 service `main.py` 启动时调 `authz_client.register_permissions(PERMISSIONS)`。authz 收到后 upsert 表 + 推 bundle 更新。

### 3.4 `authz.role`

```sql
CREATE TABLE authz.role (
    id          TEXT PRIMARY KEY CHECK (id ~ '^rol_[0-9A-Z]{26}$'),
    tenant_id   TEXT NOT NULL REFERENCES tenant.tenant(id),
    name        TEXT NOT NULL,                            -- 'tenant_admin' / 'finance_viewer'
    display_name TEXT NOT NULL,
    description TEXT,
    is_system   BOOLEAN NOT NULL DEFAULT false,           -- 内置角色不可删
    immutable   BOOLEAN NOT NULL DEFAULT false,           -- 即使非系统也禁止改
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at  TIMESTAMPTZ,
    created_by  TEXT
);
CREATE UNIQUE INDEX role_tenant_name_idx
    ON authz.role (tenant_id, name) WHERE deleted_at IS NULL;
-- RLS + standard policies
```

### 3.5 `authz.role_binding`（最热表，索引特别关键）

```sql
CREATE TABLE authz.role_binding (
    id            TEXT PRIMARY KEY CHECK (id ~ '^rbd_[0-9A-Z]{26}$'),
    tenant_id     TEXT NOT NULL REFERENCES tenant.tenant(id),
    -- principal
    principal_kind TEXT NOT NULL CHECK (principal_kind IN
                  ('USER','TEAM','ORG_UNIT','API_KEY','SERVICE_ACCOUNT')),
    principal_id  TEXT NOT NULL,
    -- role
    role_id       TEXT NOT NULL REFERENCES authz.role(id),
    -- scope
    scope_kind    TEXT NOT NULL CHECK (scope_kind IN
                  ('TENANT','ORG_UNIT','TEAM','RESOURCE','GLOBAL_SYSTEM')),
    scope_id      TEXT,                                   -- NULL 表示 TENANT 全局或 GLOBAL_SYSTEM
    -- 生命周期
    granted_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ,                            -- JIT 提权用
    granted_by    TEXT NOT NULL,
    grant_reason  TEXT,                                   -- 审批工单号或自由文本
    revoked_at    TIMESTAMPTZ,
    revoked_by    TEXT,
    revoked_reason TEXT,
    -- 审计
    audit_event_id TEXT
);

CREATE INDEX rb_principal_idx
    ON authz.role_binding (tenant_id, principal_kind, principal_id, revoked_at)
    WHERE revoked_at IS NULL;
CREATE INDEX rb_role_idx ON authz.role_binding (tenant_id, role_id);
CREATE INDEX rb_scope_idx ON authz.role_binding (tenant_id, scope_kind, scope_id);
CREATE INDEX rb_active_idx
    ON authz.role_binding (tenant_id, principal_id)
    WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now());
CREATE INDEX rb_expires_idx
    ON authz.role_binding (expires_at) WHERE expires_at IS NOT NULL AND revoked_at IS NULL;
```

**性能基线**：`(tenant_id, principal_id)` partial index 让 "用户 X 在租户 T 下的所有有效角色" 查询保持 ms 级（实测 100 万行 < 2ms）。

### 3.6 `authz.role_inherit`（DAG）

```sql
CREATE TABLE authz.role_inherit (
    tenant_id   TEXT NOT NULL,
    parent_role_id TEXT NOT NULL REFERENCES authz.role(id),
    child_role_id  TEXT NOT NULL REFERENCES authz.role(id),
    PRIMARY KEY (parent_role_id, child_role_id)
);

-- 防环：CHECK constraint 不够，用 trigger 检测插入后是否成环
CREATE OR REPLACE FUNCTION authz_check_no_cycle()
RETURNS TRIGGER AS $$
DECLARE has_cycle BOOLEAN;
BEGIN
    WITH RECURSIVE ancestors AS (
        SELECT parent_role_id, child_role_id, 1 AS depth
          FROM authz.role_inherit WHERE child_role_id = NEW.parent_role_id
        UNION ALL
        SELECT ri.parent_role_id, ri.child_role_id, a.depth + 1
          FROM authz.role_inherit ri
          JOIN ancestors a ON ri.child_role_id = a.parent_role_id
          WHERE a.depth < 50
    )
    SELECT EXISTS(SELECT 1 FROM ancestors WHERE parent_role_id = NEW.child_role_id) INTO has_cycle;
    IF has_cycle THEN
        RAISE EXCEPTION 'Role inheritance cycle detected';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER role_inherit_no_cycle BEFORE INSERT OR UPDATE ON authz.role_inherit
    FOR EACH ROW EXECUTE FUNCTION authz_check_no_cycle();
```

### 3.7 内置角色（is_system=true）

| 角色 | 范围 | 关键权限 |
|---|---|---|
| `platform_super_admin` | GLOBAL_SYSTEM | 所有 service.\*（特殊：跨租户读写） |
| `platform_security_auditor` | GLOBAL_SYSTEM | `*.read` + 审计日志读 |
| `tenant_admin` | TENANT | tenant 内所有 service.\*（除合规模式硬限） |
| `tenant_security_admin` | TENANT | `pam.*` + `compliance.*` + `audit.read` |
| `tenant_billing_admin` | TENANT | `billing.*` |
| `org_unit_admin` | ORG_UNIT | 子树内成员管理 + 资源读写 |
| `team_lead` | TEAM | team 内资源读写 + 成员邀请 |
| `member` | TENANT | 业务资源 read + 自己 create/update |
| `readonly` | TENANT | `*.read` |
| `api_user` | TENANT | 受 API Key scope 限定的权限子集 |

**内置角色定义** 放 `packages/authz/migrations/seed/system_roles.sql`，identity 创建租户时调 authz 初始化。

---

## 4. OPA 集成

### 4.1 部署架构（sidecar 主力 + 中心 bundle 服务）

```
┌─────────────── 业务 Pod ────────────────┐
│  ┌─────────────┐    ┌──────────────┐    │
│  │ service app │───→│ opa sidecar  │    │
│  │  (FastAPI)  │    │ :8181        │    │
│  └─────────────┘    └──────┬───────┘    │
│                            │ poll 30s    │
└────────────────────────────┼─────────────┘
                             │ ETag 增量
                             ▼
                  ┌──────────────────────┐
                  │ authz-service        │
                  │  bundle build & sign │
                  │  push to OCI / S3    │
                  └──────────┬───────────┘
                             │
                             ▼
                   ┌──────────────────┐
                   │ OCI Registry / S3│
                   │  versioned bundles│
                   └──────────────────┘
```

为什么选 sidecar：
- **延迟亚毫秒**（localhost loopback，OPA 自身 ~0.3ms）
- **故障域小**（单 pod 失效不波及全局）
- **租户隔离**（每 service pod 加载该 service 关心的 bundle，不必全量）
- 中心化的 PDP 模式作为**备用方案**（service mesh / IngressGateway 集成时用）

资源开销：每 sidecar ~50MB RAM、CPU < 5m。小型 service 不算重。

### 4.2 Bundle 结构

```
bundle/
├── .manifest                           # OPA manifest（roots, metadata, signing）
├── data/
│   ├── permissions.json                # 权限注册表（从 DB 导出）
│   ├── role_inherit.json               # 角色继承关系
│   └── compliance/
│       ├── pipl.json                   # 各合规模式默认规则数据
│       └── equal_protection_3.json
├── policy/
│   ├── core.rego                       # 入口 + 公共函数
│   ├── rbac.rego                       # RBAC 决策
│   ├── abac.rego                       # ABAC（时间窗、IP、设备）
│   ├── compliance.rego                 # 合规模式联动
│   └── per_service/
│       ├── identity.rego
│       ├── billing.rego
│       └── ...
└── signatures.json                     # bundle 整体签名（防中间人篡改）
```

### 4.3 入口 policy 示例

```rego
# policy/core.rego
package foundation.authz

import future.keywords.if
import future.keywords.in

default allow := false
default deny_reason := "default_deny"

# Kill switch：命中即 deny（短路）
deny if {
    data.kill_switch[input.policy_id]
}

allow if {
    not deny
    rbac_allow
    abac_allow
    compliance_allow
}

deny_reason := reason if {
    not rbac_allow
    reason := "rbac_denied"
}
deny_reason := reason if {
    rbac_allow
    not abac_allow
    reason := "abac_denied"
}
deny_reason := reason if {
    rbac_allow
    abac_allow
    not compliance_allow
    reason := "compliance_denied"
}

# RBAC: 看 input.user.role_grants 是否覆盖 input.action
rbac_allow if {
    some grant in input.user.role_grants
    grant.permission == input.action
    scope_matches(grant.scope, input.resource)
}

scope_matches(scope, resource) if {
    scope.kind == "TENANT"
    scope.id == resource.tenant_id
}
scope_matches(scope, resource) if {
    scope.kind == "RESOURCE"
    scope.id == resource.id
}
# ... 其余 scope 匹配
```

```rego
# policy/abac.rego
package foundation.authz

import future.keywords.if
import future.keywords.in

default abac_allow := true   # 无 ABAC 规则时通过

abac_allow if {
    not abac_violations
}

abac_violations contains "outside_business_hours" if {
    input.permission_definition.requires_business_hours
    not in_business_hours
}

in_business_hours if {
    h := time.clock(time.parse_rfc3339_ns(input.now))[0]
    h >= input.tenant.business_hours_start
    h < input.tenant.business_hours_end
}

abac_violations contains "outside_allowed_ip" if {
    count(input.user.allowed_ip_cidrs) > 0
    not net.cidr_contains_matches(input.user.allowed_ip_cidrs, input.request.ip)[_]
}

abac_violations contains "device_not_compliant" if {
    input.permission_definition.requires_compliant_device
    not input.user.device.is_compliant
}

abac_violations contains "data_classification_too_high" if {
    input.permission_definition.requires_classification_lte
    input.resource.classification > input.permission_definition.requires_classification_lte
}
```

### 4.4 OPA `input` 契约（极重要）

每次 `check()` 调用，SDK 构造的 input：

```json
{
  "policy_id": "billing.invoice.void",
  "action": "billing.invoice.void",
  "user": {
    "id": "usr_01J...",
    "tenant_id": "tnt_01J...",
    "department_id": "ou_01J...",
    "roles": ["finance_admin"],
    "role_grants": [
      {"permission": "billing.invoice.void", "scope": {"kind":"TENANT","id":"tnt_01J..."}}
    ],
    "allowed_ip_cidrs": ["10.0.0.0/8"],
    "device": {"is_compliant": true, "fingerprint": "..."}
  },
  "resource": {
    "type": "invoice",
    "id": "inv_01J...",
    "tenant_id": "tnt_01J...",
    "classification": 2,
    "owner_team_id": "tm_01J..."
  },
  "request": {
    "ip": "10.1.2.3",
    "user_agent": "...",
    "mfa_satisfied": true,
    "pam_elevated": false,
    "request_id": "req_01J..."
  },
  "tenant": {
    "tier": "BUSINESS",
    "compliance_modes": ["pipl", "equal_protection_3"],
    "business_hours_start": 9,
    "business_hours_end": 19
  },
  "permission_definition": {
    "risk_level": "HIGH",
    "requires_mfa": true,
    "requires_4eyes": false,
    "requires_business_hours": false,
    "requires_compliant_device": false,
    "requires_classification_lte": null
  },
  "now": "2026-05-22T10:30:00Z"
}
```

input schema 在 `contracts/opa/input.schema.json`，CI 校验 SDK 输出与 OPA 输入一致。

### 4.5 Bundle 编译与签名

`authz-service` 启动一个 `bundle-builder` worker：

1. 监听以下事件触发重编：
   - `authz.permission_definition` 表变更
   - `authz.role_*` 表变更
   - `authz.opa_policy_source` 表变更（管理员通过 UI/API 改策略）
   - `foundation.compliance.mode_changed` 事件
2. 用 `opa build -b <dir>` 生成 `.tar.gz`
3. 用 `crypto-service` 签名（默认 Ed25519 / 国密 SM2）
4. 推 OCI registry / S3，URL `bundles/foundation/v<version>.tar.gz`
5. 写 `authz.opa_bundle_release` 表 + 发事件 `foundation.authz.bundle.released`

### 4.6 Bundle 分发与灰度

```
[v1.42] ──┐
          │  ① shadow: 所有 OPA 双跑 v1.41(决策) + v1.42(对比)
          │     差异 > 阈值 → 自动告警，不发布
          │
          ▼
[v1.42] ──┐
          │  ② canary: 1 个 service pod 切到 v1.42
          │     观察 1-24h 拒绝率 / 错误率
          │
          ▼
[v1.42] ──┐
          │  ③ progressive: 5% → 25% → 50% → 100%
          │     SDK 上报决策结果，authz-service 监控异常
          │
          ▼
[v1.42 全量]
```

实现方式：
- bundle 拉取响应里携带 `target_version`；OPA 按 service `pod_id` hash 决定该拉哪个版本
- 异常时管理员一键 `helm upgrade --set authz.bundle.rollback=v1.41` 或调 `POST /bundles/rollback`
- **shadow / canary 阶段不影响生产决策**

### 4.7 Kill Switch（紧急熔断）

某条策略写错或某 service 滥用，管理员控制台一键关闭：

```
POST /api/authz/v1/kill-switches
{
  "policy_id": "billing.invoice.void",
  "action": "FALLBACK_DENY",   // 或 FALLBACK_ALLOW（极少用）
  "reason": "policy v1.42 false-positive 92%",
  "expires_at": "2026-05-22T11:00:00Z"
}
```

实现：
- 写 `authz.kill_switch` 表 + 立即发事件
- bundle-builder 在 60s 内重建 bundle 把 `kill_switch` 数据更新
- 紧急路径：authz SDK 也订阅 Redis pubsub `foundation:authz:kill_switch`，所有 service 收到秒级 invalidate cache
- 自动过期 + 必须填理由（强制审计）

### 4.8 决策日志

OPA `decision_logs` 配 plugin 推到 authz-service `/internal/decisions`：

```
service pod → opa sidecar → batch → authz-service /internal/decisions → ClickHouse audit.authz_decisions
                                                       └→ Postgres authz.decision_log（最近 30 天热查）
```

字段：`decision_id, timestamp, tenant_id, user_id, action, resource_id, allow, deny_reason, policy_version, latency_ns, bundle_sha`

合规要求：所有 `403` 拒绝 + 所有 `CRITICAL` 风险动作必须落审计 + WORM。

---

## 5. SDK 契约（`foundation_authz`）

### 5.1 核心方法

```python
from foundation_authz import AuthzClient, ResourceRef, allow, require_permission

authz = AuthzClient.from_env()

# ---------- 单个 check ----------
result = authz.check(
    action="billing.invoice.void",
    resource=ResourceRef(type="invoice", id="inv_01J...", tenant_id="tnt_..."),
    # user / tenant / device / now 等从 contextvars 自动获取
)
if not result.allow:
    raise PolicyError(deny_reason=result.deny_reason)

# ---------- decorator 模式 ----------
@require_permission("billing.invoice.void", resource_arg="invoice_id", resource_type="invoice")
async def void_invoice(invoice_id: str): ...

# ---------- 批量 check（一次决策多个资源）----------
results = authz.batch_check(
    action="billing.invoice.read",
    resources=[ResourceRef("invoice", iid, tenant_id) for iid in invoice_ids],
)
allowed_ids = [r.resource.id for r in results if r.allow]

# ---------- 反向：列出 user 能访问的资源 ID ----------
ids = authz.list_accessible_ids(
    action="billing.invoice.read",
    resource_type="invoice",
    # 通过 role_binding 反向 SQL 查 + 可选 OPA filter
)

# ---------- 反向：谁能做这件事 ----------
users = authz.who_can(action="billing.invoice.void", resource_id="inv_...")
```

### 5.2 进程内 cache 与失效

- **LRU 大小**：每 service 进程 10000 条决策，TTL 60s
- **Cache key**：`hash(user_id + action + resource_id + role_version)`
- **失效**：
  - 收到 `foundation.authz.role_binding.changed` 事件 → 清该 user 所有 entry
  - 收到 `foundation.authz.bundle.released` → 清全部
  - 收到 `foundation.identity.user.frozen` → 清该 user
- **bypass**：critical 动作（risk=CRITICAL）每次都查 OPA，不走 cache

### 5.3 错误映射（CONVENTIONS / errors.md）

| 场景 | 错误码 | HTTP |
|---|---|---|
| 拒绝 | `FOUNDATION.AUTHZ.POLICY.PERMISSION_DENIED` | 403 |
| 跨租户 | `FOUNDATION.AUTHZ.POLICY.TENANT_MISMATCH` | 403 |
| 需要 MFA 但未满足 | `FOUNDATION.AUTHZ.POLICY.MFA_REQUIRED` | 403 |
| 需要 4 眼 | `FOUNDATION.AUTHZ.POLICY.FOUR_EYES_REQUIRED` | 403 |
| 需要 JIT 提权 | `FOUNDATION.AUTHZ.POLICY.PAM_ELEVATION_REQUIRED` | 403 |
| 时间窗外 | `FOUNDATION.AUTHZ.POLICY.OUTSIDE_BUSINESS_HOURS` | 403 |
| IP 不在白名单 | `FOUNDATION.AUTHZ.POLICY.IP_NOT_ALLOWED` | 403 |
| 设备不合规 | `FOUNDATION.AUTHZ.POLICY.DEVICE_NOT_COMPLIANT` | 403 |
| OPA sidecar 不可达 | `FOUNDATION.AUTHZ.DEPENDENCY.OPA_UNAVAILABLE` | 503 |
| Kill switch 命中 | `FOUNDATION.AUTHZ.POLICY.KILL_SWITCH_DENY` | 403 |

`deny_reason` 字段保留 OPA 返回的细节，前端可按需展示给用户。

---

## 6. API 表面

> 完整 OpenAPI 在 `contracts/openapi/authz.yaml`。本节给出端点清单。

| 端点 | 方法 | 权限 | 用途 |
|---|---|---|---|
| `/decisions:check` | POST | bearer | 单个 check |
| `/decisions:batch-check` | POST | bearer | 批量 |
| `/decisions:list-accessible-ids` | POST | bearer | 反向列表 |
| `/decisions:who-can` | POST | bearer | 反向问"谁能" |
| `/permissions` | GET | tenant_admin | 列出全部已注册 permission |
| `/permissions/register` | POST | service_account | service 启动时调用注册 |
| `/roles` | GET / POST | tenant_admin | 角色 CRUD |
| `/roles/{id}` | GET / PATCH / DELETE | tenant_admin | 单角色 |
| `/roles/{id}/permissions` | POST / DELETE | tenant_admin | 改 role 的权限集合 |
| `/roles/{id}/inherits` | POST / DELETE | tenant_admin | 角色继承 |
| `/role-bindings` | GET / POST | tenant_admin | 绑定 CRUD |
| `/role-bindings/{id}` | GET / DELETE | tenant_admin | 撤销 |
| `/principals/{kind}/{id}/effective-permissions` | GET | tenant_admin | 看某人有效权限合集 |
| `/bundles` | GET | platform_admin | bundle 历史 |
| `/bundles/release` | POST | platform_admin | 发布新 bundle |
| `/bundles/rollback` | POST | platform_admin | 回滚 |
| `/bundles/{version}/diff` | GET | platform_admin | 对比 |
| `/policy-sources` | GET / POST / PATCH | platform_admin | Rego 源码管理 |
| `/policy-sources/{id}/test` | POST | platform_admin | 沙盒试跑（dry-run） |
| `/kill-switches` | GET / POST / DELETE | platform_security_admin | 紧急熔断 |
| `/decisions` | GET | tenant_admin | 决策日志查询（30 天） |
| `/internal/decisions` | POST | opa-sidecar | OPA decision log 上报 |
| `/internal/opa/bundles/{version}` | GET | opa-sidecar | bundle 拉取（带 ETag） |

---

## 7. 关键场景与端到端流程

### 7.1 业务 service 启动注册权限

```
service main.py
  ↓ authz_client.register_permissions([...])
authz /permissions/register
  ↓ upsert authz.permission_definition
  ↓ 触发 bundle 重建
  ↓ 发 foundation.authz.permissions.updated
opa sidecars
  ↓ next polling 拉新 bundle
```

### 7.2 业务 service 调 check

```
service.api.router 接到 PATCH /invoices/{id}
  ↓ @require_permission("billing.invoice.void")
SDK check()
  ↓ 查进程内 LRU → hit return
  ↓ miss → 调 sidecar OPA POST /v1/data/foundation/authz
OPA 决策（~0.3ms）
  ↓ decision log 写 stdout，fluent-bit 推 authz /internal/decisions
SDK 缓存结果
  ↓ allow → 业务继续；deny → raise PolicyError
PolicyError → 框架转 403 application/problem+json
audit-service 异步收到 decision log 落 ClickHouse + WORM（仅 deny / critical）
```

### 7.3 管理员撤销 role binding

```
admin UI → DELETE /role-bindings/{id}
  ↓ authz revoke + 写 revoked_at
  ↓ 触发 bundle 重建
  ↓ 发 foundation.authz.role_binding.changed (user_id)
其他 service SDK 收到事件
  ↓ 清该 user 的 LRU
下次该 user 任何 check → 已无该角色 → deny
```

最差延迟：**事件 + OPA polling，秒到 30s 内**。对"立即生效"严格要求的（如紧急冻结）走 identity 那条路径 + Redis 黑名单。

### 7.4 紧急 kill switch

```
某策略 v1.42 上线后线上拒绝率 60% 异常
平台 admin → POST /kill-switches {policy_id=..., action=FALLBACK_DENY}
  ↓ 写表 + Redis pubsub
  ↓ 触发 bundle 重建（60s 内更新 data.kill_switch）
所有 SDK 收 pubsub → 立即在本地 SDK 层硬拒（不等 OPA bundle 更新）
bundle 更新后 OPA 也拒
紧急修复策略 → 走正常 shadow/canary/progressive → 解除 kill switch
```

### 7.5 OPA sidecar 故障

- **fail-closed 默认**：sidecar 不可达 → SDK 返回 `OPA_UNAVAILABLE` → service 应 503
- **可选 fail-open**（极少用，仅 `*.read` low-risk）：通过 SDK config + 必须配合审计告警
- pod 健康检查包含 sidecar：sidecar 失效 → pod readiness=false → 流量切走
- 监控指标：`foundation_authz_sidecar_unavailable_total`，PagerDuty P0

---

## 8. 合规模式联动

| 模式 | 影响 |
|---|---|
| `pipl` | 默认所有 HIGH 操作 `requires_mfa=true` |
| `equal_protection_3` | + 异常 IP / 跨境登录强制 ABAC `outside_allowed_ip` 拒绝 |
| `equal_protection_4` | + 所有 HIGH 必须 PAM JIT 提权 |
| `finance_jrt0071` | + 所有 CRITICAL 强制 4 眼 + 数据分级 ≤4 才能下载 |
| `hipaa` | + 所有 PHI 访问审计写 WORM + 访问理由必填 |
| `soc2` | + 决策日志保留 ≥1 年 |
| `gdpr` | + 决策日志含数据主体权利上下文 |

合规模式变更走 `compliance-service` → `authz-service` 事件，authz 重新编译 bundle 把对应规则启停。

---

## 9. 性能目标

| 指标 | 目标 | 验证 |
|---|---|---|
| 单 check 延迟（cache hit） | P99 < 0.05ms | service 进程内 |
| 单 check 延迟（cache miss） | P99 < 2ms | 含 OPA RPC |
| batch check 100 个资源 | P99 < 20ms | 单次 OPA 多结果返 |
| list_accessible_ids 1000 ID | P99 < 50ms | 走 SQL，不走 OPA |
| bundle build & sign | < 5s | 即使含 1000 个 permission |
| bundle polling 拉取 | < 100ms | ETag 增量 |
| 事件 → cache 失效 | < 1s P99 | Redis pubsub |
| 单 sidecar QPS | ≥ 5000 | benchmarked |

详见 [Goldman Sachs OPA scaling case](https://developer.gs.com/blog/posts/scaling-opa-for-oces) 公开数据，sidecar 实测亚毫秒。

---

## 10. 测试策略

### 10.1 单元（≥90%）
- role 继承 DAG / 防环
- scope 匹配（TENANT / ORG_UNIT / TEAM / RESOURCE / GLOBAL）
- permission 注册幂等
- kill switch FALLBACK_DENY / FALLBACK_ALLOW 行为

### 10.2 OPA policy 单元（Rego test）
- 每条 Rego 规则配 `*_test.rego`
- `opa test bundle/` 跑 100% policy 覆盖
- 阳性/阴性用例都覆盖

### 10.3 集成
- service 启动 → 注册权限 → bundle 重建 → sidecar 拉到新版本 → check 通过
- role 撤销 → 事件 → cache 失效 → 下次 deny
- kill switch → 1s 内全 service 生效
- canary 流量 5% 切换正确

### 10.4 安全 fuzz
- 跨租户：A 租户用户 check B 租户资源，所有组合必须 deny（参数化 1000 次）
- input 注入：构造畸形 input（缺字段 / 类型错 / 超大 JSON）→ OPA 安全拒绝
- bundle 篡改：未签名 / 签名错误 bundle 必须被 OPA 拒载
- decision log 重放：authz `/internal/decisions` 必须验签

### 10.5 性能
- 50 万 role_binding，单 check P99 ≤ 2ms
- batch 100 资源 P99 ≤ 20ms
- 100 个 sidecar 同时拉新 bundle，authz-service 不挂

---

## 11. 部署形态差异

| 维度 | small | medium | large |
|---|---|---|---|
| authz-service 副本 | 1 | 3 | 5-10 HPA |
| OPA 模式 | sidecar | sidecar | sidecar + edge gateway centralized |
| Bundle 分发 | S3 (MinIO) | S3 + CDN | OCI registry + 同城 mirror |
| Decision log | Postgres | Postgres + ClickHouse | ClickHouse 集群 + S3 WORM |
| Cache | 进程 LRU | + Redis | + Redis 集群 |
| Kill switch 触达 | pubsub | pubsub | pubsub + mesh 配置 |

---

## 12. 与未来 ReBAC 的关系（v1.2 预留）

OPA 不擅长两种场景：
1. **"列出 user X 能访问的所有资源"**——必须遍历或反向索引；我们用 SQL `role_binding` 反向查解决（§5.1）
2. **"文档共享给同事的同事的子团队"** 这类深层关系

如果未来 agent 业务出现"共享会话"、"嵌套团队权限继承"等场景，可能要引 [OpenFGA](https://openfga.dev/) 或 [SpiceDB](https://authzed.com/spicedb)。预留接口：

- SDK `check()` 已有 `relationship_query=None` 参数（v1 不实现）
- ReBAC 决策结果会作为 OPA input 的 attribute 喂进去（混合模式）

v1.2 起判断是否引入 ReBAC——硬指标是"出现连续 3 个 use case 用 OPA 写不优雅"。

---

## 13. 关键技术风险

| 风险 | 缓解 |
|---|---|
| OPA 策略写错全局拒绝/全局放行 | shadow/canary/progressive 三阶段 + 自动 diff 监控 + kill switch + 必须经 `opa test` 覆盖 |
| sidecar 模式增加 50MB/pod 资源开销 | 实测可接受；超大集群可考虑 [OPA daemonset per node](https://blog.openpolicyagent.org/) |
| OPA 版本升级 breaking change | 锁 OPA minor 版本，patch 自动；major 升级走 ADR |
| bundle 体积爆炸（permission 数 × tenant 数） | bundle 分租户分 service；不把所有租户的 role_binding 塞进 bundle，运行时通过 input 注入 |
| decision log 量大冲爆 ClickHouse | 采样：allow 仅采 1%，deny / critical 100%；保留期按合规配 |
| OPA bundle 篡改 | 强制签名验证 + 拒载未签 bundle + bundle URL 走 mTLS |
| 进程内 cache stale 导致越权 | 关键动作（CRITICAL）bypass cache；权限撤销后 SDK 主动失效；上限 60s TTL |
| 跨 service event 丢失导致 cache 永不失效 | 事件双发（Redis pubsub + DB 表轮询）；启动时全量重建 cache |
| 业务 service 绕过 SDK 直调 OPA | CI Semgrep 规则禁止；SDK 是唯一允许入口 |
| ABAC 规则依赖时钟同步 | 所有 pod 强制 NTP；OPA `time.now_ns` + 业务 service `now` 双校验 |

---

## 14. 待解决问题

| # | 问题 | 决策机制 | 截止 |
|---|---|---|---|
| Q1 | OPA 决策日志采样率：deny 100%、allow 1% 够不够看出异常？ | 跟首 POC 一个月数据验证 | A-M3 |
| Q2 | bundle 体积超过 100MB 时怎么办（极端情况） | 分租户 bundle；当前阈值 50MB 触发告警 | A-M2 |
| Q3 | "管理员代为操作"（impersonation）授权模型 | 走 PAM JIT + 显式审计 actor=ADMIN_AS_USER | A-M4 |
| Q4 | API Key 权限模型与 user 角色如何统一 | 引入 SERVICE_ACCOUNT principal_kind；scope 同 user | A-M4 |
| Q5 | OPA policy hot reload 时正在跑的请求如何处理 | OPA 原子切换；旧请求用旧 bundle 完成 | 已定 |
| Q6 | RBAC 角色数量上限（防租户管理员瞎建 1000 个角色） | 每租户 hard cap 100，可申请提升 | A-M3 |
| Q7 | 是否提供"角色模板市场"让租户复用 | 业务驱动；初版仅平台内置 10 个 | v1.1 |
| Q8 | 多个 deny 原因如何聚合（用户友好的拒绝消息） | OPA 返优先级最高的 reason；前端 i18n 映射 | A-M3 |
| Q9 | OPA in WASM mode 编译能否进一步降延迟 | 调研 + benchmark；v1.1 决 | v1.1 |
| Q10 | 离线 audit decision log → ClickHouse 的反压 | KEDA + batch；超阈值熔断采样 | A-M5 |

---

## 15. 验证标准（M1 出口）

- [ ] OpenAPI `contracts/openapi/authz.yaml` spectral lint 通过
- [ ] 单元 / Rego 测试覆盖 ≥90%
- [ ] 内置 10 个角色 + 100+ permission 注册跑通
- [ ] sidecar OPA 在 docker-compose 起得来 + 自动拉初始 bundle
- [ ] shadow / canary / progressive 三阶段 e2e 测试通过
- [ ] kill switch P99 < 1s 全 service 生效
- [ ] 跨租户 fuzz 1000 次零越权
- [ ] OPA 决策延迟 P99 < 2ms（cache miss）
- [ ] list_accessible_ids 1000 条 P99 < 50ms
- [ ] decision log 端到端到 ClickHouse + 关键事件到 WORM
- [ ] PR 走完 service-ci.yml + security-scan.yml + helm-validate.yml

---

## 16. 参考资料

- [Open Policy Agent 官方文档](https://www.openpolicyagent.org/docs/)
- [AWS Prescriptive Guidance — OPA design models for SaaS](https://docs.aws.amazon.com/prescriptive-guidance/latest/saas-multitenant-api-access-authorization/using-opa.html)
- [Goldman Sachs scaling OPA case study](https://developer.gs.com/blog/posts/scaling-opa-for-oces)
- [OPA vs OpenFGA technical comparison](https://madappgang.com/blog/opa-vs-openfga-a-comprehensive-technical-compariso/)
- [Google Zanzibar paper](https://research.google/pubs/pub48190/)
- [SpiceDB](https://authzed.com/spicedb)
- [OpenFGA](https://openfga.dev/)
- [OPA Bundle API](https://www.openpolicyagent.org/docs/management-bundles)
- [OPA Decision Logs](https://www.openpolicyagent.org/docs/management-decision-logs)
- [Rego language reference](https://www.openpolicyagent.org/docs/policy-language)

---

## 17. 变更记录

| 日期 | 版本 | 变更 |
|---|---|---|
| 2026-05-22 | 0.1.0 | 初版（P0 #5） |

# Lifecycle Service — 设计文档 v0.1

> P2 #11 产出。覆盖 A-M2 范围。配套：
> - [audit-v1.md](./audit-v1.md)
> - [crypto-v1.md](./crypto-v1.md)
> - [multi-tenancy.md](../multi-tenancy.md)
> - [data-protection-v1.md](./data-protection-v1.md)（P2 #13）

---

## 1. Context

`lifecycle-service` 是底座**数据存续期的总调度**：

1. **Retention policy**：每个资源类型有保留期；到期触发删除流程
2. **Recycle Bin**：软删除 → 回收站 → 硬删除 三阶段
3. **Legal Hold**：法律保留覆盖一切删除流程
4. **销毁证明**：硬删时生成 PDF（数据清单 + 见证人签字 + hash 存证）
5. **Backup/Restore**：底座自身 DB + 业务卷统一编排
6. **生命周期感知的备份**：备份也是 PII，跟随原数据 retention

### 关键技术决定

| 维度 | 决定 | 理由 |
|---|---|---|
| 模型 | **资源注册式**：每类资源注册自己的 lifecycle 规则 | 业务自治；底座只提供调度 + 流程 |
| 软删除 | **`deleted_at IS NULL`** 列约定 | 与 multi-tenancy.md §6.1 一致 |
| 硬删除 | **加密密钥销毁 + 物理覆写双轨** | 字段加密的字段直接销 key；明文表用 DoD 5220 |
| Recycle Bin | 30 天默认（可配） | 减少误删恢复成本 |
| Legal Hold | 调 audit 强审计；任何 delete 必查 | 不允许硬删带 LH 的资源 |
| 销毁证明 | PDF + 数字签名 + WORM 归档 | 法律证据级 |
| Backup | pgBackRest + Velero + clickhouse-backup | 工具齐全成熟 |
| 备份合规 | 备份 KEK 独立 + 跟随原数据 retention | 备份也是 PII |
| 调度 | APScheduler（small）/ KEDA + cron（large） | 按 profile |
| 跨表协同 | event-driven outbox + 状态机 | 避免长事务 |
| 销毁方式优先级 | crypto key destroy > DoD overwrite > truncate | 越靠前越快越彻底 |

---

## 2. 职责边界

### lifecycle-service 负责
- Retention policy registry（每类资源的保留期 + 销毁方式）
- 调度删除 job（按日/小时 cron）
- Legal Hold CRUD + 校验
- Recycle Bin 列表 / 恢复 / 提前清空
- 销毁证明 PDF 生成（含 hash chain + 见证人电子签字）
- Backup/Restore 编排（调用底层工具）
- 备份生命周期（备份的备份保留期同样守约束）

### lifecycle-service 不负责
- 数据本身的存储 → 各 service 自己 DB
- 字段加密 / 密钥销毁实现 → `crypto-service`
- 数据脱敏 → `data-protection-service`
- 备份工具底层 → pgBackRest / Velero / clickhouse-backup
- 合规模式定义 → `compliance-service`
- 审计日志 → `audit-service`（lifecycle 自己也会发审计）

### 交互图

```
[业务 service]
   │  调 lifecycle SDK：
   │    register_resource_type(...)         （启动时）
   │    soft_delete(resource_id, kind)
   │    mark_legal_hold(...)
   ▼
[lifecycle-service]
   │
   ├──→ Postgres: lifecycle.* 表
   │
   ├──→ data-protection: 协调脱敏 / 销毁证明
   │
   ├──→ crypto: 销毁 KEK（= 数据销毁快速通道）
   │
   ├──→ audit: 所有生命周期事件强审计
   │
   ├──→ notification: 销毁前 N 天通知 / 销毁完成通知
   │
   └──→ tools: pgBackRest / Velero / clickhouse-backup
```

---

## 3. 模型

### 3.1 表清单

| 表 | 用途 | RLS |
|---|---|---|
| `lifecycle.resource_type` | 业务注册的资源类型 + lifecycle 规则 | ❌ 平台级 |
| `lifecycle.retention_policy_override` | 租户级 override（在合规模式 + 系统默认之上） | ✅ |
| `lifecycle.recycle_bin` | 软删后 → 等待硬删的指针 | ✅ |
| `lifecycle.legal_hold` | 法律保留 | ✅ |
| `lifecycle.destruction_certificate` | 销毁证明记录 | ✅ |
| `lifecycle.destruction_job` | 调度任务执行记录 | ✅ |
| `lifecycle.backup_plan` | 备份方案 | ✅ |
| `lifecycle.backup_run` | 备份执行记录 | ✅ |
| `lifecycle.restore_request` | 恢复请求 | ✅ |
| `lifecycle.approval_request` | 四眼审批申请（立即硬删 / 解除 LH），见 §4.4 | ✅ |

### 3.2 `lifecycle.resource_type`

```sql
CREATE TABLE lifecycle.resource_type (
    id                  TEXT PRIMARY KEY,                  -- "identity.user" / "billing.invoice"
    service             TEXT NOT NULL,                     -- "identity"
    resource_type       TEXT NOT NULL,                     -- "user"
    display_name        TEXT NOT NULL,
    -- 软删 / 硬删
    soft_delete_enabled BOOLEAN NOT NULL DEFAULT true,
    recycle_bin_days    INT NOT NULL DEFAULT 30,
    -- 保留期（基线 + 合规可加严）
    default_retention_days INT NOT NULL DEFAULT 365,
    min_retention_days  INT NOT NULL DEFAULT 0,            -- 任何 override 不可低于此
    max_retention_days  INT,                                -- NULL = 不限
    -- 销毁方式
    destruction_method  TEXT NOT NULL DEFAULT 'CRYPTO_KEY_DESTROY'
                        CHECK (destruction_method IN
                          ('CRYPTO_KEY_DESTROY', 'DOD_OVERWRITE', 'TRUNCATE', 'CUSTOM_HOOK')),
    -- 自定义销毁 hook（业务 service 暴露端点）
    custom_hook_url     TEXT,
    -- 销毁前通知
    notify_days_before  INT[] DEFAULT ARRAY[7,1],          -- 销毁前 7d / 1d 通知
    -- 销毁证明
    requires_destruction_certificate BOOLEAN NOT NULL DEFAULT true,
    -- 元
    schema_version      INT NOT NULL DEFAULT 1,
    metadata            JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

业务 service 启动时调 SDK 注册：

```python
from foundation_lifecycle import register_resource_type, RetentionPolicy

register_resource_type(
    id="identity.user",
    display_name="用户档案",
    default_retention_days=180,        # 离职后 180 天硬删
    recycle_bin_days=30,
    destruction_method="CRYPTO_KEY_DESTROY",   # 字段加密 KEK 销毁即可
    notify_days_before=[14, 7, 1],
)
register_resource_type(
    id="billing.invoice",
    display_name="发票",
    default_retention_days=2555,       # 法定 7 年
    min_retention_days=2555,            # 不允许低于
    destruction_method="DOD_OVERWRITE",
)
```

### 3.3 `lifecycle.recycle_bin`

```sql
CREATE TABLE lifecycle.recycle_bin (
    id                TEXT PRIMARY KEY,                  -- "rcb_..."
    tenant_id         TEXT NOT NULL REFERENCES tenant.tenant(id),
    resource_type_id  TEXT NOT NULL REFERENCES lifecycle.resource_type(id),
    resource_id       TEXT NOT NULL,                     -- 业务表的 row id
    -- 时间
    soft_deleted_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    purge_scheduled_at TIMESTAMPTZ NOT NULL,             -- soft_deleted_at + recycle_bin_days
    purged_at         TIMESTAMPTZ,                       -- 已执行
    -- 操作者
    deleted_by        TEXT NOT NULL,
    delete_reason     TEXT,
    -- 恢复
    restored_at       TIMESTAMPTZ,
    restored_by       TEXT,
    -- 元
    snapshot_uri      TEXT,                              -- 软删时存的恢复快照 (S3)
    audit_event_id    TEXT NOT NULL,
    metadata          JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX rcb_tenant_idx   ON lifecycle.recycle_bin (tenant_id);
CREATE INDEX rcb_scheduled_idx ON lifecycle.recycle_bin (purge_scheduled_at) WHERE purged_at IS NULL;
CREATE INDEX rcb_resource_idx ON lifecycle.recycle_bin (resource_type_id, resource_id);
```

### 3.4 `lifecycle.legal_hold`

```sql
CREATE TABLE lifecycle.legal_hold (
    id                TEXT PRIMARY KEY,                  -- "lh_..."
    tenant_id         TEXT NOT NULL REFERENCES tenant.tenant(id),
    -- 范围（任一）
    resource_type_id  TEXT REFERENCES lifecycle.resource_type(id),  -- NULL = 全资源
    resource_id       TEXT,                              -- NULL = 全实例
    user_id           TEXT,                              -- NULL = 不按用户
    -- 元数据
    reason            TEXT NOT NULL,                     -- "litigation #2026-xxx"
    case_number       TEXT,
    legal_contact     TEXT NOT NULL,                     -- 法务联系人 user_id
    granted_by        TEXT NOT NULL,
    granted_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- 解除
    released_at       TIMESTAMPTZ,
    released_by       TEXT,
    release_reason    TEXT,
    -- 审计
    grant_audit_event_id   TEXT NOT NULL,
    release_audit_event_id TEXT
);

CREATE INDEX lh_active_idx ON lifecycle.legal_hold (tenant_id) WHERE released_at IS NULL;
CREATE INDEX lh_resource_idx ON lifecycle.legal_hold (resource_type_id, resource_id) WHERE released_at IS NULL;
CREATE INDEX lh_user_idx ON lifecycle.legal_hold (user_id) WHERE released_at IS NULL AND user_id IS NOT NULL;
```

### 3.5 `lifecycle.destruction_certificate`

```sql
CREATE TABLE lifecycle.destruction_certificate (
    id                TEXT PRIMARY KEY,
    tenant_id         TEXT NOT NULL,
    -- 关联
    resource_type_id  TEXT NOT NULL,
    resource_ids      TEXT[] NOT NULL,                   -- 一份证书可覆盖多行
    -- 内容
    destruction_method TEXT NOT NULL,
    destroyed_at      TIMESTAMPTZ NOT NULL,
    destroyed_by      TEXT NOT NULL,
    witness_user_ids  TEXT[],                            -- 见证人（合规要求时）
    -- 数据快照（销毁前）
    pre_destruction_hash TEXT NOT NULL,                  -- 销毁前数据指纹
    record_count      INT NOT NULL,
    storage_bytes_freed BIGINT,
    -- 证明物
    certificate_pdf_uri TEXT NOT NULL,                   -- s3://...
    certificate_signature TEXT NOT NULL,                 -- crypto.sign(pdf)
    certificate_tsa_token TEXT,                          -- RFC 3161
    -- 关联审计
    audit_event_id    TEXT NOT NULL UNIQUE
);
```

### 3.6 `lifecycle.destruction_job`

```sql
CREATE TABLE lifecycle.destruction_job (
    id                TEXT PRIMARY KEY,
    tenant_id         TEXT,                              -- NULL = 跨租户
    -- 范围
    resource_type_id  TEXT NOT NULL,
    selector          JSONB NOT NULL,                    -- 查询条件（如 {"purge_scheduled_at_lte": "..."}）
    -- 调度
    scheduled_at      TIMESTAMPTZ NOT NULL,
    started_at        TIMESTAMPTZ,
    completed_at      TIMESTAMPTZ,
    status            TEXT NOT NULL DEFAULT 'PENDING'
                      CHECK (status IN
                        ('PENDING','RUNNING','SUCCEEDED','FAILED','CANCELLED','BLOCKED_BY_LEGAL_HOLD')),
    -- 结果
    records_processed INT NOT NULL DEFAULT 0,
    records_destroyed INT NOT NULL DEFAULT 0,
    records_blocked   INT NOT NULL DEFAULT 0,            -- 被 LH 挡住
    error_message     TEXT,
    -- 关联
    certificate_id    TEXT REFERENCES lifecycle.destruction_certificate(id),
    audit_event_id    TEXT
);

CREATE INDEX dj_status_idx ON lifecycle.destruction_job (status, scheduled_at);
```

### 3.7 `lifecycle.backup_plan` / `lifecycle.backup_run` / `lifecycle.restore_request`

```sql
CREATE TABLE lifecycle.backup_plan (
    id                TEXT PRIMARY KEY,
    tenant_id         TEXT,                              -- NULL = 平台级
    name              TEXT NOT NULL,
    backup_kind       TEXT NOT NULL CHECK (backup_kind IN
                      ('POSTGRES_FULL','POSTGRES_INCREMENTAL','CLICKHOUSE','PV_SNAPSHOT','S3_REPLICA')),
    schedule_cron     TEXT NOT NULL,
    retention_days    INT NOT NULL,
    destination_uri   TEXT NOT NULL,
    encryption_key_id TEXT NOT NULL,                     -- 备份独立 KEK
    enabled           BOOLEAN NOT NULL DEFAULT true,
    -- 合规
    geo_constraint    TEXT,                              -- "cn-only" / "eu-only"
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE lifecycle.backup_run (
    id                TEXT PRIMARY KEY,
    plan_id           TEXT NOT NULL REFERENCES lifecycle.backup_plan(id),
    started_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at      TIMESTAMPTZ,
    status            TEXT NOT NULL DEFAULT 'RUNNING'
                      CHECK (status IN ('RUNNING','SUCCEEDED','FAILED','VERIFIED')),
    backup_uri        TEXT,
    size_bytes        BIGINT,
    artifact_hash     TEXT,
    error_message     TEXT,
    -- 验证
    verified_at       TIMESTAMPTZ,
    verification_method TEXT,                            -- "RESTORE_DRY_RUN" / "HASH_CHECK"
    audit_event_id    TEXT
);

CREATE TABLE lifecycle.restore_request (
    id                TEXT PRIMARY KEY,
    tenant_id         TEXT NOT NULL,
    backup_run_id     TEXT NOT NULL REFERENCES lifecycle.backup_run(id),
    target            TEXT NOT NULL,                     -- "primary" / "staging" / "isolated"
    point_in_time     TIMESTAMPTZ,
    requested_by      TEXT NOT NULL,
    approved_by       TEXT,
    approval_audit_event_id TEXT,
    started_at        TIMESTAMPTZ,
    completed_at      TIMESTAMPTZ,
    status            TEXT NOT NULL DEFAULT 'PENDING_APPROVAL'
                      CHECK (status IN
                        ('PENDING_APPROVAL','APPROVED','RUNNING','SUCCEEDED','FAILED','REJECTED'))
);
```

---

## 4. 状态机

### 4.1 单资源生命周期

```
                    [LIVE]
                    /     \
       业务删除（软删）│      │ 直接硬删（极少；要 4 眼 + 无 LH）
                    ▼      ▼
              [RECYCLED]    │
                    │       │
        管理员恢复  │  │     │
                    ▼  │     │
                  [LIVE] │   │
                       │     │
        recycle_bin_days 到 │
                       ▼     ▼
                  [PURGE_SCHEDULED]
                       │
                       │ check legal_hold
                       ▼
                ┌──────┴──────┐
            未 LH│             │ 有 LH
                ▼             ▼
        [DESTROYING]      [HELD]
                │             │
        销毁完成│             │ LH 解除
                ▼             ▼
        [DESTROYED]       [PURGE_SCHEDULED]
        + 销毁证明
```

### 4.2 LegalHold 状态机

```
[ACTIVE] ── released ──→ [RELEASED]
```

- ACTIVE：阻挡一切硬删；写到 audit
- 解除：仅 `lifecycle.legal_hold.release` 权限 + 必填 reason + 4 眼

### 4.3 Destruction Job

```
PENDING → RUNNING → SUCCEEDED
                 ↘ FAILED → 重试 N 次 → 人工介入
                 ↘ BLOCKED_BY_LEGAL_HOLD → 自动延期，下次 retry
```

### 4.4 四眼审批（立即硬删 / 解除 LH）

§4.1 的「直接硬删」和 §4.2 的「解除」都要 4 眼：第二个人用**自己的请求**批准（pam-v1 §4），申请人不能自批（pam-v1 §14 #4）。由申请人在请求体里填一个"见证人"不算 4 眼，所以这两个操作都分成两步：

```
POST /recycle-bin/{bin_id}:hard-delete      ─┐  申请人（X-User-Id）
POST /legal-holds/{hold_id}:release         ─┘  只开一张审批单，202 + approval_request
                    │
                    ▼
             [PENDING] ── 窗口（默认 30 分钟，pam-v1 §4.3）内无人处理 ──→ [EXPIRED]
              │      │
   另一人 approve    任何人 reject（含申请人撤回）
              ▼      ▼
       [APPROVED]  [REJECTED]
   同一请求内执行：硬删（出销毁证明）/ 解除 LH
```

- 只覆盖人工发起的硬删和解除；回收站到期的定时清理（§9）不走审批。
- 每个目标同时只有一张 PENDING 单（部分唯一索引 `ar_pending_target_uq`）：再次申请返回已开的那张，不论是谁开的；已过期的单在下一次申请时置为 EXPIRED，并由新单取代。
- 过期不靠定时任务：`PENDING` 且 `expires_at <= now()` 即视为 EXPIRED（读接口与 `filter.status` 都按此算）。
- 批准即执行，执行前重新做该操作自身的检查：期间被加了 LH → 409，条目已被恢复 → 404；两种情况审批单都保持 PENDING。批准与拒绝都对审批单 `SELECT … FOR UPDATE`，两个决定先后进行，不会重复执行。
- 记录：`destroyed_by` / `released_by` = 申请人；销毁证明的见证人 = 批准人。目标已销毁 / 已解除时，申请接口直接返回 200 `{destroyed|released: true}`。
- 数据库也守着这条规则：`CHECK (status <> 'APPROVED' OR (decided_by IS NOT NULL AND decided_by <> requested_by))`。
- 事件（outbox）：`foundation.lifecycle.approval.requested` / `.approved` / `.rejected`。

```sql
CREATE TABLE lifecycle.approval_request (
    id            TEXT PRIMARY KEY,                    -- "apr_<ULID>"
    tenant_id     TEXT NOT NULL REFERENCES tenant.tenant(id) ON DELETE CASCADE,
    operation     TEXT NOT NULL CHECK (operation IN ('HARD_DELETE','RELEASE_LEGAL_HOLD')),
    target_id     TEXT NOT NULL,                       -- bin_id / hold_id
    requested_by  TEXT NOT NULL,
    requested_at  TIMESTAMPTZ NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL,                -- requested_at + 审批窗口
    status        TEXT NOT NULL DEFAULT 'PENDING'
                  CHECK (status IN ('PENDING','APPROVED','REJECTED','EXPIRED')),
    decided_by    TEXT,                                -- 批准人（硬删时即见证人）/ 拒绝人
    decided_at    TIMESTAMPTZ,
    CHECK (status <> 'APPROVED' OR (decided_by IS NOT NULL AND decided_by <> requested_by))
);
CREATE UNIQUE INDEX ar_pending_target_uq ON lifecycle.approval_request (tenant_id, operation, target_id)
    WHERE status = 'PENDING';
CREATE INDEX ar_tenant_requested_idx ON lifecycle.approval_request (tenant_id, requested_at);
```

---

## 5. 关键 API

完整 OpenAPI 在 `contracts/openapi/lifecycle.yaml`。

| 端点 | 方法 | 权限 |
|---|---|---|
| `/resource-types` | GET / POST | service_account（注册） |
| `/resource-types/{id}` | GET / PATCH | `lifecycle.resource_type.*` |
| `/retention-overrides` | GET / PUT | `lifecycle.retention.update` |
| `/recycle-bin` | GET | `lifecycle.recycle_bin.list` |
| `/recycle-bin/{id}/restore` | POST | `lifecycle.recycle_bin.restore` |
| `/recycle-bin/{id}/purge-now` | POST | `lifecycle.recycle_bin.purge`（4 眼 + 无 LH）；已实现为 `:hard-delete`，只开审批单（§4.4） |
| `/legal-holds` | GET / POST | `lifecycle.legal_hold.*`（HIGH） |
| `/legal-holds/{id}/release` | POST | `lifecycle.legal_hold.release`（HIGH + 4 眼）；已实现为 `:release`，只开审批单（§4.4） |
| `/approval-requests` | GET | 审批单列表（`filter.status` / `filter.operation`） |
| `/approval-requests/{id}` | GET | 同 |
| `/approval-requests/{id}/approve` | POST | 第二人批准并执行（不可自批，§4.4） |
| `/approval-requests/{id}/reject` | POST | 拒绝 / 申请人撤回 |
| `/destruction-jobs` | GET | `lifecycle.destruction_job.read` |
| `/destruction-jobs/{id}` | GET | 同 |
| `/destruction-certificates` | GET | `lifecycle.cert.read` |
| `/destruction-certificates/{id}/download` | GET | 同（流式 PDF） |
| `/destruction-certificates/{id}/verify` | GET | bearer（公开验签） |
| `/backup-plans` | GET / POST / PATCH | `lifecycle.backup.manage`（平台） |
| `/backup-runs` | GET | `lifecycle.backup.read` |
| `/restore-requests` | POST | `lifecycle.restore.request` |
| `/restore-requests/{id}/approve` | POST | `lifecycle.restore.approve`（4 眼） |
| `/internal/dr-drill` | POST | platform | 演练触发 |

---

## 6. 销毁方式详解

### 6.1 `CRYPTO_KEY_DESTROY`（最快最彻底）

适用：字段加密的资源（PII 字段、L4+ 文件）。

流程：
1. 校验：全部 resource_ids 必须用同一 KEK label（或同租户多 label 全部销）
2. 调 `crypto.kek_mark_for_destruction(kek_id)` → 30 天 cool-down → `crypto.kek_destroy(kek_id)`（双步 SDK，crypto-v1 §7.4 定义；中间窗口可中止）

   *业务表行处置*：KEK 销毁后，业务表已无法解密的密文行由 lifecycle.destruction_job 负责物理删除（不在 crypto 范围；crypto 仅管密钥层面）
3. 业务表行可以保留（密文已无法解）或一并 truncate
4. 生成证明：列 KEK id + 销毁前 hash + Vault destroy receipt

**优点**：毫秒级；所有备份内的相同字段同时失效（用同 KEK 加密的）。
**缺点**：仅对加密字段有效；明文字段失效不彻底。

### 6.2 `DOD_OVERWRITE`（明文字段标准销毁）

适用：未加密的业务表行 / 备份文件 / 日志文件。

实现：
- DB 行：先 UPDATE 覆写每字段为随机值 → DELETE → VACUUM FULL（防 page 残留）
- 文件：调 [shred](https://www.gnu.org/software/coreutils/manual/html_node/shred-invocation.html) 多次覆写
- S3 object：DELETE + 触发 lifecycle 清理 noncurrent versions

3 次随机覆写满足 DoD 5220.22-M 标准；金融加严到 7 次。

### 6.3 `TRUNCATE`（低敏数据）

适用：审计日志、缓存、临时表。
直接 SQL `DELETE` 或 partition `DROP PARTITION`。

### 6.4 `CUSTOM_HOOK`（业务自管）

适用：复杂资源（如沙盒卷、外部第三方系统的镜像副本）。

- 业务 service 暴露 `POST /internal/lifecycle/destroy` 端点
- lifecycle 调用并等待 `200 + destruction_proof_uri` 响应
- 验证 proof 后写证明

---

## 7. 销毁证明 PDF

### 7.0 模块职责分工（与 data-protection-v1 联动）

- **lifecycle-service**：销毁证书的**事实记录持有者** — 拥有 `lifecycle.destruction_certificate` 表（唯一来源）；编排 destruction_job 完成时调 data-protection 渲染 PDF；负责 WORM 上传 + 索引
- **data-protection-service**：**渲染器** — 暴露 `render_destruction_certificate(metadata) -> bytes` SDK，内含 Jinja2 模板 + PKCS#7 签名 + RFC 3161 TSA；**不**重复建证书表
- **crypto-service**：提供签名密钥（ES256/Ed25519/SM2）+ TSA 调用

> data-protection-v1 §6.3 已声明本模块为唯一持表方，不重复存储。

### 7.1 内容

```
═══════════════════════════════════════════
        数据销毁证明
        Data Destruction Certificate
═══════════════════════════════════════════
证书编号: dcert_01J5...
租户: 客户名 (tenant_id: tnt_...)
销毁时间: 2026-08-15 14:30:00 UTC
销毁方式: CRYPTO_KEY_DESTROY
执行者: alice@x.com (usr_...)
见证人:
  - bob@x.com (usr_...)
  - carol@x.com (usr_...)

销毁内容
─────────────────────────────────────────
资源类型: identity.user
记录数: 142
销毁前数据指纹 (SHA-256): a3f5...
存储释放: 18.4 MB

相关合规
─────────────────────────────────────────
合规模式: pipl, equal_protection_3
触发依据:
  - 用户主动注销 / GDPR Article 17 删除权
  - 适用 PIPL 第 47 条

证书签名
─────────────────────────────────────────
签名算法: Ed25519
签名密钥: foundation-cert-signing-2026q3
签名值: ...
时间戳服务: NTSC (RFC 3161)
TSA Token: ...

审计事件 ID: evt_01J5...
═══════════════════════════════════════════
本证书由 SaaS Foundation 自动生成。
任何持有者可通过 /destruction-certificates/{id}/verify 验证真伪。
═══════════════════════════════════════════
```

### 7.2 生成

- 模板：HTML + WeasyPrint 渲 PDF（中文用思源黑体）
- 签名：`crypto.sign(pdf_bytes)` + RFC 3161 TSA
- 存储：S3 WORM bucket `foundation-destruction-certs/`
- 验证端点：上传 PDF → 提取签名 → 验签 + TSA → 比对 audit 记录

---

## 8. Backup/Restore

### 8.1 备份矩阵

| 数据 | 工具 | 频率 | 保留 | 加密 |
|---|---|---|---|---|
| Postgres（业务库） | **pgBackRest** + S3 | 全量周；增量小时 | 7 天 + 月度归档 6 月 | 备份独立 KEK |
| ClickHouse | **clickhouse-backup** + S3 | 全量日 | 7 天 | 备份独立 KEK |
| PV 卷 | **Velero** + CSI snapshot | 日 | 7 天 | CSI 加密 |
| S3 / MinIO | bucket replication + versioning | 实时 | 90 天 noncurrent | bucket SSE-KMS |
| Vault | snapshot CLI（raft） | 日 | 30 天 | Vault 自签 |
| Keycloak | 走 Postgres + realm export | 每次发布 | 90 天 | 同 PG |

### 8.2 备份独立 KEK

`crypto.kek` 中预创建 `backup-encryption-<env>` 系列。备份工具调 crypto SDK 包装。**业务 KEK 销毁不影响备份 KEK**——但备份内含字段加密 ciphertext，业务 KEK 销毁后备份内对应字段也无法解（双保护）。

### 8.3 备份合规跟随原数据

- 备份保留期 ≤ 原数据 retention（取严）
- 备份地理位置 ≤ 原数据 data_residency（中国客户备份必须在境内）
- 删除原数据时同时调度删除备份内对应行（标记 `backup_destruction_pending`，下次备份覆盖完成后销毁）

### 8.4 恢复流程（受审批）

```
[业务/合规需要恢复]
   ↓ POST /restore-requests
[PENDING_APPROVAL]
   ↓ 4 眼审批（破坏性操作）
[APPROVED]
   ↓ 选择 target：
      - "primary"   = 覆盖生产（最危险，要 platform admin）
      - "staging"   = 拉到 staging 验证
      - "isolated"  = 拉到独立隔离环境（恢复演练）
   ↓
[RUNNING] → 调 pgBackRest restore / Velero restore
   ↓
[SUCCEEDED]
   ↓ 自动验证：行数、关键 sentinel 行存在、schema 版本一致
   ↓ 通知申请人 + 安全管理员
```

### 8.5 演练（合规要求）

`POST /internal/dr-drill`：
- 每月自动选最新备份恢复到 isolated env
- 验证：取 10 个 sentinel record 哈希比对、跑 health check、跑 RLS fuzz
- 失败 → P0；成功 → 写 audit + 报告归档

---

## 9. 调度与执行

### 9.1 调度器架构

```
[scheduler tier]
  cron 每日 02:00 UTC：
    1. 选 (purge_scheduled_at <= now() AND purged_at IS NULL AND no_legal_hold)
    2. 按 resource_type 分组创建 destruction_job
    3. 推队列
[worker tier]
  从队列取 job → 批量销毁（1000 行/batch）→ 生成证明 → 标记
```

### 9.2 LH 检查

每条 row 销毁前查：

```sql
SELECT 1 FROM lifecycle.legal_hold
WHERE tenant_id = $1
  AND released_at IS NULL
  AND (
     (resource_type_id = $2 AND resource_id IS NULL)        -- 类型级
     OR (resource_type_id = $2 AND resource_id = $3)        -- 实例级
     OR (user_id = $4)                                       -- 用户级
     OR (resource_type_id IS NULL)                           -- 全租户级
  ) LIMIT 1;
```

命中 → 该 row 跳过；记 `records_blocked += 1`；job 完成后告警。

### 9.3 并发与限流

- 同租户单时间只跑 1 个 job（防雪崩）
- 平台级并发上限：medium 5、large 20
- 每 batch 间 100ms 隔（不打爆 DB）

---

## 10. 合规模式联动

| 模式 | retention 默认底线 | recycle_bin_days | 销毁方式偏好 | 销毁证明 |
|---|---|---|---|---|
| `pipl` | 各资源默认 | 30 | CRYPTO 优先 | 必须 |
| `equal_protection_3` | + audit/billing 至少 1y | 30 | + DOD 兜底 | 必须 |
| `equal_protection_4` | + audit 2y | 14（更短） | + 监管报送 | 必须 + 4 眼见证 |
| `finance_jrt0071` | + audit 5y + tx 7y | 14 | + DOD 7 次 | 必须 + 监管报送 |
| `hipaa` | + PHI 6y | 30 | + DOD | 必须 |
| `soc2` | 各资源 + 审计 1y | 30 | 默认 | 默认 |
| `gdpr` | 用户驱动 DSAR | 30 | CRYPTO | 必须（DSAR 凭证） |

---

## 11. 部署形态差异

| 维度 | small | medium | large |
|---|---|---|---|
| scheduler | APScheduler | k8s CronJob | KEDA + scheduler |
| destruction worker 并发 | 1 | 5 | 20 |
| backup 目标 | MinIO 单 | MinIO HA | S3 同城/异地 |
| Velero | 关 | 开 | 开 + cross-region |
| DR drill | 手动 | 月度自动 | 周度自动 |

---

## 12. 关键技术风险

| 风险 | 缓解 |
|---|---|
| 销毁完成后业务发现"还要"（合规要求恢复） | crypto KEY destroy 30 天冷静期内可中止；超出后真不可恢复 |
| LH 漏挂导致重要数据被删 | 提前 N 天通知 + 销毁前最后再查一次 LH + 销毁 dry-run 输出"将销毁清单"给法务 review |
| 备份内含 PII 不受 retention 控制 | 备份 KEK 独立 + 备份生命周期跟随原数据 + 演练验证 |
| 销毁后用户主张"未销毁" | 证明 PDF + 签名 + TSA + audit 链 + WORM 归档 |
| 大表销毁锁表 | batch 1000 + 限流 + VACUUM 不阻塞 |
| 备份独立 KEK 丢失 → 备份失效 | KEK 有 30 天冷静期 + 离线纸质 escrow（合规模式） |
| 演练数据污染生产 | isolated env 必须独立 namespace / 独立 DB 实例 / 网络隔离 |
| 跨服务 cascade 删除遗漏（如删 user 时 audit / org 的 user_id 引用） | event-driven：foundation.identity.user.deactivated 触发各 service 走自己的 lifecycle 流程 |
| 销毁证明 PDF 不可读（10 年后字体/工具变化） | 同时存 JSON 数据 + 签名；PDF 仅人类阅读用，JSON 是机器证据 |
| Recycle Bin 撑爆磁盘 | 监控 recycle_bin 总大小；按租户配额（warn / hard limit） |

---

## 13. 测试策略

### 13.1 单元（≥90%）
- retention policy 合并取严
- 销毁方式分发
- LH 校验逻辑
- 证明 PDF 生成 + 签名验证

### 13.2 集成
- 软删 → 30 天 cron → 硬删完整流程
- LH 阻挡硬删；解除后下次 cron 销毁
- 销毁证明 PDF 生成 + 用单独脚本验签
- pgBackRest 备份 + 恢复 + 行数校验
- Velero PV snapshot + restore 到 isolated env

### 13.3 fuzz
- 1000 次随机 soft_delete + restore + purge 组合不出错
- 跨租户：A 租户的 LH 不影响 B 租户销毁

### 13.4 灾备演练
- 每月自动跑 DR drill；验证 sentinel + health + RLS

---

## 14. 待解决问题

| # | 问题 | 决策机制 | 截止 |
|---|---|---|---|
| Q1 | recycle_bin 配额是按数量还是体积？ | 优先体积（GB），数量作辅助 | A-M2 |
| Q2 | 销毁证明的"见证人"是否需要电子签名（PKI）还是仅 audit 记录？ | 金融模式电子签 + audit；普通仅 audit | A-M3 |
| Q3 | LH 是否可加附件（法律文书 PDF）？ | 是；S3 关联存储 + 校验 hash | A-M3 |
| Q4 | DR drill 频率是否客户可配？ | 是；最低月度（合规要求） | A-M3 |
| Q5 | 跨地域备份的 retention 计算用哪边时区？ | UTC 统一计算，展示按 locale | 已定 |
| Q6 | 历史销毁证明的"撤销"是否支持？ | 否；证明一旦生成不可撤；只能"标错并新发更正" | 已定 |
| Q7 | 销毁过程中失败（部分行已删）如何处理？ | 已删的不可逆；job 标 PARTIAL；剩余行下次重试 | 已定 |
| Q8 | 备份独立 KEK 的轮换会否影响旧备份恢复？ | 不；旧 KEK 版本保留 ≥ 备份 retention | A-M3 |
| Q9 | 自助导出（用户拉自己全数据）是否经 lifecycle？ | 走 data-protection；lifecycle 仅管销毁 | 已定 |
| Q10 | 销毁通知 N 天前是否要"申诉窗口"？ | 是；销毁前 7 天通知 + 申诉端点 + 申诉自动延期 30 天 | A-M3 |

---

## 15. 验证标准（A-M2 出口）

- [ ] OpenAPI spectral 通过
- [ ] 单元/集成测试 ≥90%
- [ ] 软删 → 硬删 → 证明 PDF 端到端
- [ ] LH 阻挡硬删 + 解除后正常销毁
- [ ] crypto key destroy 双步流程跑通
- [ ] pgBackRest backup + restore 演练
- [ ] DR drill 月度自动 + sentinel 校验
- [ ] 三档 helm profile 都跑

---

## 16. 参考资料

- [pgBackRest](https://pgbackrest.org/)
- [Velero](https://velero.io/)
- [clickhouse-backup](https://github.com/Altinity/clickhouse-backup)
- [DoD 5220.22-M data sanitization](https://en.wikipedia.org/wiki/Data_erasure)
- [NIST SP 800-88 Rev 1 Media Sanitization](https://csrc.nist.gov/pubs/sp/800/88/r1/final)
- [GDPR Article 17 — Right to erasure](https://gdpr-info.eu/art-17-gdpr/)
- [PIPL 第 47 条 — 删除个人信息](http://www.npc.gov.cn/npc/c30834/202108/a8c4e3672c74491a80b53a172bb753fe.shtml)

---

## 17. 变更记录

| 日期 | 版本 | 变更 |
|---|---|---|
| 2026-05-22 | 0.1.0 | 初版（P2 #11） |
| 2026-10-30 | 0.1.1 | §4.4 四眼审批：人工硬删与解除 LH 只开审批单（202），由另一人批准后执行；批准人为销毁证明见证人；新表 `lifecycle.approval_request` |

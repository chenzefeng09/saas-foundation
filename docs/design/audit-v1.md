# Audit Service — 设计文档 v0.1

> P2 #10 产出。覆盖 A-M2 范围。配套：
> - [CONVENTIONS.md](../CONVENTIONS.md) §6.5
> - [multi-tenancy.md](../multi-tenancy.md)
> - [crypto-v1.md](./crypto-v1.md)
> - [authz-v1.md](./authz-v1.md) §4.8（决策日志）

---

## 1. Context

`audit-service` 是底座**不可篡改的审计日志中枢**。所有底座/业务 service 把"用户做了什么 / 系统发生了什么"的结构化事件经它落地。它解决：

1. **完整性可证明**：用 hash chain + 数字签名 + TSA 时间戳，让任何篡改可被发现
2. **保留期合规**：等保 ≥6m / 金融 ≥1y / HIPAA ≥6y / SEC ≥6y，按租户合规模式自动应用
3. **高写入吞吐**：千 service × 千 user 并发，万级 events/s
4. **查询/导出快**：30 天热查 P99 < 500ms；冷归档 S3 + 离线检索
5. **回放支持**：任意会话可按 `tenant_id + session_id + parent_event_id` 链回放
6. **合规出口**：DSAR / 监管要求 / 客户审计 全部能一键导出（带签名）

### 关键技术决定

| 维度 | 决定 | 理由 |
|---|---|---|
| 采集 | **OTel 标准** 全栈推送；专 SDK `foundation_audit` 包装语义 | 与可观测性同生态；避免业务双写 |
| 热存储 | **ClickHouse**（append-only MergeTree） | 列存压缩 10x、写吞吐 100k+ events/s、TTL 自动分区淘汰 |
| 冷存储 | **S3 Object Lock (Compliance Mode)** | 监管/法律不可篡改的兜底；7-10 年 |
| 完整性 | **Hash chain + Merkle tree 双轨** | chain 简单可线性回溯，Merkle 用于批量验签和外部 anchor |
| 数字签名 | **每 batch（5min/10k events）签一次** | 单条签名太慢；batch 是吞吐与安全的平衡 |
| 签名算法 | **Ed25519** 默认 / **国密 SM2** 合规模式 | 走 `crypto-service` 抽象 |
| 时间戳 | **RFC 3161 TSA** —— 默认 FreeTSA，合规模式接 NTSC 商业 TSA | 法律证据级 |
| 外部锚定（可选） | 每 N 小时把 Merkle root 推 git 公共仓库 / 区块链 | 防内部全员串谋；POC 客户可选 |
| 采样 | **拒绝/安全/CRITICAL 100%**；**allow 1%** | 容量平衡；合规模式可调 |
| 投递保证 | **outbox 模式** + at-least-once + 消费者去重 | 杀进程不丢日志 |
| 查询 | ClickHouse SQL + 预定义 view + 业务 SDK | 强类型 + RLS 等价过滤 |
| 多租户 | partition by (toYYYYMM, tenant_id) | 单租户大表也快；删租户走 DROP PARTITION |
| 时区 | DateTime64(3, 'UTC') 统一存 UTC，展示按用户 locale | 跨地域一致 |

---

## 2. 职责边界

### audit-service 负责
- 接收所有底座/业务 service 通过 SDK 推送的审计事件
- 强类型校验 + hash chain + 签名 + TSA 时间戳
- 落 ClickHouse（热）+ 双写 S3 WORM（关键事件）
- 查询接口（admin 控制台 + DSAR 导出 + 监管报表）
- 完整性自检 worker（每日扫 hash chain）
- 保留期 cron（到期归档 + 销毁证明）

### audit-service 不负责
- "是否要审计"判定 → SDK 调用方决定（permission_definition.risk_level 高的自动审计）
- 决策日志（OPA）→ `authz-service` 聚合后转交 audit
- 业务日志（stdout / Loki）→ 与审计分离；高基数 stdout 不入审计
- 合规模式定义 → `compliance-service`
- 用户敏感字段脱敏 → `data-protection-service`（audit 自动调）

### 与其他 service 的交互

```
┌─────────────────────────────────────────────────────────┐
│ All services emit audit events                          │
│ foundation_audit.emit(event)                            │
└──────────────────┬──────────────────────────────────────┘
                   │ OTel OTLP / direct gRPC
                   ▼
┌─────────────────────────────────────────────────────────┐
│ audit-service (FastAPI + worker)                        │
│  1. 接收 + 校验 schema                                  │
│  2. 调 data-protection 脱敏                             │
│  3. 写 outbox 表（事务保证）                             │
│  4. batch worker:                                       │
│     - 算 hash chain                                     │
│     - 5min/10k 一个 Merkle batch                        │
│     - crypto.sign(root) + TSA timestamp                 │
│     - 写 ClickHouse + S3 WORM                           │
│  5. completeness worker:                                │
│     - 每日扫 chain 验完整性                              │
│     - 异常告警 PagerDuty                                │
└──────────┬─────────┬───────────┬───────────┬────────────┘
           │         │           │           │
           ▼         ▼           ▼           ▼
    ClickHouse   S3 (WORM)    crypto      notification
    (hot 30-90d) (cold N年)   (sign/TSA)  (告警)
```

---

## 3. 数据模型

### 3.1 ClickHouse `audit.events`

> 已在 `deploy/docker-compose/config/clickhouse/audit-schema.sql` 起骨架。本节给出最终 schema 与设计依据。

```sql
CREATE TABLE audit.events ON CLUSTER '{cluster}' (
    -- 标识
    event_id         String,                             -- "evt_01J5..."（ULID）
    schema_version   UInt16 DEFAULT 1,

    -- 时间
    occurred_at      DateTime64(3, 'UTC'),               -- 业务事件发生时刻（来自调用方）
    ingested_at      DateTime64(3, 'UTC') DEFAULT now64(3),  -- audit 入库时刻
    tsa_timestamp    Nullable(DateTime64(3, 'UTC')),     -- TSA 颁发时间戳（来自 RFC 3161）

    -- 多租户
    tenant_id        LowCardinality(String),

    -- 来源
    service          LowCardinality(String),             -- "identity" / "billing" / ...
    service_version  LowCardinality(String),

    -- 事件类型
    event_type       LowCardinality(String),             -- "foundation.identity.user.login_success"
    severity         Enum8('DEBUG'=1,'INFO'=2,'NOTICE'=3,'WARN'=4,'ERROR'=5,'SECURITY'=6,'CRITICAL'=7),
    outcome          Enum8('SUCCESS'=1,'FAILURE'=2,'DENIED'=3,'PARTIAL'=4),

    -- Actor
    actor_kind       Enum8('USER'=1,'SYSTEM'=2,'ADMIN'=3,'MIGRATOR'=4,'SERVICE_ACCOUNT'=5,'API_KEY'=6),
    actor_user_id    Nullable(String),
    actor_api_key_id Nullable(String),

    -- Target / Resource
    resource_type    LowCardinality(String),             -- "user" / "invoice" / "session"
    resource_id      Nullable(String),
    resource_path    Nullable(String),                   -- org_unit path / file path

    -- 链路
    request_id       String,                             -- "req_..."
    trace_id         Nullable(String),                   -- OTel
    span_id          Nullable(String),
    session_id       Nullable(String),
    parent_event_id  Nullable(String),                   -- 回放链

    -- 上下文
    ip               Nullable(IPv6),                     -- IPv4 自动映射
    user_agent       Nullable(String),
    country          Nullable(LowCardinality(String)),
    asn              Nullable(UInt32),

    -- 负载（脱敏后）
    payload          String,                             -- JSON；已脱敏；超过 64KB → 切到 audit.events_payload
    payload_size     UInt32,
    payload_truncated Bool DEFAULT false,

    -- 合规标签
    compliance_modes Array(LowCardinality(String)),       -- 写入时的 tenant.compliance_modes 快照
    retention_until  Date,                                -- 计算后到期硬删日期
    legal_hold       Bool DEFAULT false,

    -- 完整性
    prev_hash        FixedString(32),                    -- SHA-256 of prev event in chain
    curr_hash        FixedString(32),                    -- SHA-256 of (prev_hash + canonical(event))
    merkle_batch_id  Nullable(String),                   -- "mrk_..."
    merkle_leaf_idx  Nullable(UInt32),
    batch_signature  Nullable(String),                   -- signature 字段在 audit.merkle_batch 表，避免重复

    -- WORM 双写状态
    worm_written     Bool DEFAULT false,
    worm_uri         Nullable(String)                    -- s3://.../path/event_id.json
)
ENGINE = ReplicatedMergeTree('/clickhouse/tables/{shard}/audit_events', '{replica}')
PARTITION BY (toYYYYMM(occurred_at), tenant_id)
ORDER BY (tenant_id, occurred_at, event_id)
PRIMARY KEY (tenant_id, occurred_at)
TTL toDateTime(occurred_at) + INTERVAL retention_until DAY DELETE
    WHERE legal_hold = false                            -- Legal Hold 行不淘汰
SETTINGS index_granularity = 8192;

-- 二级索引
ALTER TABLE audit.events ADD INDEX idx_actor (actor_user_id) TYPE bloom_filter GRANULARITY 4;
ALTER TABLE audit.events ADD INDEX idx_resource (resource_type, resource_id) TYPE bloom_filter GRANULARITY 4;
ALTER TABLE audit.events ADD INDEX idx_session (session_id) TYPE bloom_filter GRANULARITY 4;
ALTER TABLE audit.events ADD INDEX idx_event_type (event_type) TYPE set(0) GRANULARITY 4;
```

**为什么选 (toYYYYMM, tenant_id) 分区**：
- 按月分区：TTL 删快（DROP PARTITION 原子）；查询常带时间范围
- 加 tenant_id：单租户删数据（销户）一条 SQL；查询热路径几乎都带 tenant_id
- 风险：100 租户 × 36 月 = 3600 partition；CH 建议 < 10000 partition，仍安全

### 3.2 `audit.merkle_batch`（batch 元）

```sql
CREATE TABLE audit.merkle_batch (
    batch_id          String,
    tenant_id         LowCardinality(String),
    service           LowCardinality(String),
    created_at        DateTime64(3, 'UTC'),
    sealed_at         DateTime64(3, 'UTC'),
    event_count       UInt32,
    first_event_id    String,
    last_event_id     String,
    merkle_root       FixedString(32),
    signature         String,                            -- crypto.sign(merkle_root)
    signature_key_id  String,                            -- crypto key reference
    tsa_token         Nullable(String),                  -- RFC 3161 TimeStampToken (base64)
    tsa_provider      LowCardinality(String),            -- "freetsa" / "ntsc" / "digicert"
    external_anchor   Nullable(String)                   -- optional git commit / blockchain tx
)
ENGINE = ReplicatedMergeTree('/clickhouse/tables/{shard}/merkle_batch', '{replica}')
PARTITION BY toYYYYMM(created_at)
ORDER BY (tenant_id, created_at, batch_id);
```

### 3.3 `audit.events_payload`（大 payload 溢出）

```sql
CREATE TABLE audit.events_payload (
    event_id     String,
    tenant_id    LowCardinality(String),
    occurred_at  DateTime64(3, 'UTC'),
    full_payload String                                   -- 原始 JSON（已脱敏）
)
ENGINE = ReplicatedMergeTree(...)
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (tenant_id, event_id);
```

### 3.4 outbox 表（Postgres，事务性投递）

```sql
CREATE TABLE audit.outbox (
    id           BIGSERIAL PRIMARY KEY,                 -- 内部投递表 ID 豁免 ULID 约定（multi-tenancy.md §6.1 注 1）
    tenant_id    TEXT NOT NULL,                         -- 强制（multi-tenancy.md §6.1）
    event_json   JSONB NOT NULL,
    enqueued_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at TIMESTAMPTZ,
    attempts     INT NOT NULL DEFAULT 0,
    last_error   TEXT
);
CREATE INDEX outbox_pending_idx ON audit.outbox (id) WHERE delivered_at IS NULL;

-- RLS：仍按 multi-tenancy.md §6 套 4 policy；BIGSERIAL 不影响 RLS 强制
ALTER TABLE audit.outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit.outbox FORCE ROW LEVEL SECURITY;
-- (policies 略，参见 multi-tenancy.md 模板)
```

业务 service 写自己的业务表 + outbox 是同一事务 → 保证审计与业务原子。worker 异步把 outbox 推 audit-service。

---

## 4. 事件 schema（强类型契约）

### 4.1 通用信封

所有审计事件都符合：

```python
class AuditEvent(BaseModel):
    # 标识
    event_id: str                  # ULID，SDK 生成
    schema_version: int = 1

    # 时间
    occurred_at: datetime           # 业务时刻

    # 来源（由 SDK 注入；业务不填）
    service: str
    service_version: str

    # 类型
    event_type: str                 # foundation.<service>.<resource>.<verb>
    severity: Literal['DEBUG','INFO','NOTICE','WARN','ERROR','SECURITY','CRITICAL']
    outcome: Literal['SUCCESS','FAILURE','DENIED','PARTIAL']

    # 多租户（SDK 自动从 contextvars 注入）
    tenant_id: str

    # Actor
    actor: ActorContext

    # Target
    resource: ResourceRef | None = None

    # 链路
    request_id: str
    trace_id: str | None
    span_id: str | None
    session_id: str | None
    parent_event_id: str | None

    # 上下文
    ip: str | None
    user_agent: str | None
    country: str | None
    asn: int | None

    # 负载（事件特有字段）
    payload: dict[str, Any]
```

### 4.2 事件类型 registry

每个 service 在 startup 注册自己暴露的事件类型，类似 permission 注册：

```python
# packages/identity/src/foundation_identity/audit_events.py
from foundation_audit import event_type

EVENTS = [
    event_type(
        "foundation.identity.user.invited",
        severity="INFO",
        sensitive_fields=["payload.email"],            # 自动经 data-protection 脱敏
        always_audit=True,                              # 不走采样
    ),
    event_type(
        "foundation.identity.user.frozen",
        severity="SECURITY",
        always_audit=True,
        worm_double_write=True,                         # 强制 S3 WORM
    ),
    event_type(
        "foundation.identity.session.created",
        severity="INFO",
        always_audit=False,                             # 受采样
        sample_rate_low_risk=0.01,                      # SUCCESS 时 1%
        sample_rate_failure=1.0,                        # FAILURE 100%
    ),
    ...
]
```

启动时 audit-service `/permissions/register` 等价端点 `POST /audit/event-types/register`。

### 4.3 强制最小事件集（CONVENTIONS §6.5 已列）

| 类别 | 事件 | severity | WORM |
|---|---|---|---|
| 用户行为 | login_success/failure, logout | INFO/SECURITY | login_failure 100% |
| 用户行为 | permission grant/revoke | SECURITY | ✅ |
| 用户行为 | 4-eyes approval | SECURITY | ✅ |
| 用户行为 | data export/download | NOTICE/SECURITY | classification ≥ L4 → ✅ |
| 系统 | config_changed | NOTICE | ✅ |
| 系统 | key_generated/rotated/destroyed | SECURITY/CRITICAL | ✅ |
| 系统 | security_policy_changed | SECURITY | ✅ |
| 访问 | file CRUD（含哈希） | NOTICE | classification ≥ L4 → ✅ |
| 访问 | db_dml on tenant table | NOTICE | 仅金融模式 100% |
| 访问 | network_connect (egress) | NOTICE | 跨境 → ✅ |
| 安全 | auth_failed | SECURITY | ✅ |
| 安全 | permission_denied | SECURITY | ✅ |
| 安全 | abnormal_login | SECURITY | ✅ |
| 安全 | malware_alert | CRITICAL | ✅ |
| 安全 | compliance_violation | CRITICAL | ✅ |

业务事件由各 service 定义，遵循 `foundation.<svc>.<resource>.<verb>` 命名。

---

## 5. 完整性机制

### 5.1 Hash chain（线性，per-tenant-per-service）

```
event[0]:  prev_hash = 32 zero bytes
           curr_hash = SHA256(prev_hash + canonical_json(event))
event[1]:  prev_hash = event[0].curr_hash
           curr_hash = SHA256(prev_hash + canonical_json(event[1]))
...
```

`canonical_json`：RFC 8785 JCS（JSON Canonicalization Scheme），保证序列化稳定（字段顺序、空格、Unicode 处理）。

**链分割维度**：`(tenant_id, service)` —— 不同 service 独立链，并行写入互不阻塞；同一 (tenant, service) 串行（worker 内 lock）。

**实现**：每个 (tenant, service) 维护一行 `audit.chain_head`（Redis hash），写入新事件时 `LOAD prev → COMPUTE → STORE` 用 Redis lua 原子。

### 5.2 Merkle tree（批量，每条链一个 batch）

每 5 分钟 或 满 10000 events（先到先触发）封一次：本次的事件里每条链 `(tenant_id, service)` 各封一个 batch，batch 不跨链：

```
                  merkle_root
                  /         \
              h12             h34
             /   \           /   \
          h1     h2        h3     h4
          |      |         |      |
        evt1   evt2      evt3   evt4 ...
```

叶子是该链这批事件的 `curr_hash`，按链内顺序编号 0..n-1。算法：标准 RFC 6962（CT log style，处理奇数叶子用复制）。

`merkle_root` 写入 `audit.merkle_batch`（一行一个 batch，记该链的 tenant_id、service、event_count、首尾 event_id；一次封出的所有行一次 insert）+ `crypto.sign(root)`（用该链租户的签名 key，见 5.3）+ TSA 颁发时间戳。

每 batch 同步给 ClickHouse 各 events 行的 `merkle_batch_id` + `merkle_leaf_idx`。

**为什么不跨链**：完整性校验（`POST /events:verify-integrity`）只读一个租户、可选一个 service 的事件，签名 key 又按租户分。跨租户或跨 service 的 batch，租户手里只有部分叶子，重算不出签过名的 root，别的租户的 key 签的 root 也验不过。每条链一个 batch，租户只凭自己的事件和自己的 key 就能验证自己的 batch。

**校验口径**：`limit` / `service` / `from_event_id` 切到一半的 batch，补齐该租户在其中的全部叶子后整批校验。租户无法整批持有的 batch（查不到 `merkle_batch` 行，或缺叶子，如改为每链一个 batch 之前封的跨租户 batch）计入 `signatures_unverifiable`：既不能证明被篡改，也不能证明完好，结果不为 valid（"Integrity not proven"），与 root 或签名不符的 `signatures_failed` 分开计数。

### 5.3 数字签名

走 `crypto-service`：

```python
sig = await crypto.sign(
    data=merkle_root,
    key_label=f"audit-signing-{tenant_id}",
    algorithm="ed25519",   # 或 sm2，按合规
)
```

KEK 在 crypto-service 管理，每 90 天轮换；签名验签兼容历史版本。

### 5.4 RFC 3161 时间戳（TSA）

每 batch 调 TSA：

```
client → TSA: TSP request (含 hash(merkle_root))
TSA   → client: TimeStampToken (含 TSA 签名 + 时间戳)
audit-service: 存 tsa_token 入 merkle_batch 表
```

**Provider 选择**：

| Provider | 用途 | 备注 |
|---|---|---|
| [FreeTSA](https://www.freetsa.org/) | 默认（开发 / 非合规客户） | 免费、RFC 3161 兼容 |
| [DigiCert TSA](https://www.digicert.com/timestamp/) | 出海客户 / SOC2 / eIDAS | 商业、qualified |
| **国家授时中心（NTSC）授时服务** | 金融政务客户 / 等保 + 国密 | 商业、国密 SM2 兼容、监管认可 |

合规模式联动决定用哪个：
- `finance_jrt0071` / `equal_protection_4` → 强制 NTSC
- `soc2` / `iso27001` → 强制 DigiCert 或同等
- 其它 → FreeTSA OK

### 5.5 外部锚定（可选 / POC 客户）

每 N 小时把 Merkle root 摘要发到外部公共可见的不可篡改介质：

- **方案 A：git 公共仓库**：CI cron 把 root + signature 提交到 GitHub repo
- **方案 B：区块链**：以太坊 / Polygon / 联盟链记一笔 hash
- **方案 C：监管报送**：定期向监管机构上报（金融行业）

防内部全员串谋（管理员 + DBA + 安全审计员同时被攻陷）。**不强制；客户可选**。

### 5.6 完整性自检 worker

每日 cron：
1. 选 N 个随机 (tenant, service) 链
2. 重算 hash chain 从某点到当前
3. 重算所有 batch 的 Merkle root 与签名验证
4. 验证 TSA token 有效
5. 任何不一致 → 写入 `audit.integrity_violation` + PagerDuty P0 + 锁定写入（防被覆盖）

---

## 6. 采集 SDK

### 6.1 同步 vs 异步

```python
from foundation_audit import audit

# 同步（业务事务内必须保证审计也成功）
async with db.transaction():
    await db.execute("INSERT ...")
    await audit.emit_sync(AuditEvent(
        event_type="foundation.billing.invoice.created",
        severity="INFO",
        outcome="SUCCESS",
        resource=ResourceRef(type="invoice", id=inv_id),
        payload={"amount": 1000, "currency": "CNY"},
    ))   # 写 outbox + 事务一起提交

# 异步（fire and forget；低风险事件）
await audit.emit(AuditEvent(...))
```

`emit_sync`：写 Postgres outbox（与业务同事务）。**保证投递**。

`emit`：先尝试 OTel OTLP 推送；失败则回落到 outbox。**at-least-once**。

### 6.2 outbox worker

每个业务 service 跑一个 outbox 后台 worker：

```
loop:
  rows = SELECT * FROM audit.outbox WHERE delivered_at IS NULL ORDER BY id LIMIT 100
  for row in rows:
    try:
      POST audit-service /events/ingest  (with idempotency key = event_id)
      UPDATE audit.outbox SET delivered_at = now() WHERE id = row.id
    except:
      UPDATE audit.outbox SET attempts = attempts + 1, last_error = ... WHERE id = row.id
  if no rows: LISTEN audit_outbox; wait
```

### 6.3 SDK 强制要求

- 业务**不允许**直接写 ClickHouse；**只能**经 `foundation_audit.emit*`
- CI Semgrep 规则禁止业务代码 import `clickhouse_driver` / `clickhouse_connect`
- payload 中 PII 字段必须用 `Sensitive(...)` 包裹 → SDK 自动调 `data-protection` 脱敏

```python
from foundation_audit import Sensitive

await audit.emit(AuditEvent(
    ...,
    payload={
        "email": Sensitive("alice@x.com", classification="L3"),     # 自动脱敏
        "amount": 1000,
    }
))
```

---

## 7. API 表面

完整 OpenAPI 在 `contracts/openapi/audit.yaml`。端点清单：

| 端点 | 方法 | 权限 | 用途 |
|---|---|---|---|
| `/events/ingest` | POST | service_account | 写入（idempotent by event_id） |
| `/events/batch-ingest` | POST | service_account | 批量写入 |
| `/events` | GET | `audit.event.read` | 查询（多过滤+游标分页） |
| `/events/{id}` | GET | `audit.event.read` | 单事件 + verify chain |
| `/events:search` | POST | `audit.event.read` | 复杂查询（DSL） |
| `/events:export` | POST | `audit.event.export` | 异步导出（CSV / JSON / PDF + signature） |
| `/exports/{job_id}` | GET | bearer + 自身 job | 导出进度 + 下载 URL |
| `/event-types` | GET | bearer | 列已注册事件类型 |
| `/event-types/register` | POST | service_account | service 启动注册 |
| `/sessions/{id}/replay` | GET | `audit.session.replay` | 单 session 全部事件按 parent_event_id 串起 |
| `/integrity/verify/{batch_id}` | GET | `audit.integrity.verify` | 验证指定 batch 完整性 |
| `/integrity/anchor` | GET | bearer | 取外部锚定状态（公开） |
| `/retention-policies` | GET / PUT | `audit.retention.update` | 租户保留期覆盖 |
| `/legal-holds` | POST / DELETE | `audit.legal_hold.*` | 关联 lifecycle 的 Legal Hold |

---

## 8. 查询模式与性能

### 8.1 典型查询

| 场景 | SQL | P99 目标 |
|---|---|---|
| 某 user 过去 30 天登录 | `WHERE tenant_id=$1 AND actor_user_id=$2 AND event_type='*.login_*' AND occurred_at > now() - 30d ORDER BY occurred_at DESC LIMIT 100` | < 50ms |
| 某 session 全事件 | `WHERE tenant_id=$1 AND session_id=$2 ORDER BY occurred_at` | < 30ms |
| 某 resource 历史 | `WHERE tenant_id=$1 AND resource_type=$2 AND resource_id=$3` | < 100ms |
| 某事件类型趋势 | `WHERE tenant_id=$1 AND event_type=$2 AND occurred_at > now() - 7d GROUP BY toStartOfHour(occurred_at)` | < 200ms |
| 跨服务搜索 | DSL → 转 CH SQL | < 500ms |

### 8.2 索引策略

- 主排序键 `(tenant_id, occurred_at, event_id)` → 时间范围 + 租户查询走主索引
- bloom_filter on `actor_user_id` / `resource_id` / `session_id` → 高基数过滤
- set on `event_type` → 低基数枚举过滤
- 分区裁剪：查询带 `occurred_at` 范围 → 跳过其他月分区

### 8.3 物化视图（可选）

热点聚合预算：

```sql
CREATE MATERIALIZED VIEW audit.events_by_user_hour
ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(occurred_at_hour)
ORDER BY (tenant_id, actor_user_id, occurred_at_hour, event_type)
AS SELECT
    tenant_id,
    actor_user_id,
    toStartOfHour(occurred_at) AS occurred_at_hour,
    event_type,
    count() AS cnt
FROM audit.events
GROUP BY tenant_id, actor_user_id, occurred_at_hour, event_type;
```

---

## 9. WORM 双写

### 9.1 触发条件
- `event_type` 注册时标 `worm_double_write=true`
- 或运行时 `severity in (SECURITY, CRITICAL)`
- 或 `outcome=DENIED`
- 或 classification ≥ L4

### 9.2 写法

每个事件作为单独 object 推 S3：

```
s3://foundation-audit-worm/
  tenant=<tenant_id>/
    year=2026/month=05/day=22/
      hour=10/
        <event_id>.json    # 含完整 event + signature + tsa_token
```

`<event_id>.json` 内容：

```json
{
  "event": { ... },
  "chain": { "prev_hash": "...", "curr_hash": "..." },
  "batch": {
    "batch_id": "mrk_01J...",
    "merkle_root": "...",
    "merkle_proof": ["...", "..."],    // 叶子到根的兄弟节点
    "signature": "...",
    "signature_key_id": "...",
    "tsa_token": "..."
  }
}
```

`merkle_proof` 让任何持有事件的人**不需要全表**就能验证此事件存在于已签名的 batch 中。

### 9.3 retention

- bucket 默认 compliance mode + 7 年
- TTL 跟 ClickHouse `retention_until` 联动
- Legal Hold → 调 `s3:PutObjectLegalHold` 显式锁

---

## 10. 合规模式联动

| 模式 | retention 默认 | TSA 强制 | 采样 | WORM 触发面 |
|---|---|---|---|---|
| 基线 / `pipl` | 6 个月 | FreeTSA OK | login_failure 100% / success 1% | severity ≥ SECURITY |
| `equal_protection_3` | 12 个月 | 同基线 | 全部 100% | severity ≥ NOTICE |
| `equal_protection_4` | 24 个月 | NTSC 强制 | 全部 100% | severity ≥ INFO |
| `finance_jrt0071` | 5 年 | NTSC + 国密 SM2 | 全部 100% | 全部 |
| `hipaa` | 6 年 | DigiCert / 国际商业 | 全部 100% | 涉及 PHI 全部 |
| `soc2` | 1 年 | 商业 TSA | 同基线 | 同基线 |
| `gdpr` | 自动按用户 DSAR 调整 | 同基线 | 同基线 | 个人数据事件全部 |

---

## 11. 部署形态差异

| 维度 | small | medium | large |
|---|---|---|---|
| ClickHouse 节点 | 1 单实例 | 3 副本 | 集群 + sharding |
| WORM | MinIO 单节点 + lock | MinIO 分布式 + lock | S3 / OSS / COS Object Lock |
| TSA provider | FreeTSA | FreeTSA / DigiCert | NTSC（合规驱动） |
| 完整性自检频率 | 每日 | 每 6h | 每小时 |
| Outbox worker 并发 | 1 | 5 | 50 KEDA |
| Merkle batch | 10000/5min | 同 | 5000/2min（更细） |
| S3 双写 | sync | async batch | async batch + multi-region |

---

## 12. 性能与容量

### 12.1 写入吞吐

ClickHouse 实测（参考 oneuptime 公开案例）：
- 单节点 100k events/s
- 集群 1M+ events/s

audit-service 瓶颈在 hash chain（每 tenant-service 串行）：
- 单链 ~50k/s
- 100 (tenant, service) 并发 → 5M/s 总（远超需要）

### 12.2 容量预算

按租户：
- 1000 用户 × 100 事件/天 × 1KB = 100MB/day
- 6 个月 = 18GB
- ClickHouse 10x 压缩 → 1.8GB

100 租户：180GB on 热盘 + 冷归档按需。

### 12.3 网络/磁盘

- ClickHouse Replicated 单写 3 副本 + 压缩 → 入站带宽乘 3 / 出站需求小
- WORM S3 写延迟 100-300ms → 异步批量

---

## 13. 关键技术风险

| 风险 | 缓解 |
|---|---|
| Hash chain 单点串行成为吞吐瓶颈 | 按 (tenant, service) 分链；同一链内 worker pool 实际是 actor + lock |
| TSA provider 故障 | 多 provider 配置 fallback；TSA 失败不阻塞写（事件入库但 `tsa_timestamp=NULL` 待补） |
| ClickHouse 节点故障数据丢失 | Replicated MergeTree 3 副本 + outbox 兜底 |
| WORM bucket 写失败 | 重试 + 死信队列 + 告警；事件本身已在 CH，不会丢 |
| 完整性自检发现篡改 | 立即锁写 + PagerDuty + 法务介入；外部锚定（区块链 / git）作铁证 |
| 大 payload 撑爆带宽 | 64KB 切到 events_payload 表；超 1MB 拒绝写入 |
| PII 漏脱敏写入审计 | data-protection 强制路径 + Semgrep 扫 `Sensitive(` 缺失 + 入库前正则兜底 |
| 跨租户查询写错权限 | RLS 等价过滤注入 + authz 检查（不依赖 CH 自身 RLS） |
| 合规期改长（如 1y→6y）→ 旧数据已过 TTL 删除 | TTL 设宽松基线（如 10 年）实际删由 lifecycle 控制；合规期改不影响已删数据 |
| 监管要求"实时报送"（金融） | webhook 订阅 SECURITY/CRITICAL 事件直推监管 endpoint |
| Outbox 表无限增长 | delivered 行 7 天后归档；按月分区 + 旧分区 detach |

---

## 14. 测试策略

### 14.1 单元（≥90%）
- canonical JSON 稳定性（同 event 反复算 hash 相同）
- hash chain：构造 1000 事件，篡改任意一条 → 自检必发现
- Merkle 算法：奇偶叶子、单叶子、空 batch
- 采样器：1% 采样率统计偏差 < 0.1%
- payload 大小切表
- Sensitive 脱敏 hook

### 14.2 集成
- 起 ClickHouse + MinIO + crypto stub + FreeTSA → 跑 e2e
- outbox 投递保证：杀进程后重启继续投
- WORM bucket 写入后**禁止**修改/删除（测 `s3:DeleteObject` 必失败）
- 跨副本一致性

### 14.3 完整性 fuzz
- 1000 次随机篡改任意位置事件 → 自检 100% 发现
- 篡改 prev_hash / curr_hash / payload / merkle_root → 全部告警
- TSA token 替换为伪造 → 验签必失败

### 14.4 性能
- 持续 1h 写入 10k events/s 不丢
- 30 天数据查询 P99 < 500ms
- WORM 双写 P99 < 1s

### 14.5 合规
- DSAR：用户 X 要求"导出我的全部数据"→ 单 SQL 完成 + PDF 带签名
- 监管：模拟客户审计要"过去 6 个月所有 SECURITY 事件" → 一键导出

---

## 15. 待解决问题

| # | 问题 | 决策机制 | 截止 |
|---|---|---|---|
| Q1 | Merkle batch 大小 5min/10k 是否合适？ | A-M2 后期跑压测，按吞吐调 | A-M3 |
| Q2 | 外部锚定（区块链）是否首版交付？ | 客户驱动；首版仅 git 公共仓库可选 | A-M5 |
| Q3 | 决策日志（OPA）是否直接写 audit.events 还是独立表？ | 独立表 `audit.authz_decisions`（容量大、schema 不同） | 已定 |
| Q4 | 业务日志（如 nginx access log）是否走审计？ | 否；走 Loki；audit 仅"业务/安全相关事件" | 已定 |
| Q5 | 跨地域多活时 hash chain 怎么合并？ | 每 region 独立链；跨 region merkle root 周期合并 | v1.2 |
| Q6 | NTSC TSA 集成方式 | A-M3 起调研对接；商业合同走 | A-M3 |
| Q7 | 审计查询的"模糊搜索" | OpenSearch mirror（业务层 search 复用） vs CH 全文索引 | A-M3 |
| Q8 | DSAR 导出含被脱敏字段的"原文"是否可解？ | 同时导出脱敏版 + 加密原文版（用户钥）→ 详 data-protection-v1 | A-M3 |
| Q9 | 自检 worker 发现篡改后是否要"自动隔离"？ | 是；自动锁写新事件 + 仅 break-glass admin 能解除 | A-M2 |
| Q10 | payload 内是否允许任意 JSON 还是限定 schema？ | event_type 注册时附 payload JSON schema；CI 校验 | A-M2 |

---

## 16. 验证标准（A-M2 出口）

- [ ] OpenAPI `contracts/openapi/audit.yaml` spectral 通过
- [ ] 单元 / 集成测试覆盖 ≥90%
- [ ] hash chain + Merkle + signature + TSA 端到端
- [ ] 完整性自检 fuzz 1000 次 100% 发现篡改
- [ ] 10k events/s 持续 1h 稳定
- [ ] WORM bucket 不可删 / 不可改测试通过
- [ ] DSAR / 监管报表导出端到端
- [ ] 与 crypto / lifecycle / data-protection 集成 e2e
- [ ] 三档 helm profile 都能跑

---

## 17. 参考资料

- [ClickHouse Audit Trail for Data Changes — OneUptime](https://oneuptime.com/blog/post/2026-03-31-clickhouse-audit-trail-data-changes/view)
- [Append-Only Event Streams in ClickHouse](https://oneuptime.com/blog/post/2026-03-31-clickhouse-model-append-only-event-streams/view)
- [Tamper-evident audit logs — Sachith Dassanayake](https://www.sachith.co.uk/audit-trails-and-tamper-evidence-scaling-strategies-practical-guide-feb-22-2026/)
- [Merkle trees for tamper-evident logs — Designgurus](https://www.designgurus.io/answers/detail/how-do-you-design-tamperevident-audit-logs-merkle-trees-hashing)
- [Accountability of Things: tamper-evident logging at scale (arxiv 2308.05557)](https://arxiv.org/pdf/2308.05557)
- [RFC 3161 Time-Stamp Protocol](https://datatracker.ietf.org/doc/html/rfc3161)
- [RFC 8785 JSON Canonicalization Scheme (JCS)](https://datatracker.ietf.org/doc/html/rfc8785)
- [RFC 6962 Certificate Transparency (Merkle)](https://datatracker.ietf.org/doc/html/rfc6962)
- [FreeTSA RFC 3161](https://www.freetsa.org/)
- [Sigstore Timestamp Authority](https://github.com/sigstore/timestamp-authority)

---

## 18. 变更记录

| 日期 | 版本 | 变更 |
|---|---|---|
| 2026-05-22 | 0.1.0 | 初版（P2 #10） |

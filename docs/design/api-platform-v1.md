# API Platform 详细设计 v1

> 对内（租户内开发者）的 API 平台：**API Key**（三级 scope）+ **OAuth2 server**（租户内应用 SSO）+ **Webhook**（事件订阅 + HMAC + 重试 + 投递审计）+ 开发者门户 UI。

| 字段 | 值 |
|---|---|
| 状态 | Draft v1 |
| Owner | API Platform 后端 |
| 实施 milestone | A-M4 |
| 相关文档 | identity / authz / audit / notification / crypto |

## 0. TL;DR

- **API Key**：3 级（tenant / user / app），scope 化、IP 白名单、限流、过期
- **OAuth2 server**：**面向租户内部应用**（非公网开发者生态）；支持 client_credentials + authorization_code + refresh_token
- **Webhook**：业务订阅事件；HMAC-SHA256 签名；指数退避重试；DLQ；投递审计
- **限流**：令牌桶 per (api_key, endpoint) + per (tenant, endpoint) 双层
- **开发者门户**：用户自助管理 API Key + Webhook + 查看用量 / 错误率

## 1. Context

- 业务场景：客户内部 IT 系统需要调底座 API（如 HR 系统读用户列表、报表系统拉计费数据）
- 安全要求：API Key 必须可吊销 + 可审计 + 限流防滥用
- Webhook 是底座事件的对外出口；可靠性是关键（不能漏推）
- **明确边界**：v1 **不做公网开放平台**（不开发者注册 / 不应用市场 / 不应用审核）；只服务租户内部

## 2. API Key

### 2.1 三级类型

| 类型 | 谁创建 | 谁使用 | 生命周期 |
|---|---|---|---|
| **tenant_key** | 租户管理员 | 后端 system-to-system（如 HR 同步） | 长期；定期轮换 |
| **user_key** | 用户自己 | 用户脚本 / CLI 工具 | 可设过期；用户退出账号自动失效 |
| **app_key** | 租户应用（OAuth client） | 应用内嵌调用 | 与应用同生命周期 |

### 2.2 数据模型

```sql
CREATE TABLE api_platform.api_key (
  tenant_id        TEXT NOT NULL,
  key_id           TEXT NOT NULL,           -- ak_01J7XYZ（公开标识）
  key_secret_hash  TEXT NOT NULL,           -- bcrypt(secret)，secret 只返回一次
  type             TEXT NOT NULL,           -- 'TENANT'/'USER'/'APP'
  owner_user_id    TEXT,                    -- USER/APP 必填
  owner_app_id     TEXT,                    -- APP 必填
  name             TEXT NOT NULL,
  scopes           TEXT[] NOT NULL,         -- ['identity:users:read','billing:invoices:read']
  ip_whitelist     INET[],
  rate_limit_per_min INT,                   -- 覆盖默认
  expires_at       TIMESTAMPTZ,
  last_used_at     TIMESTAMPTZ,
  last_used_ip     INET,
  status           TEXT NOT NULL,           -- 'ACTIVE'/'REVOKED'/'EXPIRED'
  created_by       TEXT NOT NULL,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at       TIMESTAMPTZ,
  revoked_reason   TEXT,
  PRIMARY KEY (tenant_id, key_id)
);
CREATE INDEX idx_apikey_owner ON api_platform.api_key(tenant_id, owner_user_id) WHERE status='ACTIVE';
```

### 2.3 Key 格式

```
ak_<env>_<random_24chars>.<secret_32chars>
例: ak_prod_aBc123XyZ456...AbC.SecretZyx789...

公开部分 (ak_id): ak_prod_aBc123XyZ456...AbC（可日志可显示）
私密部分 (secret): SecretZyx789...（仅创建时返回；bcrypt 入库）
```

### 2.4 验证流程

```
请求 Header: Authorization: Bearer ak_prod_xxx.secret_xxx

1. 解析 ak_id + secret
2. 查 api_key (Redis 缓存 5min) 
3. 校验 status='ACTIVE' + expires_at > now()
4. bcrypt 校验 secret_hash
5. 校验 IP ∈ ip_whitelist
6. 校验 scopes ⊇ required_scope（API endpoint metadata 声明）
7. 限流：令牌桶 (api_key, endpoint) 
8. 限流：令牌桶 (tenant, endpoint) 
9. 更新 last_used_at（异步，避免每次写库）
10. 写 audit
11. 注入租户上下文 → 业务处理
```

### 2.5 Scope 命名

```
<service>:<resource>:<action>
identity:users:read
identity:users:write
billing:invoices:read
audit:events:read
```

支持通配符：`identity:*:read` / `*:*:*`（admin scope，严控）。

## 3. OAuth2 Server（租户内应用）

### 3.1 流程支持

| Grant Type | 用途 |
|---|---|
| `client_credentials` | 应用调底座 API（server-to-server，最常用） |
| `authorization_code` + PKCE | 第三方应用代表用户访问底座（如管理员安装的内部应用） |
| `refresh_token` | 长期 token 续命 |

**不支持**：
- `password` grant（不安全）
- `implicit` grant（已 deprecated）

### 3.2 数据模型

```sql
CREATE TABLE api_platform.oauth_app (
  tenant_id        TEXT NOT NULL,
  app_id           TEXT NOT NULL,           -- 'app_01J7XYZ'
  client_id        TEXT NOT NULL,           -- OAuth client_id（公开）
  client_secret_hash TEXT NOT NULL,
  name             TEXT NOT NULL,
  description      TEXT,
  redirect_uris    TEXT[] NOT NULL,
  allowed_scopes   TEXT[] NOT NULL,
  type             TEXT NOT NULL,           -- 'CONFIDENTIAL'/'PUBLIC'（PKCE 必选）
  status           TEXT NOT NULL,
  created_by       TEXT NOT NULL,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, app_id),
  UNIQUE (tenant_id, client_id)
);

CREATE TABLE api_platform.oauth_authorization_code (
  code_hash        TEXT PRIMARY KEY,        -- SHA-256(code)
  tenant_id        TEXT NOT NULL,
  app_id           TEXT NOT NULL,
  user_id          TEXT NOT NULL,
  redirect_uri     TEXT NOT NULL,
  code_challenge   TEXT,                    -- PKCE
  code_challenge_method TEXT,               -- 'S256'
  scopes           TEXT[] NOT NULL,
  used             BOOLEAN NOT NULL DEFAULT FALSE,
  expires_at       TIMESTAMPTZ NOT NULL,    -- 10 min
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE api_platform.oauth_token (
  token_hash       TEXT PRIMARY KEY,
  tenant_id        TEXT NOT NULL,
  app_id           TEXT NOT NULL,
  user_id          TEXT,                    -- client_credentials 时 NULL
  scopes           TEXT[] NOT NULL,
  type             TEXT NOT NULL,           -- 'ACCESS'/'REFRESH'
  expires_at       TIMESTAMPTZ NOT NULL,
  revoked_at       TIMESTAMPTZ,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_oauth_token_app ON api_platform.oauth_token(tenant_id, app_id) WHERE revoked_at IS NULL;
```

### 3.3 端点

| Method | Path | 说明 |
|---|---|---|
| GET | `/api/api-platform/v1/oauth/authorize` | authorization endpoint（重定向）|
| POST | `/api/api-platform/v1/oauth/token` | token endpoint |
| POST | `/api/api-platform/v1/oauth/revoke` | revoke token |
| POST | `/api/api-platform/v1/oauth/introspect` | token introspection（RFC 7662） |
| GET | `/api/api-platform/v1/oauth/userinfo` | OIDC userinfo（可选）|

### 3.4 与 identity 关系

- identity 主管 user 身份 + SSO（Keycloak）
- 本模块的 OAuth server 是**对应用方的**门户；用户身份还是底层 Keycloak
- `authorization_code` 流：本服务调 identity.verify_user_session() 拿当前登录用户

## 4. Webhook

### 4.1 数据模型

```sql
CREATE TABLE api_platform.webhook (
  tenant_id        TEXT NOT NULL,
  webhook_id       TEXT NOT NULL,
  name             TEXT NOT NULL,
  url              TEXT NOT NULL,
  secret           BYTEA NOT NULL,          -- crypto.encrypt(HMAC secret)
  event_types      TEXT[] NOT NULL,         -- ['foundation.identity.user.created', ...]
  active           BOOLEAN NOT NULL DEFAULT TRUE,
  retry_strategy   JSONB NOT NULL,          -- {max_attempts: 8, backoff: 'exp', ...}
  custom_headers   JSONB,                   -- 业务自定义 header
  created_by       TEXT NOT NULL,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, webhook_id)
);

CREATE TABLE api_platform.webhook_delivery (
  tenant_id        TEXT NOT NULL,
  delivery_id      TEXT NOT NULL,
  webhook_id       TEXT NOT NULL,
  event_id         TEXT NOT NULL,
  event_type       TEXT NOT NULL,
  payload          JSONB NOT NULL,
  signature        TEXT NOT NULL,           -- HMAC-SHA256
  status           TEXT NOT NULL,           -- 'QUEUED'/'SENDING'/'DELIVERED'/'FAILED'/'DLQ'
  attempt          INT NOT NULL DEFAULT 0,
  next_retry_at    TIMESTAMPTZ,
  http_status      INT,
  response_body    TEXT,
  latency_ms       INT,
  delivered_at     TIMESTAMPTZ,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, delivery_id)
);
CREATE INDEX idx_wd_retry ON api_platform.webhook_delivery(status, next_retry_at) WHERE status IN ('QUEUED','FAILED');
```

### 4.2 签名（业务方验证）

```
HTTP Header:
  X-Webhook-Event-Id: evt_01J7XYZ
  X-Webhook-Event-Type: foundation.identity.user.created
  X-Webhook-Timestamp: 1748000000
  X-Webhook-Signature: t=1748000000,v1=hex(HMAC-SHA256(secret, timestamp.body))

业务方验证：
1. 检查 timestamp 在 5min 内（防重放）
2. 计算 HMAC-SHA256(secret, "1748000000." + body)
3. 与 X-Webhook-Signature 比对
4. event_id 入幂等表（重复直接 ack）
```

### 4.3 重试策略

```
attempt 1: 立即
attempt 2: +30s
attempt 3: +2min
attempt 4: +10min
attempt 5: +1h
attempt 6: +6h
attempt 7: +24h
attempt 8: +72h（最后一次）
→ DLQ
```

非 2xx / 5xx / 网络错都重试；4xx (非 408/429) 不重试直接 DLQ。

### 4.4 DLQ + 人工干预

- DLQ 表保留 30 天
- 开发者门户「失败投递」页面可手动 re-queue
- 30 天后归档（ClickHouse 长保留）

### 4.5 流量控制

每个 webhook 单独的 in-flight 限制（默认 10 并发） + per (tenant) 全局限制（默认 100 并发）。防止单租户 webhook 慢响应拖垮 worker 池。

## 5. 限流

### 5.1 两层令牌桶

```
请求来 →
  Layer 1: (api_key, endpoint) 桶 → 默认 60/min（user）/ 600/min（tenant）
  Layer 2: (tenant, endpoint) 桶 → 默认 6000/min
  
任一桶空 → 429 + Retry-After header
```

Redis 实现（lua 脚本原子操作）。

### 5.2 自定义限流

管理员控制台可调每个 endpoint 的限流；高优 endpoint（如 DSAR）可调低。

### 5.3 配额联动 billing

- 当月 api_call_count 配额（billing.quota）→ 超额阻断
- 限流是「QPS 防滥用」；配额是「月度成本控制」

## 6. SDK

```python
from foundation_api_platform import APIPlatformClient

client = APIPlatformClient.from_env()

# API Key 管理
key = client.api_keys.create(
    name="HR sync key",
    type="tenant",
    scopes=["identity:users:read", "identity:users:write"],
    expires_in_days=365,
    ip_whitelist=["10.0.0.0/24"],
)
print(key.secret)   # 仅此一次

client.api_keys.revoke(key_id="ak_01J7XYZ", reason="rotation")
client.api_keys.list(filter={"status": "ACTIVE"})

# Webhook 管理
wh = client.webhooks.create(
    name="HR User Provisioning",
    url="https://hr.tenant-a.com/foundation-webhook",
    event_types=[
        "foundation.identity.user.created",
        "foundation.identity.user.disabled",
    ],
)
print(wh.secret)   # 仅此一次

# 测试发送
client.webhooks.test(webhook_id="wh_01J7XYZ", sample_event_type="...")

# 投递日志
deliveries = client.webhooks.deliveries(
    webhook_id="wh_01J7XYZ",
    status="FAILED",
    since="2026-05-20",
)

# OAuth App 管理
app = client.oauth_apps.create(
    name="Internal HR Tool",
    redirect_uris=["https://hr.tenant-a.com/oauth/callback"],
    allowed_scopes=["identity:users:read"],
)
```

## 7. 与其他模块集成

| 模块 | 集成 |
|---|---|
| **identity** | OAuth `authorization_code` 流复用 identity 会话 |
| **authz** | scope ↔ permission 映射；API Key 调用走 authz 检查 |
| **audit** | 所有 API Key 创建 / 撤销 / 调用、OAuth token 签发、webhook 投递必审 |
| **notification** | webhook 失败告警；API Key 即将过期提醒 |
| **billing** | api_call_count 配额上报 |
| **crypto** | webhook secret / API key secret 加密存储 |
| **compliance** | API Key 调用按 PIPL 处理活动登记 |

## 8. 部署形态

| 形态 | OAuth server | Webhook worker pool | 开发者门户 |
|---|---|---|---|
| small | 1 实例 | 5 worker | 无 UI（API only） |
| medium | 3 实例 HA | 20 worker（KEDA） | UI |
| large | 5-20（HPA） | 50-200（KEDA） | UI + 全租户 dashboard |

## 9. 错误码

| code | HTTP |
|---|---|
| `FOUNDATION.API_PLATFORM.AUTHN.API_KEY_INVALID` | 401 |
| `FOUNDATION.API_PLATFORM.AUTHN.API_KEY_REVOKED` | 401 |
| `FOUNDATION.API_PLATFORM.AUTHN.API_KEY_EXPIRED` | 401 |
| `FOUNDATION.API_PLATFORM.POLICY.IP_NOT_ALLOWED` | 403 |
| `FOUNDATION.API_PLATFORM.POLICY.SCOPE_INSUFFICIENT` | 403 |
| `FOUNDATION.API_PLATFORM.RATE.LIMIT_EXCEEDED` | 429 |
| `FOUNDATION.API_PLATFORM.OAUTH.INVALID_GRANT` | 400 |
| `FOUNDATION.API_PLATFORM.OAUTH.UNSUPPORTED_GRANT_TYPE` | 400 |
| `FOUNDATION.API_PLATFORM.OAUTH.PKCE_REQUIRED` | 400 |
| `FOUNDATION.API_PLATFORM.WEBHOOK.URL_INVALID` | 400 |
| `FOUNDATION.API_PLATFORM.WEBHOOK.DELIVERY_FAILED` | 502 |

## 10. 性能与容量

| 指标 | 目标 |
|---|---|
| API Key 验证 | < 5ms（Redis 缓存） |
| OAuth token 签发 | < 50ms |
| Webhook 投递 | P95 < 2s |
| Webhook 重试 worker 吞吐 | 1000 投递/s/pool |
| 限流判断 | < 1ms（Redis Lua） |

## 11. 待解决问题

| # | 问题 | 决策 |
|---|---|---|
| 1 | API Key 轮换平滑期 | 旧 key 在创建新 key 后 7d 内仍可用；通知用户切换 |
| 2 | Webhook 投递到客户内网 | 客户配置 NAT / 反向通道；本模块不解决 |
| 3 | Webhook URL 校验 | 创建时探测 URL 通达性 + 用户确认 |
| 4 | API Key 泄漏后 detect | last_used_ip 异常告警；可疑模式自动锁定 |
| 5 | OAuth dynamic client registration | v1 不支持（仅管理员手动）；v1.1 评估 |
| 6 | Webhook 顺序保证 | 默认不保证；可按 partition_key 串行化（v1.1）|
| 7 | Token revocation 广播 | 写库后 Redis Pub/Sub 通知各 service 失效缓存 |
| 8 | OAuth scope 与 authz role 是否合并 | scope 是 OAuth 概念 + role 是 RBAC 概念；映射但分别 |

## 12. 验证标准（A-M4 出口）

| # | 验证 | 通过 |
|---|---|---|
| 1 | API Key CRUD | 创建 / 列出 / 撤销 e2e |
| 2 | API Key scope 验证 | 不足 scope 调用 → 403 |
| 3 | IP whitelist | 非白名单 IP → 403 |
| 4 | OAuth client_credentials | server-to-server e2e |
| 5 | OAuth authorization_code + PKCE | 流程 e2e |
| 6 | Webhook 创建 + 测试发送 | URL 收到正确签名 payload |
| 7 | Webhook 签名验证 | 篡改 body → 验签失败 |
| 8 | Webhook 重试 | 模拟 5xx 5 次后成功；8 次后 DLQ |
| 9 | 限流双层 | (api_key) + (tenant) 桶各触发一次 429 |
| 10 | 审计 | 所有 API Key 调用 / OAuth token / webhook 落 audit |
| 11 | RLS | 跨租户查 API Key / webhook 失败 |
| 12 | 性能 | 1000 QPS API Key 验证 < 5ms p95 |

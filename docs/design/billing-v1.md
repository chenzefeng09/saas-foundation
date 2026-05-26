# Billing 双模式详细设计 v1

> 计费引擎双模式：**私有化模式**（配额 + 用量 + 离线发票 + 合同续费） + **SaaS 模式**（Stripe/支付宝/微信 + 订阅生命周期 + 自动续费 + 对账）。
> 同一套领域模型；通过 `PaymentProvider` / `InvoiceGenerator` / `TaxCalculator` 三接口按部署形态注入不同实现。

| 字段 | 值 |
|---|---|
| 状态 | Draft v1 |
| Owner | Billing 后端 + 财务系统集成 |
| 实施 milestone | A-M4 |
| 相关文档 | identity / org / authz / compliance / notification / audit |

## 0. TL;DR

- **5 类核心实体**：Plan（套餐）/ Subscription（订阅）/ Quota（配额）/ UsageRecord（用量）/ Invoice（发票/订单）
- **3 抽象接口**：`PaymentProvider` / `InvoiceGenerator` / `TaxCalculator`，私有化 vs SaaS 注入不同实现
- **配额维度**：`seat_count` / `storage_gb` / `agent_session_count` / `llm_token_count` / `api_call_count`，业务层可扩展
- **熔断**：超额 → SDK `check_quota()` 抛 `QUOTA_EXCEEDED`；管理员设软/硬上限
- **私有化**：实施时 SRE 写入套餐 + 配额；定期出对账报告（PDF/Excel/电子发票）
- **SaaS**：Stripe webhook + HMAC + nonce 去重；试用 → 订阅 → 升降级 → 续费 → 暂停 → 取消 → 退款
- **审计**：所有计费事件必审（订阅变更 / 退款 / 配额调整 / 发票生成）

## 1. Context

- 私有化客户付款走线下合同；不需要在线支付，但需要**用量统计 + 发票**
- SaaS 客户需要标准 Stripe 流；海外 + 国内同时支持
- 「同一套领域模型」是底座可复用的关键：业务层不关心模式差异
- 合规：金融客户需要电子发票（航天信息 / 百望开放接口）；海外需要 Stripe Tax

## 2. 5 类核心实体

### 2.1 Plan（套餐）

```sql
CREATE TABLE billing.plan (
  tenant_id        TEXT NOT NULL,
  plan_id          TEXT NOT NULL,
  code             TEXT NOT NULL,           -- 'free'/'pro'/'business'/'enterprise'/'custom_xxx'
  name             TEXT NOT NULL,
  description      TEXT,
  pricing          JSONB NOT NULL,          -- {currency, mode, base_amount, per_unit, ...}
  quotas           JSONB NOT NULL,          -- {seat_count: 50, storage_gb: 100, ...}
  features         TEXT[],                  -- 功能开关（同 feature-flag 联动）
  billing_cycle    TEXT NOT NULL,           -- 'monthly'/'yearly'/'one_time'
  trial_days       INT NOT NULL DEFAULT 0,
  status           TEXT NOT NULL,           -- 'ACTIVE'/'DEPRECATED'
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, plan_id)
);
```

`tenant_id = '__global__'` 行 = 平台标准套餐；租户级行 = 客户定制套餐（Enterprise）。

### 2.2 Subscription（订阅）

```sql
CREATE TABLE billing.subscription (
  tenant_id        TEXT NOT NULL,
  subscription_id  TEXT NOT NULL,
  plan_id          TEXT NOT NULL,
  status           TEXT NOT NULL,           -- 'TRIAL'/'ACTIVE'/'PAST_DUE'/'PAUSED'/'CANCELED'/'EXPIRED'
  trial_end_at     TIMESTAMPTZ,
  current_period_start TIMESTAMPTZ NOT NULL,
  current_period_end   TIMESTAMPTZ NOT NULL,
  auto_renew       BOOLEAN NOT NULL DEFAULT TRUE,
  payment_method   TEXT,                    -- 'stripe_card_xxx' / 'alipay' / 'offline_contract'
  canceled_at      TIMESTAMPTZ,
  cancel_reason    TEXT,
  upgraded_from    TEXT,                    -- 升级链
  grace_period_end TIMESTAMPTZ,             -- 续费失败 + 7d 宽限期
  metadata         JSONB,                   -- Stripe subscription ID / 合同号 / 销售备注
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, subscription_id)
);
CREATE INDEX idx_sub_renewal ON billing.subscription(current_period_end) WHERE status IN ('ACTIVE','TRIAL');
```

### 2.3 Quota（配额）

```sql
CREATE TABLE billing.quota (
  tenant_id        TEXT NOT NULL,
  quota_dim        TEXT NOT NULL,           -- 'seat_count'/'storage_gb'/'agent_session_count'/'llm_token_count'/'api_call_count'
  period           TEXT NOT NULL,           -- 'monthly'/'lifetime'
  soft_limit       BIGINT NOT NULL,         -- 软上限：通知 + 不阻断
  hard_limit       BIGINT NOT NULL,         -- 硬上限：阻断
  current_usage    BIGINT NOT NULL DEFAULT 0,
  period_start     TIMESTAMPTZ NOT NULL,
  period_end       TIMESTAMPTZ NOT NULL,
  last_alert_at    TIMESTAMPTZ,             -- 80/90/100% 告警
  PRIMARY KEY (tenant_id, quota_dim, period_start)
);
```

### 2.4 UsageRecord（用量明细）

```sql
CREATE TABLE billing.usage_record (
  tenant_id        TEXT NOT NULL,
  record_id        TEXT NOT NULL,
  quota_dim        TEXT NOT NULL,
  amount           BIGINT NOT NULL,         -- 用量增量
  source_service   TEXT NOT NULL,           -- 'llm-gateway' / 'sandbox' / 'storage' / 'identity'
  source_event_id  TEXT,                    -- 幂等键（防重复计费）
  metadata         JSONB,                   -- {user_id, model, tokens_in, tokens_out, ...}
  occurred_at      TIMESTAMPTZ NOT NULL,
  recorded_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, record_id),
  UNIQUE (tenant_id, source_service, source_event_id)  -- 幂等
);
CREATE INDEX idx_usage_quota ON billing.usage_record(tenant_id, quota_dim, occurred_at);
```

> 高频写：UsageRecord 单独走 ClickHouse 主存储（按月分区），Postgres 仅存近期 + 聚合 (`billing.quota.current_usage`)。

### 2.5 Invoice（发票/订单）

```sql
CREATE TABLE billing.invoice (
  tenant_id        TEXT NOT NULL,
  invoice_id       TEXT NOT NULL,
  invoice_number   TEXT NOT NULL,           -- 人类可读编号 INV-2026-001234
  subscription_id  TEXT,
  type             TEXT NOT NULL,           -- 'SUBSCRIPTION'/'ONE_TIME'/'CREDIT_NOTE'/'OVERAGE'
  status           TEXT NOT NULL,           -- 'DRAFT'/'OPEN'/'PAID'/'OVERDUE'/'VOID'/'REFUNDED'
  currency         TEXT NOT NULL,
  amount_subtotal  BIGINT NOT NULL,         -- 分（人民币分 / 美分）
  amount_tax       BIGINT NOT NULL,
  amount_total     BIGINT NOT NULL,
  amount_paid      BIGINT NOT NULL DEFAULT 0,
  amount_refunded  BIGINT NOT NULL DEFAULT 0,
  issued_at        TIMESTAMPTZ NOT NULL,
  due_at           TIMESTAMPTZ NOT NULL,
  paid_at          TIMESTAMPTZ,
  void_reason      TEXT,
  pdf_uri          TEXT,                    -- 发票 PDF（含数字签名）
  external_id      TEXT,                    -- Stripe invoice id / 第三方发票号
  metadata         JSONB,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, invoice_id),
  UNIQUE (tenant_id, invoice_number)
);

CREATE TABLE billing.invoice_line (
  tenant_id        TEXT NOT NULL,
  line_id          TEXT NOT NULL,
  invoice_id       TEXT NOT NULL,
  description      TEXT NOT NULL,
  quantity         BIGINT NOT NULL,
  unit_amount      BIGINT NOT NULL,
  amount           BIGINT NOT NULL,
  period_start     TIMESTAMPTZ,
  period_end       TIMESTAMPTZ,
  metadata         JSONB,
  PRIMARY KEY (tenant_id, line_id)
);
```

## 3. 三抽象接口

### 3.1 PaymentProvider

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass

@dataclass
class PaymentIntent:
    intent_id: str          # provider 侧 ID
    client_secret: str | None  # Stripe 前端确认用
    redirect_url: str | None   # 支付宝 / 微信扫码 / 银行跳转

@dataclass
class PaymentResult:
    status: str             # 'SUCCEEDED'/'PENDING'/'FAILED'/'REFUNDED'
    transaction_id: str
    raw_payload: dict

class PaymentProvider(ABC):
    provider_name: str       # 'stripe'/'alipay'/'wechat_pay'/'offline'

    @abstractmethod
    def create_payment_intent(self, invoice: Invoice) -> PaymentIntent: ...
    @abstractmethod
    def verify_webhook(self, headers: dict, body: bytes) -> WebhookEvent: ...
    @abstractmethod
    def refund(self, transaction_id: str, amount: int, reason: str) -> PaymentResult: ...
    @abstractmethod
    def get_payment_status(self, transaction_id: str) -> PaymentResult: ...
```

实现：
- `StripeProvider`（海外）
- `AlipayProvider`（国内）
- `WeChatPayProvider`（国内）
- `OfflineProvider`（私有化模式默认；不调外部 API，只更新本地 invoice 状态）

### 3.2 InvoiceGenerator

```python
class InvoiceGenerator(ABC):
    @abstractmethod
    def generate(self, invoice: Invoice, recipient: TaxProfile) -> bytes:
        """生成 PDF（含数字签名）"""

    @abstractmethod
    def generate_credit_note(self, original_invoice: Invoice, amount: int) -> bytes: ...
```

实现：
- `BasicInvoiceGenerator`（纯模板生成）
- `ChinaElectronicInvoiceGenerator`（航天信息 / 百望接口，开电子增值税发票）
- `StripeInvoiceGenerator`（拉 Stripe Hosted Invoice URL）

### 3.3 TaxCalculator

```python
class TaxCalculator(ABC):
    @abstractmethod
    def calculate_tax(self, amount: int, currency: str, tax_profile: TaxProfile) -> int: ...
```

实现：
- `StripeTaxCalculator`（海外，托管）
- `ChinaVATCalculator`（中国增值税 6% / 3%）
- `ZeroTaxCalculator`（私有化模式默认；税务由客户自理）

## 4. 双模式启用机制

```yaml
# 租户配置（tenant.config）
billing:
  mode: "private"          # 'private' / 'saas'
  payment_providers: ["offline"]
  invoice_generator: "china_electronic"   # 私有化 + 中国客户场景
  tax_calculator: "zero"
  
# SaaS 形态
billing:
  mode: "saas"
  payment_providers: ["stripe", "alipay"]
  invoice_generator: "stripe"
  tax_calculator: "stripe"
```

通过 feature flag `billing.saas_mode` 全局可控制开关；租户级可定制（通过 `billing.tenant_config` 表）。

## 5. SaaS 订阅生命周期

### 5.1 状态机

```
NEW_USER
  ↓ 选套餐（含 trial）
TRIAL ──trial_end──> ACTIVE
  │                    │
  │ trial 期间取消     │
  ↓                    ├─auto_renew 失败──> PAST_DUE
CANCELED                                    │
                                       grace 7d ──支付成功──> ACTIVE
                                            │
                                            └ 超 grace ──> CANCELED + 降级 free
                                            
ACTIVE ──升级 plan_upgrade──> ACTIVE (新 plan)
  │      (按比例计费差额)
  │
  ├─降级 plan_downgrade──> ACTIVE (新 plan, 次周期生效)
  │
  ├─pause (用户主动)──> PAUSED ──resume──> ACTIVE
  │
  └─取消──> CANCELED (周期内仍可用)
```

### 5.2 Stripe Webhook 验签 + 幂等

```python
# 必须的 webhook 防护
1. 验证 Stripe-Signature header（HMAC-SHA256 + timestamp ≤ 5min）
2. event.id 入 webhook_inbox 表（PRIMARY KEY）→ 重复直接 ack
3. 异步 worker 处理 event，事务性
4. 处理失败 → 重试（Stripe 自动 3 天重试 + 我方独立 cron 补尝试）
```

```sql
CREATE TABLE billing.webhook_inbox (
  provider         TEXT NOT NULL,
  event_id         TEXT NOT NULL,           -- Stripe event.id
  event_type       TEXT NOT NULL,
  payload          JSONB NOT NULL,
  signature_verified BOOLEAN NOT NULL,
  status           TEXT NOT NULL,           -- 'RECEIVED'/'PROCESSING'/'PROCESSED'/'FAILED'
  attempts         INT NOT NULL DEFAULT 0,
  last_error       TEXT,
  received_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  processed_at     TIMESTAMPTZ,
  PRIMARY KEY (provider, event_id)
);
```

### 5.3 升级/降级按比例计费

升级（如 Pro 月费 $20 → Business 月费 $50）：
- 当期已支付 $20 中未使用部分按比例退抵
- 立即扣 ($50 - 未用部分) 差额
- 套餐立即生效

降级：
- 当期继续 Pro
- 下个周期切 Business 配额

### 5.4 续费失败处理

```
T+0: 自动扣款失败
T+0: 通知用户 + 进入 PAST_DUE
T+1, T+3, T+5: Stripe 重试
T+5: 通知再次（升级提醒）
T+7: 进入 CANCELED；降级到 free 套餐
     - 数据保留 90 天（lifecycle）
     - 用户重新付款 90 天内可恢复
```

## 6. 私有化模式

### 6.1 实施流程

```
1. 销售签合同 → 产生套餐 / 配额 / 续费日期
2. SRE 用「私有化部署初始化」工具录入：
   - 创建 billing.subscription (mode=offline_contract, payment_method=offline)
   - 创建 billing.plan（如未存在）
   - 写入 billing.quota
3. 系统按月生成对账报告（PDF + Excel）
4. 续费走线下合同 → SRE 手动延期 subscription
```

### 6.2 对账报告

每月 1 号自动生成上月：
- 用量明细（按 quota_dim 聚合）
- 与合同套餐对比
- 超额部分（如有）
- 发票 PDF（用 `ChinaElectronicInvoiceGenerator` 开增值税发票）

发送给客户合规联系人。

### 6.3 与 SaaS 模式的代码共用

- 99% 业务逻辑共享
- 区别仅在 `PaymentProvider` 注入：私有化注入 `OfflineProvider`（直接返回 success）
- 对账报告 = 标准 invoice 生成 + 不走支付确认

## 7. 配额熔断

### 7.1 SDK

```python
from foundation_billing import BillingClient

client = BillingClient.from_env()

# 1. 扣减前检查（同步）
try:
    client.quota.consume(
        quota_dim="llm_token_count",
        amount=1500,
        source_service="llm-gateway",
        source_event_id="req_01J7XYZ",   # 幂等键
        metadata={"model": "claude-sonnet-4", "user_id": "usr_alice"},
    )
except QuotaExceeded as e:
    # 业务层拒绝调用
    raise HTTPException(429, e.detail)

# 2. 查剩余配额
remaining = client.quota.get_remaining(
    tenant_id="tnt_a",
    quota_dim="llm_token_count",
)

# 3. 管理员手动调整（走审批）
client.quota.adjust(
    tenant_id="tnt_a",
    quota_dim="seat_count",
    new_hard_limit=200,
    reason="upgrade temp",
)
```

### 7.2 阈值告警

- 80% → 通知租户管理员
- 90% → 通知管理员 + 业务负责人
- 100% (soft) → 同上 + 业务层友好提示
- 100% (hard) → 阻断 + audit + 强制告警

## 8. API 表面

| Method | Path | 说明 |
|---|---|---|
| GET | `/api/billing/v1/plans` | 套餐列表 |
| POST | `/api/billing/v1/subscriptions` | 创建订阅（含试用） |
| GET | `/api/billing/v1/subscriptions/{id}` | 详情 |
| POST | `/api/billing/v1/subscriptions/{id}/upgrade` | 升级 |
| POST | `/api/billing/v1/subscriptions/{id}/downgrade` | 降级（下周期生效） |
| POST | `/api/billing/v1/subscriptions/{id}/cancel` | 取消 |
| POST | `/api/billing/v1/subscriptions/{id}/pause` | 暂停 |
| POST | `/api/billing/v1/subscriptions/{id}/resume` | 恢复 |
| GET | `/api/billing/v1/invoices` | 发票列表 |
| GET | `/api/billing/v1/invoices/{id}` | 详情 + PDF link |
| POST | `/api/billing/v1/invoices/{id}/refund` | 退款 |
| GET | `/api/billing/v1/quotas` | 配额 + 当前用量 |
| POST | `/api/billing/v1/quotas/check` | SDK 内部调用 |
| POST | `/api/billing/v1/quotas/consume` | SDK 内部调用 |
| POST | `/api/billing/v1/webhooks/stripe` | Stripe webhook 入口 |
| POST | `/api/billing/v1/webhooks/alipay` | 支付宝 webhook |

## 9. 与其他模块集成

| 模块 | 集成 |
|---|---|
| **identity** | seat_count 配额按租户 active user 计 |
| **org** | 团队人数变化触发 seat_count 重算 |
| **authz** | 套餐 features 控制功能开关（与 feature-flag 协作） |
| **audit** | 所有计费事件（订阅 / 退款 / 配额变更 / 发票）必审 |
| **notification** | 配额告警 / 续费失败 / 发票生成 |
| **lifecycle** | 取消订阅 → 数据保留 90d → 清除 |
| **dlp** | 跨境支付场景需查 dlp（如发票含 PII） |
| **llm-gateway** | token 用量上报 (`source_service='llm-gateway'`) |
| **sandbox**（B 阶段） | session 用量上报 |
| **storage** | storage_gb 用量定期采集 |
| **compliance** | 跨境支付需查 compliance.cross_border 是否合规 |

## 10. 错误码

| code | HTTP |
|---|---|
| `FOUNDATION.BILLING.QUOTA.EXCEEDED` | 429 |
| `FOUNDATION.BILLING.QUOTA.SOFT_LIMIT_REACHED` | 200 (warning) |
| `FOUNDATION.BILLING.SUBSCRIPTION.NOT_FOUND` | 404 |
| `FOUNDATION.BILLING.SUBSCRIPTION.INVALID_STATE_TRANSITION` | 409 |
| `FOUNDATION.BILLING.PAYMENT.FAILED` | 402 |
| `FOUNDATION.BILLING.PAYMENT.GRACE_PERIOD_EXPIRED` | 402 |
| `FOUNDATION.BILLING.WEBHOOK.SIGNATURE_INVALID` | 401 |
| `FOUNDATION.BILLING.WEBHOOK.REPLAY_DETECTED` | 409 |
| `FOUNDATION.BILLING.INVOICE.GENERATION_FAILED` | 500 |
| `FOUNDATION.BILLING.INVOICE.ALREADY_PAID` | 409 |
| `FOUNDATION.BILLING.REFUND.AMOUNT_EXCEEDS_PAID` | 422 |
| `FOUNDATION.BILLING.COMPLIANCE.CROSS_BORDER_BLOCKED` | 403 |

## 11. 部署形态

| 形态 | mode | webhook ingress | 发票生成器 |
|---|---|---|---|
| small | private (default) | 不暴露 | Basic (PDF) |
| medium | private 或 saas | + WAF | + 中国电子发票 |
| large / SaaS | saas | + WAF + DDoS + 多 AZ | + Stripe Tax + 中国电子发票 |

## 12. 性能与容量

| 接口 | 目标 |
|---|---|
| `quota.check` | < 5ms（Redis 缓存） |
| `quota.consume` | < 20ms（含 DB 写 + Redis 更新） |
| 续费定时任务 | 每天 02:00；1w 订阅 < 5 min |
| Webhook 处理 | P95 < 500ms |
| 发票 PDF 生成 | < 5s |
| ClickHouse usage 写入 | 10w/s |

## 13. 待解决问题

| # | 问题 | 决策 |
|---|---|---|
| 1 | 退款部分 vs 全额 | v1 仅全额退款；部分退款 v1.1 |
| 2 | 中国电子发票接口（航发 / 百望）选哪家 | 视客户已有接入；本模块抽象 ChinaElectronicInvoiceProvider 接口 |
| 3 | 跨币种结算 | v1 仅同币种；多币种需 Stripe Multi-Currency 或自有汇率服务 |
| 4 | 套餐升级时长在 dunning 中触发 | 拒绝升级直到 dunning 完成 |
| 5 | usage_record 高频写性能 | Postgres 仅保留 7d；ClickHouse 长期；后台 cron 聚合 quota.current_usage |
| 6 | 续费提前通知用户 | 30/15/7/1 天提前通知，可关闭 |
| 7 | trial 防滥用 | 同 email / 同 IP / 同支付方式限 1 次 trial |
| 8 | 套餐迁移数据搬运（Pro→Business） | 走 lifecycle migration tool；停写 → snapshot → 迁移 → 切流 |
| 9 | 退订客户数据保留期 | 默认 90d；可由客户合规模式延长 |
| 10 | SaaS 模式 GDPR 出账数据要求 | 发票字段不含敏感 PI；地址可托管在欧洲数据中心 |

## 14. 验证标准（A-M4 出口）

| # | 验证 | 通过 |
|---|---|---|
| 1 | 5 实体 CRUD | 全部 e2e |
| 2 | 私有化模式 | 发票 PDF 生成 + 对账报告月度自动 |
| 3 | SaaS Stripe 全链路 | 创建订阅 → 试用 → 自动续费 → 升级 → 取消 → 退款 |
| 4 | Webhook 验签 | 篡改 signature 拒绝 |
| 5 | Webhook 重放 | 同 event_id 重复 → 仅处理一次 |
| 6 | Webhook 异步 | Stripe 推送 → 我方 ack < 500ms |
| 7 | 配额熔断 | 超 hard_limit → SDK 抛异常 |
| 8 | 配额幂等 | 同 source_event_id 重复 consume → 仅计一次 |
| 9 | 续费失败 grace | 7 天后自动降 free |
| 10 | 升级按比例 | 中途升级 → 差额计算正确 |
| 11 | 国内电子发票 | 调航发 / 百望测试环境 → 开票成功 |
| 12 | RLS | 跨租户查询 invoice / subscription 失败 |
| 13 | 审计 | 所有事件落 audit |
| 14 | 性能 | 1w 订阅每日续费 < 5 min |
| 15 | 模式切换 | 同一租户 private → saas 切换可测（手工） |

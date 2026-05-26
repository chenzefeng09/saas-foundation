# Notification 详细设计 v1

> 通知中心。统一收口业务/底座所有事件 → 多通道（邮件、Webhook、WebSocket、钉钉、飞书、企业微信、短信、App Push）+ 模板 + 订阅 + i18n + 重试 + 投递审计。

| 字段 | 值 |
|---|---|
| 状态 | Draft v1 |
| Owner | Foundation 后端 |
| 实施 milestone | A-M3 |
| 相关文档 | identity / authz / audit / lifecycle |

## 0. TL;DR

- **8 个通道**：email / webhook / websocket / 钉钉 / 飞书 / 企业微信 / 短信 / app-push（v1 全部 ChannelAdapter 接口统一）
- **模板**：Jinja2 + i18n（zh-CN/en-US/ja-JP），租户可覆盖
- **订阅**：3 级（租户默认 / 角色 / 个人）+ 静音时段（quiet hours） + 摘要（digest）
- **可靠性**：outbox + 异步 worker + 指数退避重试（最多 8 次）+ DLQ + 投递审计
- **背压**：每租户每通道限流（默认 100/min）+ 全局熔断

## 1. Context

- 底座 18 个 package 全部需要通知能力（密码重置、权限变更、配额告警、合规告警、DSAR SLA、备份失败 …）
- 业务层未来也通过同一 SDK 发，避免每个 service 自己接 SMTP/钉钉
- 私有化客户多用钉钉/飞书；SaaS 海外客户多用邮件/Slack；通道差异 ≠ 业务差异

## 2. 模型

### 2.1 核心实体

```
Notification (一次通知请求)
   ├─ event_type: "foundation.identity.password_reset"
   ├─ context: {...}                     # 模板上下文
   ├─ recipients: [user_id...] | [topic] # 显式收件人 or 主题广播
   ├─ priority: low/normal/high/urgent
   └─ tenant_id
        │
        ▼
   Subscription 解析（订阅引擎）
        │
        ├─ 默认订阅（事件 → 角色）
        ├─ 角色订阅（admin 全收）
        ├─ 个人订阅（用户可订/退订）
        └─ 静音时段 / 摘要合并
        │
        ▼
   per-channel Delivery 任务（一个收件人 × 一个通道 = 一条 Delivery）
        │
        ▼
   ChannelAdapter.send() （retry + DLQ）
        │
        ▼
   DeliveryReceipt（成功/失败/打开/点击）
```

### 2.2 事件命名

遵守 CONVENTIONS §9.2 四段格式 `foundation.<service>.<entity>.<action>`：
- `foundation.identity.user.password_reset_requested`
- `foundation.billing.quota.exceeded`
- `foundation.audit.integrity.check_failed`
- `foundation.lifecycle.resource.scheduled_for_destruction`
- `app.workflow.task.assigned`（业务层同款四段）

事件 schema 注册到 `notification.event_definition` 表，含 i18n 模板 + 默认订阅规则。

## 3. SDK

```python
from foundation_notification import NotificationClient

client = NotificationClient.from_env()

# 1. 发送（最常用）
client.send(
    event_type="foundation.identity.user.password_reset_requested",
    recipients=["usr_01J7ABC"],
    context={
        "user_name": "Alice",
        "reset_link": "https://app.example.com/reset?token=xxx",
        "ttl_minutes": 15,
    },
    priority="high",
)

# 2. 广播到主题
client.send_to_topic(
    event_type="foundation.system.maintenance.scheduled",
    topic="admins",                     # 解析为所有 admin 角色用户
    context={"window": "2026-06-01 02:00-04:00 UTC"},
)

# 3. 订阅管理（用户控制台用）
client.subscriptions.subscribe(
    user_id="usr_01J7ABC",
    event_type="foundation.billing.quota.warning_80",
    channels=["email", "dingtalk"],
)
client.subscriptions.unsubscribe(user_id="usr_01J7ABC", event_type="...")

# 4. 投递查询
status = client.deliveries.get(delivery_id="dlv_01J7XYZ")
# → {status: 'delivered', delivered_at: ..., opened_at: ...}
```

## 4. ChannelAdapter 接口

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass

@dataclass
class RenderedMessage:
    subject: str | None
    body_text: str
    body_html: str | None
    attachments: list[Attachment]
    metadata: dict                       # 通道特定字段，如钉钉 msgtype

@dataclass
class DeliveryResult:
    status: str                          # 'delivered' / 'failed' / 'rejected' / 'rate_limited'
    channel_message_id: str | None
    error_code: str | None
    error_msg: str | None
    retry_after_sec: int | None          # 适配器建议的重试间隔（限流场景）

class ChannelAdapter(ABC):
    channel_name: str

    @abstractmethod
    def validate_recipient(self, recipient_addr: str) -> bool: ...

    @abstractmethod
    def render(self, template_id: str, context: dict, locale: str) -> RenderedMessage: ...

    @abstractmethod
    def send(self, recipient: Recipient, message: RenderedMessage) -> DeliveryResult: ...

    @abstractmethod
    def health(self) -> bool: ...

    # 可选
    def parse_callback(self, raw_payload: bytes) -> CallbackEvent | None:
        """处理三方 webhook 回调（打开 / 点击 / 退订）"""
        return None
```

### 4.1 内置适配器矩阵

| 通道 | recipient_addr 格式 | 模板格式 | 三方 SDK | 限流默认 |
|---|---|---|---|---|
| email | RFC 5322 | subject + text + html | `aiosmtplib` + AWS SES / 阿里云 DM | 100/min/租户 |
| webhook | URL + HMAC secret | JSON | httpx | 200/min |
| websocket | user_id (BFF push) | JSON | redis pubsub | 1000/min |
| dingtalk | user_id / 群机器人 token | markdown + actionCard | 钉钉 OAPI v2 | 60/min（钉钉硬限） |
| feishu | user_id / 群机器人 token | rich_text + card | 飞书 Open API | 100/min |
| wecom（企业微信） | user_id / 群机器人 token | text + markdown | 企微 API | 60/min |
| sms | E.164 phone | text ≤ 70 chars | 阿里云 SMS / Twilio | 1/min/号码 |
| app_push | device_token | title + body + data | FCM / APNs | 1000/min |

### 4.2 钉钉 / 飞书机器人 vs 个人消息

| 模式 | 鉴权 | 限流 | 用途 |
|---|---|---|---|
| 群机器人 | webhook url + secret | 钉钉 20/min；飞书 100/min | 系统类告警（全员可见） |
| 个人 IM | 企业 access_token + user_id | 钉钉 60/min；飞书 100/min | 个人通知（密码、审批） |

适配器内部按 `recipient.type` 自动分流。

## 5. 模板引擎

### 5.1 存储

```
notification.template
├─ template_id: "foundation.identity.password_reset"
├─ channel: "email" | "dingtalk" | ...
├─ locale: "zh-CN" | "en-US" | "ja-JP"
├─ subject_tpl: "...{{user_name}}..."
├─ body_text_tpl: Jinja2
├─ body_html_tpl: Jinja2 (email only)
├─ extras: JSONB                         # 通道扩展（如钉钉 actionCard buttons）
└─ version: int
```

- 全局基线模板（`tenant_id = '__global__'`）
- 租户覆盖（`tenant_id = 'tnt_a'`）→ 优先于全局
- 编辑流程：管理员上传 → dry-run preview → 灰度（10%）→ 全量

### 5.2 i18n

- 用户 `locale` 决定模板选择
- 缺该语言的模板自动 fallback 到租户默认 → 全局默认（en-US）
- Jinja2 自定义 filter：`{{amount | currency(locale)}}`、`{{ts | datetime(locale, tz)}}`

### 5.3 渲染安全

- Jinja2 sandbox 环境（禁 `{{ ... }}` 调任意 Python）
- HTML 输出自动转义；模板作者主动用 `{{ ... | safe }}` 才不转义
- HTML 邮件经 `bleach` whitelist 二次过滤

## 6. 订阅引擎

### 6.1 三级解析

```
解析顺序（高 → 低）：
1. 用户个人订阅（明确订 or 退订）
2. 角色订阅（admin / owner / member 默认订阅哪些事件）
3. 事件定义 default_recipients（如 audit.integrity_failed → security-admin role）
```

每级按 (event_type, channel) 维度独立决策；通道并集。

### 6.2 静音时段（quiet hours）

```
user_preference:
  quiet_hours:
    timezone: "Asia/Shanghai"
    windows:
      - {days: [Mon-Fri], from: "22:00", to: "08:00"}
      - {days: [Sat,Sun], all_day: true}
  exceptions:
    - priority: "urgent"     # urgent 不静音
```

落到 quiet hour 内的 normal / low 通知 → 加入 digest 队列；urgent 直发。

### 6.3 摘要（digest）

- 频率：hourly / daily / weekly
- 触发：static cron + 强制 flush（队列长度阈值）
- 模板：`notification.email_digest`（汇总 list）

## 7. 数据模型

```sql
-- 1. 事件定义
CREATE TABLE notification.event_definition (
  tenant_id        TEXT NOT NULL,
  event_type       TEXT NOT NULL,
  title            TEXT NOT NULL,
  description      TEXT,
  priority_default TEXT NOT NULL DEFAULT 'normal',
  default_channels TEXT[] NOT NULL,
  default_audience JSONB,                  -- {roles: [...], topics: [...]}
  category         TEXT,                   -- security/billing/system/business
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, event_type)
);

-- 2. 模板
CREATE TABLE notification.template (
  tenant_id        TEXT NOT NULL,
  template_id      TEXT NOT NULL,
  event_type       TEXT NOT NULL,
  channel          TEXT NOT NULL,
  locale           TEXT NOT NULL,
  subject_tpl      TEXT,
  body_text_tpl    TEXT NOT NULL,
  body_html_tpl    TEXT,
  extras           JSONB,
  version          INT NOT NULL DEFAULT 1,
  status           TEXT NOT NULL DEFAULT 'active',
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, template_id, channel, locale, version)
);

-- 3. 用户订阅
CREATE TABLE notification.user_subscription (
  tenant_id        TEXT NOT NULL,
  user_id          TEXT NOT NULL,
  event_type       TEXT NOT NULL,
  channel          TEXT NOT NULL,
  subscribed       BOOLEAN NOT NULL,        -- false = 显式退订
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, user_id, event_type, channel)
);

-- 4. 通知请求（outbox）
CREATE TABLE notification.outbox (
  tenant_id        TEXT NOT NULL,
  notification_id  TEXT NOT NULL,
  event_type       TEXT NOT NULL,
  context          JSONB NOT NULL,
  recipients       JSONB NOT NULL,          -- [{user_id|topic|raw_addr, ...}]
  priority         TEXT NOT NULL,
  status           TEXT NOT NULL DEFAULT 'pending',  -- pending/resolved/dispatched
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, notification_id)
);
CREATE INDEX idx_outbox_pending ON notification.outbox(status, created_at) WHERE status='pending';

-- 5. 每个 (收件人 × 通道) Delivery
CREATE TABLE notification.delivery (
  tenant_id            TEXT NOT NULL,
  delivery_id          TEXT NOT NULL,
  notification_id      TEXT NOT NULL,
  user_id              TEXT,
  channel              TEXT NOT NULL,
  recipient_addr       TEXT NOT NULL,
  template_id          TEXT NOT NULL,
  locale               TEXT NOT NULL,
  status               TEXT NOT NULL,         -- queued/sending/delivered/failed/dlq
  attempt              INT NOT NULL DEFAULT 0,
  next_retry_at        TIMESTAMPTZ,
  last_error           TEXT,
  channel_message_id   TEXT,
  delivered_at         TIMESTAMPTZ,
  opened_at            TIMESTAMPTZ,
  clicked_at           TIMESTAMPTZ,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, delivery_id)
);
CREATE INDEX idx_delivery_retry ON notification.delivery(status, next_retry_at)
  WHERE status IN ('queued','failed') AND next_retry_at IS NOT NULL;

-- 6. 用户偏好
CREATE TABLE notification.user_preference (
  tenant_id        TEXT NOT NULL,
  user_id          TEXT NOT NULL,
  locale           TEXT NOT NULL DEFAULT 'zh-CN',
  timezone         TEXT NOT NULL DEFAULT 'Asia/Shanghai',
  quiet_hours      JSONB,
  digest_frequency TEXT,                     -- 'hourly'/'daily'/'weekly'/null
  channels_disabled TEXT[] NOT NULL DEFAULT '{}',
  PRIMARY KEY (tenant_id, user_id)
);

-- 7. 通道凭据（per-tenant）
CREATE TABLE notification.channel_config (
  tenant_id        TEXT NOT NULL,
  channel          TEXT NOT NULL,
  enabled          BOOLEAN NOT NULL DEFAULT TRUE,
  config_enc       BYTEA NOT NULL,           -- crypto.encrypt(JSON)
  rate_limit_per_min INT NOT NULL DEFAULT 100,
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, channel)
);
```

RLS 全部强制 tenant_id；template / event_definition 有 `'__global__'` 行（通过 `app_admin` 写入）。

## 8. 投递可靠性

### 8.1 outbox + worker

1. SDK `send()` 写 `notification.outbox`（同业务事务）
2. dispatcher worker（KEDA 触发） pop pending outbox → 订阅解析 → 写 delivery 队列 → 标 outbox dispatched
3. sender worker pool（按 channel 分组）pull delivery → adapter.send() → 更新状态

### 8.2 重试策略

- 指数退避：30s / 1m / 5m / 15m / 1h / 4h / 12h / 24h，共 8 次
- 4xx 错误（recipient 不存在 / 模板无效）→ 不重试，直接 DLQ
- 5xx / 限流 / 网络 → 重试
- adapter 返回 `retry_after_sec` → 优先用该值

### 8.3 DLQ + 人工介入

- 8 次失败 → `status='dlq'`
- 安全管理员控制台「失败通知」页面 → 可手动 re-queue / 标 ignore
- DLQ 老化 30 天后归档（写 ClickHouse 长保留，主表删除）

### 8.4 幂等

- 业务层调 `send()` 可带 `idempotency_key`（如 password_reset_token id）
- 24h 窗口内重复 key → 直接返回原 notification_id

## 9. 与其他模块集成

| 模块 | 触发事件 |
|---|---|
| identity | `user.password_reset_requested` / `user.login_unusual` / `user.mfa_enrolled` / `user.emergency_freeze` |
| authz | `role.granted` / `role.revoked` / `policy.changed` |
| audit | `integrity.check_failed` / `worm.object_locked` / `signing_key.rotated` |
| billing | `quota.warning_80` / `quota.exceeded` / `subscription.renewal_failed` |
| lifecycle | `resource.retention_due` / `resource.legal_hold_set` / `resource.destruction_completed` |
| dlp | `scan.match_high` / `external_send.blocked` / `clearance.insufficient_repeated` |
| compliance | `dsar.received` / `dsar.due_in_7d` / `cross_border.violation` |
| pam | `elevation.requested` / `elevation.approval_pending` |
| security-ops | `vulnerability.sla_breach` / `incident.critical` |

> 完整事件 type：`foundation.<service>.<entity>.<action>`，如 `foundation.identity.user.password_reset_requested`

## 10. 部署形态

| 形态 | dispatcher | sender pool | DLQ UI |
|---|---|---|---|
| small | 1 实例 | 1 per channel | 无 UI，仅 API |
| medium | 3 实例（HA） | 3-10 per channel | 控制台 |
| large | 5-20（KEDA） | 10-100 per channel（KEDA） | 控制台 + Grafana 面板 |

## 11. 错误码

| code | HTTP |
|---|---|
| `FOUNDATION.NOTIF.EVENT.UNDEFINED` | 400 |
| `FOUNDATION.NOTIF.TEMPLATE.NOT_FOUND` | 404 |
| `FOUNDATION.NOTIF.TEMPLATE.RENDER_FAILED` | 500 |
| `FOUNDATION.NOTIF.CHANNEL.DISABLED` | 503 |
| `FOUNDATION.NOTIF.CHANNEL.RATE_LIMITED` | 429 |
| `FOUNDATION.NOTIF.RECIPIENT.INVALID` | 400 |
| `FOUNDATION.NOTIF.RECIPIENT.UNREACHABLE` | 422 |
| `FOUNDATION.NOTIF.QUIET_HOURS.DEFERRED` | 202 |
| `FOUNDATION.NOTIF.IDEMPOTENCY.DUPLICATE` | 409 |

## 12. 性能与容量

| 指标 | 目标 |
|---|---|
| SDK `send()` P95 | < 20ms（仅写 outbox） |
| 端到端延迟（email） | < 30s |
| 端到端延迟（钉钉/飞书） | < 5s |
| dispatcher 吞吐 | 1000 outbox/sec/实例 |
| 每租户配额 | 10k 通知/h（可调） |

## 13. 待解决问题

| # | 问题 | 决策 |
|---|---|---|
| 1 | 群机器人 token 泄漏风险 | 凭据加密 + 仅安全管理员可看；webhook 校验 sign 防伪造 |
| 2 | 钉钉/飞书 access_token 24h 过期 | 单独 token-refresh worker，提前 10min 刷新；本地缓存 |
| 3 | digest 何时触发 flush | cron 每小时 + 队列超 100 条强制 flush |
| 4 | 通知风暴（如审计告警全员） | 全局熔断 + 自动合并相同 event_type 1min 窗口 |
| 5 | unsubscribe 链接（邮件） | 模板自动注入 unsubscribe URL（带签名 token） |
| 6 | 跨租户广播（如平台公告） | 走 `__global__` template；recipients 用特殊主题 `__all_tenants__` + 安全管理员特批 |
| 7 | App push 设备绑定 | identity 加 `user_device` 表；本模块订阅 |
| 8 | SMS 成本控制 | 仅 priority=urgent 默认走 SMS；其他需显式订阅 |

## 14. 验证标准（A-M3 出口）

| # | 验证 | 通过 |
|---|---|---|
| 1 | 8 通道 e2e | 每通道发 1 条收到 |
| 2 | 重试 | 模拟 5xx，到第 5 次成功；DLQ 模拟到第 8 次 |
| 3 | 幂等 | 同 idempotency_key 24h 内只发 1 条 |
| 4 | 订阅 | 用户退订 → 后续不收到 |
| 5 | 静音时段 | 22:00 normal 通知 → 入 digest；urgent 仍发 |
| 6 | i18n | en-US 用户收到英文；缺翻译 fallback 默认语言 |
| 7 | 模板灰度 | 新版本 10% 流量；监控错误率回滚 |
| 8 | 限流 | 钉钉 60/min 上限测试 → rate_limited + retry_after |
| 9 | RLS | 跨租户查 delivery 失败 |
| 10 | 压测 | 1000 outbox/s 稳定；端到端 P95 < 30s |

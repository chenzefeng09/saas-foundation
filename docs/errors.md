# 错误码与错误处理规范

> 配套 [CONVENTIONS.md](./CONVENTIONS.md) §4。所有底座 service 和业务层必须遵守。

---

## 1. 设计原则

1. **机器可读 + 人可读双轨**：错误码给客户端代码判定；message 给开发者看；user_message 给终端用户看（i18n）
2. **稳定契约**：错误码一旦发布不可改语义；只可新增
3. **不泄露内部细节**：用户面错误不暴露 stack trace、内部路径、SQL、密钥片段
4. **可追溯**：每个错误带 `request_id`，便于日志关联
5. **可分类**：错误码自带 service + category 信息，便于监控告警按维度分组

---

## 2. 错误响应格式（RFC 9457 Problem Details）

### 2.1 标准响应体

`Content-Type: application/problem+json`

```json
{
  "type": "https://errors.foundation.example.com/identity/auth/invalid-credentials",
  "title": "Invalid credentials",
  "status": 401,
  "code": "FOUNDATION.IDENTITY.AUTH.INVALID_CREDENTIALS",
  "detail": "The provided email or password is incorrect.",
  "user_message": "邮箱或密码不正确，请重试。",
  "instance": "/api/identity/v1/sessions",
  "request_id": "req_01J5XXXXX",
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "timestamp": "2026-05-22T10:00:00Z",
  "errors": null,
  "retry_after": null,
  "help_url": null
}
```

### 2.2 字段说明

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `type` | string (URI) | 是 | 错误码对应的文档 URL（即使页面尚不存在也保留 URI） |
| `title` | string | 是 | 简短英文标题，固定值（同一 code 对应同一 title） |
| `status` | int | 是 | HTTP 状态码（与响应头一致） |
| `code` | string | 是 | **机器可读错误码**，格式见 §3 |
| `detail` | string | 是 | 给开发者的英文详细描述；可含动态变量；不可含敏感数据 |
| `user_message` | string | 否 | 给终端用户的本地化消息；按 `Accept-Language` 翻译 |
| `instance` | string | 是 | 触发错误的请求路径（不含 host） |
| `request_id` | string | 是 | 请求 ID（链路追踪用） |
| `trace_id` | string | 否 | OTel trace ID（若开启 trace） |
| `timestamp` | string | 是 | ISO 8601 UTC |
| `errors` | array | 否 | 字段级错误（用于表单校验，见 §6） |
| `retry_after` | int / null | 否 | 建议客户端等待秒数（限流、临时不可用） |
| `help_url` | string / null | 否 | 帮助文档 URL |

### 2.3 HTTP 响应头

```
HTTP/1.1 401 Unauthorized
Content-Type: application/problem+json
X-Request-Id: req_01J5XXXXX
WWW-Authenticate: Bearer realm="foundation", error="invalid_token"
```

- 限流场景额外带：`Retry-After: 60` + `X-RateLimit-Limit` / `X-RateLimit-Remaining` / `X-RateLimit-Reset`

---

## 3. 错误码命名规范

### 3.1 格式

```
FOUNDATION.<SERVICE>.<CATEGORY>.<NAME>
```

- **前缀** `FOUNDATION.`：固定，区分业务层错误（业务层用 `BUSINESS.` 或自定义前缀）
- **SERVICE**：能力名大写，对应 `<capability>`，例 `IDENTITY` / `AUTHZ` / `BILLING`
- **CATEGORY**：错误类别（见 §3.2 标准类别）
- **NAME**：具体错误名，`UPPER_SNAKE_CASE`，动词短语或名词短语

例子：
- `FOUNDATION.IDENTITY.AUTH.INVALID_CREDENTIALS`
- `FOUNDATION.AUTHZ.POLICY.PERMISSION_DENIED`
- `FOUNDATION.BILLING.QUOTA.EXCEEDED`
- `FOUNDATION.AUDIT.STORAGE.WORM_VIOLATION`
- `FOUNDATION.CRYPTO.KEY.NOT_FOUND`

### 3.2 标准 CATEGORY

| Category | 含义 | 典型 HTTP |
|---|---|---|
| `AUTH` | 认证（你是谁） | 401 |
| `POLICY` | 授权（你能不能做） | 403 |
| `INPUT` | 入参校验失败 | 400 |
| `RESOURCE` | 资源不存在 / 冲突 | 404 / 409 |
| `STATE` | 状态机错误（如已删除/已锁定） | 409 |
| `QUOTA` | 配额超限 | 429 |
| `RATE_LIMIT` | 速率限制 | 429 |
| `DEPENDENCY` | 依赖服务故障 | 502 / 503 / 504 |
| `STORAGE` | 存储层错误（DB / S3 / 队列） | 500 / 503 |
| `CONFIG` | 配置错误 | 500 |
| `CRYPTO` | 密码学操作失败 | 500 |
| `COMPLIANCE` | 合规策略阻断（DLP / 跨境 / 分级） | 403 |
| `INTEGRATION` | 第三方集成失败（SSO / 支付 / SCIM） | 502 |
| `INTERNAL` | 未分类内部错误（fallback） | 500 |

---

## 4. HTTP 状态码语义（强制）

| 状态码 | 用途 | 错误码示例 |
|---|---|---|
| **400** Bad Request | 入参格式错、类型错、范围错 | `FOUNDATION.*.INPUT.INVALID_FORMAT` |
| **401** Unauthorized | 未认证 / token 失效 / token 缺失 | `FOUNDATION.IDENTITY.AUTH.*` |
| **403** Forbidden | 已认证但无权限 / 合规阻断 | `FOUNDATION.AUTHZ.POLICY.*` / `FOUNDATION.*.COMPLIANCE.*` |
| **404** Not Found | 资源不存在 | `FOUNDATION.*.RESOURCE.NOT_FOUND` |
| **405** Method Not Allowed | 方法不支持 | （框架自动） |
| **406** Not Acceptable | Accept header 不支持 | （框架自动） |
| **409** Conflict | 资源冲突 / 状态机错 | `FOUNDATION.*.RESOURCE.ALREADY_EXISTS` / `FOUNDATION.*.STATE.*` |
| **410** Gone | 资源永久删除 | `FOUNDATION.*.RESOURCE.GONE` |
| **412** Precondition Failed | If-Match 失败（乐观锁） | `FOUNDATION.*.STATE.STALE_VERSION` |
| **413** Payload Too Large | 请求体过大 | `FOUNDATION.*.INPUT.PAYLOAD_TOO_LARGE` |
| **415** Unsupported Media Type | Content-Type 不支持 | （框架自动） |
| **422** Unprocessable Entity | 语义校验失败（业务规则不满足） | `FOUNDATION.*.INPUT.SEMANTIC_INVALID` |
| **429** Too Many Requests | 限流 / 配额 | `FOUNDATION.*.QUOTA.*` / `FOUNDATION.*.RATE_LIMIT.*` |
| **500** Internal Server Error | 未预期错误 | `FOUNDATION.*.INTERNAL.UNEXPECTED` |
| **502** Bad Gateway | 下游服务错误 | `FOUNDATION.*.DEPENDENCY.*` |
| **503** Service Unavailable | 服务暂不可用 / 维护 | `FOUNDATION.*.DEPENDENCY.UNAVAILABLE` |
| **504** Gateway Timeout | 下游服务超时 | `FOUNDATION.*.DEPENDENCY.TIMEOUT` |

**禁止**：
- 用 200 + body code 表达错误（除非客户端是不支持 HTTP 状态的远古系统）
- 把 401 / 403 / 404 笼统合并成"权限错误"
- 把 500 当 catch-all（必须区分内部错 vs 下游错 vs 配置错）

### 4.1 401 vs 403 区分
- **401**：你**没说你是谁** / 你说的身份**无效或过期** → 客户端应跳登录
- **403**：你**说了你是谁**但**没权限** → 客户端不应跳登录

### 4.2 404 vs 403 区分
- 资源**不存在** → 404
- 资源**存在但无权限**（且暴露存在与否本身也是泄露） → 也返 404（不返 403）防越权探测
- 资源**存在且无权限**（且存在与否是公开的） → 403

---

## 5. 错误码注册与生命周期

### 5.1 注册
- 每个 service 在 `src/foundation_<svc>/errors.py` 集中声明本服务所有错误码
- 跨服务共用错误码放 `packages/_shared/foundation/errors/`
- 必须填：`code` / `http_status` / `title` / `default_detail` / `default_user_message` / `created_at`
- 注册时 CI 校验：code 唯一、命名合规、有 i18n 翻译

### 5.2 文档生成
- 从 `errors.py` 自动生成 `/api/<svc>/v1/errors.json` 文档端点
- 也生成 markdown 表附到 service README

### 5.3 生命周期
- 新增：随时
- 改 `default_detail` / `default_user_message`：允许（属于翻译/文案）
- 改 `code` / `http_status` / `title`：**禁止**（破坏契约）
- 废弃：标记 `deprecated_since` → 6 月后才能删 + ADR 记录

---

## 6. 字段级错误（表单校验）

入参校验失败时，`errors` 字段列出每个字段的问题：

```json
{
  "type": "https://errors.foundation.example.com/_/input/validation-failed",
  "title": "Validation failed",
  "status": 422,
  "code": "FOUNDATION._.INPUT.VALIDATION_FAILED",
  "detail": "Input validation failed for 2 fields.",
  "instance": "/api/identity/v1/users",
  "request_id": "req_01J5XXXXX",
  "timestamp": "2026-05-22T10:00:00Z",
  "errors": [
    {
      "field": "email",
      "code": "INVALID_EMAIL_FORMAT",
      "detail": "Must be a valid RFC 5322 email address.",
      "user_message": "邮箱格式不正确。"
    },
    {
      "field": "password",
      "code": "PASSWORD_TOO_WEAK",
      "detail": "Password must be at least 12 chars and contain upper/lower/digit/symbol.",
      "user_message": "密码至少 12 位，需包含大小写、数字和特殊符号。"
    }
  ]
}
```

字段路径用 JSON Pointer：`field: "/items/0/email"`、`field: "/metadata/region"`。

---

## 7. 跨服务错误传播

### 7.1 上游服务调下游
- 调用方收到下游错误**不直接透传**，而是包装为本服务的 `DEPENDENCY` 错误
- 例：`identity-service` 调 `crypto-service` 失败：
  ```
  502 FOUNDATION.IDENTITY.DEPENDENCY.CRYPTO_FAILED
  detail: "Failed to verify password hash: crypto service returned 503"
  caused_by: { code: "FOUNDATION.CRYPTO.DEPENDENCY.UNAVAILABLE", request_id: "req_xxx" }
  ```
- `caused_by` 是可选字段，方便排障；线上可用 feature flag 控制是否暴露

### 7.2 客户端 SDK 行为
- SDK 自动把错误响应反序列化为 `FoundationError` 异常子类
- 异常类按 service 分包：`from foundation_identity.errors import InvalidCredentialsError`
- 业务层 catch 时优先 catch 具体子类，避免 catch 基类

### 7.3 重试策略（SDK 默认）
| 错误类别 | 重试 | 策略 |
|---|---|---|
| `AUTH` | 否 | 立即报错 |
| `POLICY` / `INPUT` / `RESOURCE` | 否 | 立即报错 |
| `QUOTA` / `RATE_LIMIT` | 是 | 等 `Retry-After`，最多 1 次 |
| `DEPENDENCY` 5xx | 是 | 指数退避 + 抖动，最多 3 次 |
| `STORAGE` 503 | 是 | 同上 |
| `INTERNAL` 500 | 否 | 立即报错（避免雪崩） |

---

## 8. 安全约束

- **绝不暴露的内容**（不能出现在 `detail` / `user_message` / `errors`）：
  - 完整 stack trace
  - 文件系统路径
  - SQL 语句
  - 内部 IP / 主机名
  - 密钥 / token / 密码 / hash
  - 第三方账号信息（如 SSO provider 详细返回体）
- **可暴露的内容**：错误码、`request_id`、`trace_id`、稳定的资源 ID、用户已知的输入值
- **CI 检测**：error message 模板必须经过 lint 检查，含 `traceback` / `secret` / `password` 等关键词时阻断

---

## 9. 审计联动

- 所有 `403 POLICY` / `403 COMPLIANCE` / `429 QUOTA` 错误**强制**写审计事件
- 审计事件类型：`foundation.<svc>.error.<category>`，`data` 含 `code`、`user_id`、`resource_id`、`request_id`
- 鉴权失败连续 N 次（默认 5 次 / 5 分钟）触发账号锁定 + 安全告警

---

## 10. 本地化（i18n）

- `user_message` 按 `Accept-Language` 翻译
- 翻译文件位置：`packages/<svc>/src/foundation_<svc>/i18n/<lang>/errors.po`
- 默认语言：`zh-CN`；最低支持：`zh-CN` / `en-US`；客户驱动增 `zh-TW` / `ja-JP` 等
- 缺翻译时回退到 `en-US`，不要回退到空字符串

---

## 11. Python SDK 错误模型示例

```python
# foundation/errors/base.py
class FoundationError(Exception):
    code: str
    http_status: int
    title: str
    detail: str
    user_message: str | None
    request_id: str | None
    trace_id: str | None
    caused_by: "FoundationError | None"
    field_errors: list["FieldError"]
    retry_after: int | None

class AuthError(FoundationError):
    """401 AUTH category"""

class PolicyError(FoundationError):
    """403 POLICY category"""

class QuotaExceededError(FoundationError):
    """429 QUOTA category"""

class DependencyError(FoundationError):
    """502/503/504 DEPENDENCY category"""

# foundation_identity/errors.py
class InvalidCredentialsError(AuthError):
    code = "FOUNDATION.IDENTITY.AUTH.INVALID_CREDENTIALS"
    http_status = 401
    title = "Invalid credentials"
```

---

## 12. 已注册错误码（首版样例，会随各 service 完善）

| Code | HTTP | Title |
|---|---|---|
| `FOUNDATION._.INPUT.VALIDATION_FAILED` | 422 | Validation failed |
| `FOUNDATION._.INPUT.PAYLOAD_TOO_LARGE` | 413 | Payload too large |
| `FOUNDATION._.INPUT.INVALID_PAGINATION` | 400 | Invalid pagination parameters |
| `FOUNDATION._.RESOURCE.NOT_FOUND` | 404 | Resource not found |
| `FOUNDATION._.RESOURCE.ALREADY_EXISTS` | 409 | Resource already exists |
| `FOUNDATION._.STATE.STALE_VERSION` | 412 | Stale version |
| `FOUNDATION._.RATE_LIMIT.EXCEEDED` | 429 | Rate limit exceeded |
| `FOUNDATION._.INTERNAL.UNEXPECTED` | 500 | Unexpected internal error |
| `FOUNDATION._.DEPENDENCY.UNAVAILABLE` | 503 | Dependency unavailable |
| `FOUNDATION._.DEPENDENCY.TIMEOUT` | 504 | Dependency timeout |
| `FOUNDATION.IDENTITY.AUTH.INVALID_CREDENTIALS` | 401 | Invalid credentials |
| `FOUNDATION.IDENTITY.AUTH.TOKEN_EXPIRED` | 401 | Token expired |
| `FOUNDATION.IDENTITY.AUTH.MFA_REQUIRED` | 401 | MFA required |
| `FOUNDATION.IDENTITY.AUTH.ACCOUNT_LOCKED` | 401 | Account locked |
| `FOUNDATION.AUTHZ.POLICY.PERMISSION_DENIED` | 403 | Permission denied |
| `FOUNDATION.AUTHZ.POLICY.TENANT_MISMATCH` | 403 | Tenant mismatch |
| `FOUNDATION.BILLING.QUOTA.EXCEEDED` | 429 | Quota exceeded |
| `FOUNDATION.BILLING.STATE.SUBSCRIPTION_EXPIRED` | 402 | Subscription expired |
| `FOUNDATION.COMPLIANCE.DLP.DOWNLOAD_BLOCKED` | 403 | Download blocked by DLP |
| `FOUNDATION.COMPLIANCE.TRANSFER.CROSS_BORDER_BLOCKED` | 403 | Cross-border transfer blocked |
| `FOUNDATION.AUDIT.STORAGE.WORM_VIOLATION` | 500 | WORM storage violation |
| `FOUNDATION.CRYPTO.KEY.NOT_FOUND` | 404 | Key not found |
| `FOUNDATION.CRYPTO.OPERATION.FAILED` | 500 | Crypto operation failed |
| `FOUNDATION.LLM_GATEWAY.PROVIDER.UNAVAILABLE` | 502 | LLM provider unavailable |
| `FOUNDATION.LLM_GATEWAY.CAPABILITY.NOT_SUPPORTED` | 422 | Required capability not supported |

完整列表随各 service 实现补全，并通过 `/api/<svc>/v1/errors.json` 自动暴露。

---

## 附录：变更记录

| 日期 | 版本 | 变更 |
|---|---|---|
| 2026-05-22 | 0.1.0 | 初版（P0 #1.2） |

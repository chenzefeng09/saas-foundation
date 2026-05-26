# SaaS Foundation — 架构总约定（CONVENTIONS）

> **本文档是底座最重要的契约文档**。所有 package 设计、代码、API、SDK、部署都必须遵守。违反约定的 PR 不予合并。
>
> 变更需经架构师评审（≥2 人 sign-off）并写入 `docs/adr/`。
>
> 配套文档：
> - 错误码规范：[errors.md](./errors.md)
> - OpenAPI 模板：[../contracts/openapi/_template.yaml](../contracts/openapi/_template.yaml)
> - SDK 模板：[../sdks/python/_template/](../sdks/python/_template/)
> - 多租户基线：[multi-tenancy.md](./multi-tenancy.md)（P0 #2 产出）

---

## 1. 服务命名与包结构

### 1.1 服务命名
- 每个能力一个独立 service，命名 `<capability>-service`：`identity-service` / `authz-service` / `org-service` / `billing-service` / `audit-service` / `lifecycle-service` / `notification-service` / `search-service` / `api-platform-service` / `llm-gateway-service` / `feature-flag-service` / `classification-service` / `dlp-service` / `crypto-service` / `compliance-service` / `pam-service` / `data-protection-service` / `security-ops-service`
- 短名（用于路径、镜像、k8s 资源名）取 `<capability>`：`identity` / `authz` / ...
- 不允许在一个 service 里塞多个能力。新能力新 service。

### 1.2 包目录结构（每个 package 一致）

```
packages/<capability>/
├── pyproject.toml                  # Poetry，Python 3.12+
├── README.md                       # 该 service 的 elevator pitch + 启动方式
├── src/foundation_<capability>/
│   ├── __init__.py                 # 暴露 __version__
│   ├── api/                        # FastAPI router（HTTP 入口）
│   │   ├── v1/                     # API 版本目录（一定带 v 前缀）
│   │   └── dependencies.py
│   ├── domain/                     # 领域模型（dataclass / pydantic / SQLModel）
│   ├── services/                   # 业务逻辑（纯 Python，不依赖 FastAPI）
│   ├── adapters/                   # 出站适配器（DB / Keycloak / OPA / Redis / ...）
│   ├── events/                     # 事件定义 + 发布器
│   ├── schemas/                    # pydantic schema（API 入参/出参）
│   ├── config.py                   # 配置（pydantic-settings 读 ENV）
│   ├── observability.py            # OTel 初始化
│   ├── errors.py                   # 服务专属错误码（继承底座基类）
│   └── main.py                     # FastAPI app 工厂
├── migrations/                     # Alembic 数据库迁移
├── tests/
│   ├── unit/
│   ├── integration/
│   └── conftest.py
├── Dockerfile
└── helm/                           # 该 service 的 helm subchart
    ├── Chart.yaml
    ├── values.yaml
    └── templates/
```

**强制原则**：
- `api/` 只做 HTTP 协议适配（解析请求、调 service、返回响应）。**业务逻辑不许写在 router**
- `services/` 不许 import FastAPI / SQLAlchemy 的 Session（通过 adapter 抽象注入）
- `adapters/` 是唯一允许 import 外部组件 SDK 的地方
- `events/` 发出的事件 schema 必须是稳定契约，跨 service 消费

---

## 2. API 设计规范

### 2.1 协议
- **对外**：REST + JSON over HTTPS（默认）；流式场景用 SSE（Server-Sent Events）
- **服务间**：默认 REST；性能敏感路径（authz check、quota check）走 gRPC（`contracts/proto/`）
- **WebSocket**：仅前端推送场景（`notification`），不用于 service 间

### 2.2 URL 路径
```
https://<host>/api/<service>/<version>/<resource>[/<id>][/<sub-resource>]
```
- `<service>`：能力短名，如 `identity`、`authz`、`billing`
- `<version>`：`v1`、`v2`，URL 显式带版本。**不接受 header version**
- `<resource>`：复数小写连字符，如 `users`、`org-units`、`role-bindings`
- 例：`/api/identity/v1/users/{user_id}/sessions`

### 2.3 HTTP 方法
| 方法 | 语义 | 幂等 | 成功状态码 |
|---|---|---|---|
| GET | 查询 | 是 | 200 |
| POST | 创建 / 非幂等操作 | 否 | 201（创建）/ 200（动作） |
| PUT | 全量替换 | 是 | 200 |
| PATCH | 部分更新（JSON Merge Patch RFC 7396） | 是 | 200 |
| DELETE | 删除 | 是 | 204 |

**禁止**：用 POST 做查询、用 GET 做修改、自定义 `/api/identity/v1/users:bulkCreate` 这种 Google 风格 verb。批量操作用 `POST /users/bulk`。

### 2.4 分页（统一）
- 游标分页**默认**：`?cursor=<opaque>&limit=50`，响应 `{"items": [...], "next_cursor": "..."}`，`next_cursor=null` 表示结尾
- 偏移分页**仅历史兼容**：`?offset=0&limit=50`，响应额外带 `total`
- `limit` 默认 50，最大 200，超出返 `400 INVALID_PAGINATION`

### 2.5 过滤、排序、字段选择
- 过滤：`?filter.<field>=<value>`，多值用 `,` 分隔
- 排序：`?sort=<field>` 升序，`?sort=-<field>` 降序，多字段逗号分隔
- 字段选择：`?fields=id,name,email`（减小响应体积）

### 2.6 请求/响应 header（强制）

**入站请求必带**：
| Header | 含义 | 由谁注入 |
|---|---|---|
| `Authorization: Bearer <jwt>` | 用户身份 | 客户端 |
| `X-Request-Id` | 请求链路 ID | 网关补；客户端可带 |
| `X-Tenant-Id` | 租户 ID | 网关从 JWT claim 提取并强制注入（详见第 3 节） |
| `Accept-Language` | 本地化 | 客户端可选 |

**出站响应必带**：
| Header | 含义 |
|---|---|
| `X-Request-Id` | 回显请求 ID |
| `X-Service-Name` | 处理服务名（debug） |
| `X-Service-Version` | 处理服务版本 |
| `Cache-Control` | 缓存策略 |

### 2.7 响应包络
**不使用 `{ code, data, message }` 这种包络**。直接返回资源 JSON。错误走标准错误格式（见 errors.md）。

**单资源**：
```json
{ "id": "usr_xxx", "email": "a@b.com", "created_at": "2026-05-22T10:00:00Z" }
```

**列表**：
```json
{
  "items": [ { ... }, { ... } ],
  "next_cursor": "eyJpZCI6Li4ufQ=="
}
```

### 2.8 时间、ID、命名
- **时间**：一律 ISO 8601 + UTC，例 `2026-05-22T10:00:00Z`。不允许带时区偏移（客户端自己换）
- **ID**：所有 ID 用**类型前缀 + ULID/UUID 编码**，例 `usr_01J...`、`org_01J...`、`tnt_01J...`、`sess_01J...`。便于日志识别、防误用
- **JSON 字段**：一律 `snake_case`（`created_at` 不是 `createdAt`）
- **枚举值**：一律 `UPPER_SNAKE_CASE`，例 `"status": "ACTIVE"`

---

## 3. 租户上下文传递（最重要的约定，错了等于没多租户）

### 3.1 总原则
- **所有 API 调用必须携带 tenant 上下文**（除少数注册/登录前的端点，需在文档显式声明）
- **租户 ID 是认证后强制注入的**，客户端**不能**自由指定 `X-Tenant-Id`；如果带了，必须等于 JWT claim 里的 `tenant_id`，否则拒绝

### 3.2 注入链路
```
浏览器/SDK
   │  Authorization: Bearer <JWT>（claim 含 tenant_id, user_id, roles）
   ▼
API Gateway (Envoy)
   │  - 校验 JWT 签名（Keycloak JWKS）
   │  - 提取 tenant_id 注入 X-Tenant-Id header（覆盖客户端任何值）
   │  - 提取 user_id 注入 X-User-Id
   │  - 注入 X-Request-Id（如果缺失则生成）
   ▼
Service (FastAPI)
   │  - middleware 读 X-Tenant-Id / X-User-Id，构造 TenantContext
   │  - 写入 contextvars.ContextVar（异步友好）
   │  - 所有 DB 连接 acquire 时执行 SET LOCAL app.tenant_id = '<id>'（RLS 生效）
   ▼
Adapters (DB / 其他 service)
   │  - DB query 自动受 RLS policy 过滤
   │  - 调下游 service 时 propagate X-Tenant-Id / X-Request-Id
```

### 3.3 SDK 行为
- 业务层用 SDK 调底座时，SDK **自动从当前请求的 TenantContext** 注入 `X-Tenant-Id`
- 业务层**不允许显式传 `tenant_id` 参数**给 SDK；想跨租户操作的特殊场景必须走 `with sdk.as_tenant("tnt_xxx"):` 显式声明 + 审计

### 3.4 系统内部任务（无用户上下文）
- 后台任务（cron、worker、event consumer）也必须带 tenant 上下文
- 跨租户的系统任务用 `system` tenant + 显式声明 `actor=SYSTEM`

### 3.5 测试约束
- 单元/集成测试必须用 `with tenant_context("tnt_test")` 包裹，禁止裸跑
- CI 静态扫描检测：业务层代码出现 `tenant_id=` 参数直接报错

---

## 4. 错误处理

详见 [errors.md](./errors.md)。本节只列骨架：

- 错误响应符合 [RFC 9457 Problem Details](https://www.rfc-editor.org/rfc/rfc9457)
- 错误码格式：`FOUNDATION.<SERVICE>.<CATEGORY>.<NAME>`，例 `FOUNDATION.IDENTITY.AUTH.INVALID_CREDENTIALS`
- HTTP 状态码遵守语义；不使用 200 + body code 这种反模式
- 服务专属错误码定义在 `errors.py`，继承底座基类 `foundation.errors.FoundationError`

---

## 5. 版本与兼容性

### 5.1 语义化版本
- 底座整体版本号：`MAJOR.MINOR.PATCH`
- 各 service 独立版本号但跟随底座 MAJOR；MINOR/PATCH 独立演进
- API 版本仅在 breaking change 时升 v2，老版本至少维护 12 个月

### 5.2 兼容性策略
- **MINOR / PATCH**：完全前向兼容；不能删字段、不能改语义、不能加必填字段
- **MAJOR**：允许 breaking；提供迁移指南 + 双写期 ≥1 month
- **新增可选字段**：随时
- **新增必填字段**：禁止（用 MAJOR 升级或者保持可选 + 默认值）
- **删除字段**：先 deprecate（响应里加 `Sunset` header）→ 2 个 MINOR 后下线
- **改字段类型**：禁止；新建字段、旧字段过渡

### 5.3 SDK 版本对齐
- SDK 版本号 = 对应底座 API MAJOR + 独立 MINOR.PATCH
- SDK 在 init 时拉服务端 `/healthz` 获取版本，若不兼容 fail-fast

---

## 6. 可观测性（OTel 三信号 + 审计四信号）

### 6.1 必装 SDK
- 所有 service 启动时强制初始化 OTel SDK（traces + metrics + logs）
- 通过 `foundation.observability.init(service_name)` 一行接入
- 拒绝直接 import `opentelemetry-*`；只走 wrapper

### 6.2 Trace 规范
- 入口自动创 root span（FastAPI instrumentor）
- 所有跨服务调用、DB 调用、外部 API 调用自动创 child span
- Span 名遵循 OTel semantic conventions（`HTTP <METHOD>` / `<db.system> <sql.operation>`）
- 自定义 attribute 用前缀 `foundation.*`，例 `foundation.tenant_id`、`foundation.user_id`

### 6.3 Metric 规范
- 名字 `foundation_<service>_<metric>_<unit>`，例 `foundation_identity_login_total`、`foundation_billing_quota_usage_ratio`
- 业务指标必带 label：`tenant_id`、`service`、`version`
- 直方图用于延迟（毫秒）

### 6.4 Log 规范
- 结构化 JSON（不允许 print / 多行 traceback 散落）
- 强制字段：`timestamp`、`level`、`service`、`trace_id`、`span_id`、`tenant_id`、`user_id`、`message`
- 高基数字段（用户输入、文件内容）走 Loki，不走 ClickHouse 审计

### 6.5 审计（第 4 信号）
- 与可观测性 log 隔离，专走 `foundation.audit` SDK
- 详见 packages/audit 设计文档（A-M2 产出）

---

## 7. 配置与机密管理

- 所有配置走 ENV（12-factor），不读本地 yaml
- 用 `pydantic-settings` 在 `config.py` 集中声明 + 类型校验
- 机密**禁止**写入 ENV 明文：开发用 `.env`（gitignore），生产从 Vault / K8s External Secrets 注入
- 严禁在代码、日志、错误信息里出现密钥 / 密码 / token
- CI 用 gitleaks + Semgrep 扫描

---

## 8. 数据库与 RLS（详见 P0 #2）

### 8.1 总原则
- 所有租户表必须有 `tenant_id` 列 + RLS policy
- 表迁移用 Alembic，schema 改动 PR 必须经 DBA review
- 连接池每次 acquire 后必须 `SET LOCAL app.tenant_id`

### 8.2 命名
- 表名：单数小写，例 `user`、`role_binding`、`org_unit`
- 列名：snake_case
- 主键：`id`（带前缀 ULID 字符串列）；外键：`<table>_id`
- 时间：`created_at`、`updated_at`、`deleted_at`（软删除）
- 审计列：`created_by`、`updated_by`、`tenant_id`

详细规范放 `docs/multi-tenancy.md`（P0 #2）。

---

## 9. 事件与异步

### 9.1 事件总线
- 默认 Redis Streams（small profile）/ NATS JetStream（medium+）
- 业务事件强制经底座 SDK `foundation.events.publish(event)`，不直接调底层

### 9.2 事件 schema
- 跨服务事件 schema 入 `contracts/events/`，CloudEvents 1.0 格式
- 字段：`id` / `type` / `source` / `time` / `tenant_id` / `data`
- `type` 命名：`foundation.<service>.<entity>.<action>`，例 `foundation.identity.user.created`

### 9.3 幂等
- 事件消费者必须幂等；用 `event_id` 去重（消费表）
- 至少一次投递，消费者负责去重

---

## 10. 测试与质量门

### 10.1 覆盖率底线
- 单元测试 ≥80%
- 关键路径（身份/权限/审计/计费）≥90%
- 集成测试覆盖所有公开 API
- CI 不达标阻断合并

### 10.2 必跑检查（CI）
- `ruff format --check` / `ruff check`
- `mypy --strict`（service 内部代码）
- `pytest --cov`
- `semgrep --config auto`（SAST）
- `trivy fs .`（SCA）
- `gitleaks detect`（Secret）
- `pip-licenses` / `cyclonedx-py`（License + SBOM）
- 契约测试：本 service 的 OpenAPI 必须能 lint 通过（`spectral lint`）

### 10.3 阻断策略
- Critical / High 安全问题阻断
- License 黑名单（GPL / AGPL）命中阻断
- mypy 错误阻断
- 覆盖率回退超 2% 阻断

---

## 11. 部署形态约定

- 每个 service 出三档资源 profile：`small` / `medium` / `large`
- Helm values 通过 `--set profile=medium` 切换，service 内部不感知 profile
- 所有 service 默认无状态；有状态（DB / Redis / OpenSearch）走 StatefulSet + Operator
- 健康检查：`/healthz`（liveness）、`/readyz`（readiness）、`/metrics`（prometheus）
- 优雅停机：收到 SIGTERM 后等当前请求结束（≤30s），关闭新连接

---

## 12. 安全基线（详细见各合规文档）

- 所有 service 间通信 mTLS（K8s + cert-manager 自动签发）
- 服务账号最小权限（K8s RBAC + namespace 隔离）
- 容器 non-root + read-only rootfs + drop capabilities
- 镜像扫描通过才能推 registry
- 任何对外接口默认 deny，按需开放

---

## 13. 国际化与本地化

- 业务消息（错误描述、邮件、通知）必须 i18n，至少 `zh-CN` / `en-US`
- 翻译文件放 `packages/<svc>/src/foundation_<svc>/i18n/`
- 响应根据 `Accept-Language` 返回；客户端可覆盖

---

## 14. 文档要求

- 每个 service `README.md` 必含：作用、依赖、本地启动、API 入口
- 每个 service 的设计文档在 `docs/design/<service>-<version>.md`（统一模板见 plan）
- 重大架构决策入 `docs/adr/NNNN-<title>.md`
- OpenAPI spec 与代码自动一致性检查（CI 强制）

---

## 附录 A：约定速查

| 主题 | 约定 |
|---|---|
| 服务命名 | `<capability>-service` |
| URL | `/api/<svc>/v1/<resource>` |
| ID | `<type>_<ULID>` |
| 时间 | ISO 8601 UTC |
| JSON 字段 | `snake_case` |
| 枚举值 | `UPPER_SNAKE_CASE` |
| 错误码 | `FOUNDATION.<SVC>.<CAT>.<NAME>` |
| 错误响应 | RFC 9457 |
| 分页 | 游标默认 `cursor + limit` |
| 租户传递 | 网关注入 `X-Tenant-Id`，业务不可覆盖 |
| 事件 | CloudEvents 1.0 |
| 配置 | ENV + pydantic-settings |
| 可观测性 | OTel + 结构化 JSON log |
| 版本 | 语义化，老 API ≥12 月维护 |

---

## 附录 B：变更记录

| 日期 | 版本 | 变更 | 评审人 |
|---|---|---|---|
| 2026-05-22 | 0.1.0 | 初版（P0 #1.1） | TBD |

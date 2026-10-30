# OpenAPI Contracts — SaaS Foundation

> 这是底座 18 个 service 的**契约源真相**。Python / TypeScript / Go 三套 SDK、API 文档、CI 兼容性检测全部由这里的 spec 驱动。
>
> 修改前必读：[docs/CONVENTIONS.md](../../docs/CONVENTIONS.md) §2 API 设计规范、[docs/errors.md](../../docs/errors.md) 错误码规范。

---

## 目录结构

```
contracts/openapi/
├── _common.yaml          # 共享 components（错误响应 / ID 类型 / 分页 / security scheme）
├── _template.yaml        # 新 service 复制起步用
├── .spectral.yaml        # 强制规则 lint
├── Makefile              # lint / bundle / sdk-gen / diff
├── README.md             # 本文件
│
├── identity.yaml         # A-M1
├── authz.yaml
├── org.yaml
├── crypto.yaml
│
├── audit.yaml            # A-M2
├── lifecycle.yaml
├── dlp.yaml
├── data-protection.yaml
│
├── notification.yaml     # A-M3
├── search.yaml
├── opa-bundle.yaml
├── scim-dingtalk.yaml
├── pam.yaml
├── feature-flag.yaml
│
├── compliance.yaml       # A-M4
├── billing.yaml
├── api-platform.yaml
├── llm-gateway.yaml
│
├── security-ops.yaml     # A-M5（含 chaos/pentest/vuln/incident/ssdlc）
│
└── bundle/               # `make bundle` 产出（gitignored）
    └── <svc>.yaml        # $ref 展开后可独立分发
```

---

## 文件即契约：六条铁律

> 这些规则由 `.spectral.yaml` 机器强制；任何 spec 提 PR 必须 `make lint` 全绿。

1. **版本写在 `servers` URL 末尾**（`/api/<service>/v1`，CONVENTIONS §2.2），path 不再带版本；版本号 URL 显式带，禁止 header version
2. **JSON 字段 `snake_case`**（CONVENTIONS §2.8；SCIM 资源 `Scim*` 沿用 RFC 7643 字段名）；枚举 `UPPER_SNAKE_CASE`（合规模式标识符例外）
3. **错误响应必 $ref `_common.yaml`**；不允许 inline 定义错误 body。要自定义描述可以内联响应，但 body 必须是 `application/problem+json`，并 $ref `_common.yaml` 的 `Error` / `ValidationError`
4. **错误码格式 `FOUNDATION.<SVC>.<CAT>.<NAME>`** 四段；各服务共用的码 `<SVC>` 为 `_`（[errors.md](../../docs/errors.md) §3.1、§12）
5. **所有 operation 必须有 `operationId`**（camelCase，给 SDK 生成器用）；必须 unique
6. **spec 根级声明 `security`（如 `[bearerAuth]`）**，覆盖所有端点；公开端点必须显式 `security: []`

---

## 新增 service spec 流程

```bash
# 1. 复制模板
cp _template.yaml my-service.yaml

# 2. 替换 info、servers、tags、paths
$EDITOR my-service.yaml

# 3. 在 Makefile 的 SPECS 列表里加入 my-service

# 4. 校验
make lint-one SVC=my-service

# 5. 全量校验 + bundle
make ci

# 6. 提 PR；CI 跑 lint + breaking change 检测
```

---

## SDK 生成

### Python

```bash
make sdk-python
```

产出在 `sdks/python/foundation_<svc>/`，包名 `foundation_<svc>`，async client（asyncio）。

业务层用法：

```python
from foundation_identity import IdentityClient, CreateUserRequest

client = IdentityClient(base_url="https://api.example.com/api/identity/v1",
                       bearer_token=token)
user = await client.create_user(CreateUserRequest(email="alice@example.com"))
```

### TypeScript

```bash
make sdk-typescript
```

产出在 `sdks/typescript/packages/<svc>/`，npm 包名 `@foundation/<svc>`，fetch-based。

```ts
import { IdentityApi, Configuration } from '@foundation/identity';
const api = new IdentityApi(new Configuration({ accessToken: token }));
const user = await api.createUser({ createUserRequest: { email: 'alice@example.com' } });
```

### Go

```bash
make sdk-go
```

产出在 `sdks/go/<svc>/`。

```go
import identity "github.com/example/foundation/sdks/go/identity"
client := identity.NewAPIClient(cfg)
user, _, err := client.UsersAPI.CreateUser(ctx).CreateUserRequest(req).Execute()
```

---

## 破坏性变更管理

### 兼容性策略

参考 [CONVENTIONS](../../docs/CONVENTIONS.md) §5 SDK 兼容性策略：

- **minor 版本前向兼容**：新增 endpoint / 新增可选字段 / 扩枚举末尾
- **major 版本可破坏**：删字段 / 改字段类型 / 改 enum 值 / 改 path

### 自动检测

```bash
# 与上一 commit 对比
make diff-prev

# 与 main 分支对比
make diff-base
```

CI 强制在合并 PR 时跑 `make diff-base`；任何 breaking change → 阻断 + 要求 `BREAKING:` commit footer + 升 major 版本号。

---

## 关键命令

| 命令 | 说明 |
|---|---|
| `make help` | 列所有 target |
| `make lint` | 全部 spec spectral 校验 |
| `make lint-one SVC=identity` | 单个 spec 校验 |
| `make bundle` | 把 `$ref` 展开为可独立分发的 yaml |
| `make sdk-all` | 生成 py + ts + go 三套 SDK |
| `make diff-base` | 对比 main 分支识破坏性变更 |
| `make docs` | 生成 ReDoc HTML 静态文档 |
| `make serve-docs SVC=identity` | 本地预览单个 service 文档 |
| `make ci` | CI 入口（lint + bundle 校验） |

---

## 与设计文档对应关系

| Spec | 详细设计 | Milestone |
|---|---|---|
| identity.yaml | [docs/design/identity-v1.md](../../docs/design/identity-v1.md) + [auth-flows-v1.md](../../docs/design/auth-flows-v1.md) | A-M1 |
| authz.yaml | [authz-v1.md](../../docs/design/authz-v1.md) | A-M1 |
| org.yaml | [org-v1.md](../../docs/design/org-v1.md) + saas-isolation-routing-v1（tenant_routing 在 org 模块） | A-M1 |
| crypto.yaml | [crypto-v1.md](../../docs/design/crypto-v1.md) | A-M1 |
| audit.yaml | [audit-v1.md](../../docs/design/audit-v1.md) | A-M2 |
| lifecycle.yaml | [lifecycle-v1.md](../../docs/design/lifecycle-v1.md) | A-M2 |
| dlp.yaml | [dlp-classification-v1.md](../../docs/design/dlp-classification-v1.md) | A-M2 |
| data-protection.yaml | [data-protection-v1.md](../../docs/design/data-protection-v1.md) | A-M2 |
| notification.yaml | [notification-v1.md](../../docs/design/notification-v1.md) | A-M3 |
| search.yaml | [search-v1.md](../../docs/design/search-v1.md) | A-M3 |
| opa-bundle.yaml | [opa-bundle-v1.md](../../docs/design/opa-bundle-v1.md) | A-M3 |
| scim-dingtalk.yaml | [scim-dingtalk-v1.md](../../docs/design/scim-dingtalk-v1.md) | A-M3 |
| pam.yaml | [pam-v1.md](../../docs/design/pam-v1.md) | A-M3 |
| feature-flag.yaml | （内嵌 Unleash 转发；薄封装） | A-M3 |
| compliance.yaml | [compliance-v1.md](../../docs/design/compliance-v1.md) + [equal-protection-checklist-v1.md](../../docs/design/equal-protection-checklist-v1.md) | A-M4 |
| billing.yaml | [billing-v1.md](../../docs/design/billing-v1.md) | A-M4 |
| api-platform.yaml | [api-platform-v1.md](../../docs/design/api-platform-v1.md) | A-M4 |
| llm-gateway.yaml | [llm-gateway-v1.md](../../docs/design/llm-gateway-v1.md) | A-M4 |
| security-ops.yaml | [ha-fault-injection-v1.md](../../docs/design/ha-fault-injection-v1.md) + [penetration-test-scope-v1.md](../../docs/design/penetration-test-scope-v1.md) + [security-ops-ci-v1.md](../../docs/design/security-ops-ci-v1.md) | A-M5 |

---

## 工具版本要求

- [Spectral CLI](https://github.com/stoplightio/spectral) ≥ 6.11
- [Redocly CLI](https://github.com/Redocly/redocly-cli) ≥ 1.16
- [oasdiff](https://github.com/tufin/oasdiff) ≥ 1.10
- [openapi-generator-cli](https://github.com/OpenAPITools/openapi-generator) ≥ 7.5 （Docker 拉镜像即可）

---

## 常见问题

**Q：为什么不直接用 FastAPI 自动生成 OpenAPI？**
A：底座是契约优先（contract-first）：spec 是 source of truth，FastAPI 实现要 conform；而非反过来。这样 SDK / 文档 / mock 不会随实现漂移。FastAPI 实现里用 `openapi_extra` 装饰器把 operationId / examples 与 spec 对齐。

**Q：业务层（agent-platform）如何使用？**
A：业务层独立 monorepo，依赖 `sdks/python/foundation_*` 包。不允许业务代码直连 service URL 或 import 底座组件内部包。

**Q：私有化客户的 SDK 怎么交付？**
A：每次 v1.0 GA 同步发布 `sdks/python-1.0.0.tar.gz` / `sdks/typescript-1.0.0.tgz` 离线包，随 helm chart 一起。

# saas-foundation

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/)
[![API](https://img.shields.io/badge/API-OpenAPI%203.1-6ba539.svg)](contracts/openapi/)
[![Errors](https://img.shields.io/badge/errors-RFC%209457-informational.svg)](docs/errors.md)

[English](README.md) · **简体中文**

通用企业级 SaaS 平台底座：**17 个可独立部署的服务**，覆盖身份、授权、组织、计费、审计、
合规、DLP、密码学、通知、搜索、LLM 网关等基础能力，以及业务层调用它们所需的 SDK。

核心是在平台能力与业务代码之间划一条硬边界。业务系统 `import foundation_sdk`，
通过 HTTP 调用底座服务；**永远不直接触碰 Keycloak、OPA、ClickHouse、OpenSearch、
LiteLLM、Vault 或 MinIO**。那些是底座自己持有的实现细节，可以整体替换而业务无感。

[**cloud·worker**](https://github.com/chenzefeng09/cloud-worker) 是构建在本底座之上的
第一个产品 —— 详见[谁在用它](#谁在用它)。

> **项目状态**：处于活跃开发中，已用于内部试点，尚未 1.0。服务接口仍在演进。
> `go` SDK 目前是占位；Python 完整，TypeScript 部分可用。

---

## 目录

- [设计目标](#设计目标)
- [包含什么](#包含什么)
- [架构](#架构)
- [多租户：三道墙](#多租户三道墙)
- [谁在用它](#谁在用它)
- [仓库结构](#仓库结构)
- [快速开始](#快速开始)
- [使用 SDK](#使用-sdk)
- [开发](#开发)
- [部署](#部署)
- [合规](#合规)
- [文档](#文档)
- [参与贡献](#参与贡献)
- [许可证](#许可证)

---

## 设计目标

- **私有化优先** —— 默认交付目标是客户自己的机房：K8s 1.24+、离线安装、不要求任何外网调用。
- **同一份 chart 兼容 SaaS** —— 切换 profile 即可得到多租户 SaaS 与分档隔离，
  而不必维护两套代码。
- **业务零感知底层组件** —— 业务层只 import SDK，看不到 Keycloak、OPA、LiteLLM、Vault、
  MinIO，因此这些组件可以被替换而不动产品代码。
- **合规是内建而非补丁** —— 等保 2.0 三级与 PIPL 在设计阶段就已覆盖；国密与信创紧随其后。
- **三档规模** —— `small` / `medium` / `large` 三档 Helm profile，含 HA 与弹性伸缩。

---

## 包含什么

17 个服务，每个只负责一项能力。「一个服务一项能力」是**强制规则**而非建议 ——
新能力就开新服务。

| 服务 | 端口 | 职责 |
|---|---|---|
| `identity` | 8001 | 会话、用户、MFA、SSO、SCIM、口令与登录策略 |
| `authz` | 8002 | 授权 —— RBAC 与 OPA/ABAC 双轨并行 |
| `org` | 8003 | 租户 → OU → 团队 → 用户 的组织层级 |
| `crypto` | 8004 | 信封加密、KEK 生命周期、签名、口令哈希 |
| `lifecycle` | 18006 | 留存策略、回收站、法务保全、销毁证明、备份编排 |
| `dlp` | 18007 | 数据防泄漏 + 内容分级分类 |
| `billing` | 8017 | 计量与计费 —— 双模（私有化 License + SaaS 订阅） |
| `notification` | 18008 | 邮件、Webhook、WebSocket、钉钉、飞书、企业微信 |
| `search` | 8009 | OpenSearch 封装 + ACL 感知的结果过滤 |
| `api-platform` | 18010 | API Key、OAuth 应用、出站 Webhook |
| `llm-gateway` | 8011 | LiteLLM 封装 —— 供应商路由、虚拟密钥、配额 |
| `feature-flag` | 8012 | Unleash 封装 |
| `audit` | 8013 | 不可篡改审计日志：OTel → ClickHouse → S3 WORM，哈希链 + 数字签名 |
| `compliance` | 18014 | ROPA、DPIA、DSAR、合规报告 |
| `pam` | 18015 | 特权访问管理 |
| `data-protection` | 18016 | 脱敏引擎、数据销毁、跨境传输、同意管理 |
| `security-ops` | 18019 | SSDLC、漏洞 SLA、SBOM、事件响应 |

此外还有 **`storage`** —— 它不是服务而是一个库：基于 boto3 的 S3/MinIO 客户端，
带租户隔离的 key 布局、配额钩子与 OTel 埋点。

上表端口是 docker-compose 开发栈的**宿主端口**。部分服务为避免冲突映射到 `1xxxx`
（`billing` 8017→8007、`notification` 18008→8008 等），详见 `deploy/docker-compose/dev.yml`。

### 底层开源组件

| 关注点 | 组件 | 由谁封装 |
|---|---|---|
| 身份提供方 | Keycloak | `identity` |
| 策略引擎 | OPA | `authz` |
| 关系型存储 | PostgreSQL + PgBouncer | 全部服务 |
| 缓存 / 队列 | Redis | 多个服务 |
| 审计数仓 | ClickHouse | `audit` |
| 搜索索引 | OpenSearch | `search` |
| 密钥 / KMS | Vault（transit） | `crypto` |
| 对象存储 | MinIO（S3 兼容） | `storage` |
| 特性开关 | Unleash | `feature-flag` |
| LLM 路由 | LiteLLM | `llm-gateway` |
| 可观测性 | OpenTelemetry、Jaeger、Prometheus | 全部服务 |

业务代码不直接接触其中任何一个。**这层间接性本身就是底座的价值所在。**

---

## 架构

```
                    你的业务系统（例如 cloud·worker）
                              │
                              │  foundation_sdk  ·  HTTP + OpenAPI 3.1
                              ▼
   ┌───────────────────────────────────────────────────────────────────┐
   │                          foundation 服务                          │
   │                                                                   │
   │  identity   authz    org      crypto     lifecycle   dlp          │
   │  billing    search   audit    compliance pam         notification │
   │  api-platform        llm-gateway   feature-flag   data-protection │
   │  security-ops                                                     │
   └───┬───────────────────────────────────────────────────────────┬───┘
       │                                                           │
       ▼                                                           ▼
   ┌────────────────────────────────┐        ┌───────────────────────────┐
   │  Keycloak · OPA · Vault        │        │  PostgreSQL + PgBouncer   │
   │  ClickHouse · OpenSearch       │        │  （RLS 强制租户隔离）     │
   │  MinIO · Redis · Unleash       │        │  Redis                    │
   │  LiteLLM                       │        └───────────────────────────┘
   └────────────────────────────────┘
              ▲
              └── 业务代码永远不直接触达这一层
```

每个服务内部结构统一（见 `docs/CONVENTIONS.md` §1.2）：

```
packages/<capability>/
├── src/foundation_<capability>/
│   ├── api/v1/        FastAPI router —— HTTP 入口，带版本
│   ├── domain/        领域模型
│   ├── services/      业务逻辑 —— 纯 Python，不 import FastAPI
│   └── adapters/      出站适配器：DB、Keycloak、OPA、Redis…
└── tests/
```

所有服务的错误统一走 RFC 9457 problem+json，错误码稳定且机器可读，
另有面向终端用户的 `user_message` 字段 —— 详见 [docs/errors.md](docs/errors.md)。

---

## 多租户：三道墙

这是底座里**后果最严重**的一份契约。租户隔离被强制执行三遍，
下面的顺序就是某一层失效时的回退顺序：

1. **网关层** —— 从 JWT 提取 `tenant_id` 并强制注入 `X-Tenant-Id`，业务代码无法覆盖。
2. **应用层** —— 每次获取数据库连接时执行 `SET LOCAL app.tenant_id`，事务内有效。
3. **数据层** —— PostgreSQL 行级安全（RLS）过滤每一条查询，并开启
   `FORCE ROW LEVEL SECURITY`，连表属主也受约束。

结果：业务代码**忘写** `WHERE tenant_id = …` 也不会跨租户泄漏；
即便应用层存在 SQL 注入，最坏也只能拿到当前租户的数据。

所有租户表必须带 `tenant_id` 列、启用 RLS + FORCE RLS、至少有一个以 `tenant_id`
为前导列的复合索引，并定义 select/insert/update/delete 四条 policy。
四个数据库角色分权 —— `app_user`（受 RLS 约束）、`app_admin`、
`app_migrator`（唯一持有 `BYPASSRLS`）、`app_observability`。
**禁止业务代码以 superuser 或 BYPASSRLS 角色连接。**

PgBouncer 必须运行在 transaction 或 session 模式；statement 模式会破坏 `SET LOCAL`，
因此被禁用。

完整契约与威胁模型见 [docs/multi-tenancy.md](docs/multi-tenancy.md)。
改动此处需 ≥2 名架构师 sign-off 并记录 ADR。
`make test-rls-fuzz` 会对所有 package 跑跨租户越权 fuzz。

---

## 谁在用它

[**cloud·worker**](https://github.com/chenzefeng09/cloud-worker) —— 一个企业级 AI Agent
平台（沙箱化 Agent 运行、可复用应用、技能、MCP、知识库）—— 完全构建在本底座之上。
它负责所有与 Agent 相关的部分；saas-foundation 在其下方负责身份、授权、组织、计费、
审计、LLM 网关、存储、密码学、DLP 与特性开关。

如果你在评估是否用本底座承载自己的产品，这条切分线值得一读：
见 [cloud·worker 的「与 saas-foundation 的关系」](https://github.com/chenzefeng09/cloud-worker/blob/main/README.zh-CN.md#与-saas-foundation-的关系)。

> **外部使用者请注意**：`foundation-sdk` 尚未发布到公网 PyPI。
> 消费方需从内部源安装，或在开发阶段从本仓库的兄弟目录检出安装。
> 详见 [docs/sdk-release.md](docs/sdk-release.md)。

---

## 仓库结构

```
saas-foundation/
├── packages/           17 个能力服务 + storage 库
├── sdks/
│   ├── python/         完整 —— FoundationClient、CookieSigner、FastAPI 辅助层
│   ├── typescript/     部分可用
│   └── go/             占位
├── contracts/
│   ├── openapi/        每个服务一份 OpenAPI 3.1 契约 + 公共组件
│   ├── opa-bundles/    OPA 策略包
│   └── proto/          gRPC 定义
├── deploy/
│   ├── docker-compose/ 本地开发栈
│   ├── helm/           umbrella chart，small/medium/large 三档 profile
│   └── offline-bundle/ 离线（无外网）安装打包
├── docs/
│   ├── CONVENTIONS.md  架构总约定 —— 先读这份
│   ├── design/         各服务详细设计
│   └── adr/            架构决策记录
├── tests/
│   ├── conformance/    业务方接入底座的自检套件
│   ├── integration/    跨服务集成
│   ├── e2e/
│   └── security/       RLS 越权 fuzz
└── tools/              CI 与开发工具
```

---

## 快速开始

**前置条件**：Docker（含 Compose v2）、Python 3.12、Poetry。

```bash
git clone https://github.com/chenzefeng09/saas-foundation.git
cd saas-foundation
```

一条龙拉起整个开发栈 —— 基础设施、服务、初始化与健康检查：

```bash
make up-full
```

它会依次执行 `make up`（缺 `.env` 时从 `.env.example` 复制，启动 Postgres、Keycloak、
ClickHouse、OpenSearch、Vault、MinIO、OPA、Unleash 及各服务）、等待容器就绪、
执行 `post-up-init`（Vault transit 密钥、MinIO bucket、Keycloak Organizations），
最后对所有服务跑健康检查。

灌入测试数据（dev 租户 + 测试用户）：

```bash
make seed
```

常用命令：

```bash
make ps
```

```bash
make logs SVC=keycloak
```

```bash
make healthcheck
```

```bash
make down
```

`make nuke` 会停服务**并删除数据卷**，不可恢复。

更多细节见 [docs/dev-quickstart.md](docs/dev-quickstart.md)。

---

## 使用 SDK

业务方依赖 `foundation_sdk`，而不是逐个依赖各服务：

```python
from foundation_sdk import FoundationClient, FoundationClientSettings, tenant_context

client = FoundationClient(FoundationClientSettings(...))

with tenant_context("tnt_..."):
    decision = await client.authz.check(user_id=..., action="document.read",
                                        resource_type="document")
```

对 FastAPI 应用，SDK 还提供中间件层 —— 请求上下文透传、RFC 9457 problem+json
异常处理、租户/用户提取：

```python
from foundation_sdk.fastapi import (
    install_request_context, register_problem_details, get_tenant_id, get_user_id,
)

install_request_context(app, service_name="my-service", service_version="1.0.0")
register_problem_details(app)
```

BFF 所需的签名会话 Cookie 由 `CookieSigner` / `CookieSignerSettings` 提供。

版本策略与升级流程见 [docs/sdk-release.md](docs/sdk-release.md)。

---

## 开发

```bash
make lint          # 全 package ruff check + mypy
```

```bash
make test          # 全 package pytest
```

```bash
make test-rls-fuzz # 跨租户越权 fuzz（tests/security/）
```

```bash
make migrate       # 以 app_migrator 跑 alembic upgrade head
```

安全与供应链：

```bash
make scan          # gitleaks + semgrep + 许可证检查
```

```bash
make sbom          # 生成 CycloneDX + SPDX
```

策略相关：

```bash
make opa-test      # OPA 策略单元测试
```

Helm：

```bash
make helm-lint     # lint 三档 profile
```

动手写代码前请先读 [docs/CONVENTIONS.md](docs/CONVENTIONS.md) —— 它约束服务命名、
包结构、API 版本、错误处理与 SDK 形态。**违反约定的 PR 不予合并。**

---

## 部署

**本地开发** —— docker-compose，见上文。

**Kubernetes** —— Helm umbrella chart，三档 profile：

| Profile | 适用场景 |
|---|---|
| `small` | 单节点 / 边缘 / PoC |
| `medium` | 标准生产，适度 HA |
| `large` | 完整 HA 与横向扩展 |

```bash
make helm-render PROFILE=medium
```

**离线部署** —— `deploy/offline-bundle/` 把镜像与 chart 打包，用于无外网环境，
这也是私有化交付的默认假设。

---

## 合规

合规在本底座里是**设计输入**，而不是事后补的认证工作。

- **等保 2.0 三级**（GB/T 22239-2019）—— 自评将 211 项技术控制中的 176 项（83%）
  与 70 项管理控制中的 58 项（83%）映射到底座能力，见
  [docs/equal-protection-checklist-v1.md](docs/equal-protection-checklist-v1.md)，
  以及[四级差距分析](docs/equal-protection-level4-gap-v1.md)。
- **PIPL** —— 同意管理、跨境传输记录、DSAR 与 ROPA 由 `compliance` 与
  `data-protection` 承载。
- **信创软硬件** —— ARM64（鲲鹏 920、飞腾 FT-2000/4 与 S2500）与 x86_64（海光、兆芯）
  已适配，龙芯在计划中，见[信创部署指南](docs/xinchuang-deployment-guide-v1.md)。
- **审计证据** —— `audit` 服务产出哈希链 + 数字签名 + WORM 存储的日志；
  RLS 是数据库层强制行为，可直接作为证据出示给审计方，而非靠口头论证。

SOC 2 与 ISO 27001 是**计划中的对齐目标，并非已获得的认证**。

---

## 文档

| 主题 | 文档 |
|---|---|
| **架构总约定 —— 先读这份** | [docs/CONVENTIONS.md](docs/CONVENTIONS.md) |
| 多租户与 RLS 基线 | [docs/multi-tenancy.md](docs/multi-tenancy.md) |
| 错误码与错误处理 | [docs/errors.md](docs/errors.md) |
| 本地开发快速上手 | [docs/dev-quickstart.md](docs/dev-quickstart.md) |
| SDK 发布与升级策略 | [docs/sdk-release.md](docs/sdk-release.md) |
| 各服务详细设计 | [docs/design/](docs/design/) |
| Helm chart | [deploy/helm/README.md](deploy/helm/README.md) |
| OpenAPI 契约 | [contracts/openapi/](contracts/openapi/) |

部分设计文档为英文。

---

## 参与贡献

- 先读 [docs/CONVENTIONS.md](docs/CONVENTIONS.md)。它是**契约**，不是风格建议。
- 保持 `make lint` 与 `make test` 通过。
- 涉及租户表的 schema 改动必须满足 [docs/multi-tenancy.md](docs/multi-tenancy.md)
  并通过 `make test-rls-fuzz`。
- 改动多租户基线或 CONVENTIONS 需 ≥2 名架构师 sign-off 并在 `docs/adr/` 下记录 ADR。
- 跨 saas-foundation / 消费方边界的改动需要在对方仓库提配套 PR —— 请在描述中说明。
- 贡献内容按 Apache 2.0 接受。

---

## 许可证

采用 **Apache License 2.0** —— 见 [LICENSE](LICENSE)。

```
Copyright 2026 The saas-foundation Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

底座所封装的开源组件 —— Keycloak、OPA、PostgreSQL、Redis、ClickHouse、OpenSearch、
Vault、MinIO、Unleash、LiteLLM —— 各自遵循其原有许可证。

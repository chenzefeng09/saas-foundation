# Contributing to SaaS Foundation

Thanks for your interest in contributing. SaaS Foundation is a reusable,
multi-tenant enterprise base — identity, authorization, organization, billing,
audit, crypto, compliance, and more — that any business system can build on
(including the [Agent Platform](https://github.com/chenzefeng09/agent-platform),
which is built on top of it). Because so much depends on the contracts and the
isolation guarantees here, contributions are held to a strict bar: this guide
and the conventions it links are **binding**, and pull requests that violate
them will not be merged.

- [Code of conduct](#code-of-conduct)
- [Repository layout](#repository-layout)
- [Development setup](#development-setup)
- [The conventions contract](#the-conventions-contract-binding)
- [Contract-first OpenAPI workflow](#contract-first-openapi-workflow)
- [Mandatory RLS cross-tenant fuzz tests](#mandatory-rls-cross-tenant-fuzz-tests)
- [Security gates](#security-gates)
- [Pull request conventions](#pull-request-conventions)
- [中文贡献指南](#中文贡献指南)

## Code of conduct

We expect all participants to interact respectfully and constructively. Report
unacceptable behavior to <chenzefeng09@gmail.com>.

## Repository layout

```
saas-foundation/
├── packages/<capability>/   # one self-contained service per capability (Poetry)
├── contracts/openapi/       # the contract source of truth — drives all SDKs
├── sdks/python/             # generated + hand-written foundation-sdk (Python)
├── sdks/typescript/         # @foundation/sdk (TypeScript, mirrors the Python surface)
├── deploy/                  # docker-compose dev stack + Helm umbrella chart
├── docs/                    # binding contracts (CONVENTIONS, multi-tenancy, errors), design, ADRs
├── tools/                   # dev + CI scripts
└── Makefile                 # top-level entrypoint (run `make help`)
```

Each capability is an independent service named `<capability>-service` with a
fixed internal structure (`api/`, `services/`, `adapters/`, `events/`,
`migrations/`, `tests/`). The full layout and its rules are specified in
[`docs/CONVENTIONS.md`](./docs/CONVENTIONS.md) §1. **One capability per service;
a new capability means a new service.**

## Development setup

### Prerequisites

| Tool | Version | Notes |
|---|---|---|
| Docker + Compose v2 | 24+ | Dev stack; Windows via WSL2 (the Makefile is bash/GNU-tools oriented) |
| Python | 3.12+ | Services and SDK |
| Poetry | 1.8+ | Per-package virtualenvs |
| Node.js | 20+ | Spectral lint and the TypeScript SDK build |
| Helm / kubectl | 3.15+ / 1.30+ | Optional, for chart work (K3s handy for local install) |

The OpenAPI toolchain (Spectral, Redocly, oasdiff, openapi-generator) and the
security scanners (gitleaks, semgrep, syft, OPA) are pulled as Docker images by
the relevant `make` targets, so you do not need to install them on the host.

### One-shot local stack

The dev stack brings up the full open-source dependency set — PostgreSQL 16,
PgBouncer, Redis, Keycloak, ClickHouse, OpenSearch, Vault, MinIO, OPA, Unleash,
the OpenTelemetry Collector + Jaeger, and Mailhog. (It runs the *dependencies*;
Foundation services themselves run from your venvs or from the integration
compose file.)

```bash
make up-full          # start deps → wait for Keycloak realm → post-up-init → healthcheck
```

`up-full` is the one-command path. The stepwise equivalent is:

```bash
make up               # start the docker-compose dependencies
make post-up-init     # business init: Vault transit, MinIO buckets, Keycloak Organizations
make healthcheck      # assert every dependency is healthy
```

Then prepare the database and seed dev data:

```bash
make migrate          # run every package's `alembic upgrade head` (as the app_migrator role)
make seed             # seed a dev tenant + test users
```

Per-package work uses Poetry directly, e.g.:

```bash
cd packages/identity
poetry install
poetry run pytest
poetry run alembic upgrade head
```

Useful top-level targets (`make help` lists them all):

| Command | What it does |
|---|---|
| `make test` | `pytest` across all packages |
| `make lint` | `ruff check` + `mypy` across all packages |
| `make format` | `ruff format` across all packages |
| `make down` | Stop the dev stack (keeps data) |
| `make nuke` | Stop the dev stack **and delete volumes** (irreversible) |
| `make integration-all` | Full docker-compose integration run (infra + identity/authz/org/crypto) |

## The conventions contract (binding)

[`docs/CONVENTIONS.md`](./docs/CONVENTIONS.md) is the single most important
document in the repository. Every package's design, code, API, SDK, and
deployment must conform to it. The highlights you will touch most often:

- **Service naming.** One capability per service, named `<capability>-service`;
  the short name (used in paths, image names, and Kubernetes resources) is
  `<capability>` (e.g. `identity`, `authz`, `billing`).
- **URL shape.** REST + JSON over HTTPS at
  `/api/<service>/v1/<resource>[/<id>][/<sub-resource>]`. The version is always
  explicit in the path (`v1`, `v2`) — header-based versioning is not accepted.
- **JSON field names are `snake_case`** (`created_at`, never `createdAt`); enum
  values are `UPPER_SNAKE_CASE`. Do not wrap responses in a
  `{code, data, message}` envelope — return the resource directly.
- **IDs are type-prefixed ULIDs/UUIDs** (`usr_…`, `org_…`, `tnt_…`); timestamps
  are ISO 8601 UTC (`2026-05-22T10:00:00Z`).
- **Four-segment error codes.** Errors follow
  [RFC 9457 Problem Details](https://www.rfc-editor.org/rfc/rfc9457) with a code
  of the form `FOUNDATION.<SERVICE>.<CATEGORY>.<NAME>`, e.g.
  `FOUNDATION.IDENTITY.AUTH.INVALID_CREDENTIALS`. See
  [`docs/errors.md`](./docs/errors.md).
- **Tenant context is injected, never client-supplied.** The gateway extracts
  `tenant_id` from the verified JWT and force-injects `X-Tenant-Id`; business
  code must not pass a `tenant_id=` argument to the SDK (a CI scan rejects it).
  Cross-tenant operations must use an explicit `with sdk.as_tenant(...)` and are
  audited. See CONVENTIONS §3.

If a change requires deviating from the conventions, that is an architecture
decision: open an ADR in [`docs/adr/`](./docs/adr/) (see
[GOVERNANCE.md](./GOVERNANCE.md)) before writing the code.

## Contract-first OpenAPI workflow

Foundation is **contract-first**: the OpenAPI specs in
[`contracts/openapi/`](./contracts/openapi/) are the source of truth. The
Python and TypeScript SDKs, the API docs, and the mocks are all generated from
them, and FastAPI implementations must conform to the spec — never the reverse.
**Do not change an API by editing service code first.** The flow is:

1. **Edit the spec.** Change `contracts/openapi/<service>.yaml` (or copy
   `_template.yaml` for a brand-new service and add it to the `SPECS` list).
   The six machine-enforced rules — `/v1` on every path, `snake_case` JSON,
   `$ref`'d shared error bodies, four-segment error codes, unique `camelCase`
   `operationId`s, and explicit `security` — are described in
   [`contracts/openapi/README.md`](./contracts/openapi/README.md).
2. **Lint with Spectral.**

   ```bash
   cd contracts/openapi
   make lint-one SVC=<service>   # single spec
   make lint                     # all specs
   ```

3. **Check for breaking changes (oasdiff gate).** CI runs `make diff-base`
   against `main` on every PR; any breaking change is **blocked** unless you
   bump the major version and add a `BREAKING:` footer to the commit.

   ```bash
   make diff-prev    # vs the previous commit
   make diff-base    # vs the main branch (the gate CI enforces)
   ```

   Per CONVENTIONS §5, MINOR/PATCH must stay forward-compatible (add optional
   fields or endpoints, extend enums at the end); deleting a field, changing a
   type, or changing a path is a MAJOR change.

4. **Regenerate the SDKs and align the implementation.**

   ```bash
   make sdk-python        # → sdks/python/foundation_<svc>/
   make sdk-typescript    # → sdks/typescript/packages/<svc>/
   # make sdk-all         # both (Go is planned and not yet generated)
   ```

   Then update the FastAPI implementation to match (use `openapi_extra` to keep
   `operationId`/examples aligned with the spec). Commit the regenerated SDK
   alongside the spec change so they never drift.

> The Go SDK target (`make sdk-go`) is referenced for the future but not yet
> wired up — `sdks/go/` is currently a stub.

## Mandatory RLS cross-tenant fuzz tests

Multi-tenant isolation is the foundation's core promise. **Any PR that adds or
changes a tenant-scoped table must add Row-Level Security fuzz tests** under the
package's `tests/security/` directory, and they must pass:

```bash
make test-rls-fuzz     # runs tests/security/ across every package
```

These tests perform many randomized cross-tenant reads/writes and assert that a
caller in tenant A can never observe or mutate tenant B's rows — even if the
business query forgets a `WHERE tenant_id`, or in the face of a SQL-injection
attempt. The rules a new table must satisfy are specified in
[`docs/multi-tenancy.md`](./docs/multi-tenancy.md):

- every tenant table carries a `tenant_id` column and has `ENABLE` **and**
  `FORCE ROW LEVEL SECURITY` with the four standard policies;
- the connection pool runs `SET LOCAL app.tenant_id` inside a transaction on
  every acquire, and `current_setting('app.tenant_id', true)` defaults to deny
  (NULL → no rows) when unset;
- PgBouncer must run in **transaction** (or session) pool mode — statement mode
  would leak `SET LOCAL` across tenants and is refused at startup;
- application DB roles (`app_user`/`app_admin`/`app_observability`) are
  `NOBYPASSRLS`; only `app_migrator` is `BYPASSRLS`, for migrations/CI only.
  PRs that grant `BYPASSRLS`/superuser to an application role are auto-rejected.

A schema change PR additionally requires DBA review (CONVENTIONS §8).

## Security gates

The same checks CI enforces can be run locally as a subset:

```bash
make scan      # gitleaks + semgrep + pip-licenses
make sbom      # syft SBOM (CycloneDX + SPDX)
```

| Gate | Tool | Blocking condition |
|---|---|---|
| Secret scanning | `gitleaks` (`make scan-secrets`) | Any committed secret/credential |
| SAST | `semgrep` (`make scan-sast`, incl. OWASP Top Ten) | ERROR/WARNING findings |
| License policy | `pip-licenses` (`make scan-license`) | **GPL / AGPL / LGPL** dependencies are banned |
| SBOM | `syft` (`make sbom`) | Generates `sbom.cdx.json` + `sbom.spdx.json` |

Additional rules: never write secrets, passwords, or tokens into code, logs, or
error messages — configuration comes from ENV via `pydantic-settings`, and real
secrets are injected from Vault / K8s External Secrets in production
(CONVENTIONS §7). Critical/High security findings block merge.

## Pull request conventions

1. **Branch.** Work on a feature branch off `main`; do not push directly to
   `main`.
2. **Commits.** Use clear, imperative messages. When an OpenAPI change is
   breaking, the commit that makes it **must** carry a `BREAKING:` footer and
   bump the relevant major version (the oasdiff gate enforces this).
3. **Self-check before opening the PR:**

   ```bash
   make lint && make test
   make test-rls-fuzz        # if you touched any tenant table
   cd contracts/openapi && make ci   # if you touched any spec
   make scan                 # secrets / SAST / license
   ```

4. **Keep it conforming.** A PR that violates `docs/CONVENTIONS.md` will not be
   merged — fix the deviation or open an ADR for it first.
5. **Coverage.** Unit coverage ≥ 80% (≥ 90% on identity/authz/audit/billing
   paths); integration tests cover every public API. A coverage regression
   beyond the threshold blocks merge.
6. **Docs.** Update the affected service `README.md`, design doc, and (for
   architecture decisions) an ADR. Spec/SDK/implementation must land together.
7. **Review.** At least one maintainer approval is required; architectural or
   convention-affecting changes require a maintainer sign-off and an ADR per
   [GOVERNANCE.md](./GOVERNANCE.md).

## License

By contributing, you agree that your contributions are licensed under the
project's [Apache License 2.0](./LICENSE).

---

## 中文贡献指南

感谢你有意为 **SaaS Foundation** 做贡献。SaaS Foundation 是一个可复用的多租户
企业级底座（身份、鉴权、组织、计费、审计、加密、合规等），任何业务系统都可以在
其上构建（包括基于它实现的
[Agent Platform](https://github.com/chenzefeng09/agent-platform)）。由于大量系统
依赖这里的契约与隔离保证，贡献门槛较高：本指南及其链接的约定文档具有**强制约束力**，
违反约定的 PR 不予合并。

### 开发环境

前置依赖：Docker + Compose v2（Windows 走 WSL2）、Python 3.12+ 与 Poetry 1.8+、
Node.js 20+、可选的 Helm/kubectl。OpenAPI 工具链与安全扫描器均以 Docker 镜像
形式由对应的 `make` 目标拉取，无需在宿主机安装。

一键起本地栈（PostgreSQL/PgBouncer/Redis/Keycloak/ClickHouse/OpenSearch/Vault/
MinIO/OPA/Unleash/OTel+Jaeger/Mailhog 等依赖）：

```bash
make up-full          # 起依赖 → 等 Keycloak realm → post-up-init → healthcheck
```

分步等价：`make up && make post-up-init && make healthcheck`。随后初始化数据库与
种子数据：

```bash
make migrate && make seed
```

单包开发用 Poetry：`cd packages/identity && poetry install && poetry run pytest`。

### 约定契约（强制）

[`docs/CONVENTIONS.md`](./docs/CONVENTIONS.md) 是仓库最重要的契约，所有 package
的设计、代码、API、SDK、部署都必须遵守：

- **服务命名**：一个能力一个 service，命名 `<capability>-service`，短名取
  `<capability>`；不允许一个 service 塞多个能力。
- **URL**：`/api/<service>/v1/<resource>`，版本号在 URL 显式声明，不接受 header 版本。
- **JSON 字段一律 `snake_case`**，枚举值 `UPPER_SNAKE_CASE`，不使用
  `{code, data, message}` 包络。
- **四段式错误码** `FOUNDATION.<SERVICE>.<CATEGORY>.<NAME>`，错误响应遵循
  RFC 9457，详见 [`docs/errors.md`](./docs/errors.md)。
- **租户上下文由网关注入，客户端不可指定**；业务代码禁止给 SDK 传 `tenant_id=`
  参数（CI 静态扫描会报错），跨租户操作须用 `with sdk.as_tenant(...)` 并被审计。

### 契约优先（Contract-first）OpenAPI 流程

底座是契约优先的：[`contracts/openapi/`](./contracts/openapi/) 的 spec 是真相源，
SDK、文档、mock 均由其生成，**禁止先改服务代码再补 spec**。

1. 改 `contracts/openapi/<service>.yaml`（新服务复制 `_template.yaml`）。
2. Spectral 校验：`cd contracts/openapi && make lint`（单个用 `make lint-one SVC=<service>`）。
3. 破坏性变更门禁（oasdiff）：CI 在 PR 上跑 `make diff-base`；任何 breaking change
   被阻断，除非升 major 版本并在 commit 上加 `BREAKING:` footer。
4. 重新生成 SDK 并对齐实现：`make sdk-python` / `make sdk-typescript`（Go SDK 规划中，
   尚未生成）。spec、SDK、实现三者必须同 PR 落地，避免漂移。

### 强制 RLS 越权 fuzz 测试

多租户隔离是底座的核心承诺。**任何新增或改动租户表的 PR 都必须在该包的
`tests/security/` 下补 RLS 越权 fuzz 测试**，并通过：

```bash
make test-rls-fuzz
```

测试对租户表做大量随机化的跨租户读写，断言 A 租户调用方永远看不到/改不到 B 租户
的数据——即便业务 SQL 漏写 `WHERE tenant_id` 或遭遇注入。新表须满足
[`docs/multi-tenancy.md`](./docs/multi-tenancy.md) 的基线：带 `tenant_id` 列且
`ENABLE` + `FORCE ROW LEVEL SECURITY`（四条 policy）、连接 acquire 时事务内
`SET LOCAL app.tenant_id`、PgBouncer 必须事务级池化、应用角色 `NOBYPASSRLS`
（仅 `app_migrator` 为 `BYPASSRLS`）。schema 变更另需 DBA review。

### 安全门禁

```bash
make scan      # gitleaks + semgrep + pip-licenses（GPL/AGPL/LGPL 依赖禁止）
make sbom      # syft 生成 CycloneDX + SPDX SBOM
```

严禁在代码、日志、错误信息里出现密钥/密码/token；配置走 ENV + `pydantic-settings`，
生产密钥由 Vault / K8s External Secrets 注入。

### PR 约定

从 `main` 切分支开发，不直接推 `main`；提 PR 前自检
`make lint && make test`（动了租户表再加 `make test-rls-fuzz`，动了 spec 再加
`cd contracts/openapi && make ci`，外加 `make scan`）。单测覆盖率 ≥80%
（身份/鉴权/审计/计费路径 ≥90%），架构或约定相关改动需 maintainer sign-off + ADR
（见 [GOVERNANCE.md](./GOVERNANCE.md)）。贡献即表示同意以本项目的
[Apache-2.0](./LICENSE) 许可证授权。

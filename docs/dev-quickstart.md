# 开发快速上手 — 30 分钟跑起来

> 新人入职指引。读完跟着做一遍，本地能跑 service、能改代码、能跑测试。

## 0. 先读的 3 份文档

1. [CONVENTIONS.md](./CONVENTIONS.md) — 架构总约定（90% 的"为什么这样写"的答案在这里）
2. [multi-tenancy.md](./multi-tenancy.md) — RLS 多租户基线（**最容易踩坑**）
3. [errors.md](./errors.md) — 错误码规范

## 1. 环境要求

| 工具 | 版本 | 安装 |
|---|---|---|
| macOS / Linux | — | （Windows 用 WSL2） |
| Docker Desktop | 24+ | https://www.docker.com/products/docker-desktop |
| Docker Compose | v2 (集成在 Docker Desktop) | — |
| Python | 3.12+ | `brew install python@3.12` / `apt install python3.12` |
| Poetry | 1.8+ | `pipx install poetry` |
| Helm | 3.15+ | `brew install helm` |
| kubectl | 1.30+ | `brew install kubectl` |
| Node.js | 20+（只为 spectral / 前端） | `brew install node` |

可选：
- `K3s`（local helm 测试）`curl -sfL https://get.k3s.io | sh -`
- `mkcert`（local TLS）`brew install mkcert`

## 2. 克隆 & 起栈（5 分钟）

```bash
git clone <repo-url> saas-foundation
cd saas-foundation

# 一条龙（推荐）：起栈 → 等就绪 → 业务级初始化 → 健康检查
make up-full

# 或分步：
make up               # 起容器
make post-up-init     # Vault transit / MinIO bucket / KC Organization
make healthcheck      # 业务断言（含 OPA policy / Vault transit / KC realm / dev user 能登录）
```

第一次 `make up-full` 约 5-8 分钟（拉镜像 + 等 Keycloak 导入 realm）；之后约 1 分钟。

健康全绿后访问：

| | URL | 默认账号 |
|---|---|---|
| Keycloak | http://localhost:8080 | `admin` / `keycloak_admin_change_me` |
| MinIO | http://localhost:9002 | `foundation` / `minio_change_me_min_12_chars` |
| Vault | http://localhost:8200 | token `dev-root-token-change-me` |
| Jaeger | http://localhost:16686 | — |
| Mailhog | http://localhost:8025 | — |
| Unleash | http://localhost:4242 | API token `unleash-insecure-admin-api-token` |

## 3. 起一个 service（10 分钟）

> 当前 P0 阶段还没有 service，只有 SDK template；下面演示按模板新建一个 service 的流程，等 P0 #4 Identity 落地后流程一致。

```bash
# 1) 复制 SDK template，改名
cp -r sdks/python/_template sdks/python/foundation_identity
cd sdks/python/foundation_identity
# 把 foundation_template / TemplateClient 替换为 foundation_identity / IdentityClient
find . -type f -name '*.py' -exec sed -i '' 's/foundation_template/foundation_identity/g' {} +
find . -type f -name '*.py' -exec sed -i '' 's/TemplateClient/IdentityClient/g' {} +

# 2) 装依赖跑测试
poetry install
poetry run pytest

# 3) service 代码同理：把 packages/_template 复制为 packages/identity，按 CONVENTIONS §1.2 结构填
```

## 4. 跑数据库迁移 + seed（2 分钟）

```bash
make migrate    # 跑所有 package 的 alembic upgrade head
make seed       # 塞示例租户 / MinIO bucket / 示例审计事件
```

验证：

```bash
make psql       # 进 Postgres
\dt tenant.*    # 看到 tenant 表
SELECT * FROM tenant.tenant;
\q
```

## 5. 改代码、跑测试（3 分钟）

```bash
# 改一个 package 后
make -C packages/<svc> format
make -C packages/<svc> lint
make -C packages/<svc> test

# 或者全跑
make format
make lint
make test
```

## 6. 跑安全扫描（CI 等价子集）

```bash
make scan-secrets    # gitleaks
make scan-sast       # semgrep
make scan-license    # pip-licenses GPL/AGPL 黑名单
make scan            # 一次跑全
make sbom            # 生成 CycloneDX/SPDX SBOM
```

## 7. Helm 渲染验证

```bash
make helm-lint                       # 三档 profile 都 lint
make helm-render                     # 默认 small
make helm-render PROFILE=medium
make helm-render PROFILE=large
```

## 8. 常见操作速查

```bash
make logs SVC=keycloak              # 跟随某 service 日志
make psql                           # 进 Postgres super
make psql-pgbouncer                 # 通过 PgBouncer 进（验证 RLS）
make clickhouse                     # 进 ClickHouse client
make down                           # 停服务保留数据
make nuke                           # ⚠️ 停 + 删数据（不可恢复）
make clean                          # 清 __pycache__/.venv/.mypy_cache
```

## 9. PR 自查清单

提 PR 前必跑：

```bash
make format
make lint
make test
make scan
```

新增/修改租户表的 PR，再走一遍 [multi-tenancy.md §16](./multi-tenancy.md#16-检查清单pr-self-review)。

## 10. 卡住了怎么办

- **`docker compose up` 失败** → `make logs SVC=<x>` 看具体原因；常见是端口冲突，改 `.env` 里的 `PORT_*`
- **OpenSearch 起不来** → 提升 `vm.max_map_count`（见 docker-compose/README.md 常见故障）
- **Keycloak 卡在 `starting`** → 第一次启动需要建 schema + 导入 realm，等 2 分钟
- **RLS fuzz 测试失败** → 八成是 PgBouncer 模式不对，跑 `docker exec foundation-pgbouncer ... 'SHOW POOLS;'` 确认是 `transaction`
- **license 扫描挂在 GPL** → 看 `license-report-*.md`，找出依赖；要么换库要么走 ADR 评审接受风险

## 11. 团队约定

- 写代码前先看 CONVENTIONS / multi-tenancy / errors 三份
- 新增/修改 API 改 `contracts/openapi/<svc>.yaml`，CI spectral 会校验
- 新增错误码改 `packages/<svc>/src/foundation_<svc>/errors.py` + i18n 翻译
- 新增 DB 表必有 tenant_id + RLS + 测试（详见 multi-tenancy.md §6, §10）
- 新增第三方依赖前先看 license（GPL/AGPL 直接 ban，例外走 ADR）

## 12. 反馈

文档不清楚 / 命令跑不通 / 流程不顺，提 issue + label `dx`。

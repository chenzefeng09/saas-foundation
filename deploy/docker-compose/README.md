# 本地开发栈

一行命令拉起底座所需全部依赖：Postgres / PgBouncer / Redis / Keycloak / ClickHouse / OpenSearch / Vault / MinIO / OPA / Unleash / OTel + Jaeger / Mailhog。

## 快速开始

```bash
cd deploy/docker-compose
cp .env.example .env             # 必要时改密码
docker compose -f dev.yml up -d
docker compose -f dev.yml ps     # 看健康状态
```

第一次拉镜像约 3-5 分钟。所有服务起来后访问：

| 服务 | 地址 | 默认账号 |
|---|---|---|
| Keycloak | http://localhost:8080 | admin / keycloak_admin_change_me |
| Postgres（直连） | localhost:5432 | postgres / postgres_super_change_me |
| Postgres（通过 PgBouncer） | localhost:6432 | app_user / app_user_change_me |
| Redis | localhost:6379 | password: redis_change_me |
| ClickHouse HTTP | http://localhost:8123 | foundation / clickhouse_change_me |
| OpenSearch | http://localhost:9200 | —（dev 关闭了 security plugin，无 TLS / 认证） |
| Vault | http://localhost:8200 | token: dev-root-token-change-me |
| MinIO Console | http://localhost:9002 | foundation / minio_change_me_min_12_chars |
| OPA | http://localhost:8181 | — |
| Unleash | http://localhost:4242 | API token: unleash-insecure-admin-api-token |
| Jaeger UI | http://localhost:16686 | — |
| Mailhog UI | http://localhost:8025 | — |

## 验证清单

```bash
# 0. 一条命令跑完下面所有断言（make healthcheck 同款）
bash tools/dev/healthcheck.sh        # 在 repo 根目录执行

# 1. PgBouncer 模式必须是 transaction（关 RLS 安全的关键）
#    admin console 要密码：pgbouncer_admin 的密码见 config/pgbouncer/userlist.txt
docker exec -e PGPASSWORD="$PGBOUNCER_ADMIN_PASSWORD" foundation-pgbouncer \
    psql -h 127.0.0.1 -p 6432 -U pgbouncer_admin -d pgbouncer -c "SHOW POOLS;"
# 期望：pool_mode = transaction

# 2. 角色齐全
docker exec foundation-postgres psql -U postgres -d foundation \
    -c "SELECT rolname, rolbypassrls FROM pg_roles WHERE rolname LIKE 'app_%';"
# 期望：app_user/app_admin/app_observability NOBYPASSRLS；app_migrator BYPASSRLS

# 3. tenant 表 + seed 数据
docker exec foundation-postgres psql -U postgres -d foundation \
    -c "SELECT id, name, tier FROM tenant.tenant;"

# 4. ClickHouse audit 库
docker exec foundation-clickhouse clickhouse-client --query "SHOW TABLES FROM audit"

# 5. Keycloak 健康：KC 25 起 /health/* 只在管理端口 9000 上，dev.yml 没有对外发布
#    （宿主机 :9000 是 ClickHouse），所以从容器内问
docker exec foundation-keycloak bash -c 'exec 3<>/dev/tcp/127.0.0.1/9000 &&
  printf "GET /health/ready HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n" >&3 && cat <&3'
# 期望：{"status": "UP", ...}

# 5b. seed 用户能用 password grant 登录（只读，不打印密码）
KC_URL=http://localhost:8080 KC_REALM_FILE=init/keycloak/foundation-realm.json \
  python3 init/keycloak-seed/seed-dev-users.py --check

# 6. OTel collector 接得到事件
curl -X POST http://localhost:4318/v1/traces -H 'Content-Type: application/json' \
  -d '{"resourceSpans":[]}'
# 期望：200
```

## Seed 用户与 RBAC 绑定（dev）

`init/keycloak/foundation-realm.json` 带 4 个 seed 用户（密码就在该文件里），
`identity-init` 在 `identity."user"` 里登记它们的 seed 角色，`authz-init` 按同一张表建 RBAC 绑定
（两处在 `dev.yml` 里各写一份，改动时须保持一致）：

| 用户 | 租户 | seed 角色 |
|---|---|---|
| admin@foundation.local | Tenant A `tnt_01J5DEVXX00000000000000001` | super_admin |
| alice@tenant-a.local | Tenant A | member |
| bob@tenant-a.local | Tenant A | member |
| carol@tenant-b.local | Tenant B `tnt_01J5DEVXX00000000000000002` | member |

两个一次性 job 每次 `docker compose up` 都会重跑，都只碰上表这几个用户：

- **`keycloak-init`**（`init/keycloak-seed/seed-dev-users.py`）：Keycloak 只在第一次启动时导入
  realm，而 realm 的密码策略与生产一致、含 `forceExpiredPasswordChange(90)`，导入 90 天后 seed
  用户全部登录失败（`Account is not fully set up`）。job 按 realm 文件重设 seed 密码（非临时，
  90 天重新计时），把 required actions 还原为 realm 文件里的值（无），并清除 brute-force 锁定。
  密码策略不改，其他用户不碰；被禁用的 seed 用户保持禁用。**你给 seed 用户改的密码会在下次
  `up` 被还原**——测改密码流程请另建用户。
- **`authz-init`**（`packages/authz/scripts/bootstrap_tenant_roles.py`）：建三个系统角色，并按上表
  给 seed 用户建 TENANT 级绑定。规则：
  - 已有 ACTIVE 绑定 → 不动（不重复建、不修改）；
  - 从未有过这条绑定 → 新建；
  - 绑定已被管理员**撤销**或已**过期** → **也不动**：重跑 seed 不会把收回的授权悄悄还回去。
    要恢复，在 RBAC 管理页重新授予（新绑定），或手动带 `--restore-revoked` 跑一次脚本；两种方式
    都写一条新绑定，被撤销的那条留作审计历史；
  - 不在 seed 里的绑定（例如 alice 被撤销的 tenant_admin）从不读取、从不修改。

只想重跑这两个 job：

```bash
docker compose -f dev.yml --env-file .env up --no-deps keycloak-init authz-init
```

有意恢复一条被撤销的 seed 绑定（例：bob 的 member；在 `packages/authz` 下执行，默认连
localhost:5432 的 app_admin，可用 `--db-url` 覆盖）：

```bash
poetry run python scripts/bootstrap_tenant_roles.py --tenant-id tnt_01J5DEVXX00000000000000001 \
  --bind-user usr_01KT7TZ70AM2RK8P0C0BOB0001=member --restore-revoked
```

`GET /api/authz/v1/bindings` 默认只列 ACTIVE 绑定；看撤销/过期的历史用
`?filter.status=REVOKED`（或 `ACTIVE,EXPIRED,REVOKED`），每条都带 `status` 与 `revoked_at`。

## 常用操作

```bash
# 仅启动数据库相关
docker compose -f dev.yml up -d postgres pgbouncer redis

# 看某服务日志
docker compose -f dev.yml logs -f keycloak

# 进入 Postgres
docker exec -it foundation-postgres psql -U postgres -d foundation

# 进入 ClickHouse
docker exec -it foundation-clickhouse clickhouse-client

# 重启单个服务
docker compose -f dev.yml restart keycloak

# 完全清空（包括数据卷！）
docker compose -f dev.yml down -v

# 仅停服务保留数据
docker compose -f dev.yml down
```

## 与生产环境差异（必须了解）

| 维度 | 本地开发 | 生产 (medium/large) |
|---|---|---|
| Postgres | 单实例 | Patroni 集群（1 主 2 从） |
| Redis | 单实例 | Sentinel 3 节点 |
| OpenSearch | 单节点 dev 模式 | 3 master + N data |
| Vault | dev 模式（root token 明文） | Raft 集群 + Shamir 解封 + 审计后端 |
| ClickHouse | 单节点 | Replicated MergeTree + Keeper |
| Keycloak | start-dev | start + production realm 配置 |
| 密码 | 明文 .env | K8s External Secrets + Vault |
| TLS | 关闭 | mTLS + cert-manager |
| PgBouncer | 内嵌 docker | 独立 Deployment + HPA |

**任何在本地"碰巧能跑"的代码，到生产可能因为 HA 行为不同而出错。** 集成测试必须包含跨节点 failover 场景。

## 常见故障

### Postgres 启动失败
- 看 `docker compose -f dev.yml logs postgres`
- 大概率是 `init/postgres/*.sql` 语法错；删 `pg_data` 卷重建

### Keycloak 起得慢 / health 一直 starting
- 第一次启动需要建 schema + 导入 realm，可能要 1-2 分钟
- 看 `docker compose -f dev.yml logs -f keycloak`，等到 `Listening on: http://0.0.0.0:8080`
- `curl localhost:8080/health/ready` 返回 404 是正常的：KC 25 的 health 在容器内管理端口 9000（见验证清单第 5 步）

### seed 用户登录报 "Account is not fully set up"
- seed 密码超过 realm 策略的 90 天有效期了；重跑 `keycloak-init`（见上文「Seed 用户与 RBAC 绑定」）

### PgBouncer 报 auth_query 失败
- 检查 `config/pgbouncer/userlist.txt` 密码与 `.env` 一致
- 重启 `docker compose -f dev.yml restart pgbouncer`

### OpenSearch 报 vm.max_map_count
```bash
# macOS：
docker run --rm --privileged --pid=host alpine nsenter -t 1 -m sysctl -w vm.max_map_count=262144
# Linux：
sudo sysctl -w vm.max_map_count=262144
```

### 端口冲突
改 `.env` 里的 `PORT_*`，重启 `docker compose -f dev.yml up -d`。

## 后续

- 当 service 实际开发时，在自己机器上跑 `docker compose -f dev.yml up -d`
- service 启动时配 `DATABASE_URL=postgres://app_user:app_user_change_me@localhost:6432/foundation`（注意走 PgBouncer 端口 6432）
- service 自己跑 Alembic 迁移（用 app_migrator 凭据）
- M1 周内会出 helm chart（P0 #3.2），CI 会自动起类似栈跑集成测试（P0 #3.3）

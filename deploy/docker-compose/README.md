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
| OpenSearch | https://localhost:9200 | admin / OpenSearch_Change_Me_123! |
| Vault | http://localhost:8200 | token: dev-root-token-change-me |
| MinIO Console | http://localhost:9002 | foundation / minio_change_me_min_12_chars |
| OPA | http://localhost:8181 | — |
| Unleash | http://localhost:4242 | API token: unleash-insecure-admin-api-token |
| Jaeger UI | http://localhost:16686 | — |
| Mailhog UI | http://localhost:8025 | — |

## 验证清单

```bash
# 1. PgBouncer 模式必须是 transaction（关 RLS 安全的关键）
docker exec foundation-pgbouncer psql -h 127.0.0.1 -p 6432 \
    -U pgbouncer_admin -d pgbouncer -c "SHOW POOLS;"
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

# 5. Keycloak 健康
curl -s http://localhost:8080/health/ready | jq .

# 6. OTel collector 接得到事件
curl -X POST http://localhost:4318/v1/traces -H 'Content-Type: application/json' \
  -d '{"resourceSpans":[]}'
# 期望：200
```

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

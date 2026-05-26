# foundation-identity

> SaaS Foundation 身份服务：sessions / users / MFA / SSO / SCIM / 密码 & MFA & session 策略。
>
> 详见 [docs/design/identity-v1.md](../../docs/design/identity-v1.md) + [contracts/openapi/identity.yaml](../../contracts/openapi/identity.yaml)。

## 启动

### 本地（依赖底座 docker-compose 栈）

```bash
# 1. 起底座栈（postgres / keycloak / redis / vault / ...）
make -C ../.. up-full

# 2. 装依赖
poetry install

# 3. 跑迁移
poetry run alembic upgrade head

# 4. 启动
poetry run foundation-identity
# → http://localhost:8001
# → http://localhost:8001/api/identity/v1/healthz
# → http://localhost:8001/docs（FastAPI 自动 swagger）
```

### Docker

```bash
docker build -t foundation-identity:dev .
docker run --rm --network=foundation-dev_foundation -p 8001:8001 \
  --env-file ../../deploy/docker-compose/.env \
  foundation-identity:dev
```

## 测试

```bash
poetry run pytest                     # 全部
poetry run pytest -m unit             # 仅单元
poetry run pytest -m integration      # 需要 Postgres
poetry run pytest --cov               # 覆盖率
```

## 目录结构（CONVENTIONS §1.2）

```
src/foundation_identity/
├── api/             # FastAPI router 层（只做协议适配）
│   └── v1/
├── services/        # 业务逻辑（纯 Python）
├── domain/          # 领域模型 / SQLAlchemy ORM
├── adapters/        # 出站（Keycloak / Audit publisher / Redis）
├── events/          # 事件 schema + outbox publisher
├── schemas/         # pydantic 入参/出参（与 OpenAPI 对齐）
├── config.py        # pydantic-settings ENV
├── observability.py # OTel 初始化
├── errors.py        # 服务错误码
└── main.py          # FastAPI app 工厂
migrations/          # Alembic
tests/{unit,integration}/
```

## 强制约定

- **租户上下文必经 middleware 注入** → DB session `SET LOCAL app.tenant_id`（[multi-tenancy.md](../../docs/multi-tenancy.md)）
- **业务逻辑禁止写在 router**（CONVENTIONS §1.2）
- **所有 user-facing 错误走 RFC 9457**（[errors.md](../../docs/errors.md)）
- **API 与 contracts/openapi/identity.yaml 同步**；CI 会跑 spec/code drift 检测

# foundation-authz

> SaaS Foundation 授权服务：RBAC + OPA(ABAC) 双轨。
>
> 详见 [docs/design/authz-v1.md](../../docs/design/authz-v1.md)
> + [contracts/openapi/authz.yaml](../../contracts/openapi/authz.yaml)
> + [docs/design/opa-bundle-v1.md](../../docs/design/opa-bundle-v1.md)。

## 启动

```bash
# 1. 起底座栈
make -C ../.. up-full

# 2. 装依赖 + 迁移
poetry install
poetry run alembic upgrade head

# 3. 启动
poetry run foundation-authz       # → http://localhost:8002
```

## 关键端点

| 路径 | 用途 |
|---|---|
| `POST /api/authz/v1/check` | 单条权限检查（核心；最常调） |
| `POST /api/authz/v1/check:batch` | 批量检查 |
| `POST /api/authz/v1/list-accessible-ids` | 用户对 resource_type 的可见 ID 集合（搜索过滤用） |
| `GET/POST /api/authz/v1/roles` | 角色 CRUD |
| `GET/POST /api/authz/v1/bindings` | 角色绑定 |
| `GET /api/authz/v1/permissions` | 业务模块启动时注册的权限定义清单 |

## 测试

```bash
poetry run pytest                # 全部
poetry run pytest -m unit        # 仅单元
```

## 与 OPA 的分工

- **RBAC 决策**（90% 场景）：authz-service 本地查 `role_binding`，毫秒级返回
- **ABAC 决策**（policy_required 标记的权限）：转发到 OPA sidecar `/v1/data/foundation/authz/allow`
- **RLS 兜底**：Postgres RLS 在数据层强制 `tenant_id` 过滤，与 authz 双保险

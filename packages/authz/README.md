# foundation-authz

> SaaS Foundation 授权服务：RBAC + 强制等级控制（MAC）+ OPA 策略。
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
| `POST /api/authz/v1/list-accessible-ids` | RBAC 候选 ID 集合；结果未按资源敏感度过滤 |
| `GET/POST /api/authz/v1/roles` | 角色 CRUD |
| `GET/POST /api/authz/v1/bindings` | 角色绑定 |
| `GET /api/authz/v1/permissions` | 业务模块启动时注册的权限定义清单 |

## 测试

```bash
poetry run pytest                # 全部
poetry run pytest -m unit        # 仅单元
```

## 等级控制与 OPA

- **可信属性**：用户 `clearance` 从 Identity 获取，资源 `sensitivity` 从 DLP 获取；请求体不能声明这两个值，依赖异常时拒绝访问
- **RBAC 决策**：authz-service 本地查询有效 `role_binding` 与作用域
- **MAC 决策**：每次资源检查都要求 `rank(clearance) >= rank(sensitivity)`，仅接受 L1–L5
- **OPA 决策**：每次检查都转发到 OPA，同时执行 kill switch、MAC、MFA、双人审批、PAM、营业时间和合规策略
- **RLS 兜底**：Postgres RLS 在数据层强制 `tenant_id` 过滤，与 authz 双保险

容器部署必须配置 `AUTHZ_IDENTITY_URL` 与 `AUTHZ_DLP_URL` 指向对应服务的
`/api/identity/v1`、`/api/dlp/v1` 基础路径；本机开发默认分别使用 8001 和
18007 端口。

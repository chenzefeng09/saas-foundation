# foundation-org

> SaaS Foundation 组织服务：四层组织树 `Tenant → OrgUnit → Team → User`。
>
> 详见 [docs/design/org-v1.md](../../docs/design/org-v1.md)
> + [contracts/openapi/org.yaml](../../contracts/openapi/org.yaml)。

## 启动

```bash
# 1. 起底座栈
make -C ../.. up-full

# 2. 装依赖 + 迁移
poetry install
poetry run alembic upgrade head

# 3. 启动
poetry run foundation-org       # → http://localhost:8003
```

## 关键端点（M1 范围）

| 路径 | 用途 |
|---|---|
| `GET/POST /api/org/v1/org-units` | 部门 CRUD |
| `GET /api/org/v1/org-units/tree` | 整租户部门树（前端展示） |
| `GET /api/org/v1/org-units/{id}/descendants` | 后代列表（ltree O(log n)） |
| `GET /api/org/v1/org-units/{id}/ancestors` | 祖先列表 |
| `POST /api/org/v1/org-units/{id}/move` | 移动子树（改 parent_id） |
| `POST /api/org/v1/org-units/{id}/archive` | 归档（软停用） |
| `GET/POST /api/org/v1/teams` | 团队 CRUD |
| `GET/POST/DELETE /api/org/v1/teams/{id}/members` | 团队成员管理 |
| `GET/PUT /api/org/v1/users/{user_id}/membership` | 用户主属 OU |
| `POST /api/org/v1/users/{user_id}/transfer` | 调动（换 OU + team） |

## 测试

```bash
poetry run pytest                # 全部
poetry run pytest -m unit        # 仅单元
```

## 关键设计

- **存储**：邻接表 (`parent_id`) + ltree path 列冗余；GiST 索引让"后代/祖先"O(log n)
- **path 自动维护**：Postgres trigger 在 insert/update parent_id/code 时重算 `path` + `depth`
- **防环**：trigger 检查新 parent 不在自己后代里
- **多租户**：RLS（`tenant_id = current_setting('app.tenant_id')`）+ path 含 tenant_id 前缀双重隔离
- **事件**：所有 OU/Team/Membership 变更写 `org_event_outbox`，worker 投递到 Redis Streams（暂未实现 worker，写入即可）

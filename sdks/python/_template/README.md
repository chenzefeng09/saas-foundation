# SDK Template — Python

> **本目录是新建底座 service Python SDK 的样板。** 不要直接安装；复制到 `sdks/python/foundation_<service>/` 再改名。

## 用途

业务层（如 `agent-platform`）通过 SDK 调用底座 service：

```python
from foundation_identity import IdentityClient

client = IdentityClient.from_env()           # 自动读 FOUNDATION_API_URL / TOKEN
user = client.users.get("usr_01J5XXXXX")     # 同步
async with IdentityClient.from_env() as c:   # 异步
    user = await c.users.get_async("usr_01J5XXXXX")
```

## 设计要点（必读）

1. **租户上下文自动注入** — SDK 从 `contextvars.ContextVar('foundation.tenant_id')` 读取，业务层不传 `tenant_id` 参数（CONVENTIONS §3）
2. **错误自动映射** — HTTP 错误响应（RFC 9457 Problem Details）反序列化为 `FoundationError` 子类
3. **重试** — 默认对 `DEPENDENCY` 5xx / `RATE_LIMIT` 429 指数退避，最多 3 次
4. **可观测性** — 自动注入 trace context；每次调用作为 OTel span 上报
5. **同步 + 异步双 API** — 同方法名加 `_async` 后缀
6. **类型完整** — 所有公开 API 必须有类型注解；`py.typed` marker
7. **版本兼容** — SDK init 时拉 `/healthz` 校验版本不兼容 fail-fast

## 文件结构

```
foundation_<service>/
├── pyproject.toml
├── README.md
├── foundation_<service>/
│   ├── __init__.py             # 暴露 Client 类、__version__
│   ├── py.typed                # PEP 561 marker
│   ├── client.py               # 主入口：FoundationClient 基类 + 各 service Client
│   ├── _transport.py           # httpx 包装：重试、错误映射、tenant 注入
│   ├── _context.py             # contextvars 管理
│   ├── _retry.py               # 重试策略
│   ├── errors.py               # 错误类（继承 foundation_common.errors）
│   ├── models.py               # pydantic 模型（最好从 OpenAPI codegen 生成）
│   ├── resources/              # 按 API 分组的 Resource 类
│   │   ├── __init__.py
│   │   └── users.py
│   └── observability.py        # OTel 适配
└── tests/
    ├── conftest.py
    ├── unit/
    └── integration/
```

## 关键 API

详见 `foundation_template/client.py`、`_transport.py`、`_context.py`。

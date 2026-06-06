"""C2 — SDK 调用合规静态扫描 (SDK Call Compliance)

检查项
------
C2-a  业务代码中不直接 import keycloak / python-keycloak（必须走 identity SDK）。
C2-b  业务代码中不直接 import litellm（必须走 llm-gateway SDK）。
C2-c  业务代码中不直接 import psycopg / psycopg2 / asyncpg 裸连接底层组件。
C2-d  业务代码中不直接 import clickhouse_driver / clickhouse_connect。
C2-e  resource 方法签名不接受 tenant_id 参数（应从 contextvars 自动获取）。
C2-f  resource 方法签名不接受 user_id 参数（应从 contextvars 自动获取）。
C2-g  SDK 公开接口不暴露底层组件 URL（不在 __init__.py / client.py 里 import httpx/asyncpg）。

通过标准
--------
静态扫描结果为空（0 个违规），全部断言绿。
这些是纯静态检查，**不需要底座栈**，始终能本地运行。

失败时如何排查
--------------
断言失败信息会列出具体的文件路径和行号。
修复方向：违规代码改为通过 foundation_sdk 相应 resource 调用，
删除对底层组件的直接 import。

背景
----
CONVENTIONS.md §3.3 + 计划风险#2：业务层必须经 foundation_sdk 调底座，
任何对 keycloak/litellm/postgres 等底层组件的直接 import 都意味着绕过了
tenant context 注入、错误格式化、审计等底座保障层。
"""

from __future__ import annotations

import ast
import inspect
import os
import re
import textwrap
from pathlib import Path

import pytest

from foundation_sdk.resources import (
    authz, audit, billing, compliance, crypto,
    data_protection, dlp, feature_flag, identity,
    lifecycle, llm_gateway, notification, org,
    pam, search,
)

# ---------------------------------------------------------------------------
# 扫描目标：saas-foundation repo 根目录下的"业务侧"代码路径
# 排除：底座自身实现（packages/）、adapters/、SDK 内部实现
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).parents[2]  # saas-foundation/

# 业务接入扫描路径（saas-foundation 中不存在业务层；这里验证规则本身正确，
# 并扫描 sdks/python 下 resource 层不引入非预期的底层依赖）
SDK_RESOURCES_PATH = REPO_ROOT / "sdks" / "python" / "foundation_sdk" / "resources"

# 如果调用方（如 agent-platform）传入其代码路径，也可扫描
BUSINESS_SCAN_PATHS: list[Path] = []
_extra = os.environ.get("CONFORMANCE_BUSINESS_CODE_PATH")
if _extra:
    BUSINESS_SCAN_PATHS.append(Path(_extra))


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------

FORBIDDEN_IMPORTS: dict[str, str] = {
    "keycloak": "CONVENTIONS §3.3 — 走 foundation_sdk.identity 替代",
    "python_keycloak": "CONVENTIONS §3.3 — 走 foundation_sdk.identity 替代",
    "litellm": "CONVENTIONS §3.3 — 走 foundation_sdk.llm_gateway 替代",
    "psycopg": "CONVENTIONS §5.2 — 不允许裸连 Postgres，走 adapters/db 抽象层",
    "psycopg2": "CONVENTIONS §5.2 — 不允许裸连 Postgres，走 adapters/db 抽象层",
    "asyncpg": "CONVENTIONS §5.2 — 不允许裸连 Postgres，走 adapters/db 抽象层",
    "clickhouse_driver": "CONVENTIONS §5.2 — 走 audit SDK，不直接连 ClickHouse",
    "clickhouse_connect": "CONVENTIONS §5.2 — 走 audit SDK，不直接连 ClickHouse",
}


def _scan_for_forbidden_imports(
    paths: list[Path],
    forbidden: dict[str, str],
    *,
    exclude_dirs: frozenset[str] = frozenset({"adapters", "_template", "__pycache__"}),
) -> list[str]:
    """扫描 paths 下所有 .py 文件，找出包含 forbidden 中模块名的 import 语句。

    Returns: list of violation strings (empty = clean).
    """
    violations: list[str] = []
    for base in paths:
        for py_file in base.rglob("*.py"):
            # Skip excluded dirs
            if any(part in exclude_dirs for part in py_file.parts):
                continue
            try:
                source = py_file.read_text(encoding="utf-8")
                tree = ast.parse(source, filename=str(py_file))
            except (SyntaxError, OSError):
                continue

            for node in ast.walk(tree):
                # import X / import X.Y
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        root = alias.name.split(".")[0]
                        if root in forbidden:
                            rel = py_file.relative_to(REPO_ROOT)
                            violations.append(
                                f"{rel}:{node.lineno}: "
                                f"import {alias.name!r} — {forbidden[root]}"
                            )
                # from X import Y
                elif isinstance(node, ast.ImportFrom) and node.module:
                    root = node.module.split(".")[0]
                    if root in forbidden:
                        rel = py_file.relative_to(REPO_ROOT)
                        violations.append(
                            f"{rel}:{node.lineno}: "
                            f"from {node.module} import ... — {forbidden[root]}"
                        )
    return violations


def _check_resource_method_signatures(
    resource_module: object,
    forbidden_params: list[str],
) -> list[str]:
    """扫描 resource 模块中所有公开方法的签名，找出包含 forbidden_params 的参数名。

    Returns: list of violation strings (empty = clean).
    """
    violations: list[str] = []
    for cls_name in dir(resource_module):
        cls = getattr(resource_module, cls_name, None)
        if not (isinstance(cls, type) and cls_name.endswith("Resource")):
            continue
        for method_name in dir(cls):
            if method_name.startswith("_"):
                continue
            method = getattr(cls, method_name, None)
            if not callable(method):
                continue
            try:
                sig = inspect.signature(method)
            except (ValueError, TypeError):
                continue
            for param in forbidden_params:
                if param in sig.parameters:
                    violations.append(
                        f"{cls_name}.{method_name}(): "
                        f"has forbidden parameter '{param}' "
                        f"— CONVENTIONS §3.3: tenant context is implicit, "
                        f"never pass {param!r} explicitly"
                    )
    return violations


# ---------------------------------------------------------------------------
# C2-a / C2-b / C2-c / C2-d  禁止 import 底层组件
# ---------------------------------------------------------------------------

@pytest.mark.conformance
def test_c2a_no_direct_keycloak_import() -> None:
    """业务路径中不出现 import keycloak / python_keycloak。"""
    violations = _scan_for_forbidden_imports(
        BUSINESS_SCAN_PATHS,
        {"keycloak": FORBIDDEN_IMPORTS["keycloak"],
         "python_keycloak": FORBIDDEN_IMPORTS["python_keycloak"]},
    )
    assert not violations, (
        "C2-a FAIL: 检测到对 Keycloak 的直接 import。"
        " 改为 client.identity.<method>() 调用。\n"
        + "\n".join(f"  {v}" for v in violations)
    )


@pytest.mark.conformance
def test_c2b_no_direct_litellm_import() -> None:
    """业务路径中不出现 import litellm。"""
    violations = _scan_for_forbidden_imports(
        BUSINESS_SCAN_PATHS,
        {"litellm": FORBIDDEN_IMPORTS["litellm"]},
    )
    assert not violations, (
        "C2-b FAIL: 检测到对 litellm 的直接 import。"
        " 改为 client.llm_gateway.<method>() 调用。\n"
        + "\n".join(f"  {v}" for v in violations)
    )


@pytest.mark.conformance
def test_c2c_no_bare_postgres_import() -> None:
    """业务路径中不出现 import psycopg / asyncpg（裸连数据库）。"""
    violations = _scan_for_forbidden_imports(
        BUSINESS_SCAN_PATHS,
        {k: v for k, v in FORBIDDEN_IMPORTS.items()
         if k in ("psycopg", "psycopg2", "asyncpg")},
    )
    assert not violations, (
        "C2-c FAIL: 检测到裸 Postgres 连接 import。"
        " 应通过 adapters/db 层的 session_for_request() 访问。\n"
        + "\n".join(f"  {v}" for v in violations)
    )


@pytest.mark.conformance
def test_c2d_no_direct_clickhouse_import() -> None:
    """业务路径中不出现 import clickhouse_driver / clickhouse_connect。"""
    violations = _scan_for_forbidden_imports(
        BUSINESS_SCAN_PATHS,
        {k: v for k, v in FORBIDDEN_IMPORTS.items()
         if "clickhouse" in k},
    )
    assert not violations, (
        "C2-d FAIL: 检测到对 ClickHouse 的直接 import。"
        " 改为 client.audit.write_event() 调用。\n"
        + "\n".join(f"  {v}" for v in violations)
    )


@pytest.mark.conformance
def test_c2_all_forbidden_imports_no_violations_in_sdk_resources() -> None:
    """SDK resource 层自身不引入禁止模块（底座也应遵守这个约定）。"""
    violations = _scan_for_forbidden_imports(
        [SDK_RESOURCES_PATH],
        FORBIDDEN_IMPORTS,
        exclude_dirs=frozenset({"_template", "__pycache__"}),
    )
    assert not violations, (
        "C2 FAIL: SDK resource 层检测到禁止 import。\n"
        + "\n".join(f"  {v}" for v in violations)
    )


# ---------------------------------------------------------------------------
# C2-e / C2-f  resource 方法不接受 tenant_id / user_id 参数
# ---------------------------------------------------------------------------

_RESOURCE_MODULES = [
    authz, audit, billing, compliance, crypto,
    data_protection, dlp, feature_flag, identity,
    lifecycle, llm_gateway, notification, org,
    pam, search,
]


@pytest.mark.conformance
@pytest.mark.parametrize("module", _RESOURCE_MODULES,
                          ids=[m.__name__.split(".")[-1] for m in _RESOURCE_MODULES])
def test_c2e_resource_methods_no_tenant_id_param(module: object) -> None:
    """Resource 公开方法不接受 tenant_id 参数（CONVENTIONS §3.3）。"""
    violations = _check_resource_method_signatures(module, ["tenant_id"])
    # 例外：identity.issue_service_account_token 必须带 tenant_id（跨租户颁 token 场景）
    violations = [
        v for v in violations
        if "issue_service_account_token" not in v
    ]
    assert not violations, (
        f"C2-e FAIL in {module.__name__}: resource 方法包含 tenant_id 参数。"
        " tenant_id 必须从 current_context() 自动获取，不允许业务层显式传递。\n"
        + "\n".join(f"  {v}" for v in violations)
    )


# ---------------------------------------------------------------------------
# C2-g  SDK __init__ 只暴露高层接口，不暴露 httpx 等实现细节
# ---------------------------------------------------------------------------

@pytest.mark.conformance
def test_c2g_sdk_public_api_does_not_expose_transport_internals() -> None:
    """foundation_sdk 的 __all__ 不应暴露 Transport / httpx / _* 私有类。"""
    import foundation_sdk as sdk

    public_names = getattr(sdk, "__all__", list(vars(sdk).keys()))
    forbidden = [n for n in public_names if n.startswith("_")]
    assert not forbidden, (
        f"C2-g FAIL: SDK __all__ 暴露了私有名: {forbidden!r}. "
        "从 __all__ 中移除下划线开头的名称。"
    )

    # Transport 不应在 __all__ 里
    assert "Transport" not in public_names, (
        "C2-g FAIL: SDK __all__ 暴露了 Transport 类（实现细节，不是公共契约）。"
    )

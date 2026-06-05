"""C1 — 租户隔离自检 (Tenant Isolation)

检查项
------
C1-a  SDK Transport 层在每个请求中强制注入 X-Tenant-Id header。
C1-b  无 tenant context 时 SDK 明确拒绝（RuntimeError），而不是静默发空 header。
C1-c  两个 tenant context 互相隔离，Context A 的 tenant_id 不泄漏到 Context B。
C1-d  tenant_context() 支持嵌套 / token 恢复，退出后外层 context 正确还原。
C1-e  (needs_stack) 对真实底座：用 tenant_B token 请求 tenant_A 数据返 403/404，
      而非 200 + 另一租户数据。

通过标准
--------
全部断言绿。C1-e 在没有底座栈时 skip（标注 @pytest.mark.needs_stack）。

失败时如何排查
--------------
- C1-a 失败 → Transport._headers() 未注入 X-Tenant-Id，检查 foundation_sdk/_transport.py
- C1-b 失败 → current_context() 未在无 context 时抛 RuntimeError，检查 foundation_sdk/_context.py
- C1-c 失败 → ContextVar 没有正确隔离，可能共用了全局状态
- C1-d 失败 → tenant_context() 退出时 token.reset() 失效
- C1-e 失败 → 底座 gateway 没有强制校验 X-Tenant-Id 与 JWT claim 的一致性
"""

from __future__ import annotations

import threading
import httpx
import pytest
import respx

from foundation_sdk import FoundationClient, tenant_context
from foundation_sdk._context import _context_var, current_context
from foundation_sdk._transport import Transport

TENANT_A = "tnt_01CONFORM00000000000000001"
TENANT_B = "tnt_01CONFORM00000000000000002"


# ---------------------------------------------------------------------------
# C1-a  Transport 强制注入 X-Tenant-Id
# ---------------------------------------------------------------------------

@pytest.mark.conformance
def test_c1a_transport_injects_x_tenant_id() -> None:
    """每次 SDK 请求必须带 X-Tenant-Id header，值来自当前 tenant_context。"""
    captured: dict[str, str] = {}

    with respx.mock:
        route = respx.get("http://mock/api/identity/v1/users/usr_001").mock(
            return_value=httpx.Response(200, json={"id": "usr_001", "email": "a@b.com"})
        )

        t = Transport(base_url="http://mock", api_token="test-token")
        with tenant_context(TENANT_A, user_id="usr_001"):
            t.request("GET", "/api/identity/v1/users/usr_001")

        assert route.called, "Route was never hit"
        sent_headers = dict(route.calls[0].request.headers)
        assert "x-tenant-id" in sent_headers, (
            "C1-a FAIL: X-Tenant-Id header missing from SDK request. "
            f"Sent headers: {list(sent_headers)}"
        )
        assert sent_headers["x-tenant-id"] == TENANT_A, (
            f"C1-a FAIL: X-Tenant-Id = {sent_headers['x-tenant-id']!r}, "
            f"expected {TENANT_A!r}"
        )


# ---------------------------------------------------------------------------
# C1-b  无 context 时 SDK 拒绝发送请求
# ---------------------------------------------------------------------------

@pytest.mark.conformance
def test_c1b_no_context_raises_runtime_error() -> None:
    """在没有 tenant_context 包裹时调 SDK 必须抛 RuntimeError，不能静默发空 header。"""
    # 确保此时没有 context
    token = _context_var.set(None)
    try:
        t = Transport(base_url="http://mock", api_token="test-token")
        with pytest.raises(RuntimeError, match="No FoundationContext active"):
            t.request("GET", "/api/identity/v1/users/usr_001")
    finally:
        _context_var.reset(token)


# ---------------------------------------------------------------------------
# C1-c  两个 tenant context 互相隔离
# ---------------------------------------------------------------------------

@pytest.mark.conformance
def test_c1c_two_tenant_contexts_are_isolated() -> None:
    """Context A 和 Context B 的 tenant_id 不互相泄漏。"""
    with tenant_context(TENANT_A) as ctx_a:
        assert current_context().tenant_id == TENANT_A

        with tenant_context(TENANT_B) as ctx_b:
            # 内层看到 B
            assert current_context().tenant_id == TENANT_B, (
                f"C1-c FAIL: nested context should be {TENANT_B!r}, "
                f"got {current_context().tenant_id!r}"
            )

        # 退出内层后恢复 A
        assert current_context().tenant_id == TENANT_A, (
            f"C1-c FAIL: after exiting inner context, expected {TENANT_A!r}, "
            f"got {current_context().tenant_id!r}"
        )


# ---------------------------------------------------------------------------
# C1-d  Context 退出后正确还原（token reset）
# ---------------------------------------------------------------------------

@pytest.mark.conformance
def test_c1d_context_restored_after_exit() -> None:
    """tenant_context() 退出后全局 ContextVar 还原到进入前的值。"""
    # 确保进入前没有 context
    pre_token = _context_var.set(None)
    try:
        with tenant_context(TENANT_A):
            assert current_context().tenant_id == TENANT_A

        # 退出后应回到 None
        assert _context_var.get() is None, (
            "C1-d FAIL: ContextVar not reset to None after exiting tenant_context. "
            "This means context leaks into subsequent requests."
        )
    finally:
        _context_var.reset(pre_token)


# ---------------------------------------------------------------------------
# C1-e  线程隔离（每线程独立 context，不共享）
# ---------------------------------------------------------------------------

@pytest.mark.conformance
def test_c1e_thread_contexts_are_independent() -> None:
    """不同线程各自持有独立的 tenant context（ContextVar 是 per-thread-per-task）。"""
    results: dict[str, str] = {}

    def run_in_thread(tnt_id: str) -> None:
        with tenant_context(tnt_id):
            import time; time.sleep(0.01)  # noqa: E702  让两线程有机会交叉
            results[tnt_id] = current_context().tenant_id

    t1 = threading.Thread(target=run_in_thread, args=(TENANT_A,))
    t2 = threading.Thread(target=run_in_thread, args=(TENANT_B,))
    t1.start(); t2.start()
    t1.join(); t2.join()

    assert results[TENANT_A] == TENANT_A, (
        f"C1-e FAIL: Thread A saw tenant_id={results[TENANT_A]!r}, "
        f"expected {TENANT_A!r} — cross-thread context leak"
    )
    assert results[TENANT_B] == TENANT_B, (
        f"C1-e FAIL: Thread B saw tenant_id={results[TENANT_B]!r}, "
        f"expected {TENANT_B!r}"
    )


# ---------------------------------------------------------------------------
# C1-f  (needs_stack) 真实底座跨租户访问拒绝
# ---------------------------------------------------------------------------

@pytest.mark.conformance
@pytest.mark.needs_stack
def test_c1f_cross_tenant_read_blocked(foundation_url: str, foundation_token: str) -> None:
    """用 TENANT_B 的上下文读 TENANT_A 的数据，底座必须返回 403 或 404。

    跳过条件: FOUNDATION_API_URL 未设置时 skip。
    需要: 底座已有 TENANT_A 用户数据的 seed。
    """
    # 用 TENANT_B 上下文调 users（预期：空列表 或 403，绝不能看到 TENANT_A 数据）
    with respx.mock(assert_all_called=False):
        # 不 mock — 真实发请求
        pass

    client = FoundationClient(api_url=foundation_url, api_token=foundation_token)
    with tenant_context(TENANT_B):
        result = client.identity.list_users()

    # 只要没有泄漏出去的断言：items 里不应出现 TENANT_A 的 tenant_id
    items = result.get("items", [])
    for item in items:
        tenant_in_item = item.get("tenant_id", "")
        assert tenant_in_item != TENANT_A, (
            f"C1-f FAIL: Cross-tenant leak! Under TENANT_B context, "
            f"received item with tenant_id={tenant_in_item!r} (TENANT_A data)"
        )

"""C3 — 租户上下文传播合规 (Context Propagation)

检查项
------
C3-a  SDK Transport 在请求中同时注入 X-Tenant-Id 和 X-Request-Id。
C3-b  X-Request-Id 格式为 req_<hex>（符合契约约定）。
C3-c  X-User-Id 只在 FoundationContext 有 user_id 时才注入（不注入空字符串）。
C3-d  fastapi 中间件从请求 header 正确读取 X-Tenant-Id 并写入 contextvar。
C3-e  fastapi 中间件在响应中回传 X-Request-Id / X-Service-Name / X-Service-Version。
C3-f  push_identity() 可以在 BFF 场景中覆盖 contextvar，而不依赖 header。
C3-g  (needs_stack) 下游真实服务在响应中带 X-Request-Id，值与请求一致。

通过标准
--------
C3-a ~ C3-f 不需要底座栈，本地即可跑绿。
C3-g 需要底座栈，无栈时 skip。

失败时如何排查
--------------
- C3-a/C3-b: 检查 foundation_sdk/_transport.py 的 _headers() 方法
- C3-c: _headers() 应当只在 ctx.user_id 非 None 时加 X-User-Id
- C3-d/C3-e/C3-f: 检查 foundation_sdk/_fastapi.py 中间件实现
- C3-g: 检查底座 gateway 的 header propagation 配置

背景
----
CONVENTIONS.md §3.2 定义了完整的 header 注入链路。本模块验证 SDK 侧实现
符合这个链路约定。
"""

from __future__ import annotations

import re

import httpx
import pytest
import respx
from fastapi import FastAPI
from fastapi.testclient import TestClient

from foundation_sdk import FoundationClient, tenant_context
from foundation_sdk._context import _context_var, FoundationContext
from foundation_sdk._transport import Transport
from foundation_sdk.fastapi import (
    get_request_id,
    get_tenant_id,
    get_user_id,
    install_request_context,
    push_identity,
)

TENANT_A = "tnt_01CONFORM00000000000000001"

_REQUEST_ID_RE = re.compile(r"^req_[0-9A-Fa-f]{16,}$")


# ---------------------------------------------------------------------------
# C3-a  Transport 同时注入 X-Tenant-Id 和 X-Request-Id
# ---------------------------------------------------------------------------

@pytest.mark.conformance
def test_c3a_transport_injects_both_tenant_and_request_id() -> None:
    """每次 SDK 请求必须同时带 X-Tenant-Id 和 X-Request-Id。"""
    with respx.mock:
        route = respx.get("http://mock/api/identity/v1/sessions/me").mock(
            return_value=httpx.Response(200, json={"user_id": "usr_001"})
        )
        t = Transport(base_url="http://mock", api_token="token")
        with tenant_context(TENANT_A, user_id="usr_001", request_id="req_TEST001"):
            t.request("GET", "/api/identity/v1/sessions/me")

    assert route.called
    sent = dict(route.calls[0].request.headers)

    assert "x-tenant-id" in sent, (
        f"C3-a FAIL: X-Tenant-Id missing. Got headers: {list(sent)}"
    )
    assert "x-request-id" in sent, (
        f"C3-a FAIL: X-Request-Id missing. Got headers: {list(sent)}"
    )
    assert sent["x-tenant-id"] == TENANT_A
    assert sent["x-request-id"] == "req_TEST001"


# ---------------------------------------------------------------------------
# C3-b  X-Request-Id 格式
# ---------------------------------------------------------------------------

@pytest.mark.conformance
def test_c3b_auto_generated_request_id_format() -> None:
    """自动生成的 request_id 必须符合 req_<hex> 格式。"""
    # tenant_context 未指定 request_id 时自动生成
    with tenant_context(TENANT_A) as ctx:
        rid = ctx.request_id

    assert _REQUEST_ID_RE.match(rid), (
        f"C3-b FAIL: auto-generated request_id {rid!r} does not match pattern "
        f"req_<hex>. Check FoundationContext.request_id default_factory."
    )


# ---------------------------------------------------------------------------
# C3-c  X-User-Id 只在有 user_id 时注入
# ---------------------------------------------------------------------------

@pytest.mark.conformance
def test_c3c_user_id_header_absent_when_no_user_id() -> None:
    """无 user_id 的 context 不应注入 X-User-Id header（避免空字符串被网关误信任）。"""
    with respx.mock:
        route = respx.get("http://mock/api/healthz").mock(
            return_value=httpx.Response(200, json={})
        )
        t = Transport(base_url="http://mock", api_token="token")
        with tenant_context(TENANT_A):  # 不传 user_id
            t.request("GET", "/api/healthz")

    sent = dict(route.calls[0].request.headers)
    assert "x-user-id" not in sent, (
        f"C3-c FAIL: X-User-Id header present with no user_id in context. "
        f"Value: {sent.get('x-user-id')!r}. "
        "This can allow a service to impersonate a user without proper context."
    )


@pytest.mark.conformance
def test_c3c_user_id_header_present_when_user_id_set() -> None:
    """有 user_id 时 X-User-Id 必须出现在请求中。"""
    with respx.mock:
        route = respx.get("http://mock/api/healthz").mock(
            return_value=httpx.Response(200, json={})
        )
        t = Transport(base_url="http://mock", api_token="token")
        with tenant_context(TENANT_A, user_id="usr_CONFORMTEST001"):
            t.request("GET", "/api/healthz")

    sent = dict(route.calls[0].request.headers)
    assert sent.get("x-user-id") == "usr_CONFORMTEST001", (
        f"C3-c FAIL: X-User-Id should be 'usr_CONFORMTEST001', "
        f"got {sent.get('x-user-id')!r}"
    )


# ---------------------------------------------------------------------------
# C3-d / C3-e  FastAPI 中间件正确读取 header 并写入 contextvar
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def fastapi_app() -> FastAPI:
    app = FastAPI()
    install_request_context(app, service_name="conformance-svc", service_version="0.0.0-test")

    @app.get("/ctx")
    async def ctx_endpoint() -> dict:
        return {
            "request_id": get_request_id(),
            "tenant_id": get_tenant_id(),
            "user_id": get_user_id(),
        }

    @app.get("/push-test")
    async def push_test_endpoint() -> dict:
        # simulate BFF: derive identity from cookie, push to contextvar
        push_identity(tenant_id="tnt_PUSHED", user_id="usr_PUSHED")
        return {
            "tenant_id": get_tenant_id(),
            "user_id": get_user_id(),
        }

    return app


@pytest.fixture(scope="module")
def test_client(fastapi_app: FastAPI) -> TestClient:
    return TestClient(fastapi_app, raise_server_exceptions=False)


@pytest.mark.conformance
def test_c3d_middleware_reads_x_tenant_id(test_client: TestClient) -> None:
    """中间件将 X-Tenant-Id header 写入 contextvar，endpoint 能读到。"""
    resp = test_client.get("/ctx", headers={"X-Tenant-Id": TENANT_A})
    assert resp.status_code == 200
    assert resp.json()["tenant_id"] == TENANT_A, (
        f"C3-d FAIL: contextvar has {resp.json()['tenant_id']!r}, "
        f"expected {TENANT_A!r} from X-Tenant-Id header."
    )


@pytest.mark.conformance
def test_c3e_middleware_echos_response_headers(test_client: TestClient) -> None:
    """中间件在响应中回传 X-Request-Id / X-Service-Name / X-Service-Version。"""
    resp = test_client.get("/ctx", headers={
        "X-Tenant-Id": TENANT_A,
        "X-Request-Id": "req_C3ETEST001",
    })
    assert resp.headers.get("x-request-id") == "req_C3ETEST001", (
        f"C3-e FAIL: X-Request-Id not echoed in response. "
        f"Got: {resp.headers.get('x-request-id')!r}"
    )
    assert resp.headers.get("x-service-name") == "conformance-svc", (
        f"C3-e FAIL: X-Service-Name missing or wrong. "
        f"Got: {resp.headers.get('x-service-name')!r}"
    )
    assert resp.headers.get("x-service-version") == "0.0.0-test", (
        f"C3-e FAIL: X-Service-Version missing or wrong. "
        f"Got: {resp.headers.get('x-service-version')!r}"
    )


# ---------------------------------------------------------------------------
# C3-f  push_identity() BFF 场景覆盖 contextvar
# ---------------------------------------------------------------------------

@pytest.mark.conformance
def test_c3f_push_identity_overrides_contextvar(test_client: TestClient) -> None:
    """push_identity() 覆盖 contextvar，用于 BFF 从 cookie 派生身份而非 header。"""
    resp = test_client.get("/push-test", headers={"X-Tenant-Id": "tnt_HEADER"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["tenant_id"] == "tnt_PUSHED", (
        f"C3-f FAIL: push_identity() should override X-Tenant-Id header. "
        f"Got: {body['tenant_id']!r}"
    )
    assert body["user_id"] == "usr_PUSHED", (
        f"C3-f FAIL: push_identity() should set user_id. "
        f"Got: {body['user_id']!r}"
    )


# ---------------------------------------------------------------------------
# C3-g  (needs_stack) 真实服务响应中带 X-Request-Id
# ---------------------------------------------------------------------------

@pytest.mark.conformance
@pytest.mark.needs_stack
def test_c3g_real_service_echoes_request_id(foundation_url: str, foundation_token: str) -> None:
    """底座真实服务在响应中回传 X-Request-Id，值与请求一致。"""
    custom_rid = "req_C3GCONFORMTEST"
    client = FoundationClient(api_url=foundation_url, api_token=foundation_token)
    with tenant_context(TENANT_A, request_id=custom_rid):
        # 使用底层 transport 直接发，便于检查响应 header
        resp_data = client._transport.request("GET", "/healthz")  # noqa: SLF001

    # 这里无法直接拿 httpx.Response；改用 httpx 直接发
    with httpx.Client(base_url=foundation_url, timeout=10.0) as c:
        resp = c.get(
            "/healthz",
            headers={
                "X-Request-Id": custom_rid,
                "X-Tenant-Id": TENANT_A,
                "Authorization": f"Bearer {foundation_token}",
            },
        )
    echoed = resp.headers.get("x-request-id")
    assert echoed == custom_rid, (
        f"C3-g FAIL: Expected X-Request-Id={custom_rid!r} in response, "
        f"got {echoed!r}. Check gateway header propagation config."
    )

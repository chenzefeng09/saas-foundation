"""C5 — DLP 下载检查 & BFF Cookie 安全合规 (DLP Check & Cookie Security)

检查项
------
C5-a  DLP Resource.check_download() 在每次调用时注入 X-Tenant-Id（DLP 检查必须带租户）。
C5-b  (needs_stack) 真实底座对 L4 级文件的下载请求，无 DLP check 应返回 403 COMPLIANCE。
C5-c  CookieSigner 使用强 secret（≥32 字符）才能构造，弱 secret 启动即失败。
C5-d  CookieSigner 占位符 secret（含 change-me 等）被拒绝，防止忘配 env 时产生可伪造 cookie。
C5-e  篡改 cookie payload 后验证失败（tamper-proof 保证租户 ID 不可被客户端更改）。
C5-f  跨 salt 的 cookie 不被接受（不同 cookie 家族互不可验）。
C5-g  cookie 过期后抛 SignatureExpiredError，而不是 SignatureInvalid。
C5-h  CookieSigner 的 sign/unsign 是 round-trip 幂等的（相同 payload 可还原）。

通过标准
--------
C5-a / C5-c ~ C5-h 不需要底座栈，本地即可跑绿。
C5-b 需要底座栈，无栈时 skip。

失败时如何排查
--------------
- C5-a: 检查 Transport._headers() — DLP 调用也走 Transport，需要 tenant_context
- C5-b: 检查底座 dlp-service 的 check-download 逻辑和合规策略配置
- C5-c/C5-d: 检查 foundation_sdk/_signing.py CookieSigner._validate_secret()
- C5-e: itsdangerous HMAC 实现问题，通常不会发生
- C5-f: 检查 CookieSignerSettings.salt 是否实际被 URLSafeTimedSerializer 使用
- C5-g: itsdangerous SignatureExpired 映射到 SignatureExpiredError 的路径

背景
----
CONVENTIONS.md §3.5 ("BFF cookie") + docs/errors.md FOUNDATION.COMPLIANCE.DLP.DOWNLOAD_BLOCKED。
业务 BFF 必须用 CookieSigner 签名 session cookie，禁止明文 JSON + base64 存 tenant_id。
"""

from __future__ import annotations

import time

import httpx
import pytest
import respx

from foundation_sdk import (
    CookieSigner,
    CookieSignerSettings,
    SignatureExpiredError,
    SignatureInvalid,
    FoundationClient,
    tenant_context,
)
from foundation_sdk._transport import Transport

TENANT_A = "tnt_01CONFORM00000000000000001"

_STRONG_SECRET = "c0nf0rm4nc3-t3st-s3cr3t-key-x" * 2  # 62 chars


# ---------------------------------------------------------------------------
# C5-a  DLP check_download 注入 X-Tenant-Id
# ---------------------------------------------------------------------------

@pytest.mark.conformance
def test_c5a_dlp_check_download_injects_tenant_id() -> None:
    """DLP Resource 的每次调用必须携带 X-Tenant-Id（DLP check 是租户级策略）。"""
    with respx.mock:
        route = respx.post("http://mock/api/dlp/v1/check-download").mock(
            return_value=httpx.Response(200, json={"allowed": True, "policy": "L2_ALLOW"})
        )
        t = Transport(base_url="http://mock", api_token="token")

        # 将 DLPResource 挂到这个 transport
        from foundation_sdk.resources.dlp import DLPResource
        dlp = DLPResource(t)

        with tenant_context(TENANT_A):
            dlp.check_download(file_id="file_001", sensitivity="L2")

    assert route.called
    sent = dict(route.calls[0].request.headers)
    assert "x-tenant-id" in sent, (
        "C5-a FAIL: X-Tenant-Id missing from DLP check-download request. "
        "DLP policies are tenant-scoped; missing tenant context means "
        "the wrong policy may be applied."
    )
    assert sent["x-tenant-id"] == TENANT_A, (
        f"C5-a FAIL: X-Tenant-Id = {sent['x-tenant-id']!r}, expected {TENANT_A!r}"
    )


# ---------------------------------------------------------------------------
# C5-b  (needs_stack) 无 DLP check 的 L4 下载被拒
# ---------------------------------------------------------------------------

@pytest.mark.conformance
@pytest.mark.needs_stack
def test_c5b_l4_download_blocked_without_dlp_check(
    foundation_url: str, foundation_token: str,
) -> None:
    """L4 级敏感文件未经 DLP 检查直接下载，底座应返回 403 COMPLIANCE。

    跳过条件: FOUNDATION_API_URL 未设置时 skip。
    """
    client = FoundationClient(api_url=foundation_url, api_token=foundation_token)
    from foundation_sdk.errors import ComplianceError, PolicyError
    with tenant_context(TENANT_A):
        with pytest.raises((ComplianceError, PolicyError)) as exc_info:
            # 没有先调 check_download，直接触发下载（底座应阻断）
            client.dlp.check_download(file_id="file_L4_no_prior_check", sensitivity="L4")

    exc = exc_info.value
    assert exc.http_status in (403, 451), (
        f"C5-b FAIL: Expected 403/451 (DLP block), got {exc.http_status}. "
        "Configure dlp-service to require explicit check for L4 content."
    )


# ---------------------------------------------------------------------------
# C5-c  弱 secret 拒绝
# ---------------------------------------------------------------------------

@pytest.mark.conformance
@pytest.mark.parametrize("weak", ["", "short", "x" * 31])
def test_c5c_weak_secret_rejected_at_construction(weak: str) -> None:
    """CookieSigner 对 <32 字符 secret 在构造时立即抛 ValueError。"""
    with pytest.raises(ValueError, match=r"≥ 32 chars"):
        CookieSigner(CookieSignerSettings(secret_key=weak))


# ---------------------------------------------------------------------------
# C5-d  占位符 secret 拒绝
# ---------------------------------------------------------------------------

@pytest.mark.conformance
@pytest.mark.parametrize("placeholder", [
    "change-me-please-this-is-32-chars!!",
    "CHANGE-ME-PLEASE-THIS-IS-32-CHARS!!",
    "this-secret-key-here-is-also-bad-no",
    "default-cookie-secret-32-chars-min",
])
def test_c5d_placeholder_secret_rejected(placeholder: str) -> None:
    """CookieSigner 对含占位符的 secret 在构造时抛 ValueError。"""
    with pytest.raises(ValueError, match="forbidden placeholder"):
        CookieSigner(CookieSignerSettings(secret_key=placeholder))


# ---------------------------------------------------------------------------
# C5-e  篡改 cookie payload 被检测到
# ---------------------------------------------------------------------------

@pytest.mark.conformance
def test_c5e_tampered_cookie_rejected() -> None:
    """客户端篡改 cookie payload（例如修改 tenant_id）必须被 CookieSigner 拒绝。"""
    signer = CookieSigner(CookieSignerSettings(secret_key=_STRONG_SECRET))
    token = signer.sign({"user_id": "usr_a", "tenant_id": "tnt_a"})

    # 翻转 token 最后几个字符（payload section）
    tampered = token[:-3] + ("A" if token[-3] != "A" else "B") + token[-2:]
    with pytest.raises(SignatureInvalid):
        signer.unsign(tampered)


# ---------------------------------------------------------------------------
# C5-f  跨 salt 的 cookie 不被接受
# ---------------------------------------------------------------------------

@pytest.mark.conformance
def test_c5f_cross_salt_cookie_rejected() -> None:
    """用 salt='bff-session' 签名的 cookie 不能被 salt='bff-csrf' 验证（防跨用途攻击）。"""
    signer_session = CookieSigner(CookieSignerSettings(
        secret_key=_STRONG_SECRET, salt="bff-session"
    ))
    signer_csrf = CookieSigner(CookieSignerSettings(
        secret_key=_STRONG_SECRET, salt="bff-csrf"
    ))
    token = signer_session.sign({"tenant_id": "tnt_a"})
    with pytest.raises(SignatureInvalid):
        signer_csrf.unsign(token)


# ---------------------------------------------------------------------------
# C5-g  过期 cookie 抛 SignatureExpiredError（非 SignatureInvalid）
# ---------------------------------------------------------------------------

@pytest.mark.conformance
def test_c5g_expired_cookie_raises_distinct_error() -> None:
    """过期 cookie 必须抛 SignatureExpiredError，而不是 SignatureInvalid。

    这让 BFF 能区分 "需要重新登录"（过期）和 "有人篡改"（非法签名）。
    """
    signer = CookieSigner(CookieSignerSettings(
        secret_key=_STRONG_SECRET, max_age_seconds=1
    ))
    token = signer.sign({"tenant_id": "tnt_a"})
    time.sleep(2.2)
    with pytest.raises(SignatureExpiredError):
        signer.unsign(token)


# ---------------------------------------------------------------------------
# C5-h  sign/unsign round-trip 幂等
# ---------------------------------------------------------------------------

@pytest.mark.conformance
def test_c5h_sign_unsign_roundtrip() -> None:
    """CookieSigner 的 sign → unsign 是无损 round-trip。"""
    signer = CookieSigner(CookieSignerSettings(secret_key=_STRONG_SECRET))
    payload = {
        "user_id": "usr_01CONFORMTEST000001",
        "tenant_id": TENANT_A,
        "display_name": "体检用户",
    }
    token = signer.sign(payload)
    recovered = signer.unsign(token)
    assert recovered == payload, (
        f"C5-h FAIL: round-trip mismatch. Expected {payload!r}, got {recovered!r}"
    )

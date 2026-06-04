"""Tests for foundation_sdk._signing.CookieSigner.

The signer is the single recommended way for business-layer BFFs to persist
opaque session state in a browser cookie.  The contract these tests pin:

* Tampering with the payload invalidates the signature (cannot escalate tenant).
* Expired cookies surface as a distinct exception so BFFs can re-issue.
* Construction fails fast on weak / placeholder secrets so a missing env var
  blows up at startup instead of silently producing forgeable cookies.
"""

from __future__ import annotations

import time

import pytest

from foundation_sdk import CookieSigner, CookieSignerSettings, SignatureExpiredError, SignatureInvalid

_STRONG_SECRET = "x" * 48  # well above the 32-char minimum
_ALT_SECRET = "y" * 48


@pytest.fixture
def signer() -> CookieSigner:
    return CookieSigner(CookieSignerSettings(secret_key=_STRONG_SECRET))


def test_sign_then_unsign_roundtrips(signer: CookieSigner) -> None:
    payload = {"user_id": "usr_01J5USER000000000000000001", "tenant_id": "tnt_01J5T000"}
    token = signer.sign(payload)
    assert signer.unsign(token) == payload


def test_tampered_payload_is_rejected(signer: CookieSigner) -> None:
    token = signer.sign({"user_id": "usr_a", "tenant_id": "tnt_a"})
    # Flip the last char of the payload section.  itsdangerous tokens look like
    # "<b64-payload>.<timestamp>.<sig>"; any flip in the payload breaks the HMAC.
    tampered = token[:-3] + ("A" if token[-3] != "A" else "B") + token[-2:]
    with pytest.raises(SignatureInvalid):
        signer.unsign(tampered)


def test_signature_from_different_secret_is_rejected() -> None:
    alice = CookieSigner(CookieSignerSettings(secret_key=_STRONG_SECRET))
    eve = CookieSigner(CookieSignerSettings(secret_key=_ALT_SECRET))
    forged = alice.sign({"tenant_id": "tnt_victim"})
    with pytest.raises(SignatureInvalid):
        eve.unsign(forged)


def test_expired_token_raises_distinct_error() -> None:
    # itsdangerous timestamp precision is one second; sleep long enough that
    # max_age=1 has definitely elapsed even with scheduler jitter.
    signer = CookieSigner(
        CookieSignerSettings(secret_key=_STRONG_SECRET, max_age_seconds=1),
    )
    token = signer.sign({"tenant_id": "tnt_a"})
    time.sleep(2.2)
    with pytest.raises(SignatureExpiredError):
        signer.unsign(token)


def test_explicit_max_age_overrides_default() -> None:
    # Default max_age is 24h; verify per-call override actually tightens it.
    signer = CookieSigner(
        CookieSignerSettings(secret_key=_STRONG_SECRET, max_age_seconds=86_400),
    )
    token = signer.sign({"tenant_id": "tnt_a"})
    time.sleep(2.2)
    # With default it would still pass; explicit short max_age must reject.
    assert signer.unsign(token) == {"tenant_id": "tnt_a"}
    with pytest.raises(SignatureExpiredError):
        signer.unsign(token, max_age_seconds=1)


@pytest.mark.parametrize("weak", ["", "short", "x" * 31])
def test_short_secret_rejected(weak: str) -> None:
    with pytest.raises(ValueError, match=r"≥ 32 chars"):
        CookieSigner(CookieSignerSettings(secret_key=weak))


@pytest.mark.parametrize(
    "placeholder",
    [
        "change-me-please-this-is-32-chars!!",
        "CHANGE-ME-PLEASE-THIS-IS-32-CHARS!!",
        "this-secret-key-here-is-also-bad-no",
        "default-cookie-secret-32-chars-min",
    ],
)
def test_placeholder_secret_rejected(placeholder: str) -> None:
    with pytest.raises(ValueError, match="forbidden placeholder"):
        CookieSigner(CookieSignerSettings(secret_key=placeholder))


def test_different_salts_do_not_cross_verify() -> None:
    a = CookieSigner(CookieSignerSettings(secret_key=_STRONG_SECRET, salt="bff-session"))
    b = CookieSigner(CookieSignerSettings(secret_key=_STRONG_SECRET, salt="bff-csrf"))
    token = a.sign({"tenant_id": "tnt_a"})
    with pytest.raises(SignatureInvalid):
        b.unsign(token)


def test_unsign_rejects_non_dict_payload(signer: CookieSigner) -> None:
    # _serializer accepts any JSON-serialisable value; we intentionally reject
    # non-dict payloads so callers don't accidentally store opaque strings.
    raw_token = signer._serializer.dumps("just-a-string")  # noqa: SLF001 — testing
    with pytest.raises(SignatureInvalid, match="must be dict"):
        signer.unsign(raw_token)

"""RFC 3161 Time-Stamp Authority (TSA) client.

Constructs a TSP TimeStampRequest, POSTs it to the configured TSA,
and returns the base64-encoded TimeStampToken + the timestamp datetime.

Library: rfc3161ng (pip install rfc3161ng).
Fallback: if TSA is unreachable or returns an error, logs a warning and
returns (None, None) — TSA failure MUST NOT block the main audit chain.

# TODO(SM2/SM3 — crypto v1.1):
#   When using hash_algorithm == "SM3", replace hashlib.sha256 with SM3
#   and switch to NTSC TSA endpoint (settings.tsa_url).
#   SM3 OID: 1.2.156.10197.1.401
#   Requires: Tongsuo Python bindings or gmssl library.
#   Not implemented here — no dependency available in current build.
"""

from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime

import httpx

from foundation_audit.config import get_settings
from foundation_audit.observability import get_logger

log = get_logger(__name__)


async def request_timestamp(
    merkle_root_hex: str,
) -> tuple[str | None, datetime | None]:
    """Request an RFC 3161 timestamp for the given Merkle root.

    Args:
        merkle_root_hex: 64-char hex string.

    Returns:
        (tsa_token_b64, tsa_timestamp) on success.
        (None, None) on any failure (TSA down, network error, parse error).
        Failure is logged as WARNING and does NOT raise.
    """
    s = get_settings()
    tsa_url = str(s.tsa_url)

    # Hash the root (SHA-256 of the hex-decoded bytes)
    root_bytes = bytes.fromhex(merkle_root_hex)
    message_imprint = hashlib.sha256(root_bytes).digest()

    # Attempt to use rfc3161ng if available
    try:
        import rfc3161ng  # type: ignore[import-untyped]
        tsr_data = rfc3161ng.make_timestamp_request(
            data=root_bytes,
            hash_algorithm=hashlib.sha256,
            nonce=True,
            cert=True,
        )
        tsa_token_b64, tsa_ts = await _send_tsr(tsa_url, tsr_data)
        if tsa_token_b64 is None:
            return None, None
        # Parse TST to extract genTime
        tst = rfc3161ng.decode_timestamp_response(
            base64.b64decode(tsa_token_b64) if isinstance(tsa_token_b64, str) else tsa_token_b64  # type: ignore[arg-type]
        )
        gen_time = rfc3161ng.get_timestamp(tst)
        if isinstance(gen_time, datetime):
            ts = gen_time.replace(tzinfo=UTC) if gen_time.tzinfo is None else gen_time
        else:
            ts = datetime.now(UTC)
        return tsa_token_b64, ts

    except ImportError:
        log.warning("tsa.rfc3161ng.not_installed", hint="pip install rfc3161ng")
        # Fall back to raw RFC 3161 request (minimal ASN.1 hand-craft)
        return await _request_timestamp_raw(tsa_url, root_bytes, message_imprint)
    except Exception as exc:
        log.warning("tsa.request.failed", error=str(exc), tsa_url=tsa_url)
        return None, None


async def _send_tsr(tsa_url: str, tsr_data: bytes) -> tuple[str | None, None]:
    """POST a TSR to the TSA endpoint, return base64 DER response or (None, None)."""
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                tsa_url,
                content=tsr_data,
                headers={"Content-Type": "application/timestamp-query"},
            )
            resp.raise_for_status()
            token_b64 = base64.b64encode(resp.content).decode()
            return token_b64, None
    except (httpx.HTTPStatusError, httpx.RequestError, Exception) as exc:
        log.warning("tsa.http.failed", error=str(exc), tsa_url=tsa_url)
        return None, None


async def _request_timestamp_raw(
    tsa_url: str,
    root_bytes: bytes,
    message_imprint: bytes,
) -> tuple[str | None, datetime | None]:
    """Minimal hand-crafted RFC 3161 TSP request without rfc3161ng.

    Constructs a DER-encoded TimeStampReq manually (SHA-256 OID).
    This is a best-effort fallback; prefer rfc3161ng in production.
    """
    try:
        # SHA-256 AlgorithmIdentifier OID: 2.16.840.1.101.3.4.2.1
        sha256_oid = bytes([
            0x30, 0x0d,  # SEQUENCE
            0x06, 0x09,  # OID tag + length 9
            0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,  # sha256
            0x05, 0x00,  # NULL
        ])
        # MessageImprint ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING }
        hashed_msg = bytes([0x04, len(message_imprint)]) + message_imprint
        msg_imprint_inner = sha256_oid + hashed_msg
        msg_imprint = bytes([0x30, len(msg_imprint_inner)]) + msg_imprint_inner

        # version INTEGER { v1(1) }
        version = bytes([0x02, 0x01, 0x01])

        # certReq BOOLEAN DEFAULT FALSE → omit (defaults to false per RFC)
        # nonce — omit for simplicity

        # TimeStampReq ::= SEQUENCE { version INTEGER, messageImprint MessageImprint, certReq BOOLEAN OPTIONAL }
        tsr_inner = version + msg_imprint
        tsr = bytes([0x30, len(tsr_inner)]) + tsr_inner

        token_b64, _ = await _send_tsr(tsa_url, tsr)
        if token_b64 is None:
            return None, None
        # We can't easily parse the TST without rfc3161ng; use current time as approximation
        return token_b64, datetime.now(UTC)
    except Exception as exc:
        log.warning("tsa.raw.failed", error=str(exc))
        return None, None

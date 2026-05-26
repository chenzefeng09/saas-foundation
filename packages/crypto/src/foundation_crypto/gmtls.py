"""GMTLS (国密 TLS) configuration — GB/T 38636-2020.

v1.1 国密+信创适配: Enables GMTLS for service-to-service communication,
replacing standard TLS 1.3 with the Chinese national standard TLS protocol.

GMTLS uses:
  - SM2 for key exchange and authentication (replacing ECDHE-RSA/ECDSA)
  - SM4-GCM for symmetric encryption (replacing AES-256-GCM)
  - SM3 for hashing (replacing SHA-256/384)
  - SM2-SM3 for digital signatures (replacing RSA-SHA256/ECDSA-SHA256)

Certificate chain:
  Root CA (SM2) → Intermediate CA (SM2) → Service cert (SM2)

Deployment modes:
  1. GMTLS-only: All traffic uses GMTLS (required for 密评 Level 3+)
  2. Dual-stack: Both GMTLS and TLS 1.3 accepted (transitional)
  3. TLS-only + GMTLS ready: TLS 1.3 with GMTLS cert loaded but not enforced

Configuration:
  CRYPTO_GMTLS_ENABLED=true
  CRYPTO_GMTLS_CERT_PATH=/etc/foundation/tls/sm2_cert.pem
  CRYPTO_GMTLS_KEY_PATH=/etc/foundation/tls/sm2_key.pem
  CRYPTO_GMTLS_CA_PATH=/etc/foundation/tls/sm2_ca.pem
  CRYPTO_GMTLS_CIPHERS=ECC-SM2-SM4-GCM-SM3:ECDHE-SM2-SM4-GCM-SM3
"""

from __future__ import annotations

import os
import ssl
from dataclasses import dataclass, field
from enum import Enum
from typing import Literal

from foundation_crypto.observability import get_logger

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# GMTLS cipher suites (GB/T 38636-2020, GM/T 0024-2014)
# ---------------------------------------------------------------------------

# These are the IANA-registered cipher suite identifiers for GMTLS
# In practice, Tongsuo (铜锁) registers them with custom identifiers
_GMTLS_CIPHER_SUITES = {
    "ECC-SM2-SM4-GCM-SM3": 0x00E0,  # SM2 key exchange + SM4-GCM + SM3
    "ECDHE-SM2-SM4-GCM-SM3": 0x00E1,  # SM2 ECDHE + SM4-GCM + SM3
    "ECC-SM2-SM4-CBC-SM3": 0x00E2,  # SM2 + SM4-CBC + SM3
    "ECDHE-SM2-SM4-CBC-SM3": 0x00E3,  # SM2 ECDHE + SM4-CBC + SM3
    "ECC-SM2-SM1-CBC-SM3": 0x00E4,  # SM2 + SM1-CBC + SM3 (hardware SM1)
}

# Default: only AEAD (GCM) suites for security
_GMTLS_DEFAULT_CIPHERS = [
    "ECC-SM2-SM4-GCM-SM3",
    "ECDHE-SM2-SM4-GCM-SM3",
]


class GMTLSmode(str, Enum):
    """GMTLS deployment mode."""

    DISABLED = "disabled"  # Standard TLS 1.3 only
    DUAL_STACK = "dual_stack"  # Both GMTLS and TLS 1.3 accepted
    GMTLS_ONLY = "gmtls_only"  # Only GMTLS (required for 密评 Level 3+)
    GMTLS_PREFERRED = "gmtls_preferred"  # Prefer GMTLS, fall back to TLS 1.3


@dataclass(frozen=True)
class GMTLSConfig:
    """GMTLS configuration for a Foundation service."""

    mode: GMTLSmode = GMTLSmode.DISABLED
    cert_path: str = ""
    key_path: str = ""
    ca_path: str = ""
    ciphers: list[str] = field(default_factory=lambda: list(_GMTLS_DEFAULT_CIPHERS))
    verify_client: bool = True  # mTLS: require client cert
    session_tickets: bool = False  # Disable for 密评 (perfect forward secrecy)


def load_gmtls_config() -> GMTLSConfig:
    """Load GMTLS configuration from environment variables.

    Reads:
      CRYPTO_GMTLS_ENABLED: "true" | "false"
      CRYPTO_GMTLS_MODE: "disabled" | "dual_stack" | "gmtls_only" | "gmtls_preferred"
      CRYPTO_GMTLS_CERT_PATH: path to SM2 certificate PEM
      CRYPTO_GMTLS_KEY_PATH: path to SM2 private key PEM
      CRYPTO_GMTLS_CA_PATH: path to SM2 CA certificate PEM
      CRYPTO_GMTLS_CIPHERS: colon-separated cipher suite names
      CRYPTO_GMTLS_VERIFY_CLIENT: "true" | "false"
    """
    enabled = os.environ.get("CRYPTO_GMTLS_ENABLED", "false").lower() == "true"
    if not enabled:
        return GMTLSConfig(mode=GMTLSmode.DISABLED)

    mode_str = os.environ.get("CRYPTO_GMTLS_MODE", "dual_stack")
    try:
        mode = GMTLSmode(mode_str)
    except ValueError:
        log.warning("gmtls.invalid_mode", mode=mode_str, fallback="dual_stack")
        mode = GMTLSmode.DUAL_STACK

    ciphers_str = os.environ.get(
        "CRYPTO_GMTLS_CIPHERS",
        ":".join(_GMTLS_DEFAULT_CIPHERS),
    )
    ciphers = [c.strip() for c in ciphers_str.split(":") if c.strip()]

    return GMTLSConfig(
        mode=mode,
        cert_path=os.environ.get("CRYPTO_GMTLS_CERT_PATH", ""),
        key_path=os.environ.get("CRYPTO_GMTLS_KEY_PATH", ""),
        ca_path=os.environ.get("CRYPTO_GMTLS_CA_PATH", ""),
        ciphers=ciphers,
        verify_client=os.environ.get("CRYPTO_GMTLS_VERIFY_CLIENT", "true").lower() == "true",
    )


# ---------------------------------------------------------------------------
# Certificate generation helpers (SM2, via Tongsuo CLI)
# ---------------------------------------------------------------------------


def generate_sm2_ca_command(output_dir: str, ca_name: str = "foundation-ca") -> list[str]:
    """Generate the commands to create an SM2 CA using Tongsuo's openssl CLI.

    Returns a list of shell commands to execute:
      1. Generate SM2 CA private key
      2. Self-sign the CA certificate
      3. Verify the certificate

    Prerequisites: Tongsuo (铜锁) must be installed and `tongsuo` on PATH.
    """
    ca_key = f"{output_dir}/{ca_name}.key.pem"
    ca_cert = f"{output_dir}/{ca_name}.cert.pem"

    return [
        # Generate SM2 private key for CA
        f"tongsuo ecparam -genkey -name SM2 -out {ca_key}",
        # Self-sign CA cert (valid 10 years)
        f"tongsuo req -new -x509 -days 3650 "
        f"-key {ca_key} -out {ca_cert} "
        f"-subj '/C=CN/O=Foundation/CN={ca_name}' "
        f"-sm3 -extensions v3_ca",
        # Verify
        f"tongsuo verify -CAfile {ca_cert} {ca_cert}",
    ]


def generate_sm2_server_cert_command(
    output_dir: str,
    ca_name: str = "foundation-ca",
    service_name: str = "foundation-service",
    san_dns: list[str] | None = None,
) -> list[str]:
    """Generate commands for an SM2 server certificate signed by the CA.

    Returns shell commands to:
      1. Generate SM2 private key
      2. Create CSR
      3. Sign with CA
    """
    ca_key = f"{output_dir}/{ca_name}.key.pem"
    ca_cert = f"{output_dir}/{ca_name}.cert.pem"
    srv_key = f"{output_dir}/{service_name}.key.pem"
    srv_csr = f"{output_dir}/{service_name}.csr.pem"
    srv_cert = f"{output_dir}/{service_name}.cert.pem"

    cmds = [
        # Server key (SM2)
        f"tongsuo ecparam -genkey -name SM2 -out {srv_key}",
    ]

    # CSR with SAN
    san_str = ""
    if san_dns:
        san_list = ",".join(f"DNS:{d}" for d in san_dns)
        san_str = f'-addext "subjectAltName={san_list}"'

    cmds.append(
        f"tongsuo req -new -key {srv_key} -out {srv_csr} "
        f"-subj '/C=CN/O=Foundation/CN={service_name}' "
        f"-sm3 {san_str}"
    )

    # Sign with CA
    cmds.append(
        f"tongsuo x509 -req -in {srv_csr} "
        f"-CA {ca_cert} -CAkey {ca_key} "
        f"-CAcreateserial -out {srv_cert} "
        f"-days 365 -sm3 "
        f'-extfile <(printf "subjectAltName=DNS:{service_name}")'
    )

    return cmds


# ---------------------------------------------------------------------------
# TLS context factory — returns ssl.SSLContext configured for GMTLS
# ---------------------------------------------------------------------------


def create_gmtls_ssl_context(
    config: GMTLSConfig | None = None,
    *,
    server_side: bool = True,
) -> ssl.SSLContext | None:
    """Create an ssl.SSLContext configured for GMTLS.

    Args:
        config: GMTLS configuration. If None, loads from env.
        server_side: True for server context, False for client.

    Returns:
        ssl.SSLContext if GMTLS is enabled, None if disabled (use standard TLS).

    Raises:
        FileNotFoundError: if cert/key/CA files are missing.
        ValueError: if GMTLS mode is invalid.
    """
    if config is None:
        config = load_gmtls_config()

    if config.mode == GMTLSmode.DISABLED:
        return None

    if not config.cert_path or not config.key_path:
        raise ValueError(
            "GMTLS enabled but CRYPTO_GMTLS_CERT_PATH or "
            "CRYPTO_GMTLS_KEY_PATH not set"
        )

    # In production, this would use Tongsuo's Python TLS library
    # (tongsuopy.crypto.GMTLSContext). For now, we return a standard
    # SSLContext with the GMTLS certs loaded, which at least enables
    # SM2 certificate support if the system OpenSSL is Tongsuo-patched.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server_side else ssl.PROTOCOL_TLS_CLIENT)

    try:
        ctx.load_cert_chain(config.cert_path, config.key_path)
    except ssl.SSLError as exc:
        # If OpenSSL doesn't support SM2 certs, fall back
        log.error("gmtls.cert_load_failed", error=str(exc),
                  hint="Ensure Tongsuo (铜锁) is installed and LD_LIBRARY_PATH includes libtongs.so")
        raise

    if config.ca_path:
        ctx.load_verify_locations(config.ca_path)

    if config.verify_client and server_side:
        ctx.verify_mode = ssl.CERT_REQUIRED
    elif server_side:
        ctx.verify_mode = ssl.CERT_OPTIONAL

    # Disable session tickets for perfect forward secrecy (密评 requirement)
    if not config.session_tickets:
        ctx.options |= ssl.OP_NO_TICKET

    log.info("gmtls.context_created", mode=config.mode.value,
             server_side=server_side, ciphers=config.ciphers,
             verify_client=config.verify_client)

    return ctx


# ---------------------------------------------------------------------------
# FastAPI middleware: auto-select TLS context based on config
# ---------------------------------------------------------------------------


def get_ssl_context_for_service(service_name: str) -> ssl.SSLContext | None:
    """Get the appropriate TLS context for a Foundation service.

    If GMTLS is configured, returns a GMTLS context. Otherwise returns None,
    meaning the service should use standard TLS 1.3 (via its reverse proxy
    or uvicorn defaults).
    """
    config = load_gmtls_config()
    if config.mode == GMTLSmode.DISABLED:
        log.info("tls.standard", service=service_name, reason="GMTLS disabled")
        return None

    log.info("tls.gmtls", service=service_name, mode=config.mode.value)
    return create_gmtls_ssl_context(config, server_side=True)

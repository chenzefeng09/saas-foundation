"""seed algorithm registry

Revision ID: 0002_seed_algorithms
Revises: 0001_crypto_init
Create Date: 2026-05-26 15:10:00 UTC

Seeds the crypto.algorithm table with international and 国密 algorithms.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0002_seed_algorithms"
down_revision: str | None = "0001_crypto_init"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SEEDS = [
    # (id, kind, family, provider, key_size_bits, fips_140, gm_certified, description, min_compliance_modes)
    # -- SYMMETRIC
    ("AES-256-GCM", "SYMMETRIC", "AES", "openssl", 256, True, False,
     "AES-256 in Galois/Counter Mode (NIST SP 800-38D)", []),
    ("SM4-GCM", "SYMMETRIC", "SM4", "tongsuo", 128, False, True,
     "SM4 in Galois/Counter Mode (GM/T 0002-2012)", ["equal_protection_4", "finance_jrt0071"]),
    # -- ASYMMETRIC_SIGN
    ("ECDSA-P256", "ASYMMETRIC_SIGN", "ECDSA", "openssl", 256, True, False,
     "ECDSA on NIST P-256 with SHA-256 (FIPS 186-5)", []),
    ("Ed25519", "ASYMMETRIC_SIGN", "Ed25519", "openssl", 256, False, False,
     "Ed25519 (RFC 8032); fast, constant-time, no prehash needed", []),
    ("SM2", "ASYMMETRIC_SIGN", "SM2", "tongsuo", 256, False, True,
     "SM2 digital signature with SM3 hash (GM/T 0003-2012)", ["equal_protection_4", "finance_jrt0071"]),
    # -- ASYMMETRIC_ENCRYPT
    ("RSA-4096", "ASYMMETRIC_ENCRYPT", "RSA", "openssl", 4096, True, False,
     "RSA-OAEP with SHA-256 (PKCS#1 v2.2)", []),
    ("SM2-ENCRYPT", "ASYMMETRIC_ENCRYPT", "SM2", "tongsuo", 256, False, True,
     "SM2 public-key encryption (GM/T 0003-2012)", ["equal_protection_4", "finance_jrt0071"]),
    # -- HASH
    ("SHA-256", "HASH", "SHA2", "openssl", 256, True, False,
     "SHA-256 (FIPS 180-4)", []),
    ("SM3", "HASH", "SM3", "tongsuo", 256, False, True,
     "SM3 cryptographic hash (GM/T 0004-2012)", ["equal_protection_4", "finance_jrt0071"]),
    # -- HMAC
    ("HMAC-SHA-256", "HMAC", "SHA2", "openssl", 256, True, False,
     "HMAC with SHA-256 (RFC 2104)", []),
    ("HMAC-SM3", "HMAC", "SM3", "tongsuo", 256, False, True,
     "HMAC with SM3 (GM/T 0004-2012)", ["equal_protection_4", "finance_jrt0071"]),
    # -- KDF
    ("HKDF-SHA-256", "KDF", "SHA2", "openssl", 256, True, False,
     "HKDF with SHA-256 (RFC 5869)", []),
    ("KDF-SM3", "KDF", "SM3", "tongsuo", 256, False, True,
     "Key derivation with SM3", ["equal_protection_4", "finance_jrt0071"]),
    # -- PASSWORD_HASH
    ("Argon2id", "PASSWORD_HASH", "Argon2", "openssl", None, False, False,
     "Argon2id (RFC 9106); memory-hard, side-channel resistant", []),
    # -- TLS_SUITE
    ("TLS-1.3-AEAD", "TLS_SUITE", "TLS", "openssl", None, False, False,
     "TLS 1.3 with AEAD cipher suites (RFC 8446)", []),
    ("GMTLS-v1.1", "TLS_SUITE", "TLS", "tongsuo", None, False, True,
     "国密 TLS 协议 (GB/T 38636-2020)", ["equal_protection_4", "finance_jrt0071"]),
    # -- RNG
    ("DRBG-HMAC-SHA256", "RNG", "DRBG", "openssl", 256, True, False,
     "NIST SP 800-90A HMAC_DRBG with SHA-256", []),
]


def upgrade() -> None:
    rows = []
    for row in _SEEDS:
        (alg_id, kind, family, provider, key_size, fips, gm, desc, modes) = row
        # Build a PostgreSQL text[] literal: '{val1,val2}' or '{}'
        modes_pg = "'{" + ",".join(modes) + "}'::text[]"
        rows.append(
            f"('{alg_id}', '{kind}', '{family}', '{provider}', "
            f"{key_size if key_size is not None else 'NULL'}, "
            f"{'TRUE' if fips else 'FALSE'}, {'TRUE' if gm else 'FALSE'}, "
            f"{'NULL' if desc is None else f'$${desc}$$'}, "
            f"{modes_pg})"
        )

    values = ",\n  ".join(rows)
    op.execute(f"""
        INSERT INTO crypto.algorithm
            (id, kind, family, provider, key_size_bits, fips_140, gm_certified,
             description, min_compliance_modes)
        VALUES
            {values}
        ON CONFLICT (id) DO NOTHING
    """)


def downgrade() -> None:
    ids = ", ".join(f"'{r[0]}'" for r in _SEEDS)
    op.execute(f"DELETE FROM crypto.algorithm WHERE id IN ({ids})")

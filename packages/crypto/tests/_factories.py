"""ORM-object factory helpers for crypto tests."""

from __future__ import annotations

from datetime import UTC, datetime

from foundation_crypto.domain.models import Algorithm, KEK, KEKHistory, Outbox


def make_algorithm(
    *,
    algo_id: str = "AES-256-GCM",
    kind: str = "SYMMETRIC",
    family: str = "AES",
    provider: str = "openssl",
    key_size_bits: int | None = 256,
    fips_140: bool = True,
    gm_certified: bool = False,
    deprecated: bool = False,
) -> Algorithm:
    return Algorithm(
        id=algo_id,
        kind=kind,
        family=family,
        provider=provider,
        key_size_bits=key_size_bits,
        fips_140=fips_140,
        gm_certified=gm_certified,
        deprecated=deprecated,
        description=f"{algo_id} test algorithm",
    )


def make_kek(
    *,
    kek_id: str = "kek_01J00000000000000000000001",
    tenant_id: str = "tnt_01J0000000000000000000TNT1",
    label: str = "pii.phone",
    purpose: str = "FIELD_ENCRYPT",
    algorithm_id: str = "AES-256-GCM",
    vault_path: str = "transit/keys/pii.phone_kek_01J00000000000000000000001",
    status: str = "ACTIVE",
    current_version: int = 1,
    auto_rotate_days: int = 90,
) -> KEK:
    now = datetime.now(UTC)
    return KEK(
        id=kek_id,
        tenant_id=tenant_id,
        label=label,
        purpose=purpose,
        algorithm_id=algorithm_id,
        vault_path=vault_path,
        current_version=current_version,
        min_decryption_version=1,
        auto_rotate_days=auto_rotate_days,
        status=status,
        last_rotated_at=now,
        created_at=now,
        updated_at=now,
        created_by="usr_01J0000000000000000000ACT1",
    )


def make_signing_kek(
    *,
    kek_id: str = "kek_01J00000000000000000000002",
    tenant_id: str = "tnt_01J0000000000000000000TNT1",
    label: str = "audit.hashchain",
    purpose: str = "AUDIT_HMAC",
    algorithm_id: str = "Ed25519",
    vault_path: str = "transit/keys/audit.hashchain_kek_01J00000000000000000000002",
    status: str = "ACTIVE",
) -> KEK:
    return make_kek(
        kek_id=kek_id,
        tenant_id=tenant_id,
        label=label,
        purpose=purpose,
        algorithm_id=algorithm_id,
        vault_path=vault_path,
        status=status,
    )


def outbox_events_of_type(added: list[object], event_type: str) -> list[Outbox]:
    return [o for o in added if isinstance(o, Outbox) and o.event_type == event_type]

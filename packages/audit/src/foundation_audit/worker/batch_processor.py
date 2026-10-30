"""Batch processor worker — outbox → ClickHouse + hash chain + signature + TSA + WORM.

Runs as a background loop:
  1. Fetch pending rows from Postgres outbox.
  2. For each event: load chain head from ClickHouse (restart-safe), compute prev/curr hash.
  3. Bulk-insert events into ClickHouse with merkle_batch_id + merkle_leaf_idx.
  4. Seal Merkle batch:
     a. Compute Merkle root from all curr_hashes.
     b. Call crypto-service to sign root (Ed25519).
     c. Call TSA for RFC 3161 timestamp (failure is non-blocking).
  5. Insert audit.merkle_batch row.
  6. For SECURITY/CRITICAL events: WORM double-write (failure is non-blocking).
  7. Mark outbox rows as delivered. On CH write failure: increment attempts/last_error,
     do NOT mark delivered (outbox acts as retry queue).
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from typing import Any

from foundation_audit.adapters import clickhouse as ch
from foundation_audit.adapters import crypto_client, tsa, worm
from foundation_audit.config import get_settings
from foundation_audit.domain.db import system_session_scope
from foundation_audit.observability import get_logger
from foundation_audit.services.hash_chain import (
    canonical_event,
    compute_chain_hash,
    compute_merkle_root,
)
from foundation_audit.services.ingest_service import IngestService

log = get_logger(__name__)


class BatchProcessor:
    """Continuously drain the outbox to ClickHouse."""

    def __init__(self) -> None:
        self._settings = get_settings()
        self._ingest = IngestService()
        self._running = False
        # In-memory chain head cache (populated from CH on first use, so restart-safe)
        self._chain_heads: dict[tuple[str, str], str] = {}
        # Track whether we've fetched the chain head from CH for each (tenant, service)
        self._ch_heads_fetched: set[tuple[str, str]] = set()

    async def _get_chain_head(self, tenant_id: str, service: str) -> str | None:
        """Return chain head from memory (if cached) or ClickHouse."""
        key = (tenant_id, service)
        if key not in self._ch_heads_fetched:
            # First time seeing this chain in this worker process: read from CH
            try:
                head = await ch.get_chain_head(tenant_id, service)
                self._ch_heads_fetched.add(key)
                if head is not None:
                    self._chain_heads[key] = head
                    log.debug("chain.head.restored_from_ch", tenant_id=tenant_id, service=service, head=head[:16])
            except Exception as exc:
                log.warning("chain.head.ch_read_failed", tenant_id=tenant_id, service=service, error=str(exc))
        return self._chain_heads.get(key)

    async def run_once(self) -> int:
        """Process one batch of pending events. Returns count processed."""
        async with system_session_scope() as session:
            rows = await self._ingest.fetch_pending(
                session, limit=self._settings.batch_max_events,
            )
            if not rows:
                return 0

            # Generate batch ID for this processing run
            batch_id = f"mrk_{uuid.uuid4().hex.upper()[:26]}"
            batch_created_at = datetime.now(UTC)

            processed: list[dict[str, Any]] = []
            row_ids: list[int] = []
            leaf_hashes: list[str] = []

            for row_id, event_json in rows:
                tenant_id = event_json.get("tenant_id", "")
                service = event_json.get("service", "")
                tenant_service = (tenant_id, service)

                # Restart-safe: load chain head from CH if not in memory yet
                prev = await self._get_chain_head(tenant_id, service)

                # Hash the form verify-integrity can rebuild from the stored row.
                prev_hash, curr_hash = compute_chain_hash(
                    prev_hash=prev,
                    event_data=canonical_event(event_json),
                    hash_algorithm=self._settings.hash_algorithm,
                )
                self._chain_heads[tenant_service] = curr_hash
                self._ch_heads_fetched.add(tenant_service)

                leaf_idx = len(leaf_hashes)
                event_json["prev_hash"] = prev_hash
                event_json["curr_hash"] = curr_hash
                event_json["ingested_at"] = batch_created_at.isoformat()
                event_json["merkle_batch_id"] = batch_id
                event_json["merkle_leaf_idx"] = leaf_idx

                processed.append(event_json)
                row_ids.append(row_id)
                leaf_hashes.append(curr_hash)

            # --- Write to ClickHouse ---
            try:
                await ch.insert_events(processed)
            except Exception as exc:
                # CH write failed: record error, do NOT mark delivered (retry next run)
                log.error("ch.insert.failed", count=len(processed), error=str(exc))
                await self._ingest.record_attempts(session, row_ids, error=str(exc))
                return 0

            # --- Compute Merkle root ---
            merkle_root = compute_merkle_root(
                leaf_hashes, hash_algorithm=self._settings.hash_algorithm,
            )

            # --- Sign Merkle root (Ed25519 via crypto-service) ---
            # Group events by (tenant, service) to pick a representative tenant for signing.
            # In practice, all events in a batch may span multiple tenants;
            # we use a per-batch signing key keyed to the first tenant seen.
            first_tenant = processed[0].get("tenant_id", "") if processed else ""
            first_service = processed[0].get("service", "") if processed else ""
            signature_b64 = ""
            signature_key_id = ""
            try:
                signature_b64, signature_key_id = await crypto_client.sign_merkle_root(
                    merkle_root, tenant_id=first_tenant,
                )
                log.debug("merkle.signed", batch_id=batch_id, key_id=signature_key_id)
            except Exception as exc:
                log.warning(
                    "merkle.sign.failed",
                    batch_id=batch_id,
                    error=str(exc),
                    hint="crypto-service unavailable; batch stored unsigned",
                )

            # --- RFC 3161 TSA timestamp (non-blocking) ---
            tsa_token: str | None = None
            tsa_ts: datetime | None = None
            if self._settings.tsa_enabled:
                try:
                    tsa_token, tsa_ts = await tsa.request_timestamp(merkle_root)
                except Exception as exc:
                    log.warning("tsa.failed", batch_id=batch_id, error=str(exc))

            # --- Insert merkle_batch row ---
            batch_row: dict[str, Any] = {
                "batch_id": batch_id,
                "tenant_id": first_tenant,
                "service": first_service,
                "created_at": batch_created_at,
                "sealed_at": datetime.now(UTC),
                "event_count": len(processed),
                "first_event_id": processed[0].get("event_id", "") if processed else "",
                "last_event_id": processed[-1].get("event_id", "") if processed else "",
                "merkle_root": merkle_root,
                "signature": signature_b64,
                "signature_key_id": signature_key_id,
                "tsa_token": tsa_token,
                "tsa_provider": self._settings.tsa_provider if tsa_token else "",
                "tsa_timestamp": tsa_ts,
                "external_anchor": None,
            }
            try:
                await ch.insert_merkle_batch(batch_row)
            except Exception as exc:
                log.warning("ch.merkle_batch.insert_failed", batch_id=batch_id, error=str(exc))

            # --- WORM double-write for SECURITY/CRITICAL events (non-blocking) ---
            if self._settings.worm_enabled:
                for event in processed:
                    worm_uri = await worm.write_worm(event)
                    if worm_uri:
                        event["worm_written"] = True
                        event["worm_uri"] = worm_uri

            # --- Mark outbox rows as delivered (only after successful CH insert) ---
            await self._ingest.mark_delivered(session, row_ids)

            log.info(
                "audit.batch.processed",
                batch_id=batch_id,
                count=len(processed),
                merkle_root=merkle_root[:16],
                signed=bool(signature_b64),
                tsa=bool(tsa_token),
                first_event=processed[0].get("event_id") if processed else None,
                last_event=processed[-1].get("event_id") if processed else None,
            )
            return len(processed)

    async def run_forever(self) -> None:
        """Run the worker loop until shutdown."""
        self._running = True
        log.info("audit.worker.started", poll_interval=self._settings.worker_poll_interval_seconds)
        while self._running:
            try:
                count = await self.run_once()
                if count == 0:
                    await asyncio.sleep(self._settings.worker_poll_interval_seconds)
            except Exception:
                log.exception("audit.worker.error")
                await asyncio.sleep(5.0)

    def stop(self) -> None:
        self._running = False


def run() -> None:
    """Entry point for `foundation-audit-worker` console script."""
    proc = BatchProcessor()
    try:
        asyncio.run(proc.run_forever())
    except KeyboardInterrupt:
        proc.stop()

"""Batch processor worker — outbox → ClickHouse + hash chain + signature.

Runs as a background loop:
  1. Fetch pending rows from Postgres outbox.
  2. Compute hash chain for each event.
  3. Batch-write to ClickHouse.
  4. Every N events or M seconds, seal a Merkle batch:
     - Compute Merkle root from all curr_hashes in the batch.
     - Call crypto-service to sign the Merkle root.
     - Write merkle_batch row to ClickHouse.
  5. Mark outbox rows as delivered.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from foundation_audit.config import get_settings
from foundation_audit.domain.db import system_session_scope
from foundation_audit.observability import get_logger
from foundation_audit.services.hash_chain import compute_chain_hash, compute_merkle_root
from foundation_audit.services.ingest_service import IngestService

log = get_logger(__name__)


class BatchProcessor:
    """Continuously drain the outbox to ClickHouse."""

    def __init__(self) -> None:
        self._settings = get_settings()
        self._ingest = IngestService()
        self._running = False
        # Per-tenant×service chain head (for hash chain computation)
        self._chain_heads: dict[tuple[str, str], str] = {}

    async def run_once(self) -> int:
        """Process one batch of pending events. Returns count processed."""
        async with system_session_scope() as session:
            rows = await self._ingest.fetch_pending(
                session, limit=self._settings.batch_max_events,
            )
            if not rows:
                return 0

            processed: list[dict] = []
            row_ids: list[int] = []
            leaf_hashes: list[str] = []

            for row_id, event_json in rows:
                # Compute hash chain
                tenant_service = (
                    event_json.get("tenant_id", ""),
                    event_json.get("service", ""),
                )
                prev = self._chain_heads.get(tenant_service)
                prev_hash, curr_hash = compute_chain_hash(
                    prev_hash=prev,
                    event_data=event_json,
                    hash_algorithm=self._settings.hash_algorithm,
                )
                self._chain_heads[tenant_service] = curr_hash

                event_json["prev_hash"] = prev_hash
                event_json["curr_hash"] = curr_hash
                event_json["ingested_at"] = datetime.now(UTC).isoformat()

                processed.append(event_json)
                row_ids.append(row_id)
                leaf_hashes.append(curr_hash)

            # TODO(M2): Write to ClickHouse via clickhouse-connect
            # For now, just mark as delivered and log
            await self._ingest.mark_delivered(session, row_ids)

            # Compute Merkle root
            merkle_root = compute_merkle_root(
                leaf_hashes, hash_algorithm=self._settings.hash_algorithm,
            )

            log.info(
                "audit.batch.processed",
                count=len(processed),
                merkle_root=merkle_root,
                first_event=processed[0]["event_id"] if processed else None,
                last_event=processed[-1]["event_id"] if processed else None,
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

"""In-process background jobs (APScheduler), started from the app lifespan.

Every replica runs its own scheduler. That is safe for the jobs below: they are
idempotent, and concurrent runs split the rows between them with ``SKIP LOCKED``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

from foundation_llm_gateway.config import Settings
from foundation_llm_gateway.domain.db import admin_session_scope
from foundation_llm_gateway.observability import get_logger
from foundation_llm_gateway.services.llm_gateway_service import LLMGatewayService

log = get_logger(__name__)


async def purge_expired_ephemeral_keys_job(*, grace_hours: int, batch_size: int) -> int:
    """Delete ephemeral keys that expired more than ``grace_hours`` ago; returns how many.

    Each batch commits in its own short transaction. The cutoff is fixed once
    per run, so the loop ends even while new keys keep expiring. Errors are
    logged, not raised: the next run resumes where this one stopped.
    """
    expired_before = datetime.now(UTC) - timedelta(hours=grace_hours)
    svc = LLMGatewayService()
    purged = 0
    try:
        while True:
            # No request-scoped FoundationContext here, and the rows span every
            # tenant, so use the admin engine (actor=ADMIN, admin_all policy).
            async with admin_session_scope() as session:
                n = await svc.purge_expired_ephemeral_keys(
                    session, expired_before=expired_before, limit=batch_size,
                )
            purged += n
            if n < batch_size:
                break
    except Exception as exc:
        log.error("ephemeral_key.purge_error", purged=purged, error=str(exc))
        return purged
    log.info("ephemeral_key.purge_complete", purged=purged,
             expired_before=expired_before.isoformat())
    return purged


def start_scheduler(settings: Settings) -> AsyncIOScheduler | None:
    """Start a scheduler running the enabled jobs; ``None`` when none is enabled."""
    if not settings.ephemeral_key_purge_enabled:
        return None
    scheduler = AsyncIOScheduler()
    # Standard 5-field cron ("m h dom mon dow"), evaluated in UTC whatever the
    # container's local zone is.
    scheduler.add_job(
        purge_expired_ephemeral_keys_job,
        trigger=CronTrigger.from_crontab(settings.ephemeral_key_purge_cron, timezone=UTC),
        kwargs={
            "grace_hours": settings.ephemeral_key_purge_grace_hours,
            "batch_size": settings.ephemeral_key_purge_batch_size,
        },
        id="ephemeral_key_purge",
        replace_existing=True,
    )
    log.info("scheduler.add_job", job="ephemeral_key_purge",
             cron=settings.ephemeral_key_purge_cron,
             grace_hours=settings.ephemeral_key_purge_grace_hours)
    scheduler.start()
    log.info("scheduler.start")
    return scheduler

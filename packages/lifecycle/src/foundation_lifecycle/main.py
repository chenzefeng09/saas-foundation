"""FastAPI app factory."""

from __future__ import annotations
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any
import uvicorn
from fastapi import FastAPI
from foundation_lifecycle import __version__
from foundation_lifecycle.api.exception_handlers import install_exception_handlers
from foundation_lifecycle.api.middleware import RequestIdMiddleware, TenantContextMiddleware
from foundation_lifecycle.api.v1 import api_v1
from foundation_lifecycle.config import get_settings
from foundation_lifecycle.domain.db import dispose_engine
from foundation_lifecycle.observability import get_logger, setup_observability

log = get_logger(__name__)


async def _run_reconcile_job(drift_alert_pct: float) -> None:
    """APScheduler entry — opens its own session and storage client."""
    from foundation_lifecycle.domain.db import admin_session_scope
    from foundation_lifecycle.services.storage_quota_reconcile import (
        reconcile_used_bytes,
    )
    from foundation_storage import StorageClient, get_settings as get_storage_settings

    storage_client = StorageClient.as_system(get_storage_settings())
    try:
        # APScheduler jobs run with no request-scoped FoundationContext, so
        # session_scope() would raise "FoundationContext missing".  Use the
        # admin engine (actor=ADMIN, admin_all RLS policy) so the reconcile can
        # scan every tenant's quota rows cross-tenant.
        async with admin_session_scope() as session:
            report = await reconcile_used_bytes(
                session,
                storage_client,
                drift_alert_pct=drift_alert_pct,
            )
        log.info(
            "storage.quota.reconcile_complete",
            quotas_scanned=report.quotas_scanned,
            drifts_corrected=report.drifts_corrected,
            total_drift_bytes=report.total_drift_bytes,
        )
    except Exception as exc:
        log.error("storage.quota.reconcile_error", error=str(exc))


async def _run_orphan_reconcile_job(
    *, dry_run: bool, grace_period_days: int
) -> None:
    """APScheduler entry — daily S3 ↔ DB orphan sweep (storage-v1 §6.3).

    Phase 7: persist a summary row to ``lifecycle.orphan_reconcile_report``
    after a successful sweep so the admin UI has a history to render.
    Failures stay log-only — we don't pollute the table with half-runs.
    """
    from datetime import UTC, datetime

    import ulid

    from foundation_lifecycle.domain.db import admin_session_scope
    from foundation_lifecycle.domain.models import OrphanReconcileReport
    from foundation_lifecycle.services.storage_orphan_reconcile import (
        reconcile_orphans,
    )
    from foundation_storage import StorageClient, get_settings as get_storage_settings

    report_id = f"orr_{ulid.new()!s}"
    started_at = datetime.now(UTC)
    storage_client = StorageClient.as_system(get_storage_settings())
    try:
        # APScheduler background job: no request-scoped FoundationContext, so
        # use the admin engine (actor=ADMIN) for the cross-tenant sweep — same
        # scope used below to persist the report row.
        async with admin_session_scope() as session:
            report = await reconcile_orphans(
                session,
                storage_client,
                dry_run=dry_run,
                grace_period_days=grace_period_days,
                run_id=report_id,
            )
        completed_at = datetime.now(UTC)
        duration_ms = int(
            (completed_at - started_at).total_seconds() * 1000
        )
        log.info(
            "storage.orphan.reconcile_complete",
            run_id=report_id,
            direction_a_orphans=report.direction_a_orphans,
            direction_a_deleted=report.direction_a_deleted,
            direction_b_missing=report.direction_b_missing,
            duration_ms=duration_ms,
            dry_run=dry_run,
        )
        # Persist via the admin engine so the cross-tenant insert doesn't
        # depend on a request-scoped tenant id (no RLS on the table).
        async with admin_session_scope() as admin_session:
            admin_session.add(
                OrphanReconcileReport(
                    id=report_id,
                    started_at=started_at,
                    completed_at=completed_at,
                    duration_ms=duration_ms,
                    dry_run=dry_run,
                    grace_period_days=grace_period_days,
                    direction_a_orphans=report.direction_a_orphans,
                    direction_a_deleted=report.direction_a_deleted,
                    direction_b_missing=report.direction_b_missing,
                )
            )
    except Exception as exc:
        log.error(
            "storage.orphan.reconcile_error",
            run_id=report_id,
            error=str(exc),
        )


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    log.info("startup", version=__version__)
    s = get_settings()
    scheduler: Any | None = None
    if s.reconcile_enabled or s.orphan_reconcile_enabled:
        from apscheduler.schedulers.asyncio import AsyncIOScheduler
        from apscheduler.triggers.cron import CronTrigger

        scheduler = AsyncIOScheduler()
        # Standard 5-field cron: "m h dom mon dow"
        if s.reconcile_enabled:
            scheduler.add_job(
                _run_reconcile_job,
                trigger=CronTrigger.from_crontab(s.reconcile_cron),
                kwargs={"drift_alert_pct": s.reconcile_drift_alert_pct},
                id="storage_quota_reconcile",
                replace_existing=True,
            )
            log.info(
                "scheduler.add_job",
                job="storage_quota_reconcile",
                cron=s.reconcile_cron,
            )
        if s.orphan_reconcile_enabled:
            scheduler.add_job(
                _run_orphan_reconcile_job,
                trigger=CronTrigger.from_crontab(s.orphan_reconcile_cron),
                kwargs={
                    "dry_run": s.orphan_reconcile_dry_run,
                    "grace_period_days": s.orphan_grace_period_days,
                },
                id="storage_orphan_reconcile",
                replace_existing=True,
            )
            log.info(
                "scheduler.add_job",
                job="storage_orphan_reconcile",
                cron=s.orphan_reconcile_cron,
                dry_run=s.orphan_reconcile_dry_run,
            )
        scheduler.start()
        log.info("scheduler.start")
    try:
        yield
    finally:
        if scheduler is not None:
            scheduler.shutdown(wait=False)
            log.info("scheduler.shutdown")
        log.info("shutdown")
        await dispose_engine()

def create_app() -> FastAPI:
    s = get_settings()
    app = FastAPI(title="Lifecycle Service API", version=__version__,
        description="SaaS Foundation — Lifecycle Service",
        openapi_url=f"{s.api_prefix}/openapi.json", docs_url=f"{s.api_prefix}/docs",
        redoc_url=f"{s.api_prefix}/redoc", lifespan=_lifespan)
    app.add_middleware(TenantContextMiddleware); app.add_middleware(RequestIdMiddleware)
    install_exception_handlers(app); setup_observability(app)
    app.include_router(api_v1, prefix=s.api_prefix)
    return app

app = create_app()

def run() -> None:
    s = get_settings()
    uvicorn.run("foundation_lifecycle.main:app", host=s.http_host, port=s.http_port, reload=s.env == "dev", access_log=False)

if __name__ == "__main__": run()

"""Application lifespan hooks.

Registered in ``app.factory.create_app`` and executed once per process:

* **Startup** — configure logging, verify database connectivity.
* **Shutdown** — dispose the SQLAlchemy engine and release pool connections.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI

from app.core.config import DEFAULT_BOOTSTRAP_ADMIN_PASSWORD, settings
from app.core.logging_config import configure_logging, get_logger
from app.db.init_db import init_db
from app.db.session import check_db_connectivity, dispose_engine
from app.db.session import SessionLocal
from app.models.scan import Scan
from app.services.scheduled_drift_email import (
    drift_scan_interval_minutes,
    run_scheduled_drift_email_scan,
)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Manage startup and graceful shutdown lifecycle hooks."""
    configure_logging()
    logger = get_logger(__name__)

    logger.info(
        "application starting",
        extra={
            "environment": settings.app.environment,
            "version": settings.app.version,
        },
    )

    await asyncio.to_thread(check_db_connectivity)
    logger.info("database connectivity verified")

    environment_name = (settings.app.environment or "development").lower()
    if environment_name not in {"development", "test"}:
        admin_password = settings.admin_password.get_secret_value() if settings.admin_password else ""
        if not admin_password.strip() or admin_password == DEFAULT_BOOTSTRAP_ADMIN_PASSWORD:
            raise RuntimeError("ADMIN_PASSWORD must be set and must not equal the default bootstrap password outside development")

    with SessionLocal() as db:
        init_db(db)
        stale_cutoff = datetime.now(timezone.utc) - timedelta(minutes=settings.scan_stale_minutes)
        stale_scans = (
            db.query(Scan)
            .filter(Scan.status.in_(["queued", "running"]))
            .filter(Scan.updated_at < stale_cutoff)
            .all()
        )
        for scan in stale_scans:
            scan.status = "failed"
            scan.error = "orphaned"
        if stale_scans:
            db.commit()
            logger.warning(
                "recovered stale scans",
                extra={"count": len(stale_scans), "cutoff": stale_cutoff.isoformat()},
            )
    logger.info("database bootstrap complete")

    scheduler = AsyncIOScheduler()
    interval_minutes = drift_scan_interval_minutes()
    scheduler.add_job(
        run_scheduled_drift_email_scan,
        trigger="interval",
        minutes=interval_minutes,
        id="scheduled_drift_email_scan",
        replace_existing=True,
        next_run_time=datetime.now(timezone.utc),
        max_instances=1,
        coalesce=True,
    )
    scheduler.start()
    app.state.scheduler = scheduler
    logger.info(
        "drift email scheduler started",
        extra={"interval_minutes": interval_minutes},
    )

    try:
        yield
    finally:
        scheduler.shutdown()
        logger.info("drift email scheduler stopped")

        await asyncio.to_thread(dispose_engine)
        logger.info("database engine disposed")

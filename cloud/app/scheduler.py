"""The job dispatcher, the Compose `scheduler` service (C5.9; docs/decisions.md
2026-10-11, "C5.10 and C5.9", points 7 to 9). Run as `python -m app.scheduler`.

Every `TICK_S` seconds, two jobs under APScheduler, each once at start too:

- **plans** (`tick_plans`): `MspRepo.list()`, then one transaction per MSP:
  its enabled plans, and per plan the period that is current now (the latest
  cron occurrence at or before now, `app.cadence.due_at`), skipped when it
  began before the plan was made; one queued run for it through
  `RunRepo.create_scheduled`, whose `INSERT ... ON CONFLICT DO NOTHING` under
  the period's unique makes one run however many ticks or processes ask. Only
  the current period is made: a scheduler that was down makes today's run
  when it comes back, never yesterday's. A plan whose cron the parser refuses
  (a row written past the repo) is skipped with one line and the other plans
  go on; an MSP whose transaction raises is rolled back and logged, and the
  next MSP runs. A plan whose Worker is revoked still gets its run (point 9).
- **sweep** (`tick_sweep`): `RunRepo.requeue_stale` per MSP, each in its own
  transaction.

`DATABASE_URL` and `LOG_LEVEL` alone, as a migration reads them. Every line
holds ids and counts: nothing of a profile, a credential or a tenant value is
read here, so none can be written. The process never exits on a tick's failure;
SIGTERM and SIGINT (Compose's stop) end it.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import signal
import sys
import time
from dataclasses import dataclass
from typing import Any
from uuid import UUID

import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.cadence import CadenceError, due_at, parse
from app.db import make_engine_for_url, make_session_factory
from app.logging import configure_logging
from app.repo.connectors import ConnectorRepo
from app.repo.msps import MspRepo
from app.repo.plans import PlanRepo
from app.repo.runs import RunRepo
from app.settings import SettingsError, database_url_from_environment, log_level_from_environment

TICK_S = 300
MISFIRE_GRACE_S = 60

log = structlog.get_logger("app.scheduler")


def now() -> dt.datetime:
    """The Cloud's clock; a test moves it."""
    return dt.datetime.now(dt.timezone.utc)


@dataclass
class PlansTick:
    msps: int = 0
    plans: int = 0
    created: int = 0
    skipped: int = 0
    failed: int = 0


@dataclass
class SweepTick:
    msps: int = 0
    requeued: int = 0
    expired: int = 0
    failed: int = 0


async def _msp_ids(session_factory: async_sessionmaker, job: str) -> list[UUID] | None:
    try:
        async with session_factory() as session, session.begin():
            return [msp.id for msp in await MspRepo(session).list()]
    except Exception as error:  # noqa: BLE001 - the database gone: logged, the next tick retries
        log.error("tick failed", job=job, exc_info=error)
        return None


async def _plans_of(session: Any, msp_id: UUID, at: dt.datetime, summary: PlansTick) -> None:
    for plan in await PlanRepo(session).list(msp_id, enabled=True):
        summary.plans += 1
        try:
            cadence = parse(plan.cadence_cron)
        except CadenceError:
            summary.skipped += 1
            log.warning("plan skipped", msp_id=str(msp_id), plan_id=str(plan.id), reason="cadence_cron")
            continue
        due = due_at(cadence, at)
        if due < plan.created_at:
            continue
        connector = await ConnectorRepo(session).get(msp_id, plan.connector_id)
        if connector is None:
            raise RuntimeError("a plan's connector is gone")
        run = await RunRepo(session).create_scheduled(
            msp_id,
            plan_id=plan.id,
            client_id=plan.client_id,
            connector_id=plan.connector_id,
            worker_id=connector.worker_id,
            scheduled_for=due,
        )
        if run is not None:
            summary.created += 1
            log.info(
                "run created",
                msp_id=str(msp_id),
                plan_id=str(plan.id),
                run_id=str(run.id),
                scheduled_for=due.isoformat(),
            )


async def tick_plans(session_factory: async_sessionmaker, at: dt.datetime | None = None) -> PlansTick:
    """One queued run per enabled plan and current period, one transaction per MSP."""
    at = now() if at is None else at
    started = time.perf_counter()
    summary = PlansTick()
    msp_ids = await _msp_ids(session_factory, "plans")
    if msp_ids is None:
        summary.failed += 1
    else:
        for msp_id in msp_ids:
            summary.msps += 1
            try:
                async with session_factory() as session, session.begin():
                    await _plans_of(session, msp_id, at, summary)
            except Exception as error:  # noqa: BLE001 - this MSP's tick rolled back; the next MSP runs
                summary.failed += 1
                log.error("tick failed", job="plans", msp_id=str(msp_id), exc_info=error)
    log.info(
        "tick",
        job="plans",
        msps=summary.msps,
        plans=summary.plans,
        created=summary.created,
        skipped=summary.skipped,
        failed=summary.failed,
        duration_ms=int((time.perf_counter() - started) * 1000),
    )
    return summary


async def tick_sweep(session_factory: async_sessionmaker, at: dt.datetime | None = None) -> SweepTick:
    """`RunRepo.requeue_stale` per MSP, each in its own transaction."""
    at = now() if at is None else at
    started = time.perf_counter()
    summary = SweepTick()
    msp_ids = await _msp_ids(session_factory, "sweep")
    if msp_ids is None:
        summary.failed += 1
    else:
        for msp_id in msp_ids:
            summary.msps += 1
            try:
                async with session_factory() as session, session.begin():
                    requeued, expired = await RunRepo(session).requeue_stale(msp_id, at)
            except Exception as error:  # noqa: BLE001 - this MSP's sweep rolled back; the next MSP runs
                summary.failed += 1
                log.error("tick failed", job="sweep", msp_id=str(msp_id), exc_info=error)
                continue
            summary.requeued += requeued
            summary.expired += expired
            if requeued or expired:
                log.info("runs swept", msp_id=str(msp_id), requeued=requeued, expired=expired)
    log.info(
        "tick",
        job="sweep",
        msps=summary.msps,
        requeued=summary.requeued,
        expired=summary.expired,
        failed=summary.failed,
        duration_ms=int((time.perf_counter() - started) * 1000),
    )
    return summary


def build_scheduler(session_factory: Any, *, start_at: dt.datetime) -> AsyncIOScheduler:
    """The two jobs every `TICK_S` seconds, each once at `start_at` too."""
    scheduler = AsyncIOScheduler(timezone=dt.timezone.utc)
    for job_id, func in (("plans", tick_plans), ("sweep", tick_sweep)):
        scheduler.add_job(
            func,
            IntervalTrigger(seconds=TICK_S, timezone=dt.timezone.utc),
            args=[session_factory],
            id=job_id,
            max_instances=1,
            coalesce=True,
            misfire_grace_time=MISFIRE_GRACE_S,
            next_run_time=start_at,
        )
    return scheduler


def install_stop_signals(loop: asyncio.AbstractEventLoop, stop: asyncio.Event) -> None:
    """SIGTERM and SIGINT set `stop`, where the loop can take a handler
    (Linux, the image); Windows' loop can't, and a test runs here."""
    for signum in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(signum, stop.set)
        except NotImplementedError:
            return


async def serve(url: str, *, stop: asyncio.Event | None = None) -> int:
    """Run the scheduler until `stop` is set."""
    engine = make_engine_for_url(url)
    session_factory = make_session_factory(engine)
    scheduler = build_scheduler(session_factory, start_at=now())
    stop = asyncio.Event() if stop is None else stop
    install_stop_signals(asyncio.get_running_loop(), stop)
    scheduler.start()
    log.info("scheduler started", tick_s=TICK_S)
    try:
        await stop.wait()
    finally:
        scheduler.shutdown(wait=False)
        await engine.dispose()
        log.info("scheduler stopped")
    return 0


def main() -> int:
    try:
        url = database_url_from_environment()
        level = log_level_from_environment()
    except SettingsError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from None
    configure_logging(level)
    return asyncio.run(serve(url))


if __name__ == "__main__":  # pragma: no cover - the process's entry
    sys.exit(main())

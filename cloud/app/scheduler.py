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
  (a row written past the repo), or whose cron never occurs, is skipped with
  one line and the other plans go on; each plan's run is made under its own
  savepoint, so a plan that raises is rolled back alone, logged by type, and
  the MSP's other plans keep their runs; an MSP whose transaction raises is
  rolled back and logged, and the next MSP runs. A run is counted and its
  `run created` line written once its MSP's transaction has committed, never
  before. A plan whose Worker is revoked still gets its run (point 9).
- **sweep** (`tick_sweep`): `RunRepo.requeue_stale` per MSP, each in its own
  transaction.

And a third, **reports** (`tick_reports`; C6.6, docs/decisions.md 2026-10-13,
"C6.6, C6.5 and C6.7", point 1), on the 1st of each month at
`REPORT_HOUR_UTC` and once at start: for every MSP, the clients with a run
of the newest closed month (`app.report.data.closed_month`: the previous
month from `REPORT_HOUR_UTC` on the 1st, the one before it until then, so a
start in the first hours of a month never makes a report of a month that
still takes results; `RunRepo.clients_in_period`, one read in its own
transaction), then **one transaction per client** calling
`app.report.generate.generate` for that month's final report, committed as
soon as it is made (its object is put inside that transaction, so an MSP-wide
rollback would leave objects without rows); a month that has its report is
`existing`, never a failure (one read, no render); a client whose report
fails (a render, a put, the database) is rolled back alone and logged by
type (`report failed`), and the next client is made; a report is counted and
named (`report created`) after its commit. The start run makes a scheduler
restarted after a 1st it missed catch up, and costs a restart on any other
day one read per client. A final report is never re-made.

`DATABASE_URL`, `LOG_LEVEL` and, for the report job's bucket, the five `S3_*`
variables (`storage_settings_from_environment`; never the app's session
secret): a process started without one of the seven exits naming it. Every
line holds ids and counts. The plans and the sweep read nothing of a profile,
a credential or a tenant value; the report job reads what a report prints
(names, runs, items) and logs none of it. The process never exits on a
tick's failure; SIGTERM and SIGINT (Compose's stop) end it.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import signal
import sys
import time
from dataclasses import dataclass
from typing import Any, NamedTuple
from uuid import UUID

import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.cadence import CadenceError, due_at, parse
from app.db import make_engine_for_url, make_session_factory
from app.logging import configure_logging
from app.report.data import FINAL_AFTER, closed_month
from app.report.generate import ALREADY_REPORTED, generate
from app.repo.connectors import ConnectorRepo
from app.repo.errors import RepoError
from app.repo.msps import MspRepo
from app.repo.plans import PlanRepo
from app.repo.runs import RunRepo
from app.settings import (
    SettingsError,
    database_url_from_environment,
    log_level_from_environment,
    storage_settings_from_environment,
)
from app.storage import Storage

TICK_S = 300
MISFIRE_GRACE_S = 60
# C6.6: the report job's hour on the 1st (the hour a month's final report
# may first be made, `FINAL_AFTER`), and how late it may still run that
# morning (a scheduler busy or paused at 03:00).
REPORT_HOUR_UTC = int(FINAL_AFTER.total_seconds() // 3600)
REPORT_MISFIRE_GRACE_S = 3600

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


@dataclass
class ReportsTick:
    msps: int = 0
    clients: int = 0
    created: int = 0
    existing: int = 0
    failed: int = 0


async def _msp_ids(session_factory: async_sessionmaker, job: str) -> list[UUID] | None:
    try:
        async with session_factory() as session, session.begin():
            return [msp.id for msp in await MspRepo(session).list()]
    except Exception as error:  # noqa: BLE001 - the database gone: logged, the next tick retries
        log.error("tick failed", job=job, exc_info=error)
        return None


class DuePlan(NamedTuple):
    """A plan's values, read before any savepoint: one rolled back may
    expire the session's rows."""

    id: UUID
    client_id: UUID
    connector_id: UUID
    cadence_cron: str
    created_at: dt.datetime


class MadeRun(NamedTuple):
    plan_id: UUID
    run_id: UUID
    scheduled_for: dt.datetime


async def _run_of(session: Any, msp_id: UUID, plan: DuePlan, due: dt.datetime) -> MadeRun | None:
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
    return None if run is None else MadeRun(plan.id, run.id, due)


async def _plans_of(session: Any, msp_id: UUID, at: dt.datetime, summary: PlansTick) -> list[MadeRun]:
    """The runs made for the MSP's plans, for the caller to count and log
    once the transaction has committed."""
    made: list[MadeRun] = []
    plans = [
        DuePlan(plan.id, plan.client_id, plan.connector_id, plan.cadence_cron, plan.created_at)
        for plan in await PlanRepo(session).list(msp_id, enabled=True)
    ]
    for plan in plans:
        summary.plans += 1
        try:
            due = due_at(parse(plan.cadence_cron), at)
        except CadenceError:
            summary.skipped += 1
            log.warning("plan skipped", msp_id=str(msp_id), plan_id=str(plan.id), reason="cadence_cron")
            continue
        if due < plan.created_at:
            continue
        try:
            async with session.begin_nested():
                run = await _run_of(session, msp_id, plan, due)
        except Exception as error:  # noqa: BLE001 - this plan's run rolled back; the next plan runs
            summary.failed += 1
            log.error("plan failed", msp_id=str(msp_id), plan_id=str(plan.id), exc_info=error)
            continue
        if run is not None:
            made.append(run)
    return made


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
                    made = await _plans_of(session, msp_id, at, summary)
            except Exception as error:  # noqa: BLE001 - this MSP's tick rolled back; the next MSP runs
                summary.failed += 1
                log.error("tick failed", job="plans", msp_id=str(msp_id), exc_info=error)
                continue
            # Committed: only now is a run counted and named.
            summary.created += len(made)
            for run in made:
                log.info(
                    "run created",
                    msp_id=str(msp_id),
                    plan_id=str(run.plan_id),
                    run_id=str(run.run_id),
                    scheduled_for=run.scheduled_for.isoformat(),
                )
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


async def tick_reports(session_factory: async_sessionmaker, storage: Storage, at: dt.datetime | None = None) -> ReportsTick:
    """The newest closed month's final report for every client with a run in
    it, one transaction per client (C6.6)."""
    at = now() if at is None else at
    started = time.perf_counter()
    summary = ReportsTick()
    period = closed_month(at)
    msp_ids = await _msp_ids(session_factory, "reports")
    if msp_ids is None:
        summary.failed += 1
    else:
        for msp_id in msp_ids:
            summary.msps += 1
            try:
                async with session_factory() as session, session.begin():
                    client_ids = sorted(await RunRepo(session).clients_in_period(msp_id, start=period.start_at, end=period.end_at))
            except Exception as error:  # noqa: BLE001 - this MSP's clients unread; the next MSP runs
                summary.failed += 1
                log.error("tick failed", job="reports", msp_id=str(msp_id), exc_info=error)
                continue
            for client_id in client_ids:
                summary.clients += 1
                ids = {"msp_id": str(msp_id), "client_id": str(client_id), "period": period.name}
                try:
                    async with session_factory() as session, session.begin():
                        created = await generate(session, storage, msp_id, client_id, period, now=at)
                except RepoError as error:
                    if error.reason == ALREADY_REPORTED:
                        summary.existing += 1
                        log.debug("report exists", **ids)
                        continue
                    summary.failed += 1
                    log.error("report failed", **ids, exc_info=error)
                    continue
                except Exception as error:  # noqa: BLE001 - this client's report rolled back; the next client is made
                    summary.failed += 1
                    log.error("report failed", **ids, exc_info=error)
                    continue
                # Committed: only now is the report counted and named.
                summary.created += 1
                log.info("report created", **ids, report_id=created.values["report_id"])
    log.info(
        "tick",
        job="reports",
        msps=summary.msps,
        clients=summary.clients,
        created=summary.created,
        existing=summary.existing,
        failed=summary.failed,
        duration_ms=int((time.perf_counter() - started) * 1000),
    )
    return summary


def build_scheduler(session_factory: Any, storage: Any, *, start_at: dt.datetime) -> AsyncIOScheduler:
    """The two jobs every `TICK_S` seconds, and the report job on the 1st at
    `REPORT_HOUR_UTC`, each once at `start_at` too."""
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
    scheduler.add_job(
        tick_reports,
        CronTrigger(day=1, hour=REPORT_HOUR_UTC, minute=0, timezone=dt.timezone.utc),
        args=[session_factory, storage],
        id="reports",
        max_instances=1,
        coalesce=True,
        misfire_grace_time=REPORT_MISFIRE_GRACE_S,
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


async def serve(url: str, storage: Storage, *, stop: asyncio.Event | None = None) -> int:
    """Run the scheduler until `stop` is set."""
    engine = make_engine_for_url(url)
    session_factory = make_session_factory(engine)
    scheduler = build_scheduler(session_factory, storage, start_at=now())
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
        storage = Storage.for_writing(storage_settings_from_environment())
        level = log_level_from_environment()
    except SettingsError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from None
    configure_logging(level)
    return asyncio.run(serve(url, storage))


if __name__ == "__main__":  # pragma: no cover - the process's entry
    sys.exit(main())

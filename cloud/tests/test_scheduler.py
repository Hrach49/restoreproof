"""C5.9's Done-when by name, and the dispatcher (docs/decisions.md 2026-10-11,
"C5.10 and C5.9", points 7 to 9 and 11): every five minutes, for each MSP
and each of its enabled plans, one queued run for the period that is current,
unless one exists; the sweep per MSP; a plan whose cron can't be read skipped
with one line while the rest go on; a plan that raises rolled back alone;
an MSP whose tick fails rolled back and logged while the next MSP's runs are
made, and no run counted or named before its MSP's commit. On a migrated database of the
test's own: a tick is one transaction per MSP, as the process runs it.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import io
import json
import signal
import uuid

import pytest
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import create_async_engine

from app import scheduler
from app.db import make_session_factory
from app.logging import configure_logging
from app.repo.clients import ClientRepo
from app.repo.connectors import ConnectorRepo
from app.repo.msps import MspRepo
from app.repo.plans import PlanRepo
from app.repo.runs import RunRepo
from app.repo.workers import WorkerRepo
from app.scheduler import TICK_S, build_scheduler, tick_plans, tick_sweep
from tests.test_repo_connectors import profile_for

UTC = dt.timezone.utc
T = dt.datetime(2026, 10, 11, 12, 0, 30, tzinfo=UTC)
PEM = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----\n"
SENTINEL_ORG = "Sentinel-Organisation-7f3a"


def a_hash(seed: str) -> str:
    return uuid.uuid5(uuid.NAMESPACE_DNS, seed).hex * 2


def at(*args) -> dt.datetime:
    return dt.datetime(*args, tzinfo=UTC)


class Lab:
    """Two MSPs, each with a client, a Worker and a connector; plans made to
    order with their own `created_at`; the log in a StringIO."""

    def __init__(self, database: str):
        self.engine = create_async_engine(database, connect_args={"server_settings": {"timezone": "UTC"}})
        self.factory = make_session_factory(self.engine)
        self.stream = io.StringIO()
        configure_logging("info", stream=self.stream)

    async def fill(self) -> "Lab":
        async with self.factory() as s, s.begin():
            self.msp_id = (await MspRepo(s).create(name="a")).id
            self.other_msp_id = (await MspRepo(s).create(name="b")).id
            self.client_id, self.worker_id, self.connector_id = await self._world(s, self.msp_id, "a")
            self.other_client_id, self.other_worker_id, self.other_connector_id = await self._world(s, self.other_msp_id, "b")
        return self

    async def _world(self, s, msp_id, name):
        client = await ClientRepo(s).create(msp_id, name=f"{name} client", tenant_id=uuid.uuid4())
        worker = await WorkerRepo(s).create(
            msp_id, f"{name} worker", public_key_pem=PEM, key_id=a_hash(f"{name} key"), api_token_hash=a_hash(f"{name} token")
        )
        profile = profile_for(client.tenant_id, veeam_org_name=SENTINEL_ORG)
        connector = await ConnectorRepo(s).create(msp_id, client.id, worker.id, profile)
        return client.id, worker.id, connector.id

    async def plan(self, cron: str, *, created_at: dt.datetime, enabled: bool = True, other: bool = False) -> uuid.UUID:
        msp_id = self.other_msp_id if other else self.msp_id
        client_id = self.other_client_id if other else self.client_id
        connector_id = self.other_connector_id if other else self.connector_id
        async with self.factory() as s, s.begin():
            plan = await PlanRepo(s).create(
                msp_id, client_id, connector_id, sample_mail=5, sample_sp=3, sample_od=2,
                cadence_cron=cron, now=created_at, enabled=enabled,
            )
            await s.execute(text("UPDATE test_plan SET created_at = :at WHERE id = :id"), {"at": created_at, "id": plan.id})
            return plan.id

    async def plant_cron(self, plan_id: uuid.UUID, cron: str) -> None:
        """A cron past the repo's rule, by SQL: what a hand could leave in a row."""
        async with self.factory() as s, s.begin():
            await s.execute(text("UPDATE test_plan SET cadence_cron = :cron WHERE id = :id"), {"cron": cron, "id": plan_id})

    async def runs(self, msp_id=None) -> list[tuple[uuid.UUID, dt.datetime | None, str]]:
        async with self.factory() as s, s.begin():
            rows = await RunRepo(s).list(self.msp_id if msp_id is None else msp_id)
            return sorted((r.plan_id, r.scheduled_for, r.state) for r in rows)

    async def run_rows(self, msp_id=None) -> list:
        async with self.factory() as s, s.begin():
            return await RunRepo(s).list(self.msp_id if msp_id is None else msp_id)

    def log(self, event_name: str | None = None) -> list[dict]:
        entries = [json.loads(line) for line in self.stream.getvalue().splitlines() if line.startswith("{")]
        return [e for e in entries if event_name is None or e.get("event") == event_name]

    async def close(self) -> None:
        await self.engine.dispose()


@pytest.fixture
async def lab(own_database):
    lab = await Lab(own_database).fill()
    try:
        yield lab
    finally:
        await lab.close()


# --- The Done-when, by name ---------------------------------------------------------------------


async def test_a_plan_with_a_5_minute_cron_creates_queued_runs_on_schedule(lab):
    plan_id = await lab.plan("*/5 * * * *", created_at=T)
    disabled = await lab.plan("*/5 * * * *", created_at=T, enabled=False)
    theirs = await lab.plan("*/5 * * * *", created_at=T, other=True)
    expected: list = []

    for tick, period in [
        # The plan was made at 12:00:30: the 12:00 period began before it and
        # is not the plan's; its first run is the 12:05 period's.
        (at(2026, 10, 11, 12, 0, 30), None),
        (at(2026, 10, 11, 12, 3, 0), None),
        (at(2026, 10, 11, 12, 5, 0), at(2026, 10, 11, 12, 5)),
        (at(2026, 10, 11, 12, 5, 10), None),  # the same period again
        (at(2026, 10, 11, 12, 10, 1), at(2026, 10, 11, 12, 10)),
    ]:
        summary = await tick_plans(lab.factory, tick)
        if period is not None:
            expected.append((plan_id, period, "queued"))
        assert (summary.created, summary.failed) == (2 if period is not None else 0, 0), tick
        assert await lab.runs() == sorted(expected), tick

    assert disabled not in {plan for plan, _, _ in await lab.runs()}
    assert await lab.runs(lab.other_msp_id) == [(theirs, p, "queued") for _, p, _ in expected]
    rows = await lab.run_rows()
    assert all((r.client_id, r.connector_id, r.worker_id, r.dispatched_at, r.attempt) == (lab.client_id, lab.connector_id, lab.worker_id, None, 0) for r in rows)
    created = lab.log("run created")
    assert len(created) == 4
    assert {e["plan_id"] for e in created} == {str(plan_id), str(theirs)}
    assert all(set(e) >= {"msp_id", "plan_id", "run_id", "scheduled_for"} for e in created)
    every_row = rows + await lab.run_rows(lab.other_msp_id)
    assert all(e["run_id"] in {str(r.id) for r in every_row} for e in created)
    text_log = lab.stream.getvalue()
    assert SENTINEL_ORG not in text_log and "tenant" not in text_log


# --- Failure paths ----------------------------------------------------------------------------


async def test_a_plan_whose_cron_cannot_be_read_is_skipped_and_the_others_run(lab):
    bad = await lab.plan("*/5 * * * *", created_at=T)
    await lab.plant_cron(bad, "0 2 * * * *; nonsense")
    good = await lab.plan("*/5 * * * *", created_at=T)

    summary = await tick_plans(lab.factory, at(2026, 10, 11, 12, 5, 0))

    assert (summary.created, summary.skipped, summary.failed) == (1, 1, 0)
    assert await lab.runs() == [(good, at(2026, 10, 11, 12, 5), "queued")]
    (skipped,) = lab.log("plan skipped")
    assert (skipped["msp_id"], skipped["plan_id"], skipped["reason"], skipped["level"]) == (str(lab.msp_id), str(bad), "cadence_cron", "warning")
    assert "nonsense" not in lab.stream.getvalue()


@pytest.mark.parametrize("cron", ["0 0 31 2 *", "0 2 30 2 *"])
async def test_a_planted_cron_that_never_occurs_is_skipped_and_the_others_run(lab, cron):
    """The review's finding 2: croniter takes the text and can't walk it;
    the plan is skipped like any unreadable cron, not the MSP's tick lost."""
    bad = await lab.plan("*/5 * * * *", created_at=T)
    await lab.plant_cron(bad, cron)
    good = await lab.plan("*/5 * * * *", created_at=T)

    summary = await tick_plans(lab.factory, at(2026, 10, 11, 12, 5, 0))

    assert (summary.created, summary.skipped, summary.failed) == (1, 1, 0)
    assert await lab.runs() == [(good, at(2026, 10, 11, 12, 5), "queued")]
    (skipped,) = lab.log("plan skipped")
    assert (skipped["plan_id"], skipped["reason"]) == (str(bad), "cadence_cron")
    assert lab.log("tick failed") == []


async def test_a_plan_whose_run_fails_is_rolled_back_alone_and_the_msp_s_other_plans_run(lab, monkeypatch):
    """The review's finding 3: the plans before and after the one that
    raises keep their runs, and the failed plan's insert is gone."""
    first = await lab.plan("*/5 * * * *", created_at=T)
    bad = await lab.plan("*/5 * * * *", created_at=T)
    last = await lab.plan("*/5 * * * *", created_at=T)
    theirs = await lab.plan("*/5 * * * *", created_at=T, other=True)
    original = RunRepo.create_scheduled

    async def failing(self, msp_id, **values):
        run = await original(self, msp_id, **values)  # the row is in, then the fault
        if values["plan_id"] == bad:
            raise RuntimeError("Sentinel-Fault")
        return run

    monkeypatch.setattr(RunRepo, "create_scheduled", failing)

    summary = await tick_plans(lab.factory, at(2026, 10, 11, 12, 5, 0))

    period = at(2026, 10, 11, 12, 5)
    assert (summary.msps, summary.plans, summary.created, summary.failed) == (2, 4, 3, 1)
    assert await lab.runs() == sorted([(first, period, "queued"), (last, period, "queued")])
    assert await lab.runs(lab.other_msp_id) == [(theirs, period, "queued")]
    (failed,) = lab.log("plan failed")
    assert (failed["msp_id"], failed["plan_id"], failed["exc_type"], failed["level"]) == (
        str(lab.msp_id), str(bad), "RuntimeError", "error"
    )
    assert lab.log("tick failed") == []
    assert {e["plan_id"] for e in lab.log("run created")} == {str(first), str(last), str(theirs)}
    assert "Sentinel-Fault" not in lab.stream.getvalue()

    # The fault gone, the next tick makes the plan's run for the same period.
    monkeypatch.setattr(RunRepo, "create_scheduled", original)
    summary = await tick_plans(lab.factory, at(2026, 10, 11, 12, 6, 0))
    assert (summary.created, summary.failed) == (1, 0)
    assert (bad, period, "queued") in await lab.runs()


async def test_a_plan_the_database_refuses_is_rolled_back_alone(lab, monkeypatch):
    """A statement the database refused leaves the transaction unusable
    without the savepoint: the next plan's run shows it held."""
    bad = await lab.plan("*/5 * * * *", created_at=T)
    good = await lab.plan("*/5 * * * *", created_at=T)
    original = RunRepo.create_scheduled

    async def refused(self, msp_id, **values):
        if values["plan_id"] == bad:
            await self.session.execute(text("SELECT 1 / 0"))
        return await original(self, msp_id, **values)

    monkeypatch.setattr(RunRepo, "create_scheduled", refused)

    summary = await tick_plans(lab.factory, at(2026, 10, 11, 12, 5, 0))

    assert (summary.created, summary.failed) == (1, 1)
    assert await lab.runs() == [(good, at(2026, 10, 11, 12, 5), "queued")]
    assert lab.log("plan failed")[0]["plan_id"] == str(bad)


async def test_an_msp_whose_tick_fails_is_rolled_back_and_the_next_msp_runs(lab, monkeypatch):
    """The MSP's own failure, after its plans' runs were made: nothing of
    it is committed, counted or named (the review's finding 3), and the
    next MSP's run is made."""
    mine = await lab.plan("*/5 * * * *", created_at=T)
    await lab.plan("*/5 * * * *", created_at=T)
    theirs = await lab.plan("*/5 * * * *", created_at=T, other=True)
    original = scheduler._plans_of
    made_before_the_fault = []

    async def failing(session, msp_id, at_, summary):
        made = await original(session, msp_id, at_, summary)
        if msp_id == lab.msp_id:
            made_before_the_fault.extend(made)
            raise RuntimeError("Sentinel-Fault")
        return made

    monkeypatch.setattr(scheduler, "_plans_of", failing)

    summary = await tick_plans(lab.factory, at(2026, 10, 11, 12, 5, 0))

    assert len(made_before_the_fault) == 2
    assert (summary.msps, summary.created, summary.failed) == (2, 1, 1)
    assert await lab.runs() == []
    assert await lab.runs(lab.other_msp_id) == [(theirs, at(2026, 10, 11, 12, 5), "queued")]
    (failed,) = lab.log("tick failed")
    assert (failed["msp_id"], failed["exc_type"], failed["level"]) == (str(lab.msp_id), "RuntimeError", "error")
    assert "Sentinel-Fault" not in lab.stream.getvalue()
    assert mine not in {plan for plan, _, _ in await lab.runs()}
    (created,) = lab.log("run created")
    assert (created["msp_id"], created["plan_id"]) == (str(lab.other_msp_id), str(theirs))
    assert all(str(run.run_id) not in lab.stream.getvalue() for run in made_before_the_fault)
    (tick,) = [e for e in lab.log("tick") if e["job"] == "plans"]
    assert (tick["created"], tick["failed"]) == (1, 1)


async def test_a_run_is_named_only_after_its_msp_s_commit(lab, monkeypatch):
    plan_id = await lab.plan("*/5 * * * *", created_at=T)
    seen_at_commit = []
    original = scheduler._plans_of

    async def spying(session, msp_id, at_, summary):
        made = await original(session, msp_id, at_, summary)
        seen_at_commit.append((summary.created, len(lab.log("run created")), len(made)))
        return made

    monkeypatch.setattr(scheduler, "_plans_of", spying)

    summary = await tick_plans(lab.factory, at(2026, 10, 11, 12, 5, 0))

    # This MSP: its run made, nothing counted or named yet; the next MSP sees it done.
    assert seen_at_commit == [(0, 0, 1), (1, 1, 0)]
    assert summary.created == 1
    assert [e["plan_id"] for e in lab.log("run created")] == [str(plan_id)]


async def test_a_connector_the_keys_say_exists_but_is_gone_is_the_plan_s_failure(lab, monkeypatch):
    await lab.plan("*/5 * * * *", created_at=T)

    async def nothing(self, msp_id, connector_id):
        return None

    monkeypatch.setattr(ConnectorRepo, "get", nothing)

    summary = await tick_plans(lab.factory, at(2026, 10, 11, 12, 5, 0))

    assert (summary.created, summary.failed) == (0, 1)
    assert lab.log("plan failed")[0]["exc_type"] == "RuntimeError"
    assert lab.log("tick failed") == []


async def test_a_period_that_began_before_the_plan_was_made_gets_no_run(lab):
    plan_id = await lab.plan("0 2 * * *", created_at=at(2026, 10, 11, 15, 10))

    assert (await tick_plans(lab.factory, at(2026, 10, 11, 15, 10, 30))).created == 0
    assert (await tick_plans(lab.factory, at(2026, 10, 11, 23, 59, 59))).created == 0
    assert await lab.runs() == []
    assert (await tick_plans(lab.factory, at(2026, 10, 12, 2, 0, 0))).created == 1
    assert await lab.runs() == [(plan_id, at(2026, 10, 12, 2, 0), "queued")]


async def test_a_plan_made_at_its_own_minute_gets_that_period(lab):
    """created_at equal to the period's start: not before it."""
    plan_id = await lab.plan("0 2 * * *", created_at=at(2026, 10, 12, 2, 0, 0))

    assert (await tick_plans(lab.factory, at(2026, 10, 12, 2, 0, 0))).created == 1
    assert await lab.runs() == [(plan_id, at(2026, 10, 12, 2, 0), "queued")]


async def test_only_the_current_period_is_made_up_after_a_pause(lab):
    plan_id = await lab.plan("0 2 * * *", created_at=at(2026, 10, 1))

    summary = await tick_plans(lab.factory, at(2026, 10, 11, 14, 0))

    assert summary.created == 1
    assert await lab.runs() == [(plan_id, at(2026, 10, 11, 2, 0), "queued")]


async def test_a_plan_re_enabled_gets_its_current_period_at_the_next_tick(lab):
    plan_id = await lab.plan("0 2 * * *", created_at=at(2026, 10, 1), enabled=False)
    assert (await tick_plans(lab.factory, at(2026, 10, 11, 14, 0))).created == 0
    async with lab.factory() as s, s.begin():
        assert await PlanRepo(s).set_enabled(lab.msp_id, plan_id, True) == 1

    assert (await tick_plans(lab.factory, at(2026, 10, 11, 14, 5))).created == 1
    assert await lab.runs() == [(plan_id, at(2026, 10, 11, 2, 0), "queued")]


async def test_a_revoked_worker_s_plan_still_gets_its_run(lab):
    plan_id = await lab.plan("*/5 * * * *", created_at=T)
    async with lab.factory() as s, s.begin():
        assert await WorkerRepo(s).revoke(lab.msp_id, lab.worker_id, T) == 1

    assert (await tick_plans(lab.factory, at(2026, 10, 11, 12, 5))).created == 1
    (row,) = await lab.run_rows()
    assert (row.plan_id, row.state, row.dispatched_at) == (plan_id, "queued", None)


async def test_two_ticks_at_once_make_one_run(lab):
    plan_id = await lab.plan("*/5 * * * *", created_at=T)

    summaries = await asyncio.gather(
        tick_plans(lab.factory, at(2026, 10, 11, 12, 5)), tick_plans(lab.factory, at(2026, 10, 11, 12, 5, 1))
    )

    assert sorted(s.created for s in summaries) == [0, 1]
    assert sum(s.failed for s in summaries) == 0
    assert await lab.runs() == [(plan_id, at(2026, 10, 11, 12, 5), "queued")]


async def test_a_tick_is_one_select_per_msp_and_two_statements_per_run_made(lab):
    await lab.plan("*/5 * * * *", created_at=T)
    counted: list[str] = []

    def record(_conn, _cursor, statement, _params, _context, _executemany):
        counted.append(statement.strip().split()[0].upper())

    event.listen(lab.engine.sync_engine, "before_cursor_execute", record)
    try:
        await tick_plans(lab.factory, at(2026, 10, 11, 12, 5))
        busy = [s for s in counted if s in ("SELECT", "INSERT", "UPDATE", "WITH")]
        counted.clear()
        await tick_plans(lab.factory, at(2026, 10, 11, 12, 5, 30))
        idle = [s for s in counted if s in ("SELECT", "INSERT", "UPDATE", "WITH")]
    finally:
        event.remove(lab.engine.sync_engine, "before_cursor_execute", record)

    # The MSPs, then per MSP its plans; the busy MSP's connector and the INSERT;
    # a repeat is the INSERT alone, since the connector is read first.
    assert busy == ["SELECT", "SELECT", "SELECT", "INSERT", "SELECT"]
    assert idle == ["SELECT", "SELECT", "SELECT", "INSERT", "SELECT"]


async def test_the_tick_takes_now_from_the_clock_when_none_is_given(lab, monkeypatch):
    plan_id = await lab.plan("*/5 * * * *", created_at=T)
    monkeypatch.setattr(scheduler, "now", lambda: at(2026, 10, 11, 12, 5, 7))

    summary = await tick_plans(lab.factory)

    assert summary.created == 1
    assert await lab.runs() == [(plan_id, at(2026, 10, 11, 12, 5), "queued")]
    (line,) = lab.log("tick")
    assert (line["job"], line["msps"], line["plans"], line["created"], line["skipped"], line["failed"]) == ("plans", 2, 1, 1, 0, 0)
    assert "duration_ms" in line


def test_now_is_the_cloud_s_clock_in_utc():
    stamp = scheduler.now()

    assert stamp.utcoffset() == dt.timedelta(0)
    assert abs((dt.datetime.now(UTC) - stamp).total_seconds()) < 5


# --- The sweep ---------------------------------------------------------------------------------


async def test_the_sweep_calls_requeue_stale_per_msp_and_logs_what_moved(lab):
    plan_id = await lab.plan("*/5 * * * *", created_at=T)
    theirs = await lab.plan("*/5 * * * *", created_at=T, other=True)
    await tick_plans(lab.factory, at(2026, 10, 11, 12, 5))
    async with lab.factory() as s, s.begin():
        for msp_id, worker_id in ((lab.msp_id, lab.worker_id), (lab.other_msp_id, lab.other_worker_id)):
            taken = await RunRepo(s).dispatch(msp_id, worker_id, at(2026, 10, 11, 12, 6))
            assert len(taken) == 1
        await s.execute(text("UPDATE test_run SET attempt = 3 WHERE msp_id = :msp"), {"msp": lab.other_msp_id})

    early = await tick_sweep(lab.factory, at(2026, 10, 11, 18, 5, 59))
    late = await tick_sweep(lab.factory, at(2026, 10, 11, 18, 6, 0))

    assert (early.msps, early.requeued, early.expired, early.failed) == (2, 0, 0, 0)
    assert (late.msps, late.requeued, late.expired, late.failed) == (2, 1, 1, 0)
    assert await lab.runs() == [(plan_id, at(2026, 10, 11, 12, 5), "queued")]
    assert await lab.runs(lab.other_msp_id) == [(theirs, at(2026, 10, 11, 12, 5), "expired")]
    swept = lab.log("runs swept")
    assert sorted((e["msp_id"], e["requeued"], e["expired"]) for e in swept) == sorted(
        [(str(lab.msp_id), 1, 0), (str(lab.other_msp_id), 0, 1)]
    )
    ticks = lab.log("tick")
    assert [t["job"] for t in ticks][-2:] == ["sweep", "sweep"]


async def test_a_sweep_whose_msp_fails_logs_it_and_goes_on(lab, monkeypatch):
    original = RunRepo.requeue_stale

    async def failing(self, msp_id, now):
        if msp_id == lab.msp_id:
            raise RuntimeError("Sentinel-Fault")
        return await original(self, msp_id, now)

    monkeypatch.setattr(RunRepo, "requeue_stale", failing)

    summary = await tick_sweep(lab.factory, T)

    assert (summary.msps, summary.failed) == (2, 1)
    (failed,) = lab.log("tick failed")
    assert (failed["msp_id"], failed["job"], failed["exc_type"]) == (str(lab.msp_id), "sweep", "RuntimeError")
    assert "Sentinel-Fault" not in lab.stream.getvalue()


async def test_the_sweep_takes_now_from_the_clock_when_none_is_given(lab, monkeypatch):
    monkeypatch.setattr(scheduler, "now", lambda: T)

    summary = await tick_sweep(lab.factory)

    assert (summary.msps, summary.requeued, summary.expired) == (2, 0, 0)
    assert lab.log("runs swept") == []


async def test_a_tick_that_cannot_list_the_msps_is_logged_and_raises_nothing(own_database):
    """The database gone between two ticks: `tick failed` with no MSP, and
    the next tick in five minutes."""
    stream = io.StringIO()
    configure_logging("info", stream=stream)
    engine = create_async_engine("postgresql+asyncpg://nobody:nothing@127.0.0.1:1/none")
    try:
        plans = await tick_plans(make_session_factory(engine), T)
        sweep = await tick_sweep(make_session_factory(engine), T)
    finally:
        await engine.dispose()

    assert (plans.msps, plans.failed, sweep.msps, sweep.failed) == (0, 1, 0, 1)
    failed = [json.loads(line) for line in stream.getvalue().splitlines() if '"tick failed"' in line]
    assert [f.get("msp_id") for f in failed] == [None, None]
    assert all("exc_type" in f and "stack" in f for f in failed)


# --- The process ---------------------------------------------------------------------------------


def test_the_scheduler_runs_the_two_jobs_every_five_minutes_and_both_at_once_at_start():
    start = at(2026, 10, 11, 12, 0)

    built = build_scheduler(object(), object(), start_at=start)

    assert isinstance(built, AsyncIOScheduler)
    assert TICK_S == 300
    jobs = {job.id: job for job in built.get_jobs() if job.id != "reports"}
    assert set(jobs) == {"plans", "sweep"}
    for job in jobs.values():
        assert isinstance(job.trigger, IntervalTrigger) and job.trigger.interval == dt.timedelta(seconds=TICK_S)
        assert (job.max_instances, job.coalesce, job.misfire_grace_time) == (1, True, 60)
        assert job.next_run_time == start
    assert jobs["plans"].func is tick_plans and jobs["sweep"].func is tick_sweep
    assert str(built.timezone) == "UTC"


async def test_serve_starts_the_scheduler_waits_for_the_stop_and_shuts_down(monkeypatch):
    stream = io.StringIO()
    configure_logging("info", stream=stream)
    events: list[str] = []

    class FakeScheduler:
        def __init__(self):
            self.jobs = []

        def start(self):
            events.append("start")

        def shutdown(self, wait=True):
            events.append(f"shutdown wait={wait}")

    def build(factory, storage, *, start_at):
        events.append(f"built storage={storage}")
        return FakeScheduler()

    monkeypatch.setattr(scheduler, "build_scheduler", build)
    stop = asyncio.Event()

    async def stop_soon():
        await asyncio.sleep(0.05)
        events.append("stop")
        stop.set()

    task = asyncio.create_task(stop_soon())
    code = await scheduler.serve("postgresql+asyncpg://nobody:nothing@127.0.0.1:1/none", "the storage", stop=stop)
    await task

    assert code == 0
    assert events == ["built storage=the storage", "start", "stop", "shutdown wait=False"]
    lines = [json.loads(line) for line in stream.getvalue().splitlines() if line.startswith("{")]
    assert [l["event"] for l in lines if l["event"].startswith("scheduler")] == ["scheduler started", "scheduler stopped"]
    assert [l for l in lines if l["event"] == "scheduler started"][0]["tick_s"] == TICK_S
    assert "nothing" not in stream.getvalue() and "nobody" not in stream.getvalue()


@pytest.mark.parametrize("available", [True, False])
async def test_the_stop_signals_are_installed_where_the_loop_has_them(monkeypatch, available):
    installed = []
    loop = asyncio.get_running_loop()

    def add(sig, callback):
        if not available:
            raise NotImplementedError
        installed.append(sig)

    monkeypatch.setattr(loop, "add_signal_handler", add)
    stop = asyncio.Event()

    scheduler.install_stop_signals(loop, stop)

    assert installed == ([signal.SIGTERM, signal.SIGINT] if available else [])


def test_main_reads_the_database_url_and_the_log_level_and_serves(monkeypatch):
    seen = {}

    async def fake_serve(url, storage, *, stop=None):
        seen["url"] = url
        return 0

    monkeypatch.setattr(scheduler, "serve", fake_serve)
    monkeypatch.setattr(scheduler, "configure_logging", lambda level: seen.setdefault("level", level))
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://nobody:nothing@127.0.0.1:1/none")
    monkeypatch.setenv("LOG_LEVEL", "WARNING")
    for name, value in (("S3_ENDPOINT", "http://s3.test:9000"), ("S3_ACCESS_KEY", "a"), ("S3_SECRET_KEY", "s"), ("S3_BUCKET", "b")):
        monkeypatch.setenv(name, value)

    assert scheduler.main() == 0
    assert seen == {"url": "postgresql+asyncpg://nobody:nothing@127.0.0.1:1/none", "level": "warning"}


def test_main_stops_naming_the_variable_when_the_url_is_missing(monkeypatch, capsys):
    monkeypatch.delenv("DATABASE_URL", raising=False)

    with pytest.raises(SystemExit) as raised:
        scheduler.main()

    assert raised.value.code == 1
    assert capsys.readouterr().err.strip() == "settings error: DATABASE_URL is missing"


def test_the_scheduler_reads_no_profile_and_no_token():
    from pathlib import Path

    source = Path(scheduler.__file__).read_text(encoding="utf-8")

    assert "config_json" not in source and "token" not in source and "api_" not in source
    # C6.6: the report job writes the bucket through `Storage.for_writing` on
    # the five S3 variables alone; the app's `load_settings` (SECRET_KEY) stays out.
    assert "load_settings" not in source and "SECRET_KEY" not in source


# --- C6.6: the monthly report job (docs/decisions.md 2026-10-13, "C6.6, C6.5 and C6.7", point 1) ---


from botocore.stub import ANY, Stubber  # noqa: E402

from app.report import generate as report_generate  # noqa: E402
from app.report.render import Rendered  # noqa: E402
from app.repo.audit import AuditRepo  # noqa: E402
from app.repo.reports import ReportRepo  # noqa: E402
from app.scheduler import REPORT_HOUR_UTC, REPORT_MISFIRE_GRACE_S, tick_reports  # noqa: E402
from app.storage import Storage, make_s3_client  # noqa: E402
from tests.conftest import make_settings  # noqa: E402

FIRST = at(2026, 10, 1, 3, 0)  # the job's occurrence after a September
FAKE = Rendered("<html>1</html>", "1" * 64, "<html>2</html>", b"%PDF-fake", "2" * 64)


class ReportsLab(Lab):
    """The dispatcher's lab with a plan per client, runs of September 2026
    made by hand, and the bucket on botocore's Stubber."""

    async def fill(self) -> "ReportsLab":
        await super().fill()
        self.plan_id = await self.plan("0 2 * * *", created_at=at(2026, 8, 1))
        self.other_plan_id = await self.plan("0 2 * * *", created_at=at(2026, 8, 1), other=True)
        self.settings = make_settings()
        client = make_s3_client(self.settings)
        self.stubber = Stubber(client)
        self.stubber.activate()
        self.storage = Storage(client, self.settings.s3_bucket)
        return self

    async def run(self, *, other: bool = False, state: str = "pass", finished_at: dt.datetime | None = at(2026, 9, 10, 2, 5), created_at: dt.datetime | None = None) -> uuid.UUID:
        msp_id = self.other_msp_id if other else self.msp_id
        async with self.factory() as s, s.begin():
            row = await RunRepo(s).create(
                msp_id,
                plan_id=self.other_plan_id if other else self.plan_id,
                client_id=self.other_client_id if other else self.client_id,
                connector_id=self.other_connector_id if other else self.connector_id,
                worker_id=self.other_worker_id if other else self.worker_id,
            )
            await s.execute(
                text("UPDATE test_run SET state = :state, finished_at = :finished, created_at = :created, recovery_ms = 1000 WHERE id = :id"),
                {"state": state, "finished": finished_at, "created": created_at or (finished_at or at(2026, 9, 10)) - dt.timedelta(minutes=1), "id": row.id},
            )
            return row.id

    def key(self, *, other: bool = False, period: str = "2026-09") -> str:
        msp_id = self.other_msp_id if other else self.msp_id
        client_id = self.other_client_id if other else self.client_id
        return f"msp/{msp_id}/reports/{client_id}/{period}.pdf"

    def expect_put(self, key: str) -> None:
        self.stubber.add_response("put_object", {"ETag": '"x"'}, expected_params={"Bucket": self.settings.s3_bucket, "Key": key, "Body": ANY, "ContentType": "application/pdf"})

    def fail_put(self, key: str) -> None:
        self.stubber.add_client_error("put_object", service_error_code="InternalError", expected_params={"Bucket": self.settings.s3_bucket, "Key": key, "Body": ANY, "ContentType": "application/pdf"})

    async def reports(self, msp_id=None) -> list:
        async with self.factory() as s, s.begin():
            return await ReportRepo(s).list(self.msp_id if msp_id is None else msp_id)

    async def audit(self, msp_id=None) -> list[tuple]:
        async with self.factory() as s, s.begin():
            return [(r.action, r.user_id, r.ip) for r in await AuditRepo(s).list(self.msp_id if msp_id is None else msp_id) if r.action == "report.create"]


@pytest.fixture
async def rlab(own_database, monkeypatch):
    lab = await ReportsLab(own_database).fill()
    monkeypatch.setattr(report_generate, "render_report", lambda data: FAKE)
    try:
        yield lab
    finally:
        await lab.close()


async def test_the_job_makes_every_client_s_final_report_of_the_previous_month_and_names_it_after_its_commit(rlab):
    await rlab.run()
    await rlab.run(other=True, state="fail")
    rlab.expect_put(rlab.key())
    rlab.expect_put(rlab.key(other=True))

    summary = await tick_reports(rlab.factory, rlab.storage, FIRST)

    assert (summary.msps, summary.clients, summary.created, summary.existing, summary.failed) == (2, 2, 2, 0, 0)
    rlab.stubber.assert_no_pending_responses()
    for msp_id in (rlab.msp_id, rlab.other_msp_id):
        (row,) = await rlab.reports(msp_id)
        assert (row.period_start, row.period_end, row.interim, row.generated_at, row.content_sha256, row.file_sha256) == (
            dt.date(2026, 9, 1), dt.date(2026, 9, 30), False, FIRST, FAKE.content_sha256, FAKE.file_sha256,
        )
        assert await rlab.audit(msp_id) == [("report.create", None, None)]
    created = rlab.log("report created")
    assert sorted((e["msp_id"], e["client_id"], e["period"]) for e in created) == sorted(
        [(str(rlab.msp_id), str(rlab.client_id), "2026-09"), (str(rlab.other_msp_id), str(rlab.other_client_id), "2026-09")]
    )
    assert {e["report_id"] for e in created} == {str(r.id) for m in (rlab.msp_id, rlab.other_msp_id) for r in await rlab.reports(m)}
    (tick,) = rlab.log("tick")
    assert {k: tick[k] for k in ("job", "msps", "clients", "created", "existing", "failed")} == {"job": "reports", "msps": 2, "clients": 2, "created": 2, "existing": 0, "failed": 0}
    assert isinstance(tick["duration_ms"], int)


async def test_a_client_without_a_run_in_the_month_gets_no_report_and_one_with_an_expired_run_alone_gets_one(rlab):
    await rlab.run(state="expired", finished_at=None, created_at=at(2026, 9, 3))
    await rlab.run(other=True, finished_at=at(2026, 10, 1, 0, 30))  # October's: not this month's
    rlab.expect_put(rlab.key())

    summary = await tick_reports(rlab.factory, rlab.storage, FIRST)

    assert (summary.clients, summary.created, summary.failed) == (1, 1, 0)
    assert len(await rlab.reports()) == 1 and await rlab.reports(rlab.other_msp_id) == []
    rlab.stubber.assert_no_pending_responses()


async def test_a_month_that_has_its_report_is_existing_with_no_render_and_one_read_per_client(rlab, monkeypatch):
    await rlab.run()
    rlab.expect_put(rlab.key())
    assert (await tick_reports(rlab.factory, rlab.storage, FIRST)).created == 1
    monkeypatch.setattr(report_generate, "render_report", lambda data: pytest.fail("rendered a month that has its report"))
    seen: list[str] = []

    def listen(_conn, _cursor, statement, _params, _context, _executemany):
        seen.append(statement.split()[0].upper())

    event.listen(rlab.engine.sync_engine, "before_cursor_execute", listen)
    try:
        summary = await tick_reports(rlab.factory, rlab.storage, FIRST + dt.timedelta(days=12))
    finally:
        event.remove(rlab.engine.sync_engine, "before_cursor_execute", listen)

    assert (summary.msps, summary.clients, summary.created, summary.existing, summary.failed) == (2, 1, 0, 1, 0)
    # The MSPs, each MSP's clients, and the one read of the month's final report.
    assert seen == ["SELECT"] * 4
    assert len(await rlab.reports()) == 1
    assert len(rlab.log("report created")) == 1


async def test_a_client_whose_put_fails_is_rolled_back_alone_and_logged_by_type_while_the_next_client_s_report_is_made(rlab):
    """Two clients of one MSP: the first's put fails, the second's report is
    committed; one transaction per client."""
    async with rlab.factory() as s, s.begin():
        second = await ClientRepo(s).create(rlab.msp_id, name="second", tenant_id=uuid.uuid4())
        connector = await ConnectorRepo(s).create(rlab.msp_id, second.id, rlab.worker_id, profile_for(second.tenant_id, veeam_org_name=SENTINEL_ORG))
        plan = await PlanRepo(s).create(rlab.msp_id, second.id, connector.id, sample_mail=1, sample_sp=0, sample_od=0, cadence_cron="0 2 * * *", now=at(2026, 8, 1))
        run = await RunRepo(s).create(rlab.msp_id, plan_id=plan.id, client_id=second.id, connector_id=connector.id, worker_id=rlab.worker_id)
        await s.execute(text("UPDATE test_run SET state = 'pass', finished_at = :f, created_at = :f WHERE id = :id"), {"f": at(2026, 9, 12), "id": run.id})
    await rlab.run()
    first, last = sorted([rlab.client_id, second.id])
    rlab.fail_put(f"msp/{rlab.msp_id}/reports/{first}/2026-09.pdf")
    rlab.expect_put(f"msp/{rlab.msp_id}/reports/{last}/2026-09.pdf")

    summary = await tick_reports(rlab.factory, rlab.storage, FIRST)

    assert (summary.clients, summary.created, summary.failed) == (2, 1, 1)
    rlab.stubber.assert_no_pending_responses()
    (row,) = await rlab.reports()
    assert row.client_id == last
    assert await rlab.audit() == [("report.create", None, None)]
    (failed,) = rlab.log("report failed")
    assert (failed["msp_id"], failed["client_id"], failed["period"], failed["exc_type"]) == (str(rlab.msp_id), str(first), "2026-09", "ReportFailed")
    assert "stack" in failed and "InternalError" not in json.dumps(failed)
    assert [e["client_id"] for e in rlab.log("report created")] == [str(last)]


def _raise(error: BaseException):
    raise error


async def test_a_render_that_fails_is_the_client_s_failure_by_its_type(rlab, monkeypatch):
    await rlab.run()
    monkeypatch.setattr(report_generate, "render_report", lambda data: _raise(OSError("no pango")))

    summary = await tick_reports(rlab.factory, rlab.storage, FIRST)

    assert (summary.created, summary.failed) == (0, 1)
    assert await rlab.reports() == []
    (failed,) = rlab.log("report failed")
    assert failed["exc_type"] == "ReportFailed" and "pango" not in json.dumps(failed)


async def test_a_client_whose_report_fails_outside_the_repos_is_logged_by_type_and_the_next_client_is_made(rlab, monkeypatch):
    """Neither a repo refusal nor a `ReportFailed`: the database gone under
    one client's transaction, say. Rolled back alone, logged by type."""
    await rlab.run()
    await rlab.run(other=True)
    rlab.expect_put(rlab.key(other=True))
    real = scheduler.generate

    async def broken(session, storage, msp_id, client_id, period, **kwargs):
        if msp_id == rlab.msp_id:
            raise RuntimeError("gone")
        return await real(session, storage, msp_id, client_id, period, **kwargs)

    monkeypatch.setattr(scheduler, "generate", broken)

    summary = await tick_reports(rlab.factory, rlab.storage, FIRST)

    assert (summary.msps, summary.clients, summary.created, summary.failed) == (2, 2, 1, 1)
    (failed,) = rlab.log("report failed")
    assert (failed["msp_id"], failed["client_id"], failed["exc_type"]) == (str(rlab.msp_id), str(rlab.client_id), "RuntimeError")
    assert await rlab.reports() == [] and len(await rlab.reports(rlab.other_msp_id)) == 1


async def test_an_msp_whose_clients_cannot_be_read_is_logged_and_the_next_msp_s_report_is_made(rlab, monkeypatch):
    await rlab.run()
    await rlab.run(other=True)
    rlab.expect_put(rlab.key(other=True))
    real = RunRepo.clients_in_period

    async def broken(self, msp_id, *, start, end):
        if msp_id == rlab.msp_id:
            raise RuntimeError("gone")
        return await real(self, msp_id, start=start, end=end)

    monkeypatch.setattr(RunRepo, "clients_in_period", broken)

    summary = await tick_reports(rlab.factory, rlab.storage, FIRST)

    assert (summary.msps, summary.clients, summary.created, summary.failed) == (2, 1, 1, 1)
    (failed,) = rlab.log("tick failed")
    assert (failed["job"], failed["msp_id"], failed["exc_type"]) == ("reports", str(rlab.msp_id), "RuntimeError")
    assert len(await rlab.reports(rlab.other_msp_id)) == 1


async def test_a_job_that_cannot_list_the_msps_is_logged_and_raises_nothing(rlab):
    engine = create_async_engine("postgresql+asyncpg://nobody:nothing@127.0.0.1:1/none")
    try:
        summary = await tick_reports(make_session_factory(engine), rlab.storage, FIRST)
    finally:
        await engine.dispose()

    assert (summary.msps, summary.failed) == (0, 1)
    (failed,) = rlab.log("tick failed")
    assert failed["job"] == "reports" and failed.get("msp_id") is None


async def test_the_job_takes_now_from_the_clock_when_none_is_given(rlab, monkeypatch):
    await rlab.run()
    monkeypatch.setattr(scheduler, "now", lambda: FIRST + dt.timedelta(days=5))
    rlab.expect_put(rlab.key())

    summary = await tick_reports(rlab.factory, rlab.storage)

    assert summary.created == 1
    (row,) = await rlab.reports()
    assert row.generated_at == FIRST + dt.timedelta(days=5) and row.period_start == dt.date(2026, 9, 1)


async def test_the_job_renders_a_real_report_whose_object_is_the_pdf_the_row_names(own_database):
    """One real render in the job's own process shape: the put's bytes are
    the row's file hash."""
    import hashlib

    lab = await ReportsLab(own_database).fill()
    try:
        await lab.run()
        bodies: list[bytes] = []
        lab.storage.client.meta.events.register("before-parameter-build.s3.PutObject", lambda params, **_kw: bodies.append(params["Body"]))
        lab.expect_put(lab.key())

        summary = await tick_reports(lab.factory, lab.storage, FIRST)

        assert summary.created == 1
        (row,) = await lab.reports()
        (pdf,) = bodies
        assert pdf.startswith(b"%PDF-") and hashlib.sha256(pdf).hexdigest() == row.file_sha256
    finally:
        await lab.close()


def test_the_scheduler_runs_the_report_job_on_the_first_at_three_utc_and_once_at_start():
    from apscheduler.triggers.cron import CronTrigger

    start = at(2026, 10, 11, 12, 0)
    storage = object()

    built = build_scheduler(object(), storage, start_at=start)

    jobs = {job.id: job for job in built.get_jobs()}
    assert set(jobs) == {"plans", "sweep", "reports"}
    job = jobs["reports"]
    assert job.func is tick_reports and job.args[1] is storage
    assert isinstance(job.trigger, CronTrigger)
    fields = {field.name: str(field) for field in job.trigger.fields}
    assert (fields["day"], fields["hour"], fields["minute"], fields["second"]) == ("1", str(REPORT_HOUR_UTC), "0", "0")
    assert (fields["year"], fields["month"], fields["day_of_week"]) == ("*", "*", "*")
    assert str(job.trigger.timezone) == "UTC" and REPORT_HOUR_UTC == 3
    assert (job.max_instances, job.coalesce, job.misfire_grace_time) == (1, True, REPORT_MISFIRE_GRACE_S) and REPORT_MISFIRE_GRACE_S == 3600
    assert job.next_run_time == start
    # After the start run: the 1st at 03:00 UTC, every month.
    nxt = job.trigger.get_next_fire_time(None, start)
    assert nxt == at(2026, 11, 1, 3, 0)
    assert job.trigger.get_next_fire_time(nxt, nxt) == at(2026, 12, 1, 3, 0)


def test_main_reads_the_five_s3_variables_too_and_refuses_a_missing_one_by_name(monkeypatch, capsys):
    seen = {}

    async def fake_serve(url, storage, *, stop=None):
        seen["url"] = url
        seen["bucket"] = storage.bucket
        return 0

    monkeypatch.setattr(scheduler, "serve", fake_serve)
    monkeypatch.setattr(scheduler, "configure_logging", lambda level: None)
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://nobody:nothing@127.0.0.1:1/none")
    for name, value in (("S3_ENDPOINT", "http://s3.test:9000"), ("S3_ACCESS_KEY", "a"), ("S3_SECRET_KEY", "s"), ("S3_BUCKET", "b")):
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("SECRET_KEY", raising=False)

    assert scheduler.main() == 0
    assert seen == {"url": "postgresql+asyncpg://nobody:nothing@127.0.0.1:1/none", "bucket": "b"}

    monkeypatch.delenv("S3_BUCKET")
    with pytest.raises(SystemExit) as raised:
        scheduler.main()
    assert raised.value.code == 1
    assert capsys.readouterr().err.strip() == "settings error: S3_BUCKET is missing"

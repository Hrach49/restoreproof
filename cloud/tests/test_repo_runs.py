"""C5.6: `RunRepo.dispatch` and `RunRepo.requeue_stale` by themselves
(docs/decisions.md 2026-10-10, "C5.5 and C5.6", points 4 and 8).

`dispatch` is one statement: the Worker's oldest queued runs, at most five,
moved to `dispatched` with `dispatched_at` set and `attempt` counted, under
`FOR UPDATE SKIP LOCKED`. `requeue_stale` is the scheduler's sweep (C5.9 calls
it per MSP): a run dispatched six hours ago or more goes back to `queued`, or
to `expired` after three attempts.
"""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from sqlalchemy import event, text

from app.repo.clients import ClientRepo
from app.repo.connectors import ConnectorRepo
from app.repo.msps import MspRepo
from app.repo.plans import PlanRepo
from app.repo.runs import DISPATCH_LIMIT, DISPATCH_TIMEOUT, MAX_ATTEMPTS, ReceivedRun, RunRepo
from app.repo.workers import WorkerRepo
from tests.test_repo_connectors import profile_for

UTC = dt.timezone.utc
NOW = dt.datetime(2026, 10, 10, 12, 0, 0, tzinfo=UTC)
SIX_HOURS = dt.timedelta(hours=6)
ONE_SECOND = dt.timedelta(seconds=1)
PEM = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----\n"


def a_hash(seed: str) -> str:
    return uuid.uuid5(uuid.NAMESPACE_DNS, seed).hex * 2


class Queue:
    """One MSP with a client on two Workers, a plan on each, and runs made to
    order with their own `created_at`."""

    @classmethod
    async def make(cls, session, name="a") -> "Queue":
        q = cls()
        q.session = session
        q.msp = await MspRepo(session).create(name=name)
        q.client = await ClientRepo(session).create(q.msp.id, name=f"{name} client", tenant_id=uuid.uuid4())
        q.worker = await WorkerRepo(session).create(
            q.msp.id, f"{name} w1", public_key_pem=PEM, key_id=a_hash(f"{name} k1"), api_token_hash=a_hash(f"{name} t1")
        )
        q.other_worker = await WorkerRepo(session).create(
            q.msp.id, f"{name} w2", public_key_pem=PEM, key_id=a_hash(f"{name} k2"), api_token_hash=a_hash(f"{name} t2")
        )
        q.connector = await ConnectorRepo(session).create(
            q.msp.id, q.client.id, q.worker.id, profile_for(q.client.tenant_id)
        )
        q.other_connector = await ConnectorRepo(session).create(
            q.msp.id, q.client.id, q.other_worker.id, profile_for(q.client.tenant_id)
        )
        q.plan = await PlanRepo(session).create(
            q.msp.id, q.client.id, q.connector.id, sample_mail=5, sample_sp=3, sample_od=2, cadence_cron="0 2 * * *", now=NOW
        )
        q.other_plan = await PlanRepo(session).create(
            q.msp.id, q.client.id, q.other_connector.id, sample_mail=1, sample_sp=1, sample_od=1, cadence_cron="0 3 * * *", now=NOW
        )
        q.runs = RunRepo(session)
        return q

    async def run(self, *, created_at: dt.datetime, other: bool = False, state: str | None = None):
        plan = self.other_plan if other else self.plan
        connector = self.other_connector if other else self.connector
        worker = self.other_worker if other else self.worker
        row = await self.runs.create(
            self.msp.id, plan_id=plan.id, client_id=self.client.id, connector_id=connector.id, worker_id=worker.id
        )
        # created_at is the transaction's now(): set it by hand for an order.
        await self.session.execute(
            text("UPDATE test_run SET created_at = :at WHERE id = :id"), {"at": created_at, "id": row.id}
        )
        if state is not None:
            assert await self.runs.set_state(self.msp.id, row.id, state) == 1
        await self.session.refresh(row)
        return row

    async def queued(self, count: int, *, other: bool = False, start: dt.datetime = NOW) -> list:
        return [await self.run(created_at=start + dt.timedelta(minutes=i), other=other) for i in range(count)]

    async def fresh(self, row):
        await self.session.refresh(row)
        return row


def test_the_policy_s_constants():
    assert DISPATCH_LIMIT == 5
    assert DISPATCH_TIMEOUT == SIX_HOURS
    assert MAX_ATTEMPTS == 3


# --- dispatch ----------------------------------------------------------------------------


async def test_a_dispatch_takes_the_oldest_five_in_order_and_marks_them(session):
    q = await Queue.make(session)
    rows = await q.queued(6)
    later = NOW + dt.timedelta(hours=1)

    taken = await q.runs.dispatch(q.msp.id, q.worker.id, later)

    assert [d.run.id for d in taken] == [row.id for row in rows[:5]]
    for d in taken:
        assert (d.run.state, d.run.dispatched_at, d.run.attempt) == ("dispatched", later, 1)
        # The review's finding 5: the plan, connector and client come with the
        # run, in one joined statement, each its own.
        assert (d.plan.id, d.connector.id, d.client.id) == (q.plan.id, q.connector.id, q.client.id)
        assert (d.plan.msp_id, d.connector.msp_id, d.client.msp_id) == (q.msp.id, q.msp.id, q.msp.id)
    sixth = await q.fresh(rows[5])
    assert (sixth.state, sixth.dispatched_at, sixth.attempt) == ("queued", None, 0)

    second = await q.runs.dispatch(q.msp.id, q.worker.id, later + ONE_SECOND)
    assert [d.run.id for d in second] == [rows[5].id]
    assert await q.runs.dispatch(q.msp.id, q.worker.id, later + ONE_SECOND) == []


async def test_the_order_is_created_at_then_id(session):
    q = await Queue.make(session)
    same_time = [await q.run(created_at=NOW) for _ in range(3)]
    older = await q.run(created_at=NOW - dt.timedelta(days=1))

    taken = await q.runs.dispatch(q.msp.id, q.worker.id, NOW)

    assert [d.run.id for d in taken] == [older.id] + sorted(row.id for row in same_time)


async def test_the_limit_is_the_caller_s_within_the_policy_s(session):
    q = await Queue.make(session)
    rows = await q.queued(4)

    taken = await q.runs.dispatch(q.msp.id, q.worker.id, NOW, limit=2)

    assert [d.run.id for d in taken] == [row.id for row in rows[:2]]
    with pytest.raises(ValueError):
        await q.runs.dispatch(q.msp.id, q.worker.id, NOW, limit=6)
    with pytest.raises(ValueError):
        await q.runs.dispatch(q.msp.id, q.worker.id, NOW, limit=0)


async def test_another_worker_s_runs_and_another_msp_s_are_not_taken(session):
    a = await Queue.make(session, "a")
    b = await Queue.make(session, "b")
    mine = await a.queued(2)
    others = await a.queued(2, other=True)
    theirs = await b.queued(2)

    taken = await a.runs.dispatch(a.msp.id, a.worker.id, NOW)
    crossed = await a.runs.dispatch(a.msp.id, b.worker.id, NOW)

    assert [d.run.id for d in taken] == [row.id for row in mine]
    assert crossed == []
    for row in others + theirs:
        assert (await a.fresh(row)).state == "queued"


@pytest.mark.parametrize("state", ["dispatched", "pass", "fail", "error", "expired"])
async def test_a_run_in_any_other_state_is_never_dispatched(session, state):
    q = await Queue.make(session)
    row = await q.run(created_at=NOW, state=state)

    assert await q.runs.dispatch(q.msp.id, q.worker.id, NOW) == []
    assert (await q.fresh(row)).attempt == 0


async def test_a_dispatch_counts_every_attempt(session):
    q = await Queue.make(session)
    (row,) = await q.queued(1)

    for attempt in (1, 2, 3):
        taken = await q.runs.dispatch(q.msp.id, q.worker.id, NOW + attempt * SIX_HOURS)
        assert [(d.run.id, d.run.attempt) for d in taken] == [(row.id, attempt)]
        assert await q.runs.requeue_stale(q.msp.id, NOW + (attempt + 1) * SIX_HOURS) == (
            (1, 0) if attempt < MAX_ATTEMPTS else (0, 1)
        )

    final = await q.fresh(row)
    assert (final.state, final.attempt) == ("expired", 3)
    assert await q.runs.dispatch(q.msp.id, q.worker.id, NOW + 10 * SIX_HOURS) == []


async def test_an_idle_dispatch_is_one_statement_and_a_busy_one_two(session, test_engine):
    """The review's finding 5: no re-select when nothing was taken, and the
    rows' plan, connector and client in one joined select."""
    q = await Queue.make(session)
    await q.queued(3)
    counted: list[str] = []

    def record(_conn, _cursor, statement, _params, _context, _executemany):
        counted.append(statement.strip().split()[0].upper())

    event.listen(test_engine.sync_engine, "before_cursor_execute", record)
    try:
        busy = await q.runs.dispatch(q.msp.id, q.worker.id, NOW)
        busy_statements = [s for s in counted if s in ("SELECT", "UPDATE", "WITH")]
        counted.clear()
        idle = await q.runs.dispatch(q.msp.id, q.worker.id, NOW)
        idle_statements = [s for s in counted if s in ("SELECT", "UPDATE", "WITH")]
    finally:
        event.remove(test_engine.sync_engine, "before_cursor_execute", record)

    assert len(busy) == 3 and idle == []
    assert busy_statements == ["WITH", "SELECT"]
    assert idle_statements == ["WITH"]


# --- requeue_stale -----------------------------------------------------------------------------


async def test_a_run_is_stale_at_exactly_six_hours(session):
    q = await Queue.make(session)
    (row,) = await q.queued(1)
    (taken,) = await q.runs.dispatch(q.msp.id, q.worker.id, NOW)

    assert await q.runs.requeue_stale(q.msp.id, NOW + SIX_HOURS - ONE_SECOND) == (0, 0)
    assert (await q.fresh(row)).state == "dispatched"
    assert await q.runs.requeue_stale(q.msp.id, NOW + SIX_HOURS) == (1, 0)
    requeued = await q.fresh(row)
    assert (requeued.state, requeued.attempt, requeued.dispatched_at) == ("queued", 1, NOW)


async def test_the_sweep_answers_how_many_went_back_and_how_many_expired(session):
    q = await Queue.make(session)
    rows = await q.queued(3)
    await q.runs.dispatch(q.msp.id, q.worker.id, NOW)
    await session.execute(
        text("UPDATE test_run SET attempt = 3 WHERE id = :id"), {"id": rows[0].id}
    )
    await session.execute(
        text("UPDATE test_run SET attempt = 7 WHERE id = :id"), {"id": rows[1].id}
    )

    assert await q.runs.requeue_stale(q.msp.id, NOW + SIX_HOURS) == (1, 2)
    assert [(await q.fresh(row)).state for row in rows] == ["expired", "expired", "queued"]
    assert await q.runs.requeue_stale(q.msp.id, NOW + SIX_HOURS) == (0, 0)


async def test_the_sweep_leaves_the_other_states_and_the_other_msp_alone(session):
    a = await Queue.make(session, "a")
    b = await Queue.make(session, "b")
    queued = await a.run(created_at=NOW)
    passed = await a.run(created_at=NOW, state="pass")
    (theirs,) = await b.queued(1)
    await b.runs.dispatch(b.msp.id, b.worker.id, NOW)

    assert await a.runs.requeue_stale(a.msp.id, NOW + 2 * SIX_HOURS) == (0, 0)
    assert (await a.fresh(queued)).state == "queued"
    assert (await a.fresh(passed)).state == "pass"
    assert (await a.fresh(theirs)).state == "dispatched"
    assert await b.runs.requeue_stale(b.msp.id, NOW + 2 * SIX_HOURS) == (1, 0)


# --- receive (C5.7) ---------------------------------------------------------------------


def received(**changes) -> ReceivedRun:
    """A bundle's columns as C5.7 maps them (docs/decisions.md 2026-10-10, C5.7, point 11)."""
    values = dict(
        state="pass",
        error_code=None,
        error_message=None,
        started_at=NOW,
        finished_at=NOW + dt.timedelta(minutes=4),
        total_ms=240_000,
        recovery_ms=200_000,
        restore_point_at=NOW - dt.timedelta(hours=14),
        bundle_key="msp/x/runs/y/",
        bundle_sha256="ab" * 32,
        tsa_ok=True,
        tsa_time=NOW + dt.timedelta(minutes=5),
        cleanup_ok=True,
    )
    return ReceivedRun(**{**values, **changes})


async def dispatched_run(q: Queue, *, state: str = "dispatched", attempt: int = 1, other: bool = False):
    """A run the Worker was handed `attempt` times, now in `state`."""
    row = await q.run(created_at=NOW, other=other)
    await q.session.execute(
        text("UPDATE test_run SET state = :state, dispatched_at = :at, attempt = :attempt WHERE id = :id"),
        {"state": state, "at": NOW, "attempt": attempt, "id": row.id},
    )
    return await q.fresh(row)


@pytest.mark.parametrize("state", ["dispatched", "queued", "expired"])
async def test_a_run_that_was_handed_out_takes_its_bundle_whatever_the_sweep_did_since(session, state):
    """dispatched; queued again by the sweep and not yet polled; expired after
    three attempts (the W4.8 case: a late `error interrupted`)."""
    q = await Queue.make(session)
    attempt = 3 if state == "expired" else 1
    row = await dispatched_run(q, state=state, attempt=attempt)
    update = received(state="error", error_code="interrupted", error_message="the run was interrupted")

    touched = await q.runs.receive(q.msp.id, row.id, worker_id=q.worker.id, update=update)

    assert touched == 1
    row = await q.fresh(row)
    assert (row.state, row.error_code, row.error_message) == ("error", "interrupted", "the run was interrupted")
    # The dispatch's own columns are kept.
    assert (row.dispatched_at, row.attempt) == (NOW, attempt)


async def test_a_bundle_s_columns_are_written_as_given_and_signature_ok_is_true(session):
    q = await Queue.make(session)
    row = await dispatched_run(q)
    update = received()

    assert await q.runs.receive(q.msp.id, row.id, worker_id=q.worker.id, update=update) == 1

    row = await q.fresh(row)
    for column in ReceivedRun.__dataclass_fields__:
        assert getattr(row, column) == getattr(update, column), column
    assert row.signature_ok is True


async def test_a_run_never_handed_out_takes_no_bundle(session):
    q = await Queue.make(session)
    row = await q.run(created_at=NOW)
    assert (row.state, row.dispatched_at, row.attempt) == ("queued", None, 0)

    assert await q.runs.receive(q.msp.id, row.id, worker_id=q.worker.id, update=received()) == 0

    row = await q.fresh(row)
    assert (row.state, row.bundle_sha256, row.signature_ok) == ("queued", None, None)


@pytest.mark.parametrize("state", ["pass", "fail", "error"])
async def test_a_run_that_holds_a_bundle_takes_no_second(session, state):
    q = await Queue.make(session)
    row = await dispatched_run(q)
    first = received(state=state, error_code="internal" if state == "error" else None)
    assert await q.runs.receive(q.msp.id, row.id, worker_id=q.worker.id, update=first) == 1

    assert await q.runs.receive(q.msp.id, row.id, worker_id=q.worker.id, update=received(bundle_sha256="cd" * 32)) == 0

    row = await q.fresh(row)
    assert (row.state, row.bundle_sha256) == (state, "ab" * 32)


async def test_another_worker_s_run_another_msp_s_and_an_absent_one_take_no_bundle(session):
    q = await Queue.make(session)
    b = await Queue.make(session, name="b")
    mine = await dispatched_run(q)
    others = await dispatched_run(q, other=True)
    theirs = await dispatched_run(b)

    assert await q.runs.receive(q.msp.id, others.id, worker_id=q.worker.id, update=received()) == 0
    assert await q.runs.receive(q.msp.id, theirs.id, worker_id=b.worker.id, update=received()) == 0
    assert await q.runs.receive(q.msp.id, uuid.uuid4(), worker_id=q.worker.id, update=received()) == 0
    assert await q.runs.receive(q.msp.id, mine.id, worker_id=q.worker.id, update=received()) == 1

    for row in (others, theirs):
        row = await q.fresh(row)
        assert (row.state, row.bundle_sha256) == ("dispatched", None)


async def test_a_get_answers_the_row_as_the_database_has_it_not_the_session_s_stale_copy(session):
    """C5.7 point 11: after an UPDATE that touched no row the route reads the
    run again and must see what another transaction left, not the identity
    map's copy."""
    q = await Queue.make(session)
    row = await dispatched_run(q)
    first = await q.runs.get(q.msp.id, row.id)
    assert first.state == "dispatched"
    await session.execute(
        text("UPDATE test_run SET state = 'pass', bundle_sha256 = :sha WHERE id = :id"), {"sha": "ef" * 32, "id": row.id}
    )

    again = await q.runs.get(q.msp.id, row.id)

    assert again is first  # the one instance...
    assert (again.state, again.bundle_sha256) == ("pass", "ef" * 32)  # ...with the database's values


async def test_receive_is_one_update(session, test_engine):
    q = await Queue.make(session)
    row = await dispatched_run(q)
    counted: list[str] = []

    def record(_conn, _cursor, statement, _params, _context, _executemany):
        counted.append(statement.strip().split()[0].upper())

    event.listen(test_engine.sync_engine, "before_cursor_execute", record)
    try:
        assert await q.runs.receive(q.msp.id, row.id, worker_id=q.worker.id, update=received()) == 1
    finally:
        event.remove(test_engine.sync_engine, "before_cursor_execute", record)

    assert counted == ["UPDATE"]


# --- C5.9: create_scheduled, one INSERT under the period's unique ------------------------------


PERIOD = dt.datetime(2026, 10, 11, 2, 0, tzinfo=UTC)


async def test_a_scheduled_run_is_made_once_per_plan_and_period(session):
    q = await Queue.make(session)
    kwargs = {"plan_id": q.plan.id, "client_id": q.client.id, "connector_id": q.connector.id, "worker_id": q.worker.id}

    first = await q.runs.create_scheduled(q.msp.id, scheduled_for=PERIOD, **kwargs)
    again = await q.runs.create_scheduled(q.msp.id, scheduled_for=PERIOD, **kwargs)
    next_period = await q.runs.create_scheduled(q.msp.id, scheduled_for=PERIOD + dt.timedelta(days=1), **kwargs)
    other_plan = await q.runs.create_scheduled(
        q.msp.id, plan_id=q.other_plan.id, client_id=q.client.id, connector_id=q.other_connector.id,
        worker_id=q.other_worker.id, scheduled_for=PERIOD,
    )

    assert first is not None and again is None
    assert next_period is not None and other_plan is not None
    assert (first.state, first.scheduled_for, first.dispatched_at, first.attempt) == ("queued", PERIOD, None, 0)
    assert (first.msp_id, first.plan_id, first.client_id, first.connector_id, first.worker_id) == (
        q.msp.id, q.plan.id, q.client.id, q.connector.id, q.worker.id
    )
    assert first.created_at is not None
    assert {r.id for r in await q.runs.list(q.msp.id)} == {first.id, next_period.id, other_plan.id}
    # The session still answers: a conflict is no error.
    assert (await q.fresh(first)).scheduled_for == PERIOD


async def test_a_scheduled_run_is_one_insert_and_a_repeat_the_same_one(session, test_engine):
    q = await Queue.make(session)
    kwargs = {"plan_id": q.plan.id, "client_id": q.client.id, "connector_id": q.connector.id, "worker_id": q.worker.id}
    counted: list[str] = []

    def record(_conn, _cursor, statement, _params, _context, _executemany):
        counted.append(statement.strip().split()[0].upper())

    event.listen(test_engine.sync_engine, "before_cursor_execute", record)
    try:
        await q.runs.create_scheduled(q.msp.id, scheduled_for=PERIOD, **kwargs)
        first = [s for s in counted if s in ("SELECT", "UPDATE", "INSERT", "WITH")]
        counted.clear()
        await q.runs.create_scheduled(q.msp.id, scheduled_for=PERIOD, **kwargs)
        repeat = [s for s in counted if s in ("SELECT", "UPDATE", "INSERT", "WITH")]
    finally:
        event.remove(test_engine.sync_engine, "before_cursor_execute", record)

    assert first == ["INSERT"] and repeat == ["INSERT"]


async def test_a_scheduled_run_needs_the_period(session):
    q = await Queue.make(session)

    with pytest.raises(TypeError):
        await q.runs.create_scheduled(q.msp.id, plan_id=q.plan.id, client_id=q.client.id, connector_id=q.connector.id, worker_id=q.worker.id)
    with pytest.raises(ValueError):
        await q.runs.create_scheduled(
            q.msp.id, plan_id=q.plan.id, client_id=q.client.id, connector_id=q.connector.id, worker_id=q.worker.id,
            scheduled_for=dt.datetime(2026, 10, 11, 2, 0),
        )


async def test_two_sessions_make_one_run_for_one_period(own_database):
    """Two ticks or two scheduler processes: the unique and ON CONFLICT DO
    NOTHING make one run, and both transactions commit."""
    import asyncio

    from sqlalchemy.ext.asyncio import create_async_engine

    from app.db import make_session_factory

    engine = create_async_engine(own_database, connect_args={"server_settings": {"timezone": "UTC"}})
    try:
        factory = make_session_factory(engine)
        async with factory() as setup, setup.begin():
            q = await Queue.make(setup)
            ids = (q.msp.id, q.plan.id, q.client.id, q.connector.id, q.worker.id)
        msp_id, plan_id, client_id, connector_id, worker_id = ids

        async def make():
            async with factory() as s, s.begin():
                row = await RunRepo(s).create_scheduled(
                    msp_id, plan_id=plan_id, client_id=client_id, connector_id=connector_id, worker_id=worker_id, scheduled_for=PERIOD
                )
                return None if row is None else row.id

        answers = await asyncio.gather(make(), make())
        async with factory() as s, s.begin():
            runs = await RunRepo(s).list(msp_id)
    finally:
        await engine.dispose()

    assert sorted(a is None for a in answers) == [False, True]
    assert [r.scheduled_for for r in runs] == [PERIOD]


# --- C6.2: the pages' reads (docs/decisions.md 2026-10-12, "C6.1, C6.2 and C6.3", point 16) ---


from app.repo.items import ItemRepo  # noqa: E402
from app.repo.runs import FINAL_STATES, PAGE_SIZE, PENDING_STATES, DayCount, RunRow  # noqa: E402


def test_the_pages_states_partition_the_run_states():
    from app.models import RUN_STATES

    assert set(FINAL_STATES) | set(PENDING_STATES) == set(RUN_STATES)
    assert not set(FINAL_STATES) & set(PENDING_STATES)
    assert PAGE_SIZE == 50


async def test_last_finished_and_pending_per_client_answer_one_run_each(session):
    q = await Queue.make(session)
    b = await Queue.make(session, "b")
    await q.run(created_at=NOW - dt.timedelta(hours=1), state="expired")
    first_pass = await q.run(created_at=NOW, state="pass")
    latest_final = await q.run(created_at=NOW + dt.timedelta(hours=1), state="fail")
    oldest_pending = await q.run(created_at=NOW + dt.timedelta(hours=2))
    await q.run(created_at=NOW + dt.timedelta(hours=3), state="dispatched")
    theirs = await b.run(created_at=NOW + dt.timedelta(hours=9), state="error")

    last = await q.runs.last_finished_per_client(q.msp.id)
    pending = await q.runs.pending_per_client(q.msp.id)

    assert {c: r.id for c, r in last.items()} == {q.client.id: latest_final.id}
    assert {c: r.id for c, r in pending.items()} == {q.client.id: oldest_pending.id}
    assert {c: r.id for c, r in (await b.runs.last_finished_per_client(b.msp.id)).items()} == {b.client.id: theirs.id}
    assert await b.runs.pending_per_client(b.msp.id) == {}
    assert first_pass.id not in {r.id for r in last.values()}


async def test_last_finished_per_client_breaks_a_tie_on_created_at_by_the_larger_id(session):
    q = await Queue.make(session)
    runs = [await q.run(created_at=NOW, state="pass") for _ in range(3)]

    last = await q.runs.last_finished_per_client(q.msp.id)

    assert last[q.client.id].id == max(r.id for r in runs)


async def test_a_page_is_newest_first_with_each_run_s_item_count_and_keysets_on_before(session):
    q = await Queue.make(session)
    runs = [await q.run(created_at=NOW + dt.timedelta(minutes=i), state="pass") for i in range(7)]
    await ItemRepo(session).create(q.msp.id, runs[6].id, position=0, type="mail", name="a", expected_kind="fields")
    await ItemRepo(session).create(q.msp.id, runs[6].id, position=1, type="mail", name="b", expected_kind="fields")
    await ItemRepo(session).create(q.msp.id, runs[2].id, position=0, type="onedrive", name="c", expected_kind="metadata")

    first = await q.runs.page(q.msp.id, q.client.id, limit=3)
    second = await q.runs.page(q.msp.id, q.client.id, before=first[-1].run.id, limit=3)
    third = await q.runs.page(q.msp.id, q.client.id, before=second[-1].run.id, limit=3)
    fourth = await q.runs.page(q.msp.id, q.client.id, before=third[-1].run.id, limit=3)

    assert all(isinstance(row, RunRow) for row in first)
    assert [(row.run.id, row.items) for row in first] == [(runs[6].id, 2), (runs[5].id, 0), (runs[4].id, 0)]
    assert [(row.run.id, row.items) for row in second] == [(runs[3].id, 0), (runs[2].id, 1), (runs[1].id, 0)]
    assert [row.run.id for row in third] == [runs[0].id]
    assert fourth == []
    whole = await q.runs.page(q.msp.id, q.client.id)
    assert [row.run.id for row in whole] == [r.id for r in reversed(runs)]


async def test_a_page_before_a_run_that_is_not_the_client_s_is_empty(session):
    q = await Queue.make(session)
    b = await Queue.make(session, "b")
    await q.run(created_at=NOW, state="pass")
    theirs = await b.run(created_at=NOW + dt.timedelta(hours=1), state="pass")

    assert await q.runs.page(q.msp.id, q.client.id, before=theirs.id) == []
    assert await q.runs.page(q.msp.id, q.client.id, before=uuid.uuid4()) == []
    assert await q.runs.page(q.msp.id, b.client.id) == []
    assert len(await q.runs.page(q.msp.id, q.client.id)) == 1


@pytest.mark.parametrize("limit", [0, 51, -1])
async def test_a_page_limit_outside_the_size_is_refused(session, limit):
    q = await Queue.make(session)

    with pytest.raises(ValueError, match="limit must be 1 to 50"):
        await q.runs.page(q.msp.id, q.client.id, limit=limit)


async def test_a_page_s_items_are_one_statement_with_the_runs(session, test_engine):
    q = await Queue.make(session)
    for i in range(3):
        await q.run(created_at=NOW + dt.timedelta(minutes=i), state="pass")
    statements = []

    @event.listens_for(test_engine.sync_engine, "before_cursor_execute")
    def count(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement.split()[0])

    try:
        rows = await q.runs.page(q.msp.id, q.client.id)
        paged = await q.runs.page(q.msp.id, q.client.id, before=rows[0].run.id)
        strip = await q.runs.daily_states(q.msp.id, q.client.id, since=NOW - dt.timedelta(days=1))
        last = await q.runs.last_finished_per_client(q.msp.id)
        pending = await q.runs.pending_per_client(q.msp.id)
    finally:
        event.remove(test_engine.sync_engine, "before_cursor_execute", count)

    assert (len(rows), len(paged), len(strip), len(last), len(pending)) == (3, 2, 1, 1, 0)
    assert statements == ["SELECT"] * 5


async def test_daily_states_counts_each_utc_day_s_states_since_the_given_time(session):
    q = await Queue.make(session)
    b = await Queue.make(session, "b")
    await q.run(created_at=dt.datetime(2026, 9, 30, 12, tzinfo=UTC), state="pass")  # before since
    await q.run(created_at=dt.datetime(2026, 10, 1, 23, 59, 59, tzinfo=UTC), state="pass")
    await q.run(created_at=dt.datetime(2026, 10, 2, 0, 0, 0, tzinfo=UTC), state="fail")
    await q.run(created_at=dt.datetime(2026, 10, 2, 12, tzinfo=UTC), state="pass")
    await q.run(created_at=dt.datetime(2026, 10, 2, 13, tzinfo=UTC), state="pass")
    await q.run(created_at=dt.datetime(2026, 10, 3, 1, tzinfo=UTC))  # queued counts as its own state
    await b.run(created_at=dt.datetime(2026, 10, 2, 12, tzinfo=UTC), state="error")

    counts = await q.runs.daily_states(q.msp.id, q.client.id, since=dt.datetime(2026, 10, 1, tzinfo=UTC))

    assert counts == [
        DayCount(dt.date(2026, 10, 1), "pass", 1),
        DayCount(dt.date(2026, 10, 2), "fail", 1),
        DayCount(dt.date(2026, 10, 2), "pass", 2),
        DayCount(dt.date(2026, 10, 3), "queued", 1),
    ]
    assert await q.runs.daily_states(q.msp.id, b.client.id, since=dt.datetime(2026, 1, 1, tzinfo=UTC)) == []
    with pytest.raises(ValueError, match="without a zone"):
        await q.runs.daily_states(q.msp.id, q.client.id, since=dt.datetime(2026, 10, 1))


# --- C6.4: the report's month (docs/decisions.md 2026-10-12, "C6.4", points 4 and 5) ------------

OCT = dt.datetime(2026, 10, 1, tzinfo=UTC)
NOV = dt.datetime(2026, 11, 1, tzinfo=UTC)


async def finished(q: Queue, state: str, *, created_at: dt.datetime, finished_at: dt.datetime | None, other: bool = False):
    row = await q.run(created_at=created_at, state=state, other=other)
    await q.session.execute(text("UPDATE test_run SET finished_at = :f WHERE id = :id"), {"f": finished_at, "id": row.id})
    return await q.fresh(row)


async def test_period_answers_the_finished_runs_by_the_time_they_ended_and_the_expired_ones_by_creation(session):
    """A pass, fail or error run is the month's by `coalesce(finished_at,
    created_at)`; an expired run by `created_at`; queued and dispatched
    never; oldest first by that time then id. Both edges: the month's first
    second is in, the next month's first second is out."""
    q = await Queue.make(session)
    b = await Queue.make(session, "b")
    first = await finished(q, "pass", created_at=dt.datetime(2026, 9, 30, 23, 58, tzinfo=UTC), finished_at=OCT)
    last = await finished(q, "fail", created_at=dt.datetime(2026, 10, 31, 23, 0, tzinfo=UTC), finished_at=NOV - ONE_SECOND)
    fallback = await finished(q, "error", created_at=dt.datetime(2026, 10, 15, 12, tzinfo=UTC), finished_at=None)
    expired = await q.run(created_at=dt.datetime(2026, 10, 20, tzinfo=UTC), state="expired")
    await finished(q, "pass", created_at=dt.datetime(2026, 10, 31, 23, 59, tzinfo=UTC), finished_at=NOV)  # next month's
    await finished(q, "pass", created_at=dt.datetime(2026, 9, 1, tzinfo=UTC), finished_at=OCT - ONE_SECOND)  # last month's
    await q.run(created_at=dt.datetime(2026, 10, 10, tzinfo=UTC))  # queued
    await q.run(created_at=dt.datetime(2026, 10, 10, tzinfo=UTC), state="dispatched")
    await q.run(created_at=dt.datetime(2026, 9, 10, tzinfo=UTC), state="expired")  # last month's
    await finished(b, "pass", created_at=dt.datetime(2026, 10, 10, tzinfo=UTC), finished_at=dt.datetime(2026, 10, 10, tzinfo=UTC))

    rows = await q.runs.period(q.msp.id, q.client.id, start=OCT, end=NOV)

    assert [row.id for row in rows] == [first.id, fallback.id, expired.id, last.id]
    assert await q.runs.period(q.msp.id, b.client.id, start=OCT, end=NOV) == []
    assert await q.runs.period(b.msp.id, q.client.id, start=OCT, end=NOV) == []


async def test_period_orders_runs_of_one_moment_by_id_and_refuses_a_naive_edge(session):
    q = await Queue.make(session)
    at = dt.datetime(2026, 10, 5, 12, tzinfo=UTC)
    same = [await finished(q, "pass", created_at=at, finished_at=at) for _ in range(3)]

    rows = await q.runs.period(q.msp.id, q.client.id, start=OCT, end=NOV)

    assert [row.id for row in rows] == sorted(row.id for row in same)
    for start, end in ((dt.datetime(2026, 10, 1), NOV), (OCT, dt.datetime(2026, 11, 1))):
        with pytest.raises(ValueError, match="without a zone"):
            await q.runs.period(q.msp.id, q.client.id, start=start, end=end)


async def test_period_is_one_statement(session, test_engine):
    q = await Queue.make(session)
    await finished(q, "pass", created_at=OCT, finished_at=OCT)
    statements: list[str] = []

    def record(_conn, _cursor, statement, _params, _context, _executemany):
        statements.append(statement.strip().split()[0].upper())

    event.listen(test_engine.sync_engine, "before_cursor_execute", record)
    try:
        rows = await q.runs.period(q.msp.id, q.client.id, start=OCT, end=NOV)
    finally:
        event.remove(test_engine.sync_engine, "before_cursor_execute", record)

    assert len(rows) == 1
    assert statements == ["SELECT"]

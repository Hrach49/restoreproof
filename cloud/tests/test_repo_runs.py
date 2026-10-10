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
from sqlalchemy import text

from app.repo.clients import ClientRepo
from app.repo.connectors import ConnectorRepo
from app.repo.msps import MspRepo
from app.repo.plans import PlanRepo
from app.repo.runs import DISPATCH_LIMIT, DISPATCH_TIMEOUT, MAX_ATTEMPTS, RunRepo
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
            q.msp.id, q.client.id, q.connector.id, sample_mail=5, sample_sp=3, sample_od=2, cadence_cron="0 2 * * *"
        )
        q.other_plan = await PlanRepo(session).create(
            q.msp.id, q.client.id, q.other_connector.id, sample_mail=1, sample_sp=1, sample_od=1, cadence_cron="0 3 * * *"
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

    assert [row.id for row in taken] == [row.id for row in rows[:5]]
    for row in taken:
        assert (row.state, row.dispatched_at, row.attempt) == ("dispatched", later, 1)
    sixth = await q.fresh(rows[5])
    assert (sixth.state, sixth.dispatched_at, sixth.attempt) == ("queued", None, 0)

    second = await q.runs.dispatch(q.msp.id, q.worker.id, later + ONE_SECOND)
    assert [row.id for row in second] == [rows[5].id]
    assert await q.runs.dispatch(q.msp.id, q.worker.id, later + ONE_SECOND) == []


async def test_the_order_is_created_at_then_id(session):
    q = await Queue.make(session)
    same_time = [await q.run(created_at=NOW) for _ in range(3)]
    older = await q.run(created_at=NOW - dt.timedelta(days=1))

    taken = await q.runs.dispatch(q.msp.id, q.worker.id, NOW)

    assert [row.id for row in taken] == [older.id] + sorted(row.id for row in same_time)


async def test_the_limit_is_the_caller_s_within_the_policy_s(session):
    q = await Queue.make(session)
    rows = await q.queued(4)

    taken = await q.runs.dispatch(q.msp.id, q.worker.id, NOW, limit=2)

    assert [row.id for row in taken] == [row.id for row in rows[:2]]
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

    assert [row.id for row in taken] == [row.id for row in mine]
    assert crossed == []
    for row in others + theirs:
        assert (await a.fresh(row)).state == "queued"


@pytest.mark.parametrize("state", ["dispatched", "received", "pass", "fail", "error", "expired"])
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
        assert [(r.id, r.attempt) for r in taken] == [(row.id, attempt)]
        assert await q.runs.requeue_stale(q.msp.id, NOW + (attempt + 1) * SIX_HOURS) == (
            (1, 0) if attempt < MAX_ATTEMPTS else (0, 1)
        )

    final = await q.fresh(row)
    assert (final.state, final.attempt) == ("expired", 3)
    assert await q.runs.dispatch(q.msp.id, q.worker.id, NOW + 10 * SIX_HOURS) == []


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
    received = await a.run(created_at=NOW, state="received")
    (theirs,) = await b.queued(1)
    await b.runs.dispatch(b.msp.id, b.worker.id, NOW)

    assert await a.runs.requeue_stale(a.msp.id, NOW + 2 * SIX_HOURS) == (0, 0)
    assert (await a.fresh(queued)).state == "queued"
    assert (await a.fresh(received)).state == "received"
    assert (await a.fresh(theirs)).state == "dispatched"
    assert await b.runs.requeue_stale(b.msp.id, NOW + 2 * SIX_HOURS) == (1, 0)

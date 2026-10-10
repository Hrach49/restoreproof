"""The test runs of an MSP. The bundle (C5.7) adds its methods here; nothing
deletes a run but retention (C7.3).

Dispatch (C5.6; docs/decisions.md 2026-10-10, "C5.5 and C5.6", points 4 and
8): `dispatch` is one statement that moves the Worker's oldest queued runs,
at most `DISPATCH_LIMIT`, to `dispatched` with `dispatched_at` set and
`attempt` counted, the rows chosen once under `FOR UPDATE SKIP LOCKED`, so two
polls at once never take one row; then one joined select answers each run with
its plan, connector and client, and nothing when nothing was taken.
`requeue_stale` is the scheduler's sweep, called per MSP (C5.9): a run
dispatched `DISPATCH_TIMEOUT` ago or more goes back to `queued`, or to
`expired` once it has had `MAX_ATTEMPTS`. "Received" is the state C5.7 sets
when the run's bundle arrives; the Worker acknowledges nothing else.
"""

from __future__ import annotations

import datetime as dt
from typing import NamedTuple
from uuid import UUID

from sqlalchemy import and_, select, update

from app.models import Client, Connector, TestPlan, TestRun
from app.repo.base import Repo

# C5.6's "max 5": the Worker's kMaxJobs and the schema's maxItems.
DISPATCH_LIMIT = 5
# "Dispatched but not received within 6 hours goes back to queued, after 3
# attempts to expired."
DISPATCH_TIMEOUT = dt.timedelta(hours=6)
MAX_ATTEMPTS = 3


class Dispatched(NamedTuple):
    """A run handed to its Worker, with what a job is made of."""

    run: TestRun
    plan: TestPlan
    connector: Connector
    client: Client


class RunRepo(Repo):
    async def create(
        self, msp_id: UUID, *, plan_id: UUID, client_id: UUID, connector_id: UUID, worker_id: UUID
    ) -> TestRun:
        return await self._add(
            TestRun(
                msp_id=msp_id,
                plan_id=plan_id,
                client_id=client_id,
                connector_id=connector_id,
                worker_id=worker_id,
            )
        )

    async def get(self, msp_id: UUID, run_id: UUID) -> TestRun | None:
        return await self._one(select(TestRun).where(TestRun.msp_id == msp_id, TestRun.id == run_id))

    async def list(self, msp_id: UUID, *, client_id: UUID | None = None) -> list[TestRun]:
        statement = select(TestRun).where(TestRun.msp_id == msp_id)
        if client_id is not None:
            statement = statement.where(TestRun.client_id == client_id)
        return await self._all(statement.order_by(TestRun.created_at.desc(), TestRun.id))

    async def set_state(self, msp_id: UUID, run_id: UUID, state: str) -> int:
        return await self._touched(
            update(TestRun).where(TestRun.msp_id == msp_id, TestRun.id == run_id).values(state=state)
        )

    async def dispatch(
        self, msp_id: UUID, worker_id: UUID, now: dt.datetime, *, limit: int = DISPATCH_LIMIT
    ) -> list[Dispatched]:
        """The Worker's oldest queued runs, at most `limit`, each now
        `dispatched` at `now` with one more attempt, oldest first, each with
        its plan, connector and client."""
        if not 1 <= limit <= DISPATCH_LIMIT:
            raise ValueError(f"limit must be 1 to {DISPATCH_LIMIT}")
        # A MATERIALIZED CTE, not `id IN (subquery)`: Postgres runs the latter
        # as a semi-join that rescans the locking subquery per outer row, and
        # LockRows then re-checks the rows this statement already updated, so
        # the limit slides past them (six taken of six, limit five; a test).
        # The CTE picks the rows once.
        chosen = (
            select(TestRun.id)
            .where(TestRun.msp_id == msp_id, TestRun.worker_id == worker_id, TestRun.state == "queued")
            .order_by(TestRun.created_at, TestRun.id)
            .limit(limit)
            .with_for_update(skip_locked=True)
            .cte("chosen")
            .prefix_with("MATERIALIZED")
        )
        taken = await self._all(
            update(TestRun)
            .where(TestRun.msp_id == msp_id, TestRun.id == chosen.c.id)
            .values(state="dispatched", dispatched_at=now, attempt=TestRun.attempt + 1)
            .returning(TestRun.id)
            .execution_options(synchronize_session=False)
        )
        if not taken:
            return []
        # The rows as they now are, oldest first (RETURNING promises no order,
        # and the session may hold stale instances of them), each joined to
        # its plan, connector and client by keys that start with msp_id.
        rows = await self._rows(
            select(TestRun, TestPlan, Connector, Client)
            .join(TestPlan, and_(TestPlan.msp_id == TestRun.msp_id, TestPlan.id == TestRun.plan_id))
            .join(Connector, and_(Connector.msp_id == TestRun.msp_id, Connector.id == TestRun.connector_id))
            .join(Client, and_(Client.msp_id == TestRun.msp_id, Client.id == TestRun.client_id))
            .where(TestRun.msp_id == msp_id, TestRun.id.in_(taken))
            .order_by(TestRun.created_at, TestRun.id)
            .execution_options(populate_existing=True)
        )
        return [Dispatched(*row) for row in rows]

    async def requeue_stale(self, msp_id: UUID, now: dt.datetime) -> tuple[int, int]:
        """The sweep: every run dispatched `DISPATCH_TIMEOUT` ago or more goes
        back to `queued` (its count and time kept), or to `expired` once it
        has had `MAX_ATTEMPTS`. Answers (requeued, expired)."""
        stale = (
            TestRun.msp_id == msp_id,
            TestRun.state == "dispatched",
            TestRun.dispatched_at <= now - DISPATCH_TIMEOUT,
        )
        expired = await self._touched(
            update(TestRun).where(*stale, TestRun.attempt >= MAX_ATTEMPTS).values(state="expired")
        )
        requeued = await self._touched(
            update(TestRun).where(*stale, TestRun.attempt < MAX_ATTEMPTS).values(state="queued")
        )
        return requeued, expired

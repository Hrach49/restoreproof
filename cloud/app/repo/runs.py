"""The test runs of an MSP. Nothing deletes a run but retention (C7.3).

Dispatch (C5.6; docs/decisions.md 2026-10-10, "C5.5 and C5.6", points 4 and
8): `dispatch` is one statement that moves the Worker's oldest queued runs,
at most `DISPATCH_LIMIT`, to `dispatched` with `dispatched_at` set and
`attempt` counted, the rows chosen once under `FOR UPDATE SKIP LOCKED`, so two
polls at once never take one row; then one joined select answers each run with
its plan, connector and client, and nothing when nothing was taken.
`requeue_stale` is the scheduler's sweep, called per MSP (C5.9): a run
dispatched `DISPATCH_TIMEOUT` ago or more goes back to `queued`, or to
`expired` once it has had `MAX_ATTEMPTS`. `create_scheduled` is the
scheduler's other statement (C5.9): one queued run per plan and cron period,
the period's unique deciding under two ticks or two processes.

The bundle (C5.7; docs/decisions.md 2026-10-10, C5.7, points 5 and 11):
`receive` is one `UPDATE` that moves a run the Worker was handed to its
bundle's `pass`, `fail` or `error` with the bundle's columns, and its `WHERE`
holds the rule (this MSP, this run, this Worker, a state the Cloud handed out,
`dispatched_at` set), so its rowcount settles a race with a second upload
(the sweep and the poll leave a run one that takes a bundle, so they never
make it miss). There is no `received` state: the bundle's status is known in the
request that receives it. `get` answers the row as the database has it
(`populate_existing`), never the identity map's stale copy, since the route
reads the run again after an `UPDATE` that touched nothing.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import NamedTuple
from uuid import UUID

from sqlalchemy import and_, func, select, true, tuple_
from sqlalchemy import update as sa_update
from sqlalchemy.dialects.postgresql import distinct_on
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.models import Client, Connector, TestItem, TestPlan, TestRun
from app.repo.base import Repo

# C5.6's "max 5": the Worker's kMaxJobs and the schema's maxItems.
DISPATCH_LIMIT = 5
# "Dispatched but not received within 6 hours goes back to queued, after 3
# attempts to expired."
DISPATCH_TIMEOUT = dt.timedelta(hours=6)
MAX_ATTEMPTS = 3


# The states a bundle may arrive for: dispatched; queued again by the sweep
# and not yet polled; expired after three attempts (a late upload, W4.8).
# With `dispatched_at IS NOT NULL`: a run never handed out takes no bundle.
RECEIVABLE_STATES = ("dispatched", "queued", "expired")

# C6.2 (docs/decisions.md 2026-10-12, "C6.1, C6.2 and C6.3", points 16 and
# 17): a run that is over, for the pages' "last run"; one still to happen.
FINAL_STATES = ("pass", "fail", "error", "expired")
PENDING_STATES = ("queued", "dispatched")
PAGE_SIZE = 50

# C5.9: one run per plan and cron period (app/models.py, TestRun).
SCHEDULED_UNIQUE = "uq_test_run_msp_id_plan_id_scheduled_for"


class Dispatched(NamedTuple):
    """A run handed to its Worker, with what a job is made of."""

    run: TestRun
    plan: TestPlan
    connector: Connector
    client: Client


class RunRow(NamedTuple):
    """A run of the history table with the count of its items (C6.2)."""

    run: TestRun
    items: int


class DayCount(NamedTuple):
    """How many runs of one state began on one UTC day (C6.2's strip)."""

    day: dt.date
    state: str
    count: int


@dataclass(frozen=True)
class ReceivedRun:
    """What a bundle writes into its run (C5.7 point 11); `signature_ok` is
    always true, since a bundle that didn't verify is never stored."""

    state: str
    error_code: str | None
    error_message: str | None
    started_at: dt.datetime | None
    finished_at: dt.datetime | None
    total_ms: int | None
    recovery_ms: int | None
    restore_point_at: dt.datetime | None
    bundle_key: str
    bundle_sha256: str
    tsa_ok: bool | None
    tsa_time: dt.datetime | None
    cleanup_ok: bool | None


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

    async def create_scheduled(
        self,
        msp_id: UUID,
        *,
        plan_id: UUID,
        client_id: UUID,
        connector_id: UUID,
        worker_id: UUID,
        scheduled_for: dt.datetime,
    ) -> TestRun | None:
        """The scheduler's run for the period starting at `scheduled_for`
        (C5.9; docs/decisions.md 2026-10-11, "C5.10 and C5.9", point 8): one
        `INSERT ... ON CONFLICT DO NOTHING` under
        `uq_test_run_msp_id_plan_id_scheduled_for`, answering the row, or
        `None` when the period has its run. The constraint and the statement
        decide together, so two ticks or two scheduler processes make one
        run with no lock, no read before the write and no error."""
        if scheduled_for.utcoffset() is None:
            raise ValueError("a time without a zone: give an aware UTC datetime")
        statement = (
            pg_insert(TestRun)
            .values(
                msp_id=msp_id,
                plan_id=plan_id,
                client_id=client_id,
                connector_id=connector_id,
                worker_id=worker_id,
                scheduled_for=scheduled_for,
            )
            .on_conflict_do_nothing(constraint=SCHEDULED_UNIQUE)
            .returning(TestRun)
        )
        return await self._one(statement.execution_options(populate_existing=True))

    async def get(self, msp_id: UUID, run_id: UUID) -> TestRun | None:
        return await self._one(
            select(TestRun)
            .where(TestRun.msp_id == msp_id, TestRun.id == run_id)
            .execution_options(populate_existing=True)
        )

    async def receive(self, msp_id: UUID, run_id: UUID, *, worker_id: UUID, update: ReceivedRun) -> int:
        """File the run's bundle: 1 when the run is this Worker's, was handed
        out and holds no bundle yet; else 0 and nothing changes."""
        return await self._touched(
            sa_update(TestRun)
            .where(
                TestRun.msp_id == msp_id,
                TestRun.id == run_id,
                TestRun.worker_id == worker_id,
                TestRun.state.in_(RECEIVABLE_STATES),
                TestRun.dispatched_at.is_not(None),
            )
            .values(
                state=update.state,
                error_code=update.error_code,
                error_message=update.error_message,
                started_at=update.started_at,
                finished_at=update.finished_at,
                total_ms=update.total_ms,
                recovery_ms=update.recovery_ms,
                restore_point_at=update.restore_point_at,
                bundle_key=update.bundle_key,
                bundle_sha256=update.bundle_sha256,
                signature_ok=True,
                tsa_ok=update.tsa_ok,
                tsa_time=update.tsa_time,
                cleanup_ok=update.cleanup_ok,
            )
            .execution_options(synchronize_session=False)
        )

    async def list(self, msp_id: UUID, *, client_id: UUID | None = None) -> list[TestRun]:
        statement = select(TestRun).where(TestRun.msp_id == msp_id)
        if client_id is not None:
            statement = statement.where(TestRun.client_id == client_id)
        return await self._all(statement.order_by(TestRun.created_at.desc(), TestRun.id))

    async def last_finished_per_client(self, msp_id: UUID) -> dict[UUID, TestRun]:
        """Per client, its latest run that is over (`FINAL_STATES`), by
        `(created_at, id)`: the `/clients` page's last run (C6.2, point 17)."""
        rows = await self._all(
            select(TestRun)
            .ext(distinct_on(TestRun.client_id))
            .where(TestRun.msp_id == msp_id, TestRun.state.in_(FINAL_STATES))
            .order_by(TestRun.client_id, TestRun.created_at.desc(), TestRun.id.desc())
        )
        return {run.client_id: run for run in rows}

    async def pending_per_client(self, msp_id: UUID) -> dict[UUID, TestRun]:
        """Per client, its oldest run still to happen (`PENDING_STATES`)."""
        rows = await self._all(
            select(TestRun)
            .ext(distinct_on(TestRun.client_id))
            .where(TestRun.msp_id == msp_id, TestRun.state.in_(PENDING_STATES))
            .order_by(TestRun.client_id, TestRun.created_at, TestRun.id)
        )
        return {run.client_id: run for run in rows}

    async def page(self, msp_id: UUID, client_id: UUID, *, before: UUID | None = None, limit: int = PAGE_SIZE) -> list[RunRow]:
        """The client's runs newest first by `(created_at, id)`, each with its
        item count, at most `limit`: the rows before the run `before` names
        (keyset; a run that isn't the client's gives an empty page), or the
        newest when it is None (C6.2, point 18). One statement."""
        if not 1 <= limit <= PAGE_SIZE:
            raise ValueError(f"limit must be 1 to {PAGE_SIZE}")
        counts = (
            select(TestItem.run_id, func.count().label("n"))
            .where(TestItem.msp_id == msp_id)
            .group_by(TestItem.run_id)
            .subquery("counts")
        )
        statement = (
            select(TestRun, func.coalesce(counts.c.n, 0))
            .outerjoin(counts, counts.c.run_id == TestRun.id)
            .where(TestRun.msp_id == msp_id, TestRun.client_id == client_id)
        )
        if before is not None:
            anchor = (
                select(TestRun.created_at.label("created_at"), TestRun.id.label("id"))
                .where(TestRun.msp_id == msp_id, TestRun.client_id == client_id, TestRun.id == before)
                .subquery("anchor")
            )
            statement = statement.join(anchor, true()).where(
                tuple_(TestRun.created_at, TestRun.id) < tuple_(anchor.c.created_at, anchor.c.id)
            )
        rows = await self._rows(statement.order_by(TestRun.created_at.desc(), TestRun.id.desc()).limit(limit))
        return [RunRow(run, int(items)) for run, items in rows]

    async def daily_states(self, msp_id: UUID, client_id: UUID, *, since: dt.datetime) -> list[DayCount]:
        """How many of the client's runs of each state began on each UTC day
        since `since`, for the strip (C6.2, point 18). One statement; the
        session is in UTC, so the day is the UTC day."""
        if since.utcoffset() is None:
            raise ValueError("a time without a zone: give an aware UTC datetime")
        day = func.date_trunc("day", TestRun.created_at)
        rows = await self._rows(
            select(day, TestRun.state, func.count())
            .where(TestRun.msp_id == msp_id, TestRun.client_id == client_id, TestRun.created_at >= since)
            .group_by(day, TestRun.state)
            .order_by(day, TestRun.state)
        )
        return [DayCount(stamp.astimezone(dt.timezone.utc).date(), state, int(count)) for stamp, state, count in rows]

    async def set_state(self, msp_id: UUID, run_id: UUID, state: str) -> int:
        return await self._touched(
            sa_update(TestRun).where(TestRun.msp_id == msp_id, TestRun.id == run_id).values(state=state)
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
            sa_update(TestRun)
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
            sa_update(TestRun).where(*stale, TestRun.attempt >= MAX_ATTEMPTS).values(state="expired")
        )
        requeued = await self._touched(
            sa_update(TestRun).where(*stale, TestRun.attempt < MAX_ATTEMPTS).values(state="queued")
        )
        return requeued, expired

"""`GET /clients` and `GET /clients/{client_id}` (C6.2; docs/decisions.md
2026-10-12, "C6.1, C6.2 and C6.3", points 17 and 18).

`/clients`: one row per client with its last finished run (`FINAL_STATES`,
by `RunRepo.last_finished_per_client`), that run's state and recovery time,
and the next scheduled run: a run still to happen first (`pending_per_client`:
"queued since" or "running since"), else the earliest next occurrence over
the client's enabled plans (`app/cadence.py`), "no Worker" when every such
plan's Worker is revoked, "none" without a plan it can read. Four statements
after the frame's two, whatever the rows.

`/clients/{client_id}`: 404 for a client that isn't this MSP's; the run
history newest first in pages of `PAGE_SIZE` by keyset (`?before=<run id>`:
the rows alone for an htmx request, the whole page from there otherwise), and
the 90-day strip, one cell per UTC day ending today, coloured by the day's
worst state (`fail`, then `error`, then `pass`; nothing else is a test).
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request, Response

from app import cadence, ui
from app.db import SessionDep
from app.models import Client, TestPlan, TestRun, Worker
from app.repo.clients import ClientRepo
from app.repo.plans import PlanRepo
from app.repo.runs import PAGE_SIZE, DayCount, RunRepo, RunRow
from app.ui import HX_REQUEST, LayoutDep, render

router = APIRouter()

STRIP_DAYS = 90
# The day's colour is its worst test; expired, queued and dispatched are no test.
WORST_FIRST = ("fail", "error", "pass")


@dataclass(frozen=True)
class NextRun:
    """What the "next scheduled run" cell says: `kind` is `queued`,
    `running`, `next`, `no_worker` or `none`; `at` the time for the first three."""

    kind: str
    at: dt.datetime | None = None


@dataclass(frozen=True)
class ClientRow:
    client: Client
    last: TestRun | None
    next: NextRun


def next_run(client_id: UUID, pending: TestRun | None, plans: list[tuple[TestPlan, Worker]], at: dt.datetime) -> NextRun:
    if pending is not None:
        return NextRun("running" if pending.state == "dispatched" else "queued", pending.created_at)
    soonest: dt.datetime | None = None
    revoked_only = True
    for plan, worker in plans:
        if plan.client_id != client_id:
            continue
        if worker.revoked_at is not None:
            continue
        revoked_only = False
        try:
            occurrence = cadence.parse(plan.cadence_cron).next_after(at)
        except cadence.CadenceError:
            continue  # the scheduler skips it too
        if soonest is None or occurrence < soonest:
            soonest = occurrence
    if soonest is not None:
        return NextRun("next", soonest)
    if revoked_only and any(plan.client_id == client_id for plan, _ in plans):
        return NextRun("no_worker")
    return NextRun("none")


@router.get("/clients", response_class=Response)
async def clients(layout: LayoutDep, session: SessionDep) -> Response:
    msp_id = layout.user.msp_id
    runs = RunRepo(session)
    rows_of_clients = await ClientRepo(session).list(msp_id)
    last = await runs.last_finished_per_client(msp_id)
    pending = await runs.pending_per_client(msp_id)
    plans = await PlanRepo(session).list_with_workers(msp_id, enabled=True)
    at = ui.now()
    rows = [ClientRow(client, last.get(client.id), next_run(client.id, pending.get(client.id), plans, at)) for client in rows_of_clients]
    return render("clients.html", layout=layout, rows=rows)


def strip(counts: list[DayCount], today: dt.date) -> list[tuple[dt.date, str | None, dict[str, int]]]:
    """`STRIP_DAYS` cells ending today: the day, its worst state or None, its counts by state."""
    by_day: dict[dt.date, dict[str, int]] = {}
    for day, state, count in counts:
        by_day.setdefault(day, {})[state] = count
    cells = []
    for offset in range(STRIP_DAYS - 1, -1, -1):
        day = today - dt.timedelta(days=offset)
        seen = by_day.get(day, {})
        worst = next((state for state in WORST_FIRST if seen.get(state)), None)
        cells.append((day, worst, seen))
    return cells


@router.get("/clients/{client_id}", response_class=Response)
async def client_page(client_id: UUID, request: Request, layout: LayoutDep, session: SessionDep, before: UUID | None = None) -> Response:
    msp_id = layout.user.msp_id
    client = await ClientRepo(session).get(msp_id, client_id)
    if client is None:
        raise HTTPException(status_code=404, detail="no such client")
    runs = RunRepo(session)
    rows: list[RunRow] = await runs.page(msp_id, client_id, before=before)
    more = rows[-1].run.id if len(rows) == PAGE_SIZE else None
    if request.headers.get(HX_REQUEST) == "true":
        return render("_runs.html", layout=layout, client=client, rows=rows, more=more)
    at = ui.now()
    since = dt.datetime.combine(at.date() - dt.timedelta(days=STRIP_DAYS - 1), dt.time(0), tzinfo=dt.timezone.utc)
    cells = strip(await runs.daily_states(msp_id, client_id, since=since), at.date())
    return render("client.html", layout=layout, client=client, rows=rows, more=more, cells=cells, before=before)

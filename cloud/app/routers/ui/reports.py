"""`GET /reports`, `GET /clients/{client_id}/reports`, `GET
/reports/{report_id}/file` and `POST /clients/{client_id}/reports/generate`
(C6.6; docs/decisions.md 2026-10-13, "C6.6, C6.5 and C6.7", point 2).

The lists: every report of the MSP (`/reports`, the nav entry) or one
client's, newest period first then newest generation, in pages of
`PAGE_SIZE` by keyset (`?before=<report id>`: the rows alone for an htmx
request, the whole page otherwise), each row the client, the period, the kind
("interim" or "final"), the generation time, both hashes and a Download link.
Either role reads, downloads and generates: a report is the client's own
evidence, made in the user's name on one audit row.

The download: another site's request 403 before anything (`SameOrigin`, as
the bundle's: a GET that writes a row); the report this MSP's or 404; one
audit row `report.download` `report:<id>` with the user and the address,
committed before the answer; then 302 with `Cache-Control: no-store` to a URL
pre-signed for `LINK_SECONDS` against the endpoint a browser reaches. No
bucket list: the key is the row's.

"Generate now": an interim report of the current month, `generate` with the
user and the address under a savepoint, 303 to the client's reports page.
Every refusal is the client's reports page with one line, never a 500: the
cap (one interim report per client per `GENERATE_EVERY` seconds; 429 with
`Retry-After`, no render, no row), the render slot (one render at a time per
process; a slot not free in `RENDER_WAIT_S` is 429), a `RepoError` (a client
with nothing this month, two clicks in one second: 409, the error's own
words), a `ReportFailed` (a render or a put that failed: 503, the type logged
with the ids and never the message). The savepoint rolls the report's rows
back alone, and the request's transaction commits nothing of it.
"""

from __future__ import annotations

import asyncio
import datetime as dt
from uuid import UUID

import structlog
from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import RedirectResponse

from app import audit, ui
from app.auth.sessions import CurrentUser
from app.db import SessionDep
from app.report.data import month_of
from app.report.generate import ReportFailed, generate
from app.repo.clients import ClientRepo
from app.repo.errors import RepoError
from app.repo.reports import PAGE_SIZE, ReportRepo, ReportRow
from app.routers.ui.runs import LINK_SECONDS
from app.ui import HX_REQUEST, LayoutDep, SameOrigin, render

router = APIRouter()
log = structlog.get_logger("app.reports")

# One interim report per client per ten minutes: two a minute apart render
# the same rows to the same bytes (the PDF prints minutes), and a render is
# CPU seconds.
GENERATE_EVERY = dt.timedelta(seconds=600)
# One render at a time per process; a click while one runs waits this long
# for the slot and is then answered, so a request holds its connection
# across at most one render.
RENDER_WAIT_S = 5
RETRY_AFTER_S = 60
NO_SUCH_CLIENT = "no such client"
NO_SUCH_REPORT = "no such report"
BUSY = "A report is being made; try again in a minute."


async def _client_of(session, msp_id: UUID, client_id: UUID):
    client = await ClientRepo(session).get(msp_id, client_id)
    if client is None:
        raise HTTPException(status_code=404, detail=NO_SUCH_CLIENT)
    return client


def _page(rows: list[ReportRow]) -> UUID | None:
    return rows[-1].report.id if len(rows) == PAGE_SIZE else None


@router.get("/reports", response_class=Response)
async def reports(request: Request, layout: LayoutDep, session: SessionDep, before: UUID | None = None) -> Response:
    rows = await ReportRepo(session).page(layout.user.msp_id, before=before)
    name = "_reports.html" if request.headers.get(HX_REQUEST) == "true" else "reports.html"
    return render(name, layout=layout, rows=rows, more=_page(rows), client=None, path="/reports")


@router.get("/clients/{client_id}/reports", response_class=Response)
async def client_reports(client_id: UUID, request: Request, layout: LayoutDep, session: SessionDep, before: UUID | None = None) -> Response:
    msp_id = layout.user.msp_id
    client = await _client_of(session, msp_id, client_id)
    rows = await ReportRepo(session).page(msp_id, client_id=client_id, before=before)
    name = "_reports.html" if request.headers.get(HX_REQUEST) == "true" else "client_reports.html"
    return render(name, layout=layout, client=client, rows=rows, more=_page(rows), path=f"/clients/{client_id}/reports", month=month_of(ui.now().date()), notice=None)


@router.get("/reports/{report_id}/file", response_class=Response)
async def download(report_id: UUID, request: Request, _same_origin: SameOrigin, layout: LayoutDep, session: SessionDep) -> Response:
    report = await ReportRepo(session).get(layout.user.msp_id, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail=NO_SUCH_REPORT)
    await audit.record(session, request, report.msp_id, audit.REPORT_DOWNLOAD, f"report:{report.id}", user_id=layout.user.id)
    url = request.app.state.storage.presigned_get_url(report.storage_key, expires_s=LINK_SECONDS)
    return RedirectResponse(url, status_code=302, headers={"Cache-Control": "no-store"})


def capped(rows: list[ReportRow], month_start: dt.date, at: dt.datetime) -> dt.datetime | None:
    """When the client's newest report is an interim one of this month made
    less than `GENERATE_EVERY` ago: the time the next may be made, else None."""
    if not rows:
        return None
    newest = rows[0].report
    if not newest.interim or newest.period_start != month_start:
        return None
    next_at = newest.generated_at + GENERATE_EVERY
    return next_at if at < next_at else None


async def _refused(request: Request, layout, client, session, *, status: int, line: str, retry_after: int | None = None) -> Response:
    rows = await ReportRepo(session).page(layout.user.msp_id, client_id=client.id)
    headers = {"Retry-After": str(retry_after)} if retry_after is not None else None
    return render(
        "client_reports.html", status_code=status, headers=headers, layout=layout, client=client, rows=rows, more=_page(rows),
        path=f"/clients/{client.id}/reports", month=month_of(ui.now().date()), notice=line,
    )


@router.post("/clients/{client_id}/reports/generate", response_class=Response)
async def generate_now(client_id: UUID, request: Request, _same_origin: SameOrigin, layout: LayoutDep, user: CurrentUser, session: SessionDep) -> Response:
    msp_id = user.msp_id
    client = await _client_of(session, msp_id, client_id)
    at = ui.now()
    month = month_of(at.date())
    next_at = capped(await ReportRepo(session).page(msp_id, client_id=client_id, limit=1), month.start, at)
    if next_at is not None:
        line = f"An interim report of this month was made at {ui.utc(next_at - GENERATE_EVERY)}; the next can be made from {ui.utc(next_at)}."
        return await _refused(request, layout, client, session, status=429, line=line, retry_after=max(1, int((next_at - at).total_seconds())))
    slot: asyncio.Semaphore = request.app.state.render_slot
    try:
        await asyncio.wait_for(slot.acquire(), RENDER_WAIT_S)
    except TimeoutError:
        return await _refused(request, layout, client, session, status=429, line=BUSY, retry_after=RETRY_AFTER_S)
    try:
        async with session.begin_nested():
            await generate(session, request.app.state.storage, msp_id, client_id, month, now=at, user_id=user.id, ip=audit.client_ip(request))
    except ReportFailed as error:
        log.error("report failed", msp_id=str(msp_id), client_id=str(client_id), period=month.name, exc_info=error)
        return await _refused(request, layout, client, session, status=503, line=str(error))
    except RepoError as error:
        return await _refused(request, layout, client, session, status=409, line=str(error))
    finally:
        slot.release()
    return RedirectResponse(f"/clients/{client_id}/reports", status_code=303)

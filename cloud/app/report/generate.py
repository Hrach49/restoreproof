"""Making a report (C6.4; docs/decisions.md 2026-10-12, "C6.4", points 1, 7
and 8): the month's data, the two passes in a thread, the `report` row, one
audit row `report.create`, then the object, in that order, so a refused row
writes no object and a put that fails rolls the row back with the caller's
transaction. The transaction is the caller's (the CLI commits one per
command; C6.6's route and job will do the same); nothing here commits.

What fails outside the database is a `ReportFailed`, worded here and never
left to the caller's guess (the C6.4 review's finding 11: the CLI printed
`database: unreachable` for a library that would not load and for a bucket
that did not answer): the two passes `report: not rendered (<type>)`, the put
`storage: put failed (<type>)`, the cause's type alone, never its message
(botocore's quotes the endpoint).
"""

from __future__ import annotations

import asyncio
import datetime as dt
from uuid import UUID

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.onboarding import Created, worded
from app.repo.audit import AuditRepo
from app.repo.errors import CONSTRAINT_WORDS, RepoError
from app.repo.reports import ReportRepo
from app.report.data import NOT_CLOSED, Period, closed, gather, interim_for
from app.report.render import render_report
from app.storage import Storage

REPORT_CREATE = "report.create"
PDF_TYPE = "application/pdf"


class ReportFailed(RepoError):
    """A report not made for a reason outside the database: no refusal of the
    request, so a route answers it as its own fault, never a 409."""


def now() -> dt.datetime:
    """The Cloud's clock for the CLI's report; a test moves it."""
    return dt.datetime.now(dt.timezone.utc)


# The index's own word, so the read before the render and the index agree.
ALREADY_REPORTED = CONSTRAINT_WORDS["uq_report_final_period"][1]


def storage_key(msp_id: UUID, client_id: UUID, period: Period, interim: bool, now: dt.datetime) -> str:
    """The issue's key for a final report; an interim one carries its
    generation time, so a second is a second object."""
    stamp = f"-interim-{now.astimezone(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}" if interim else ""
    return f"msp/{msp_id}/reports/{client_id}/{period.name}{stamp}.pdf"


async def generate(
    session: AsyncSession,
    storage: Storage,
    msp_id: UUID,
    client_id: UUID,
    period: Period,
    *,
    now: dt.datetime,
    user_id: UUID | None = None,
    ip: str | None = None,
) -> Created:
    # A month's final report is made once, and never while the month still
    # takes results (the C6.6 review's findings 1 and 2: a report made the
    # minute a month ended froze it before its last results had arrived):
    # asked first, before the month is read (C6.6's job asks for every client
    # of a month, so a month that has its report costs one read), so the word
    # is the period's; the index is the line for two at once.
    final = not interim_for(period, now)
    if final and not closed(period, now):
        raise RepoError("period", NOT_CLOSED)
    if final and await ReportRepo(session).final(msp_id, client_id, period.start) is not None:
        raise RepoError("period", ALREADY_REPORTED)
    data = await gather(session, msp_id, client_id, period, now=now)
    try:
        rendered = await asyncio.to_thread(render_report, data)
    except Exception as error:  # noqa: BLE001 - the libraries' and the template's faults alike; the type alone
        raise ReportFailed("report", f"not rendered ({type(error).__name__})") from error
    key = storage_key(msp_id, client_id, period, data.interim, now)
    try:
        row = await ReportRepo(session).create(
            msp_id,
            client_id,
            period_start=period.start,
            period_end=period.end,
            storage_key=key,
            content_sha256=rendered.content_sha256,
            file_sha256=rendered.file_sha256,
            interim=data.interim,
            generated_at=now,
        )
    except IntegrityError as error:
        # A final report's key is its period's, so whichever of the two
        # uniques refused a final one, another was made meanwhile (the C6.6
        # review's finding 7: the loser of two at once was told
        # `storage_key: already used`, and the job counted it as a failure).
        raise (RepoError("period", ALREADY_REPORTED) if final else worded(error)) from None
    await AuditRepo(session).write(msp_id, REPORT_CREATE, f"report:{row.id}", user_id=user_id, ip=ip)
    try:
        await asyncio.to_thread(storage.put, key, rendered.pdf, PDF_TYPE)
    except Exception as error:  # noqa: BLE001 - botocore's errors are of several families; the type alone
        raise ReportFailed("storage", f"put failed ({type(error).__name__})") from error
    return Created(
        (
            ("report_id", str(row.id)),
            ("period", period.name),
            ("interim", "true" if data.interim else "false"),
            ("storage_key", key),
            ("content_sha256", rendered.content_sha256),
            ("file_sha256", rendered.file_sha256),
        )
    )

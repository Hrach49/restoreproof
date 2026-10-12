"""Making a report (C6.4; docs/decisions.md 2026-10-12, "C6.4", points 1, 7
and 8): the month's data, the two passes in a thread, the `report` row, one
audit row `report.create`, then the object, in that order, so a refused row
writes no object and a put that fails rolls the row back with the caller's
transaction. The transaction is the caller's (the CLI commits one per
command; C6.6's route and job will do the same); nothing here commits.
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
from app.report.data import Period, gather
from app.report.render import render_report
from app.storage import Storage

REPORT_CREATE = "report.create"
PDF_TYPE = "application/pdf"


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
    data = await gather(session, msp_id, client_id, period, now=now)
    # A month's final report is made once: asked before the two passes, so
    # the word is the period's; the index is the line for two at once.
    if not data.interim and await ReportRepo(session).final(msp_id, client_id, period.start) is not None:
        raise RepoError("period", ALREADY_REPORTED)
    rendered = await asyncio.to_thread(render_report, data)
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
        raise worded(error) from None
    await AuditRepo(session).write(msp_id, REPORT_CREATE, f"report:{row.id}", user_id=user_id, ip=ip)
    await asyncio.to_thread(storage.put, key, rendered.pdf, PDF_TYPE)
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

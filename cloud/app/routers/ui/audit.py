"""`GET /audit` (C6.3; docs/decisions.md 2026-10-12, "C6.1, C6.2 and C6.3",
point 24): the admin's page of the MSP's audit rows, newest first, the last
`DEFAULT_DAYS` by default (`?days=`, 1 to `MAX_DAYS`), in pages of
`PAGE_SIZE` by keyset (`?before=<row id>`: the rows alone for an htmx request,
the whole page from there otherwise), each with its user's address or a dash
for the CLI's and the Worker's rows. Nothing deletes a row."""

from __future__ import annotations

import datetime as dt
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query, Request, Response

from app import ui
from app.auth.sessions import CurrentAdmin
from app.db import SessionDep
from app.repo.audit import PAGE_SIZE, AuditRepo
from app.ui import HX_REQUEST, LayoutDep, render

router = APIRouter()

DEFAULT_DAYS = 30
MAX_DAYS = 3650


@router.get("/audit", response_class=Response)
async def audit_page(
    request: Request,
    layout: LayoutDep,
    _admin: CurrentAdmin,
    session: SessionDep,
    days: Annotated[int, Query(ge=1, le=MAX_DAYS)] = DEFAULT_DAYS,
    before: UUID | None = None,
) -> Response:
    at = ui.now()
    since = at - dt.timedelta(days=days)
    rows = await AuditRepo(session).page(layout.user.msp_id, since=since, before=before)
    more = rows[-1].row.id if len(rows) == PAGE_SIZE else None
    name = "_audit_rows.html" if request.headers.get(HX_REQUEST) == "true" else "audit.html"
    return render(name, layout=layout, rows=rows, more=more, days=days, since=since)

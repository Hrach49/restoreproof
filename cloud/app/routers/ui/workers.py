"""`GET /workers` and `POST /workers/{worker_id}/revoke` (C6.2;
docs/decisions.md 2026-10-12, "C6.1, C6.2 and C6.3", point 21).

The page: one row per Worker (`WorkerRepo.list`): name, version, last seen
(red past `LATE_AFTER` by the Cloud's clock, or never), the last error with
its time, the outbox depth, the uptime, and for an unrevoked Worker the
Revoke form. The revoke (an admin, same origin): 404 for a Worker not this
MSP's; `onboarding.revoke_worker` with the user and the address, the CLI's
function and its one `worker.revoke` row; already revoked meanwhile is 409
with the CLI's words; then the row again for an htmx request, 303 to the
page otherwise.
"""

from __future__ import annotations

import datetime as dt
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import PlainTextResponse, RedirectResponse

from app import audit, onboarding, ui
from app.auth.sessions import CurrentAdmin
from app.db import SessionDep
from app.repo.errors import RepoError
from app.repo.workers import WorkerRepo
from app.ui import HX_REQUEST, LayoutDep, SameOrigin, render

router = APIRouter()

# C5.8's threshold: a heartbeat every 15 minutes, late by a run plus a hold at most.
LATE_AFTER = dt.timedelta(hours=24)


def late(last_seen_at: dt.datetime | None, at: dt.datetime) -> bool:
    return last_seen_at is None or at - last_seen_at > LATE_AFTER


@router.get("/workers", response_class=Response)
async def workers(layout: LayoutDep, session: SessionDep) -> Response:
    rows = await WorkerRepo(session).list(layout.user.msp_id)
    return render("workers.html", layout=layout, rows=rows, at=ui.now(), late=late)


@router.post("/workers/{worker_id}/revoke", response_class=Response)
async def revoke(worker_id: UUID, request: Request, layout: LayoutDep, admin: CurrentAdmin, session: SessionDep, _same_origin: SameOrigin) -> Response:
    msp_id = admin.msp_id
    workers_repo = WorkerRepo(session)
    if await workers_repo.get(msp_id, worker_id) is None:
        raise HTTPException(status_code=404, detail="no such Worker")
    try:
        await onboarding.revoke_worker(session, msp_id, worker_id=worker_id, user_id=admin.id, ip=audit.client_ip(request))
    except RepoError as error:
        return PlainTextResponse(str(error), status_code=409)
    if request.headers.get(HX_REQUEST) == "true":
        worker = await workers_repo.get(msp_id, worker_id)
        return render("_worker.html", layout=layout, worker=worker, at=ui.now(), late=late)
    return RedirectResponse("/workers", status_code=303)

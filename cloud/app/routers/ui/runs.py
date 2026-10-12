"""`GET /runs/{run_id}` and `GET /runs/{run_id}/files/{name}` (C6.2;
docs/decisions.md 2026-10-12, "C6.1, C6.2 and C6.3", points 19 and 20).

The run page: 404 for a run that isn't this MSP's; the run's columns, its
client and Worker, the items from `test_item`, and the files under its prefix
as the bucket lists them (one call, in a thread), each a link to the download
route, grouped as the bundle (`result.json`, `signature.json`,
`timestamp.tst`) and the attachments. A run without a bundle lists no file.

The download: a request another site sent the browser to is 403 before
anything (`SameOrigin`: this GET writes a row in the user's name and the
`SameSite=Lax` cookie travels on a cross-site link; the code review's
finding 9); the name held to `FILE_NAME`, the run this MSP's, the name one
the bucket lists (404 otherwise); then one audit row `bundle.download`
`run:<id> <name>` with the user and the address, committed before the answer;
then 302 to a URL pre-signed for `LINK_SECONDS` against the endpoint a browser
reaches, with `Cache-Control: no-store`. The row records the link handed out;
the fetch goes to the bucket.
"""

from __future__ import annotations

import asyncio
import re
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import RedirectResponse

from app import audit
from app.db import SessionDep
from app.repo.clients import ClientRepo
from app.repo.items import ItemRepo
from app.repo.runs import RunRepo
from app.repo.workers import WorkerRepo
from app.ui import LayoutDep, SameOrigin, render

router = APIRouter()

LINK_SECONDS = 600
BUNDLE_FILES = ("result.json", "signature.json", "timestamp.tst")
FILE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
NO_SUCH_RUN = "no such run"
NO_SUCH_FILE = "no such file"


async def _run_of(session, msp_id: UUID, run_id: UUID):
    run = await RunRepo(session).get(msp_id, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail=NO_SUCH_RUN)
    return run


async def _files_of(request: Request, bundle_key: str | None) -> list[str]:
    if bundle_key is None:
        return []
    return await asyncio.to_thread(request.app.state.storage.list, bundle_key)


@router.get("/runs/{run_id}", response_class=Response)
async def run_page(run_id: UUID, request: Request, layout: LayoutDep, session: SessionDep) -> Response:
    msp_id = layout.user.msp_id
    run = await _run_of(session, msp_id, run_id)
    client = await ClientRepo(session).get(msp_id, run.client_id)
    worker = await WorkerRepo(session).get(msp_id, run.worker_id)
    items = await ItemRepo(session).list(msp_id, run.id)
    files = await _files_of(request, run.bundle_key)
    bundle = [name for name in files if name in BUNDLE_FILES]
    attachments = [name for name in files if name not in BUNDLE_FILES]
    return render("run.html", layout=layout, run=run, client=client, worker=worker, items=items, bundle=bundle, attachments=attachments)


@router.get("/runs/{run_id}/files/{name}", response_class=Response)
async def download(run_id: UUID, name: str, request: Request, _same_origin: SameOrigin, layout: LayoutDep, session: SessionDep) -> Response:
    if not FILE_NAME.fullmatch(name):
        raise HTTPException(status_code=404, detail=NO_SUCH_FILE)
    run = await _run_of(session, layout.user.msp_id, run_id)
    if name not in await _files_of(request, run.bundle_key):
        raise HTTPException(status_code=404, detail=NO_SUCH_FILE)
    await audit.record(session, request, run.msp_id, audit.BUNDLE_DOWNLOAD, f"run:{run.id} {name}", user_id=layout.user.id)
    url = request.app.state.storage.presigned_get_url(run.bundle_key + name, expires_s=LINK_SECONDS)
    return RedirectResponse(url, status_code=302, headers={"Cache-Control": "no-store"})

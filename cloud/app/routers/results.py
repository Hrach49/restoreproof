"""The results routes, served under /v1.

`POST /results` (C5.7; docs/decisions.md 2026-10-10, C5.7): the Worker's
multipart upload of a signed run folder, the parts `result`, `signature`,
`timestamp` (when there) and one per listed attachment under its own name.
The route reads the request under explicit limits (nothing else in the stack
bounds a body: the cap is held on the bytes as they arrive, whatever
Content-Length said), hands the parts to `app/results.py`, which decides
everything (the verification in a thread: it is CPU work of up to seconds),
and runs the statements: the run's one `UPDATE` (whose rowcount settles a
race with another upload; it stamps `received_at` with the Cloud's clock,
which a report's month goes by for a result that arrives late), the items in one `INSERT`, the audit row, then the
objects under
`msp/<msp_id>/runs/<run_id>/`; 202 `{"run_id", "state"}` once the transaction
is committed (`SessionDep`). A refusal is returned, not raised, so its one
audit row commits and nothing else (nothing was written before it). The
transaction is `get_session`'s.
"""

from __future__ import annotations

import asyncio
import datetime as dt
from typing import Annotated, Any, Literal

from collections.abc import AsyncGenerator

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict
from starlette.datastructures import FormData
from starlette.formparsers import MultiPartException, MultiPartParser
from starlette.requests import ClientDisconnect

from app import results
from app.auth.dependency import current_worker
from app.db import SessionDep
from app.models import Worker
from app.repo.audit import AuditRepo
from app.repo.clients import ClientRepo
from app.repo.items import ItemRepo
from app.repo.plans import PlanRepo
from app.repo.runs import RunRepo
from app.routers.errors import NOT_AUTHENTICATED, refusal

router = APIRouter()

MULTIPART = "multipart/form-data"
AUDIT_RECEIVED = "result.received"
AUDIT_REJECTED = "result.rejected"


def now() -> dt.datetime:
    """The Cloud's clock, the run's `received_at`; a test moves it."""
    return dt.datetime.now(dt.timezone.utc)


class Accepted(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str
    state: Literal["pass", "fail", "error"]


UPLOAD_BODY: dict[str, Any] = {
    "requestBody": {
        "required": True,
        "content": {
            MULTIPART: {
                "schema": {
                    "type": "object",
                    "required": [results.RESULT_PART, results.SIGNATURE_PART],
                    "additionalProperties": False,
                    "properties": {
                        results.RESULT_PART: {"type": "string", "format": "binary", "description": "result.json, the result's canonical bytes"},
                        results.SIGNATURE_PART: {"type": "string", "format": "binary", "description": "signature.json"},
                        results.TIMESTAMP_PART: {"type": "string", "format": "binary", "description": "timestamp.tst, when the run was timestamped"},
                        "items.csv": {"type": "string", "format": "binary", "description": "an attachment the result lists, under its name"},
                        "veeam-session.log": {"type": "string", "format": "binary", "description": "an attachment the result lists, under its name"},
                        "screenshot.png": {"type": "string", "format": "binary", "description": "an attachment the result lists, under its name"},
                    },
                }
            }
        },
    }
}


def _refused(detail: str, status: int) -> JSONResponse:
    return JSONResponse(status_code=status, content={"detail": detail})


class _Body:
    """The request's body, counted as it arrives: the cap is held on the
    bytes themselves, since a server that frames a body by its chunks
    (`Transfer-Encoding: chunked` beside a small Content-Length, which h11
    takes) hands over more than the header said. Over the cap the stream ends
    in the parser's own exception, so the parser closes what it spooled."""

    def __init__(self, request: Request) -> None:
        self._request = request
        self.over = False

    async def chunks(self) -> AsyncGenerator[bytes, None]:
        taken = 0
        async for chunk in self._request.stream():
            taken += len(chunk)
            if taken > results.MAX_UPLOAD_BYTES:
                self.over = True
                raise MultiPartException("over the cap")
            yield chunk


async def _parts(request: Request) -> dict[str, bytes] | results.Refused:
    """The request's parts as bytes by name, or the refusal: the headers
    first (415, 411, 413), then the form under the limits (413 once the body
    itself passes the cap, 400 malformed, a part twice), then each part's
    size against its limit before it is read. The parser is starlette's,
    called directly: `request.form()` reads a media type in another case as
    no form at all, and answers the parser's text as an HTTPException."""
    media_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if media_type != MULTIPART:
        return results.Refused(415, results.BODY_NOT_MULTIPART)
    length = request.headers.get("content-length", "")
    if not (length.isascii() and length.isdigit()):
        return results.Refused(411, results.BODY_NO_LENGTH)
    if int(length) > results.MAX_UPLOAD_BYTES:
        return results.Refused(413, results.BODY_TOO_LARGE)
    body = _Body(request)
    parser = MultiPartParser(request.headers, body.chunks(), max_files=results.MAX_FILE_PARTS, max_fields=0, max_part_size=4096)
    try:
        form = await parser.parse()
    except (MultiPartException, ClientDisconnect, UnicodeError):
        # The parser's text names the fault and is never answered: one fixed
        # word. A sender that went away mid-body and a charset no name
        # decodes under are a body that doesn't read, not this app's failure.
        if body.over:
            return results.Refused(413, results.BODY_TOO_LARGE)
        return results.Refused(400, results.BODY_MALFORMED)
    try:
        return await _read(form)
    finally:
        await form.close()  # the spooled files, on every path


async def _read(form: FormData) -> dict[str, bytes] | results.Refused:
    names: set[str] = set()
    for name, _ in form.multi_items():
        if name in names:
            return results.Refused(400, results.PART_TWICE)
        names.add(name)
    parts: dict[str, bytes] = {}
    for name, upload in form.multi_items():
        refused = results.size_refusal(name, upload.size or 0)
        if refused is not None:
            return refused
        parts[name] = await upload.read()
    return parts


@router.post(
    "/results",
    status_code=202,
    response_model=Accepted,
    openapi_extra=UPLOAD_BODY,
    responses={
        401: NOT_AUTHENTICATED,
        400: refusal("The bundle doesn't verify (the verifier's word), or the body is malformed, has a part twice or a part the result doesn't list, or the result verifies and the tables can't hold it (`result_unstorable`)."),
        404: refusal("No such run of this Worker (`run_id: no such run`)."),
        409: refusal("The run was never handed out (`run_id: not dispatched`), the bundle's client isn't the run's (`client_mismatch`), or the run holds another bundle (`bundle_conflict`)."),
        411: refusal("No Content-Length."),
        413: refusal("The body, or a listed attachment, is over the cap."),
        415: refusal("Not multipart/form-data."),
    },
)
async def upload(request: Request, worker: Annotated[Worker, Depends(current_worker)], session: SessionDep):
    ip = request.client.host if request.client is not None else None
    audit = AuditRepo(session)

    async def rejected(refused: results.Refused) -> JSONResponse:
        who = f"run:{refused.run_id}" if refused.run_id is not None else f"worker:{worker.id}"
        await audit.write(worker.msp_id, AUDIT_REJECTED, f"{who} {refused.word}", ip=ip)
        return _refused(refused.word, refused.status)

    parts = await _parts(request)
    if isinstance(parts, results.Refused):
        return await rejected(parts)
    # In a thread: the scan, the parses, the schema and the hashes are CPU
    # work of up to seconds, and on the loop they would hold every other
    # request of every MSP.
    verified = await asyncio.to_thread(
        results.verify_upload,
        parts,
        public_key_pem=worker.public_key_pem,
        key_id=worker.key_id,
        tsa_ca=request.app.state.tsa_ca_pem,
    )
    if isinstance(verified, results.Refused):
        return await rejected(verified)

    runs = RunRepo(session)
    run_id = results.run_uuid(verified.result)
    run = await runs.get(worker.msp_id, run_id) if run_id is not None else None
    refused = results.check_run(verified.result, run, worker.id, verified.bundle_sha256)
    if refused is not None:
        return await rejected(refused)
    if results.already_received(run, verified.bundle_sha256):
        return Accepted(run_id=str(run.id), state=run.state)
    client = await ClientRepo(session).get(worker.msp_id, run.client_id)
    if client is None:
        raise RuntimeError("a run of this MSP without its client")
    refused = results.check_client(verified.result, run, client)
    if refused is not None:
        return await rejected(refused)

    key = results.bundle_key(worker.msp_id, run.id)
    update = results.run_update(verified, key)
    touched = await runs.receive(worker.msp_id, run.id, worker_id=worker.id, update=update, at=now())
    if touched == 0:
        # Another upload filed the run meanwhile (the sweep and the poll leave
        # a run one that takes a bundle, so they never make the UPDATE miss).
        # The row as it is now decides: that bundle again, or another.
        run = await runs.get(worker.msp_id, run.id)
        refused = results.check_run(verified.result, run, worker.id, verified.bundle_sha256)
        if refused is not None:
            return await rejected(refused)
        if results.already_received(run, verified.bundle_sha256):
            return Accepted(run_id=str(run.id), state=run.state)
        # Every state takes a bundle or holds one (`FINISHED_STATES`), so a
        # miss on a row that still takes one is this app's failure.
        raise RuntimeError("the run's UPDATE touched nothing and the run holds no bundle")
    await ItemRepo(session).create_many(worker.msp_id, run.id, results.item_rows(verified.result))
    await audit.write(worker.msp_id, AUDIT_RECEIVED, f"run:{run.id}", ip=ip)
    # C6.8, point 11: a pass or fail with canaries moves its plan's cursor to
    # the Worker's signed `cursor_next`, only from the cursor it was sent with;
    # it commits or rolls back with the run's rows and objects.
    advance = results.cursor_advance(verified.result)
    if advance is not None:
        await PlanRepo(session).advance_canary_cursor(worker.msp_id, run.plan_id, sent=advance[0], next=advance[1])

    storage = request.app.state.storage

    def put_all() -> None:
        storage.put(key + "result.json", verified.result_bytes, results.CONTENT_TYPES[results.RESULT_PART])
        storage.put(key + "signature.json", verified.signature_bytes, results.CONTENT_TYPES[results.SIGNATURE_PART])
        if verified.timestamp_bytes is not None:
            storage.put(key + "timestamp.tst", verified.timestamp_bytes, results.OCTET_STREAM)
        for name, data in verified.attachments.items():
            storage.put(key + name, data, results.OCTET_STREAM)

    await asyncio.to_thread(put_all)
    return Accepted(run_id=str(run.id), state=update.state)

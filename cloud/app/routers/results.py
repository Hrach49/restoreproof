"""The results routes, served under /v1.

`POST /results` (C5.7; docs/decisions.md 2026-10-10, C5.7): the Worker's
multipart upload of a signed run folder, the parts `result`, `signature`,
`timestamp` (when there) and one per listed attachment under its own name.
The route reads the request under explicit limits (nothing else in the stack
bounds a body), hands the parts to `app/results.py`, which decides everything,
and runs the statements: the run's one `UPDATE` (whose rowcount settles a
race), the items in one `INSERT`, the audit row, then the objects under
`msp/<msp_id>/runs/<run_id>/`; 202 `{"run_id", "state"}` once the transaction
is committed (`SessionDep`). A refusal is returned, not raised, so its one
audit row commits and nothing else (nothing was written before it). The
transaction is `get_session`'s.
"""

from __future__ import annotations

import asyncio
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict
from starlette.datastructures import UploadFile
from starlette.exceptions import HTTPException
from starlette.formparsers import MultiPartException

from app import results
from app.auth.dependency import current_worker
from app.db import SessionDep
from app.models import Worker
from app.repo.audit import AuditRepo
from app.repo.clients import ClientRepo
from app.repo.items import ItemRepo
from app.repo.runs import RunRepo
from app.routers.errors import NOT_AUTHENTICATED, refusal

router = APIRouter()

MULTIPART = "multipart/form-data"
AUDIT_RECEIVED = "result.received"
AUDIT_REJECTED = "result.rejected"


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


async def _parts(request: Request) -> dict[str, bytes] | results.Refused:
    """The request's parts as bytes by name, or the refusal: the headers
    first (415, 411, 413), then the form under the limits (400 malformed, a
    part twice), then each part's size against its limit before it is read."""
    media_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if media_type != MULTIPART:
        return results.Refused(415, results.BODY_NOT_MULTIPART)
    length = request.headers.get("content-length", "")
    if not length.isdigit():
        return results.Refused(411, results.BODY_NO_LENGTH)
    if int(length) > results.MAX_UPLOAD_BYTES:
        return results.Refused(413, results.BODY_TOO_LARGE)
    try:
        form = await request.form(max_files=results.MAX_FILE_PARTS, max_fields=0, max_part_size=4096)
    except (MultiPartException, HTTPException):
        # starlette raises its own HTTPException(400, <the parser's text>)
        # for a request that has an app; the text names the fault and is
        # never answered: one fixed word.
        return results.Refused(400, results.BODY_MALFORMED)
    parts: dict[str, bytes] = {}
    uploads: list[tuple[str, UploadFile]] = []
    for name, upload in form.multi_items():
        if name in parts:
            return results.Refused(400, results.PART_TWICE)
        parts[name] = b""
        uploads.append((name, upload))
    for name, upload in uploads:
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
        400: refusal("The bundle doesn't verify (the verifier's word), or the body is malformed, has a part twice or a part the result doesn't list."),
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
    verified = results.verify_upload(
        parts, public_key_pem=worker.public_key_pem, key_id=worker.key_id, tsa_ca=request.app.state.tsa_ca_pem
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
    touched = await runs.receive(worker.msp_id, run.id, worker_id=worker.id, update=update)
    if touched == 0:
        # Another transaction moved the run meanwhile: a second upload, or the
        # sweep. The row as it is now decides (point 11).
        run = await runs.get(worker.msp_id, run.id)
        refused = results.check_run(verified.result, run, worker.id, verified.bundle_sha256)
        if refused is not None:
            return await rejected(refused)
        if results.already_received(run, verified.bundle_sha256):
            return Accepted(run_id=str(run.id), state=run.state)
        touched = await runs.receive(worker.msp_id, run.id, worker_id=worker.id, update=update)
        if touched == 0:
            raise RuntimeError("the run couldn't be filed twice over")
    await ItemRepo(session).create_many(worker.msp_id, run.id, results.item_rows(verified.result))
    await audit.write(worker.msp_id, AUDIT_RECEIVED, f"run:{run.id}", ip=ip)

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

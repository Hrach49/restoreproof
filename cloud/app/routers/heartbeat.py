"""The heartbeat route, served under /v1.

`POST /heartbeat` (C5.8; docs/decisions.md 2026-10-11, "C5.8"): the Worker's
five-key heartbeat as `rp::send_heartbeat` sends it since W4.8 (the issue's
four keys plus `last_error_at`), a closed body with every field held to the
Worker's own form: `version` as registration takes it, `last_error` a word's
shape (never the Worker's list, which grows with the Worker), `last_error_at`
the Worker's one time form, the two counts strict integers under the canonical
form's bound, the error and its time both or neither. The Worker behind the
bearer token gets its own row written in one `UPDATE` (`WorkerRepo.heartbeat`):
`last_seen_at` from the Cloud's clock, the five fields as sent, a null
replacing a value. A revoked or unknown Worker is `current_worker`'s one 401
after its lookup and before anything is written; a revoke that landed since
the lookup makes the `UPDATE` touch nothing and is the same 401, nothing
written. 204 with no body, as the Worker takes any 2xx and reads nothing. No
audit row: the row is its own record. The transaction is `get_session`'s,
committed before the response starts (`SessionDep`). Nothing of the body or
the token reaches a log line: the route logs nothing of its own.

The token before the body (the C5.8 review's finding 1): the body is no
parameter of the route, which FastAPI would read and parse before any
dependency ran. `heartbeat_body` depends on `current_worker` and reads the
request itself, so a caller without a token is answered the 401 with nothing
of its body read, and a body nothing can parse (not JSON, nested past the
parser's depth, a number past the interpreter's digits, a key twice) is the
same 422 as a body outside the model, never FastAPI's own 400.
"""

from __future__ import annotations

import datetime as dt
import json
import re
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request, Response
from fastapi.exceptions import RequestValidationError
from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    WithJsonSchema,
    model_validator,
)

from app.auth.dependency import current_worker, not_authenticated
from app.db import SessionDep
from app.models import Worker
from app.repo.workers import WorkerRepo
from app.routers.errors import BODY_OVER_THE_CAP, NOT_AUTHENTICATED
from app.routers.workers import Version

router = APIRouter()

# canonical-json-v1's bound on an integer: the Worker sends nothing above it.
MAX_COUNT = 2**53 - 1
# heartbeat_time_text's form (worker/src/heartbeat.cpp): UTC to the millisecond.
TIME_RULE = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$"
TIME_FORM = "%Y-%m-%dT%H:%M:%S.%fZ"
# The rule as the contract's readers take it: `\d` is 0 to 9 and nothing else.
_TIME = re.compile(TIME_RULE, re.ASCII)


def _error_time(value: object) -> dt.datetime:
    """The Worker's time text as an aware UTC datetime, parsed here once: the
    rule takes the shape, the calendar the value (a 30th of February or an
    hour 24 is a 422, never a 500 at the row)."""
    if not isinstance(value, str) or _TIME.fullmatch(value) is None:
        raise ValueError("not the Worker's time form")
    return dt.datetime.strptime(value, TIME_FORM).replace(tzinfo=dt.timezone.utc)


# A service error word's shape: rp::service_error_codes()'s words and
# upload_http_<status> all fit; the list itself is the Worker's.
ErrorWord = Annotated[str, StringConstraints(pattern=r"^[a-z0-9_]{1,64}$")]
ErrorTime = Annotated[
    dt.datetime, BeforeValidator(_error_time), WithJsonSchema({"type": "string", "pattern": TIME_RULE})
]
Count = Annotated[int, Field(strict=True, ge=0, le=MAX_COUNT)]


class HeartbeatBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Version
    last_error: ErrorWord | None
    last_error_at: ErrorTime | None
    outbox_depth: Count
    uptime_s: Count

    @model_validator(mode="after")
    def both_or_neither(self) -> HeartbeatBody:
        if (self.last_error is None) != (self.last_error_at is None):
            raise ValueError("last_error and last_error_at come together or not at all")
        return self


def _no_key_twice(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """A closed body names each key once; the parser alone keeps the last."""
    members = dict(pairs)
    if len(members) != len(pairs):
        raise ValueError("a key twice")
    return members


def _is_json(content_type: str | None) -> bool:
    return content_type is not None and content_type.split(";", 1)[0].strip().lower() == "application/json"


def _unreadable(kind: str, message: str) -> RequestValidationError:
    """FastAPI's 422 for a body it couldn't parse, with nothing of the body in it."""
    return RequestValidationError([{"type": kind, "loc": ("body",), "msg": message, "input": None}])


async def heartbeat_body(
    request: Request, worker: Annotated[Worker, Depends(current_worker)]
) -> HeartbeatBody:
    """The body, read only for an authenticated Worker (`worker` is here for
    that order alone)."""
    if not _is_json(request.headers.get("content-type")):
        raise _unreadable("json_type", "the body is application/json")
    raw = await request.body()
    try:
        document = json.loads(raw, object_pairs_hook=_no_key_twice)
    except (ValueError, RecursionError):
        raise _unreadable("json_invalid", "JSON decode error") from None
    try:
        return HeartbeatBody.model_validate(document)
    except ValidationError as fault:
        errors = fault.errors(include_url=False)
        raise RequestValidationError([{**e, "loc": ("body", *e["loc"])} for e in errors]) from None


def now() -> dt.datetime:
    """The Cloud's clock, what `last_seen_at` is; a test moves it."""
    return dt.datetime.now(dt.timezone.utc)


@router.post(
    "/heartbeat",
    status_code=204,
    response_class=Response,
    responses={
        401: NOT_AUTHENTICATED,
        413: BODY_OVER_THE_CAP,
        422: {
            "description": "Validation Error",
            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/HTTPValidationError"}}},
        },
    },
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {"application/json": {"schema": HeartbeatBody.model_json_schema()}},
        }
    },
)
async def heartbeat(
    body: Annotated[HeartbeatBody, Depends(heartbeat_body)],
    worker: Annotated[Worker, Depends(current_worker)],
    session: SessionDep,
) -> Response:
    touched = await WorkerRepo(session).heartbeat(
        worker.msp_id,
        worker.id,
        at=now(),
        version=body.version,
        last_error=body.last_error,
        last_error_at=body.last_error_at,
        outbox_depth=body.outbox_depth,
        uptime_s=body.uptime_s,
    )
    if touched == 0:
        # Revoked since the token's lookup: the one 401, nothing written.
        raise not_authenticated()
    return Response(status_code=204)

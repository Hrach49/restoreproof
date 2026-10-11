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
before any statement; a revoke that landed since the lookup makes the `UPDATE`
touch nothing and is the same 401, nothing written. 204 with no body, as the
Worker takes any 2xx and reads nothing. No audit row: the row is its own record.
The transaction is `get_session`'s, committed before the response starts
(`SessionDep`). Nothing of the body or the token reaches a log line: the route
logs nothing of its own.
"""

from __future__ import annotations

import datetime as dt
from typing import Annotated

from fastapi import APIRouter, Depends, Response
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator, model_validator

from app.auth.dependency import current_worker, not_authenticated
from app.db import SessionDep
from app.models import Worker
from app.repo.workers import WorkerRepo
from app.routers.errors import NOT_AUTHENTICATED

router = APIRouter()

# canonical-json-v1's bound on an integer: the Worker sends nothing above it.
MAX_COUNT = 2**53 - 1
# heartbeat_time_text's form (worker/src/heartbeat.cpp): UTC to the millisecond.
TIME_RULE = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$"
TIME_FORM = "%Y-%m-%dT%H:%M:%S.%fZ"

# What `rpworker --version` prints: printable ASCII, as RegisterBody.version.
Version = Annotated[str, StringConstraints(min_length=1, max_length=64, pattern=r"^[ -~]+$")]
# A service error word's shape: rp::service_error_codes()'s words and
# upload_http_<status> all fit; the list itself is the Worker's.
ErrorWord = Annotated[str, StringConstraints(pattern=r"^[a-z0-9_]{1,64}$")]
ErrorTime = Annotated[str, StringConstraints(pattern=TIME_RULE)]
Count = Annotated[int, Field(strict=True, ge=0, le=MAX_COUNT)]


class HeartbeatBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Version
    last_error: ErrorWord | None
    last_error_at: ErrorTime | None
    outbox_depth: Count
    uptime_s: Count

    @field_validator("last_error_at")
    @classmethod
    def a_real_time(cls, value: str | None) -> str | None:
        """The pattern took the shape; the calendar takes the value (a 30th of
        February or an hour 24 is a 422, never a 500 at the row)."""
        if value is not None:
            dt.datetime.strptime(value, TIME_FORM)
        return value

    @model_validator(mode="after")
    def both_or_neither(self) -> HeartbeatBody:
        if (self.last_error is None) != (self.last_error_at is None):
            raise ValueError("last_error and last_error_at come together or not at all")
        return self

    def error_time(self) -> dt.datetime | None:
        """`last_error_at` as an aware UTC datetime, the Worker's own time."""
        if self.last_error_at is None:
            return None
        return dt.datetime.strptime(self.last_error_at, TIME_FORM).replace(tzinfo=dt.timezone.utc)


def now() -> dt.datetime:
    """The Cloud's clock, what `last_seen_at` is; a test moves it."""
    return dt.datetime.now(dt.timezone.utc)


@router.post(
    "/heartbeat",
    status_code=204,
    response_class=Response,
    responses={401: NOT_AUTHENTICATED},
)
async def heartbeat(
    body: HeartbeatBody, worker: Annotated[Worker, Depends(current_worker)], session: SessionDep
) -> Response:
    touched = await WorkerRepo(session).heartbeat(
        worker.msp_id,
        worker.id,
        at=now(),
        version=body.version,
        last_error=body.last_error,
        last_error_at=body.error_time(),
        outbox_depth=body.outbox_depth,
        uptime_s=body.uptime_s,
    )
    if touched == 0:
        # Revoked since the token's lookup: the one 401, nothing written.
        raise not_authenticated()
    return Response(status_code=204)

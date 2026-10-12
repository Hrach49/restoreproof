"""`current_worker`: the Worker behind `Authorization: Bearer <token>` (C5.4).

The token is taken only from `Bearer <token>`, one space, nothing before or
after. Whatever came, the work is the same: one hash (of the empty string when
there was no token), one lookup by that hash, one constant-time comparison of
the stored and computed hashes; no token, a missing row, a difference or a set
`revoked_at` is one and the same 401 with `{"detail": "not authenticated"}` and
`WWW-Authenticate: Bearer`. The empty token is refused after that work whatever
the database holds, so a Worker row under the empty string's hash is never the
answer to a request without a header. On success the Worker and its `msp_id`
are on `request.state`. `current_user` (sessions, C6.1) is not here.
"""

from __future__ import annotations

import hmac
import re
from typing import Annotated

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.auth.tokens import token_hash
from app.db import SessionDep
from app.models import Worker
from app.repo.lookup import Lookup

_BEARER = re.compile(r"Bearer (\S+)")
# Compared against when no row was found, so the comparison always runs.
_NO_HASH = "0" * 64

# For the OpenAPI document alone (C5.11; docs/decisions.md 2026-10-12, point
# 3): a route that depends on `current_worker` is documented as taking the
# Worker's bearer token, with no second edit. Its result is never read
# (`_presented_token` is the one parse) and with `auto_error=False` it never
# answers, so every refusal stays the one 401 below.
WORKER_TOKEN_SCHEME = HTTPBearer(
    auto_error=False,
    scheme_name="workerToken",
    description="The Worker's API token, answered once by `POST /v1/workers/register` (`api_token`).",
)


def not_authenticated() -> HTTPException:
    """The one 401 for every failure to authenticate: here and at
    registration (app/auth/registration.py), the same words and header."""
    return HTTPException(
        status_code=401, detail="not authenticated", headers={"WWW-Authenticate": "Bearer"}
    )


def _presented_token(request: Request) -> str:
    match = _BEARER.fullmatch(request.headers.get("authorization", ""))
    return match.group(1) if match else ""


async def current_worker(
    request: Request,
    session: SessionDep,
    _documented: Annotated[HTTPAuthorizationCredentials | None, Depends(WORKER_TOKEN_SCHEME)] = None,
) -> Worker:
    token = _presented_token(request)
    presented = token_hash(token)
    worker = await Lookup(session).find_worker_by_token_hash(presented)
    stored = _NO_HASH if worker is None else worker.api_token_hash
    same = hmac.compare_digest(stored, presented)
    if not token or worker is None or not same or worker.revoked_at is not None:
        raise not_authenticated()
    request.state.worker = worker
    request.state.msp_id = worker.msp_id
    return worker

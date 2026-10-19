"""The workers routes, served under /v1.

`POST /workers/register` (C5.5; docs/decisions.md 2026-10-10, "C5.5 and
C5.6", point 3): a closed body of the install token, the public key, the
Worker's name and version; 201 with the Worker's id, its API token (once) and
its key's id. The refusals are `app/auth/registration.py`'s: 401 for the
token, 400 for the key, 409 for a key already registered, in that order, each
in the OpenAPI document; a body that isn't the model is FastAPI's 422. The
transaction is `get_session`'s, committed before the response starts
(`SessionDep`).

`POST /workers/self/revoke` (W7.3; docs/decisions.md 2026-10-19, "W7.3 (#82)
and W7.4 (#83)", point 5): the Worker revokes itself at uninstall. The token's
Worker, `current_worker`'s one 401 for no, another or a revoked token before
anything is written; then `onboarding.revoke_worker`, the CLI's and the
`/workers` page's function (one `UPDATE`, one `worker.revoke` audit row with
the Worker's address and no user); 204 with no body. No body is read. A
Worker revoked already never reaches the route (its token is the 401), so
there is no second answer to word; from the commit on the heartbeat, the poll
and a second revoke are that 401.
"""

from __future__ import annotations

import datetime as dt
from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from app import audit, onboarding
from app.auth.dependency import current_worker
from app.auth.registration import register_worker
from app.db import SessionDep
from app.models import Worker
from app.routers.errors import BODY_OVER_THE_CAP, NOT_AUTHENTICATED, refusal

router = APIRouter()

# What `rpworker --version` prints: printable ASCII. The one rule for a
# Worker's version, registration's and the heartbeat's (the C5.8 review's
# finding 7): a version one takes the other takes.
Version = Annotated[str, StringConstraints(min_length=1, max_length=64, pattern=r"^[ -~]+$")]


class RegisterBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Not held to the token's 43-character shape: whatever is sent is hashed
    # and looked up, so a token of another shape gets the same 401.
    install_token: str = Field(min_length=1, max_length=256)
    # A key file is about 120 characters; the rule takes white space around.
    public_key_pem: str = Field(min_length=1, max_length=4096)
    # The lengths are the fields' own; the patterns say what a character may be.
    worker_name: str = Field(min_length=1, max_length=128, pattern=r"^[^\x00-\x1f\x7f]+$")
    version: Version


class Registered(BaseModel):
    model_config = ConfigDict(extra="forbid")

    worker_id: str
    api_token: str
    key_id: str


@router.post(
    "/workers/register",
    status_code=201,
    response_model=Registered,
    responses={
        401: NOT_AUTHENTICATED,
        400: refusal("The key is not an accepted Ed25519 public key (the file's form, a non-canonical encoding, no point of the curve, or a small-order point)."),
        409: refusal("The key is already registered."),
        413: BODY_OVER_THE_CAP,
    },
)
async def register(body: RegisterBody, request: Request, session: SessionDep) -> Registered:
    registration = await register_worker(
        session,
        install_token=body.install_token,
        public_key_pem=body.public_key_pem,
        worker_name=body.worker_name,
        version=body.version,
        now=dt.datetime.now(dt.timezone.utc),
        ip=request.client.host if request.client is not None else None,
    )
    return Registered(
        worker_id=str(registration.worker.id),
        api_token=registration.api_token,
        key_id=registration.key.key_id,
    )


@router.post(
    "/workers/self/revoke",
    status_code=204,
    response_class=Response,
    responses={401: NOT_AUTHENTICATED, 413: BODY_OVER_THE_CAP},
)
async def revoke_self(
    request: Request, worker: Annotated[Worker, Depends(current_worker)], session: SessionDep
) -> Response:
    await onboarding.revoke_worker(
        session, worker.msp_id, worker_id=worker.id, user_id=None, ip=audit.client_ip(request)
    )
    return Response(status_code=204)

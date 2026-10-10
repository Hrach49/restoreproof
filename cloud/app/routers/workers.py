"""The workers routes, served under /v1.

`POST /workers/register` (C5.5; docs/decisions.md 2026-10-10, "C5.5 and
C5.6", point 3): a closed body of the install token, the public key, the
Worker's name and version; 201 with the Worker's id, its API token (once) and
its key's id. The refusals are `app/auth/registration.py`'s: 401 for the
token, 400 for the key, 409 for a key already registered, in that order; a
body that isn't the model is FastAPI's 422. The transaction is `get_session`'s.
"""

from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.registration import register_worker
from app.db import get_session

router = APIRouter()


class RegisterBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Not held to the token's 43-character shape: whatever is sent is hashed
    # and looked up, so a token of another shape gets the same 401.
    install_token: str = Field(min_length=1, max_length=256)
    # A key file is about 120 characters; the rule takes white space around.
    public_key_pem: str = Field(min_length=1, max_length=4096)
    worker_name: str = Field(min_length=1, max_length=128, pattern=r"^[^\x00-\x1f\x7f]{1,128}$")
    # What `rpworker --version` prints.
    version: str = Field(min_length=1, max_length=64, pattern=r"^[ -~]{1,64}$")


class Registered(BaseModel):
    model_config = ConfigDict(extra="forbid")

    worker_id: str
    api_token: str
    key_id: str


@router.post("/workers/register", status_code=201, response_model=Registered)
async def register(
    body: RegisterBody, request: Request, session: AsyncSession = Depends(get_session)
) -> Registered:
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

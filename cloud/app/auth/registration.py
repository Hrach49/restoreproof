"""A Worker's registration (C5.5; docs/decisions.md 2026-10-10, "C5.5 and
C5.6", point 3): the logic behind `POST /v1/workers/register`.

The checks run in one order, each with one answer: the install token first
(`accept_install_token`, one 401 for a token that is unknown, used or expired,
after the same work whatever the token), then the key (`registered_key`, one
400 for a file that breaks the rule, a non-canonical encoding and a small-order
point), then the key's unique (`uq_worker_key_id` refusing the flush, 409). So
nothing but a 401 is ever answered to a caller without a valid install token.
Everything runs in the request's one transaction, which `get_session` commits
on the 201 and rolls back on anything raised, so a failed registration leaves
the token unused. The API token is minted here, hashed into the row and
answered once; it is stored nowhere and written to no log line. One audit row
per registration, in the same transaction.

Strict (100% line and branch): this decides who becomes a Worker.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.public_keys import RegisteredKey, registered_key
from app.auth.tokens import accept_install_token, new_token, token_hash
from app.models import Worker
from app.repo.audit import AuditRepo
from app.repo.workers import WorkerRepo

KEY_UNIQUE = "uq_worker_key_id"
AUDIT_ACTION = "worker.register"


@dataclass(frozen=True)
class Registration:
    worker: Worker
    api_token: str  # shown once, stored nowhere
    key: RegisteredKey


def not_authenticated() -> HTTPException:
    return HTTPException(
        status_code=401, detail="not authenticated", headers={"WWW-Authenticate": "Bearer"}
    )


def key_refused() -> HTTPException:
    return HTTPException(status_code=400, detail="public_key_pem: not an accepted Ed25519 public key")


def already_registered() -> HTTPException:
    return HTTPException(status_code=409, detail="public_key_pem: already registered")


async def register_worker(
    session: AsyncSession,
    *,
    install_token: str,
    public_key_pem: str,
    worker_name: str,
    version: str,
    now: dt.datetime,
    ip: str | None,
) -> Registration:
    """Register the Worker, or raise the one HTTPException its refusal is."""
    token_row = await accept_install_token(session, install_token, now)
    if token_row is None:
        raise not_authenticated()
    key = registered_key(public_key_pem)
    if key is None:
        raise key_refused()
    api_token = new_token()
    try:
        worker = await WorkerRepo(session).create(
            token_row.msp_id,
            worker_name,
            public_key_pem=key.pem,
            key_id=key.key_id,
            api_token_hash=token_hash(api_token),
            install_token_id=token_row.id,
            version=version,
        )
    except IntegrityError as error:
        if KEY_UNIQUE in str(error.orig):
            raise already_registered() from None
        raise
    await AuditRepo(session).write(
        token_row.msp_id, AUDIT_ACTION, f"worker:{worker.id}", user_id=None, ip=ip
    )
    return Registration(worker=worker, api_token=api_token, key=key)

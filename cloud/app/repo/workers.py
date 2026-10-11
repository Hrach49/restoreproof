"""The Workers of an MSP. A Worker is revoked, never deleted: its runs are
evidence. The lookup by its token's hash is `lookup.Lookup`'s.

`create` stores the key's id as it is given (`app/auth/public_keys.py` is the
one place that makes a `key_id` from a key; the database's `uq_worker_key_id`
refuses a second registration of one key) and refuses the empty token's hash
(the C5.4 review's finding 2): a row under `sha256("")` would be the answer to
a request without a header, which the dependency refuses on its own; this is
the second line. The constant comes from the standard library, so app.repo
imports nothing of app.auth.
"""

from __future__ import annotations

import datetime as dt
import hashlib
from uuid import UUID

from sqlalchemy import select, update

from app.models import Worker
from app.repo.base import Repo
from app.repo.errors import RepoError

EMPTY_TOKEN_HASH = hashlib.sha256(b"").hexdigest()


class WorkerRepo(Repo):
    async def create(
        self,
        msp_id: UUID,
        name: str,
        *,
        public_key_pem: str,
        key_id: str,
        api_token_hash: str,
        install_token_id: UUID | None = None,
        version: str | None = None,
    ) -> Worker:
        if api_token_hash == EMPTY_TOKEN_HASH:
            raise RepoError("api_token_hash", "the empty token's hash")
        return await self._add(
            Worker(
                msp_id=msp_id,
                name=name,
                public_key_pem=public_key_pem,
                key_id=key_id,
                api_token_hash=api_token_hash,
                install_token_id=install_token_id,
                version=version,
            )
        )

    async def get(self, msp_id: UUID, worker_id: UUID) -> Worker | None:
        return await self._one(select(Worker).where(Worker.msp_id == msp_id, Worker.id == worker_id))

    async def list(self, msp_id: UUID) -> list[Worker]:
        return await self._all(
            select(Worker).where(Worker.msp_id == msp_id).order_by(Worker.name, Worker.id)
        )

    async def revoke(self, msp_id: UUID, worker_id: UUID, at: dt.datetime) -> int:
        """Set `revoked_at` once; a Worker already revoked keeps its time."""
        return await self._touched(
            update(Worker)
            .where(Worker.msp_id == msp_id, Worker.id == worker_id, Worker.revoked_at.is_(None))
            .values(revoked_at=at)
        )

    async def heartbeat(
        self,
        msp_id: UUID,
        worker_id: UUID,
        *,
        at: dt.datetime,
        version: str,
        last_error: str | None,
        last_error_at: dt.datetime | None,
        outbox_depth: int,
        uptime_s: int,
    ) -> int:
        """Write a heartbeat into the Worker's row (C5.8; docs/decisions.md
        2026-10-11, "C5.8", point 3): `last_seen_at` is `at`, the Cloud's
        clock, the rest the Worker's own words, a null replacing a value. One
        `UPDATE` whose `WHERE` holds `revoked_at IS NULL`, so a revoke that
        landed since the token's lookup answers 0 and writes nothing. The
        session's own copy of the row, which `current_worker` loaded, is kept
        in step (the default synchronisation, as `revoke`; still one statement)."""
        return await self._touched(
            update(Worker)
            .where(Worker.msp_id == msp_id, Worker.id == worker_id, Worker.revoked_at.is_(None))
            .values(
                last_seen_at=at,
                version=version,
                last_error=last_error,
                last_error_at=last_error_at,
                outbox_depth=outbox_depth,
                uptime_s=uptime_s,
            )
        )

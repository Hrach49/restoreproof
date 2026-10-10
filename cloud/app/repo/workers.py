"""The Workers of an MSP. A Worker is revoked, never deleted: its runs are
evidence. The lookup by its token's hash is `lookup.Lookup`'s."""

from __future__ import annotations

import datetime as dt
from uuid import UUID

from sqlalchemy import select, update

from app.models import Worker
from app.repo.base import Repo


class WorkerRepo(Repo):
    async def create(self, msp_id: UUID, name: str, public_key_pem: str, api_token_hash: str) -> Worker:
        return await self._add(
            Worker(msp_id=msp_id, name=name, public_key_pem=public_key_pem, api_token_hash=api_token_hash)
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

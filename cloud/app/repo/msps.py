"""The MSPs. `create` is the one repo method without an `msp_id`: it makes one."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select

from app.models import DEFAULT_RETENTION_DAYS, Msp
from app.repo.base import Repo


class MspRepo(Repo):
    async def create(self, name: str, retention_days: int = DEFAULT_RETENTION_DAYS) -> Msp:
        return await self._add(Msp(name=name, retention_days=retention_days))

    async def get(self, msp_id: UUID) -> Msp | None:
        return await self._one(select(Msp).where(Msp.id == msp_id))

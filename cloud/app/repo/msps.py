"""The MSPs. `create` and `list` are the two repo methods without an `msp_id`:
the first makes an MSP; the second is the scheduler's one read across every
MSP (C5.9; docs/decisions.md 2026-10-11, "C5.10 and C5.9", point 10), from
which the dispatcher and the sweep go MSP by MSP, each then with that MSP's
`msp_id` on every statement. tests/test_tenant_scope.py names both."""

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

    async def list(self) -> list[Msp]:
        """Every MSP, by name then id: the scheduler's read, and nothing else's."""
        return await self._all(select(Msp).order_by(Msp.name, Msp.id))

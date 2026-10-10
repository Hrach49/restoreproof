"""The test runs of an MSP. Dispatch (C5.6) and the bundle (C5.7) add their
methods here; nothing deletes a run but retention (C7.3)."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select, update

from app.models import TestRun
from app.repo.base import Repo


class RunRepo(Repo):
    async def create(
        self, msp_id: UUID, *, plan_id: UUID, client_id: UUID, connector_id: UUID, worker_id: UUID
    ) -> TestRun:
        return await self._add(
            TestRun(
                msp_id=msp_id,
                plan_id=plan_id,
                client_id=client_id,
                connector_id=connector_id,
                worker_id=worker_id,
            )
        )

    async def get(self, msp_id: UUID, run_id: UUID) -> TestRun | None:
        return await self._one(select(TestRun).where(TestRun.msp_id == msp_id, TestRun.id == run_id))

    async def list(self, msp_id: UUID, *, client_id: UUID | None = None) -> list[TestRun]:
        statement = select(TestRun).where(TestRun.msp_id == msp_id)
        if client_id is not None:
            statement = statement.where(TestRun.client_id == client_id)
        return await self._all(statement.order_by(TestRun.created_at.desc(), TestRun.id))

    async def set_state(self, msp_id: UUID, run_id: UUID, state: str) -> int:
        return await self._touched(
            update(TestRun).where(TestRun.msp_id == msp_id, TestRun.id == run_id).values(state=state)
        )

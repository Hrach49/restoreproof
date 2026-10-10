"""The test plans of an MSP: a client's connector, the sample sizes and a cadence."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import delete, select, update

from app.models import TestPlan
from app.repo.base import Repo


class PlanRepo(Repo):
    async def create(
        self,
        msp_id: UUID,
        client_id: UUID,
        connector_id: UUID,
        *,
        sample_mail: int,
        sample_sp: int,
        sample_od: int,
        cadence_cron: str,
        enabled: bool = True,
    ) -> TestPlan:
        return await self._add(
            TestPlan(
                msp_id=msp_id,
                client_id=client_id,
                connector_id=connector_id,
                sample_mail=sample_mail,
                sample_sp=sample_sp,
                sample_od=sample_od,
                cadence_cron=cadence_cron,
                enabled=enabled,
            )
        )

    async def get(self, msp_id: UUID, plan_id: UUID) -> TestPlan | None:
        return await self._one(select(TestPlan).where(TestPlan.msp_id == msp_id, TestPlan.id == plan_id))

    async def list(self, msp_id: UUID, *, client_id: UUID | None = None) -> list[TestPlan]:
        statement = select(TestPlan).where(TestPlan.msp_id == msp_id)
        if client_id is not None:
            statement = statement.where(TestPlan.client_id == client_id)
        return await self._all(statement.order_by(TestPlan.id))

    async def set_enabled(self, msp_id: UUID, plan_id: UUID, enabled: bool) -> int:
        return await self._touched(
            update(TestPlan)
            .where(TestPlan.msp_id == msp_id, TestPlan.id == plan_id)
            .values(enabled=enabled)
        )

    async def delete(self, msp_id: UUID, plan_id: UUID) -> int:
        return await self._touched(
            delete(TestPlan).where(TestPlan.msp_id == msp_id, TestPlan.id == plan_id)
        )

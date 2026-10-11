"""The test plans of an MSP: a client's connector, the sample sizes and a cadence.

`create` holds `cadence_cron` (C5.9; docs/decisions.md 2026-10-11, "C5.10 and
C5.9", point 6): five fields, UTC, parsed by croniter, at most every five
minutes and at least monthly from `now`, refused as a `RepoError` naming the key and never the text, before
any row is written. The rule lives here and not in the CLI so every writer of
a plan is held, as a connector's profile is. The sizes are the database's
CHECKs (the Worker's J3 rule), worded by `constraint_refusal`.
"""

from __future__ import annotations

import datetime as dt
from uuid import UUID

from sqlalchemy import delete, select, update

from app.cadence import CadenceError, check_monthly, check_spacing, parse
from app.models import TestPlan
from app.repo.base import Repo
from app.repo.errors import RepoError


def _check_cadence(cadence_cron: str, now: dt.datetime) -> None:
    try:
        cadence = parse(cadence_cron)
        check_spacing(cadence)
        check_monthly(cadence, now)
    except CadenceError as error:
        raise RepoError("cadence_cron", error.reason) from None


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
        now: dt.datetime,
        enabled: bool = True,
    ) -> TestPlan:
        _check_cadence(cadence_cron, now)
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

    async def list(
        self, msp_id: UUID, *, client_id: UUID | None = None, enabled: bool | None = None
    ) -> list[TestPlan]:
        statement = select(TestPlan).where(TestPlan.msp_id == msp_id)
        if client_id is not None:
            statement = statement.where(TestPlan.client_id == client_id)
        if enabled is not None:
            statement = statement.where(TestPlan.enabled.is_(enabled))
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

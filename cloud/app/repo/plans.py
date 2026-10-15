"""The test plans of an MSP: a client's connector, the sample sizes and a cadence.

`create` holds `cadence_cron` (C5.9; docs/decisions.md 2026-10-11, "C5.10 and
C5.9", point 6): five fields, UTC, parsed by croniter, at most every five
minutes and at least monthly from `now`, refused as a `RepoError` naming the key and never the text, before
any row is written. The rule lives here and not in the CLI so every writer of
a plan is held, as a connector's profile is. The sizes are the database's
CHECKs (the Worker's J3 rule), worded by `constraint_refusal`.

C6.8 (docs/decisions.md 2026-10-15, points 8 to 11): a plan's canary opt-in is
its cursor, three values of the Worker's job rule (0 to 999999) or none;
`create` holds them before the database's CHECK.
"""

from __future__ import annotations

import datetime as dt
from uuid import UUID

from sqlalchemy import and_, delete, select, update

from app.cadence import CadenceError, check_monthly, check_spacing, parse
from app.models import Connector, TestPlan, Worker
from app.repo.base import Repo
from app.repo.errors import RepoError


# The Worker's largest cursor value (worker/src/job_rules.hpp kMaxCursor).
MAX_CURSOR = 999_999
CURSOR_RULE = f"not 0 to {MAX_CURSOR}"


def _cursor_in_rule(cursor: tuple[int, int, int]) -> bool:
    return all(0 <= value <= MAX_CURSOR for value in cursor)


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
        canary_cursor: tuple[int, int, int] | None = None,
    ) -> TestPlan:
        _check_cadence(cadence_cron, now)
        if canary_cursor is not None and not _cursor_in_rule(canary_cursor):
            raise RepoError("canary_cursor", CURSOR_RULE)
        mail, sp, od = canary_cursor if canary_cursor is not None else (None, None, None)
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
                canary_cursor_mail=mail,
                canary_cursor_sp=sp,
                canary_cursor_od=od,
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

    async def list_with_workers(self, msp_id: UUID, *, enabled: bool | None = None) -> list[tuple[TestPlan, Worker]]:
        """Each plan with its connector's Worker, by keys that start with
        `msp_id` (C6.2, point 17: the `/clients` page's "next scheduled run"
        and "no Worker"). One statement."""
        statement = (
            select(TestPlan, Worker)
            .join(Connector, and_(Connector.msp_id == TestPlan.msp_id, Connector.id == TestPlan.connector_id))
            .join(Worker, and_(Worker.msp_id == Connector.msp_id, Worker.id == Connector.worker_id))
            .where(TestPlan.msp_id == msp_id)
        )
        if enabled is not None:
            statement = statement.where(TestPlan.enabled.is_(enabled))
        return [(plan, worker) for plan, worker in await self._rows(statement.order_by(TestPlan.id))]

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

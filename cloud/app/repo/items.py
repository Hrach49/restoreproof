"""The items of a run, as the bundle's result lists them (C5.7;
docs/decisions.md 2026-10-10, C5.7, point 12): one row per item of
`expected.items`, at its `position` (the result's `index`), with what
`check.items` found for it. `create_many` writes a result's rows in one
statement; `list` answers them in the result's order. C6.4's two reads of a
month (`counts_by_type_in_period`, `unmatched_in_period`) join the items to
their runs under `app/repo/runs.py`'s `period_filter`, so a report's three
reads name the same runs."""

from __future__ import annotations

import datetime as dt
from collections.abc import Sequence
from dataclasses import dataclass
from typing import NamedTuple
from uuid import UUID

from sqlalchemy import and_, func, select

from app.models import TestItem, TestRun
from app.repo.base import Repo
from app.repo.runs import period_filter, period_time

# C6.4: the runs whose unmatched items the Failures section lists.
FAILED_STATES = ("fail", "error")


class TypeCount(NamedTuple):
    """How many items of one type and one expected kind one run has (C6.4's
    Test log; C6.8: the kind, so the report says what each test compared),
    and how many of them were compared: found, with `match` known (the C6.8
    code review's finding 1: a missing item or one nobody checked was not
    compared by anything)."""

    run_id: UUID
    type: str
    expected_kind: str
    count: int
    compared: int


@dataclass(frozen=True)
class ItemRow:
    """One item as the route maps it from the result (point 12's table)."""

    position: int
    type: str
    name: str
    expected_kind: str
    expected_sha256: str | None
    found_sha256: str | None
    found: bool | None
    match: bool | None
    reason: str | None
    ms: int | None


class ItemRepo(Repo):
    async def create(
        self,
        msp_id: UUID,
        run_id: UUID,
        *,
        position: int,
        type: str,
        name: str,
        expected_kind: str,
        expected_sha256: str | None = None,
        found_sha256: str | None = None,
        found: bool | None = None,
        match: bool | None = None,
        reason: str | None = None,
        ms: int | None = None,
    ) -> TestItem:
        return await self._add(
            TestItem(
                msp_id=msp_id,
                run_id=run_id,
                position=position,
                type=type,
                name=name,
                expected_kind=expected_kind,
                expected_sha256=expected_sha256,
                found_sha256=found_sha256,
                found=found,
                match=match,
                reason=reason,
                ms=ms,
            )
        )

    async def create_many(self, msp_id: UUID, run_id: UUID, rows: Sequence[ItemRow]) -> int:
        """Every row under the caller's MSP and run, in one INSERT; none for
        no rows. Answers how many were written."""
        if not rows:
            return 0
        self.session.add_all(
            [TestItem(msp_id=msp_id, run_id=run_id, **row.__dict__) for row in rows]
        )
        await self.session.flush()
        return len(rows)

    async def list(self, msp_id: UUID, run_id: UUID) -> list[TestItem]:
        return await self._all(
            select(TestItem)
            .where(TestItem.msp_id == msp_id, TestItem.run_id == run_id)
            .order_by(TestItem.position, TestItem.id)
        )

    def _of_period(self, msp_id: UUID, client_id: UUID, start: dt.datetime, end: dt.datetime):
        """The items of the month's runs (`period_filter`, so the three reads
        of a report agree), joined on the key that starts with msp_id; no
        list of run ids travels to the database."""
        return (
            select(TestItem)
            .join(TestRun, and_(TestRun.msp_id == TestItem.msp_id, TestRun.id == TestItem.run_id))
            .where(TestItem.msp_id == msp_id, *period_filter(client_id, start, end))
        )

    async def counts_by_type_in_period(
        self, msp_id: UUID, client_id: UUID, *, start: dt.datetime, end: dt.datetime
    ) -> list[TypeCount]:
        """How many items of each type and expected kind each of the month's
        runs has, in the runs' order, then by type, then by kind (C6.4, point
        5: the Test log's counts; C6.8, point 1: the kinds the Summary and the
        Method read). One statement."""
        statement = (
            self._of_period(msp_id, client_id, start, end)
            .with_only_columns(
                TestItem.run_id,
                TestItem.type,
                TestItem.expected_kind,
                func.count(),
                func.count().filter(TestItem.found.is_(True), TestItem.match.is_not(None)),
            )
            .group_by(TestItem.run_id, TestItem.type, TestItem.expected_kind, period_time(), TestRun.id)
            .order_by(period_time(), TestRun.id, TestItem.type, TestItem.expected_kind)
        )
        return [
            TypeCount(run_id, type_, kind, int(count), int(compared))
            for run_id, type_, kind, count, compared in await self._rows(statement)
        ]

    async def unmatched_in_period(
        self, msp_id: UUID, client_id: UUID, *, start: dt.datetime, end: dt.datetime
    ) -> list[TestItem]:
        """The items of the month's `fail` and `error` runs that did not match
        (`match` false or not known), by run (the month's order) then
        position (C6.4, point 5: the Failures section). One statement."""
        return await self._all(
            self._of_period(msp_id, client_id, start, end)
            .where(TestRun.state.in_(FAILED_STATES), TestItem.match.is_not(True))
            .order_by(period_time(), TestRun.id, TestItem.position, TestItem.id)
        )

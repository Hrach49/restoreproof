"""The items of a run, as the bundle's result lists them (C5.7;
docs/decisions.md 2026-10-10, C5.7, point 12): one row per item of
`expected.items`, at its `position` (the result's `index`), with what
`check.items` found for it. `create_many` writes a result's rows in one
statement; `list` answers them in the result's order."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import select

from app.models import TestItem
from app.repo.base import Repo


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

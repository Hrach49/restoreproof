"""The items of a run, as the bundle's result lists them (C5.7 writes them)."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select

from app.models import TestItem
from app.repo.base import Repo


class ItemRepo(Repo):
    async def create(
        self,
        msp_id: UUID,
        run_id: UUID,
        *,
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

    async def list(self, msp_id: UUID, run_id: UUID) -> list[TestItem]:
        return await self._all(
            select(TestItem)
            .where(TestItem.msp_id == msp_id, TestItem.run_id == run_id)
            .order_by(TestItem.name, TestItem.id)
        )

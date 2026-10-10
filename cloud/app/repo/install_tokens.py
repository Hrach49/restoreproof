"""The install tokens of an MSP, stored as their hash (C5.4). The lookup by
hash alone is `lookup.Lookup`'s; `mark_used` is the acceptance."""

from __future__ import annotations

import datetime as dt
from uuid import UUID

from sqlalchemy import select, update

from app.models import InstallToken
from app.repo.base import Repo


class InstallTokenRepo(Repo):
    async def create(self, msp_id: UUID, *, token_hash: str, expires_at: dt.datetime) -> InstallToken:
        return await self._add(InstallToken(msp_id=msp_id, token_hash=token_hash, expires_at=expires_at))

    async def get(self, msp_id: UUID, token_id: UUID) -> InstallToken | None:
        return await self._one(
            select(InstallToken).where(InstallToken.msp_id == msp_id, InstallToken.id == token_id)
        )

    async def list(self, msp_id: UUID) -> list[InstallToken]:
        return await self._all(
            select(InstallToken)
            .where(InstallToken.msp_id == msp_id)
            .order_by(InstallToken.expires_at, InstallToken.id)
        )

    async def mark_used(self, msp_id: UUID, token_id: UUID, at: dt.datetime) -> int:
        """Use the token once: 0 rows when it is used, expired or not this MSP's.

        The conditions are in the statement, so two accepts at once can't both
        win: the second re-reads the row after the first's lock.
        """
        return await self._touched(
            update(InstallToken)
            .where(
                InstallToken.msp_id == msp_id,
                InstallToken.id == token_id,
                InstallToken.used_at.is_(None),
                InstallToken.expires_at > at,
            )
            .values(used_at=at)
        )

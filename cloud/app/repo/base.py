"""What every repo is: a class over one `AsyncSession`, flushing and never
committing."""

from __future__ import annotations

from typing import Any

from sqlalchemy import Executable
from sqlalchemy.ext.asyncio import AsyncSession


class Repo:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def _add(self, row: Any) -> Any:
        self.session.add(row)
        await self.session.flush()
        return row

    async def _one(self, statement: Executable) -> Any:
        return await self.session.scalar(statement)

    async def _all(self, statement: Executable) -> list:
        return list(await self.session.scalars(statement))

    async def _touched(self, statement: Executable) -> int:
        """Run an update or delete and answer how many rows it reached."""
        result = await self.session.execute(statement)
        return result.rowcount

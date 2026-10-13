"""The clients of an MSP: one Microsoft 365 tenant each (C5.13)."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import delete, select, update

from app.models import Client
from app.repo.base import Repo


class ClientRepo(Repo):
    async def create(
        self, msp_id: UUID, name: str, tenant_id: UUID, screenshots_enabled: bool = False
    ) -> Client:
        return await self._add(
            Client(msp_id=msp_id, name=name, tenant_id=tenant_id, screenshots_enabled=screenshots_enabled)
        )

    async def get(self, msp_id: UUID, client_id: UUID) -> Client | None:
        return await self._one(select(Client).where(Client.msp_id == msp_id, Client.id == client_id))

    async def get_by_tenant(self, msp_id: UUID, tenant_id: UUID) -> Client | None:
        return await self._one(
            select(Client).where(Client.msp_id == msp_id, Client.tenant_id == tenant_id)
        )

    async def hold(self, msp_id: UUID, client_id: UUID) -> bool:
        """Take the client's row for the rest of the transaction, or answer
        False at once when another transaction has it (the C6.6 review's
        finding 6: "Generate now" makes one report of a client at a time in
        whatever process, and the next click reads the cap only once this
        one has committed). `FOR NO KEY UPDATE`, so a run or a report made
        for the client meanwhile is not kept waiting; `SKIP LOCKED`, so
        nothing waits here. False for no such client too."""
        statement = (
            select(Client.id)
            .where(Client.msp_id == msp_id, Client.id == client_id)
            .with_for_update(key_share=True, skip_locked=True)
        )
        return await self._one(statement) is not None

    async def list(self, msp_id: UUID) -> list[Client]:
        return await self._all(
            select(Client).where(Client.msp_id == msp_id).order_by(Client.name, Client.id)
        )

    async def update(self, msp_id: UUID, client_id: UUID, *, name: str, screenshots_enabled: bool) -> int:
        return await self._touched(
            update(Client)
            .where(Client.msp_id == msp_id, Client.id == client_id)
            .values(name=name, screenshots_enabled=screenshots_enabled)
        )

    async def delete(self, msp_id: UUID, client_id: UUID) -> int:
        return await self._touched(delete(Client).where(Client.msp_id == msp_id, Client.id == client_id))

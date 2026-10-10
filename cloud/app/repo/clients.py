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

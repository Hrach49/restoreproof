"""The users of an MSP. The login's lookup by address alone is C6.1's."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select

from app.models import User
from app.repo.base import Repo


class UserRepo(Repo):
    async def create(self, msp_id: UUID, email: str, password_hash: str, role: str) -> User:
        return await self._add(User(msp_id=msp_id, email=email, password_hash=password_hash, role=role))

    async def get(self, msp_id: UUID, user_id: UUID) -> User | None:
        return await self._one(select(User).where(User.msp_id == msp_id, User.id == user_id))

    async def list(self, msp_id: UUID) -> list[User]:
        return await self._all(select(User).where(User.msp_id == msp_id).order_by(User.email, User.id))

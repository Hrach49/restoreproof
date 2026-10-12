"""The users of an MSP. The login's lookup by address alone is
`lookup.Lookup.find_user_by_email` (C6.1). `set_password_hash` is the one
writer of a hash after creation: a reset gives `changed_at`, which ends every
session issued before it; a re-hash under newer parameters at a successful
login gives None and leaves the sessions."""

from __future__ import annotations

import datetime as dt
from uuid import UUID

from sqlalchemy import select, update

from app.models import User
from app.repo.base import Repo


class UserRepo(Repo):
    async def create(self, msp_id: UUID, email: str, password_hash: str, role: str) -> User:
        return await self._add(User(msp_id=msp_id, email=email, password_hash=password_hash, role=role))

    async def get(self, msp_id: UUID, user_id: UUID) -> User | None:
        return await self._one(select(User).where(User.msp_id == msp_id, User.id == user_id))

    async def list(self, msp_id: UUID) -> list[User]:
        return await self._all(select(User).where(User.msp_id == msp_id).order_by(User.email, User.id))

    async def set_password_hash(
        self, msp_id: UUID, user_id: UUID, password_hash: str, *, changed_at: dt.datetime | None
    ) -> int:
        """Replace the hash; with `changed_at`, mark the password changed."""
        values: dict = {"password_hash": password_hash}
        if changed_at is not None:
            values["password_changed_at"] = changed_at
        return await self._touched(
            update(User).where(User.msp_id == msp_id, User.id == user_id).values(**values)
        )

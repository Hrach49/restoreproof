"""The three reads that happen before any MSP is known (C5.4, C6.1): a Worker
by its API token's hash, an install token by its hash, a user by their
address. Each is over a single-column unique of the model
(`uq_worker_api_token_hash`, `uq_install_token_token_hash`,
`uq_user_email_lower`) and answers the row, which carries its `msp_id`;
everything after it goes through a repo with that `msp_id`.
tests/test_tenant_scope.py holds that these are the only such methods."""

from __future__ import annotations

from sqlalchemy import func, select

from app.models import InstallToken, User, Worker
from app.repo.base import Repo


class Lookup(Repo):
    async def find_worker_by_token_hash(self, token_hash: str) -> Worker | None:
        return await self._one(select(Worker).where(Worker.api_token_hash == token_hash))

    async def find_install_token_by_hash(self, token_hash: str) -> InstallToken | None:
        return await self._one(select(InstallToken).where(InstallToken.token_hash == token_hash))

    async def find_user_by_email(self, email: str) -> User | None:
        """The user of the address, in any case (the login's lookup, C6.1).
        Both sides are lowered by PostgreSQL, as `uq_user_email_lower` is:
        Python's `str.lower()` maps other letters (a dotted capital I, a final
        sigma), and the user stored under one was found by no login."""
        return await self._one(select(User).where(func.lower(User.email) == func.lower(email.strip())))

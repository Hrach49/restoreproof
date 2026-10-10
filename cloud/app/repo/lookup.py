"""The two reads that happen before any MSP is known (C5.4): a Worker by its
API token's hash, an install token by its hash. Each is over a single-column
unique of the model (`uq_worker_api_token_hash`, `uq_install_token_token_hash`)
and answers the row, which carries its `msp_id`; everything after it goes
through a repo with that `msp_id`. tests/test_tenant_scope.py holds that these
are the only such methods."""

from __future__ import annotations

from sqlalchemy import select

from app.models import InstallToken, Worker
from app.repo.base import Repo


class Lookup(Repo):
    async def find_worker_by_token_hash(self, token_hash: str) -> Worker | None:
        return await self._one(select(Worker).where(Worker.api_token_hash == token_hash))

    async def find_install_token_by_hash(self, token_hash: str) -> InstallToken | None:
        return await self._one(select(InstallToken).where(InstallToken.token_hash == token_hash))

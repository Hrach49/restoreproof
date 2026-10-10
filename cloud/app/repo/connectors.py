"""The connectors of an MSP: a client on a Worker, with the client's profile
(C5.13; docs/decisions.md 2026-10-10, "C5.3 and C5.4", point 2).

`config_json` is a `restoreproof.client-profile.v1` whose `graph_tenant_id` is
the client's tenant. The checks run in one order, each a `RepoError` naming the
key and a fixed reason, never a value: the schema first (read by path from
shared/schemas/), then the client (read with `msp_id`, so another MSP's is "no
such client"), then the GUID parsed and compared as a uuid, so either case is
the same tenant, then the Worker (the same way). Every create, update and
delete that touched a row writes one audit_log row in the same transaction; one
that touched none writes none. `worker_id` and `client_id` never change: a
client on another Worker is another connector.
"""

from __future__ import annotations

import uuid
from functools import lru_cache
from typing import Any
from uuid import UUID

from jsonschema import Draft202012Validator
from sqlalchemy import delete, select, update

from app.models import DEFAULT_CONNECTOR_TYPE, Client, Connector, Worker
from app.repo.audit import AuditRepo
from app.repo.base import Repo
from app.repo.clients import ClientRepo
from app.repo.errors import RepoError
from app.repo.workers import WorkerRepo
from app.schemas import load_schema

PROFILE_SCHEMA = "client-profile.v1.json"


@lru_cache(maxsize=1)
def _validator() -> Draft202012Validator:
    return Draft202012Validator(load_schema(PROFILE_SCHEMA))


def _check_schema(config_json: Any) -> None:
    if not _validator().is_valid(config_json):
        raise RepoError("config_json", "not a client-profile.v1")


def _check_tenant(config_json: Any, client: Client) -> None:
    if uuid.UUID(config_json["graph_tenant_id"]) != client.tenant_id:
        raise RepoError("graph_tenant_id", "not the client's tenant")


class ConnectorRepo(Repo):
    async def create(
        self,
        msp_id: UUID,
        client_id: UUID,
        worker_id: UUID,
        config_json: Any,
        type: str = DEFAULT_CONNECTOR_TYPE,
        *,
        user_id: UUID | None = None,
        ip: str | None = None,
    ) -> Connector:
        _check_schema(config_json)
        _check_tenant(config_json, await self._client(msp_id, client_id))
        await self._worker(msp_id, worker_id)
        row = await self._add(
            Connector(
                msp_id=msp_id, client_id=client_id, worker_id=worker_id, type=type, config_json=config_json
            )
        )
        await self._audit(msp_id, "create", row.id, user_id, ip)
        return row

    async def get(self, msp_id: UUID, connector_id: UUID) -> Connector | None:
        return await self._one(
            select(Connector).where(Connector.msp_id == msp_id, Connector.id == connector_id)
        )

    async def list(
        self, msp_id: UUID, *, client_id: UUID | None = None, worker_id: UUID | None = None
    ) -> list[Connector]:
        statement = select(Connector).where(Connector.msp_id == msp_id)
        if client_id is not None:
            statement = statement.where(Connector.client_id == client_id)
        if worker_id is not None:
            statement = statement.where(Connector.worker_id == worker_id)
        return await self._all(statement.order_by(Connector.id))

    async def update(
        self,
        msp_id: UUID,
        connector_id: UUID,
        config_json: Any,
        *,
        user_id: UUID | None = None,
        ip: str | None = None,
    ) -> int:
        row = await self.get(msp_id, connector_id)
        if row is None:
            return 0
        _check_schema(config_json)
        _check_tenant(config_json, await self._client(msp_id, row.client_id))
        touched = await self._touched(
            update(Connector)
            .where(Connector.msp_id == msp_id, Connector.id == connector_id)
            .values(config_json=config_json)
        )
        if touched:
            await self._audit(msp_id, "update", connector_id, user_id, ip)
        return touched

    async def delete(
        self, msp_id: UUID, connector_id: UUID, *, user_id: UUID | None = None, ip: str | None = None
    ) -> int:
        touched = await self._touched(
            delete(Connector).where(Connector.msp_id == msp_id, Connector.id == connector_id)
        )
        if touched:
            await self._audit(msp_id, "delete", connector_id, user_id, ip)
        return touched

    async def _client(self, msp_id: UUID, client_id: UUID) -> Client:
        client = await ClientRepo(self.session).get(msp_id, client_id)
        if client is None:
            raise RepoError("client_id", "no such client")
        return client

    async def _worker(self, msp_id: UUID, worker_id: UUID) -> Worker:
        worker = await WorkerRepo(self.session).get(msp_id, worker_id)
        if worker is None:
            raise RepoError("worker_id", "no such worker")
        return worker

    async def _audit(
        self, msp_id: UUID, action: str, connector_id: UUID, user_id: UUID | None, ip: str | None
    ) -> None:
        await AuditRepo(self.session).write(
            msp_id, f"connector.{action}", f"connector:{connector_id}", user_id=user_id, ip=ip
        )

"""C5.13's Done-when (#136), one named parametrised test per line
(docs/decisions.md 2026-10-11, "C5.10 and C5.9", point 11): a second client
with the same tenant ID in one MSP is rejected; a connector whose profile names
another tenant is rejected; a bundle for a different client than dispatched
gets 409. The first two through the repo and through the CLI's functions,
each with its control; the third through `POST /v1/results` on the C5.7 lab.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.exc import IntegrityError

from app import results
from app.onboarding import create_client, create_connector
from app.repo.clients import ClientRepo
from app.repo.connectors import ConnectorRepo
from app.repo.errors import RepoError, constraint_refusal
from app.repo.msps import MspRepo
from app.repo.workers import WorkerRepo
from tests.test_repo_connectors import profile_for
from tests.test_results import (
    assert_refused,
    lab,  # noqa: F401 - the C5.7 lab, a fixture
    null_client_id,
    organisation_no_guid,
    other_client_id,
    other_organisation,
    other_tenant,
    pass_without_the_check,
    tenant_no_guid,
)

PEM = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----\n"
TENANT_TWICE = "tenant_id: already a client of this MSP"
ANOTHER_TENANT = "graph_tenant_id: not the client's tenant"


def a_hash(seed: str) -> str:
    return uuid.uuid5(uuid.NAMESPACE_DNS, seed).hex * 2


class World:
    @classmethod
    async def make(cls, session) -> "World":
        w = cls()
        w.msp_id = (await MspRepo(session).create(name="a")).id
        w.other_msp_id = (await MspRepo(session).create(name="b")).id
        w.tenant = uuid.uuid4()
        w.client = await ClientRepo(session).create(w.msp_id, name="first", tenant_id=w.tenant)
        w.second_client = await ClientRepo(session).create(w.msp_id, name="second", tenant_id=uuid.uuid4())
        w.other_client = await ClientRepo(session).create(w.other_msp_id, name="theirs", tenant_id=uuid.uuid4())
        w.worker = await WorkerRepo(session).create(
            w.msp_id, "w", public_key_pem=PEM, key_id=a_hash("k"), api_token_hash=a_hash("t")
        )
        return w


# --- Line 1 ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("spelling", ["the same text", "upper case", "through the CLI's create_client"])
async def test_a_second_client_with_the_same_tenant_id_in_one_msp_is_rejected(session, spelling):
    w = await World.make(session)
    tenant = uuid.UUID(str(w.tenant).upper()) if spelling == "upper case" else w.tenant

    with pytest.raises((IntegrityError, RepoError)) as raised:
        async with session.begin_nested():
            if spelling == "through the CLI's create_client":
                await create_client(session, w.msp_id, name="again", tenant_id=tenant)
            else:
                await ClientRepo(session).create(w.msp_id, name="again", tenant_id=tenant)

    refusal = raised.value if isinstance(raised.value, RepoError) else constraint_refusal(raised.value)
    assert str(refusal) == TENANT_TWICE
    assert [c.name for c in await ClientRepo(session).list(w.msp_id)] == ["first", "second"]
    # The control: the same tenant is a client of another MSP.
    theirs = await ClientRepo(session).create(w.other_msp_id, name="same tenant", tenant_id=w.tenant)
    assert theirs.tenant_id == w.tenant


# --- Line 2 ---------------------------------------------------------------------------------------


def _tenants(w: World) -> dict[str, uuid.UUID]:
    return {
        "another client's of the same MSP": w.second_client.tenant_id,
        "another MSP's client's": w.other_client.tenant_id,
        "a GUID nobody has": uuid.uuid4(),
    }


@pytest.mark.parametrize("named", ["another client's of the same MSP", "another MSP's client's", "a GUID nobody has"])
@pytest.mark.parametrize("through", ["the repo", "the CLI's create_connector"])
async def test_a_connector_whose_profile_names_another_tenant_is_rejected(session, named, through):
    w = await World.make(session)
    profile = profile_for(_tenants(w)[named])

    with pytest.raises(RepoError) as raised:
        async with session.begin_nested():
            if through == "the repo":
                await ConnectorRepo(session).create(w.msp_id, w.client.id, w.worker.id, profile)
            else:
                await create_connector(session, w.msp_id, client_id=w.client.id, worker_id=w.worker.id, profile=profile)

    assert str(raised.value) == ANOTHER_TENANT
    assert str(_tenants(w)[named]) not in str(raised.value) and str(w.tenant) not in str(raised.value)
    assert await ConnectorRepo(session).list(w.msp_id) == []
    # The control: the client's own tenant, in the other case, is its tenant.
    upper = profile_for(w.tenant, graph_tenant_id=str(w.tenant).upper())
    connector = await create_connector(session, w.msp_id, client_id=w.client.id, worker_id=w.worker.id, profile=upper)
    assert "connector_id" in connector.values


# --- Line 3 ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "patch",
    [other_client_id, null_client_id, other_tenant, tenant_no_guid, other_organisation, organisation_no_guid, pass_without_the_check],
    ids=lambda f: f.__name__,
)
async def test_a_bundle_for_a_different_client_than_dispatched_gets_409(lab, patch):  # noqa: F811
    run_id = await lab.run()
    parts = lab.bundle(run_id, patch=patch)
    before = await lab.counts()

    response = await lab.upload(parts)

    await assert_refused(lab, response, 409, results.CLIENT_MISMATCH, run_id=run_id, before=before)
    assert (await lab.run_row(run_id)).state == "dispatched"

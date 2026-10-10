"""C5.13's rules that are the repository layer's (docs/decisions.md 2026-10-10,
"C5.3 and C5.4", point 2): a connector's config_json is a client-profile.v1
whose graph_tenant_id is its client's tenant, refused as a RepoError that names
the key and never a value; every connector create, update and delete writes
one audit_log row in the same transaction.
"""

from __future__ import annotations

import json
import uuid

import pytest
from sqlalchemy.exc import IntegrityError

from app.repo.audit import AuditRepo
from app.repo.clients import ClientRepo
from app.repo.connectors import ConnectorRepo
from app.repo.errors import RepoError
from app.repo.msps import MspRepo
from app.repo.plans import PlanRepo
from app.repo.workers import WorkerRepo
from tests.test_result_schema import shared_dir

VALID_PROFILE = json.loads(
    (shared_dir() / "testdata" / "client-profile-v1" / "valid.json").read_bytes().decode("utf-8")
)
PEM = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----\n"


def profile_for(tenant_id: uuid.UUID, **changes) -> dict:
    """The shared valid profile, naming `tenant_id`."""
    return {**VALID_PROFILE, "graph_tenant_id": str(tenant_id), **changes}


class Lab:
    """One MSP with a client and a worker, and a second MSP with a client."""

    @classmethod
    async def make(cls, session) -> "Lab":
        lab = cls()
        lab.session = session
        lab.msp = await MspRepo(session).create(name="a")
        lab.other_msp = await MspRepo(session).create(name="b")
        lab.client = await ClientRepo(session).create(lab.msp.id, name="client", tenant_id=uuid.uuid4())
        lab.other_client = await ClientRepo(session).create(lab.other_msp.id, name="other", tenant_id=uuid.uuid4())
        lab.worker = await WorkerRepo(session).create(
            lab.msp.id, name="worker", public_key_pem=PEM, api_token_hash="a" * 64
        )
        lab.connectors = ConnectorRepo(session)
        lab.audit = AuditRepo(session)
        return lab

    async def audit_rows(self, msp_id=None) -> list:
        """The MSP's audit rows. Rows written in one transaction share `now()`,
        so a test never relies on their order."""
        return await self.audit.list(self.msp.id if msp_id is None else msp_id)

    async def create(self, **changes):
        values = {
            "client_id": self.client.id,
            "worker_id": self.worker.id,
            "config_json": profile_for(self.client.tenant_id),
        }
        return await self.connectors.create(self.msp.id, **{**values, **changes})


def values_of(document) -> list[str]:
    return [str(value) for value in document.values()] if isinstance(document, dict) else [str(document)]


# --- Create ----------------------------------------------------------------------


async def test_a_connector_is_created_with_an_audit_row_in_the_same_transaction(session):
    lab = await Lab.make(session)
    user_id = uuid.uuid4()  # the audit row's user is held by a key: use none here

    connector = await lab.create(user_id=None, ip="10.0.0.9")

    assert connector.msp_id == lab.msp.id
    assert connector.type == "veeam_m365"
    assert connector.config_json == profile_for(lab.client.tenant_id)
    rows = await lab.audit_rows()
    assert [(row.action, row.target, row.user_id, row.ip) for row in rows] == [
        ("connector.create", f"connector:{connector.id}", None, "10.0.0.9")
    ]
    assert rows[0].msp_id == lab.msp.id
    assert user_id not in {row.user_id for row in rows}


async def test_the_audit_row_names_the_user_who_did_it(session):
    lab = await Lab.make(session)
    from app.repo.users import UserRepo

    user = await UserRepo(session).create(lab.msp.id, email="u@example.test", password_hash="x", role="admin")
    connector = await lab.create(user_id=user.id)

    (row,) = await lab.audit_rows()
    assert (row.user_id, row.ip, row.target) == (user.id, None, f"connector:{connector.id}")


async def test_the_tenant_is_compared_as_a_uuid_not_as_text(session):
    lab = await Lab.make(session)
    upper = str(lab.client.tenant_id).upper()

    connector = await lab.create(config_json=profile_for(lab.client.tenant_id, graph_tenant_id=upper))

    assert connector.config_json["graph_tenant_id"] == upper


async def test_a_profile_naming_another_tenant_is_refused_without_either_value(session):
    lab = await Lab.make(session)
    other_tenant = uuid.uuid4()

    with pytest.raises(RepoError) as raised:
        await lab.create(config_json=profile_for(other_tenant))

    assert (raised.value.key, raised.value.reason) == ("graph_tenant_id", "not the client's tenant")
    assert str(raised.value) == "graph_tenant_id: not the client's tenant"
    assert str(other_tenant) not in str(raised.value)
    assert str(lab.client.tenant_id) not in str(raised.value)
    assert await lab.connectors.list(lab.msp.id) == []
    assert await lab.audit_rows() == []


async def test_the_other_msp_s_tenant_in_a_profile_is_refused_the_same_way(session):
    lab = await Lab.make(session)

    with pytest.raises(RepoError, match="^graph_tenant_id: not the client's tenant$"):
        await lab.create(config_json=profile_for(lab.other_client.tenant_id))


@pytest.mark.parametrize(
    ("name", "document"),
    [
        ("not an object", "restoreproof.client-profile.v1"),
        ("empty", {}),
        ("another format", profile_for(uuid.UUID(int=1), format="restoreproof.result.v1")),
        ("a key missing", {k: v for k, v in profile_for(uuid.UUID(int=1)).items() if k != "test_mailbox"}),
        ("a key too many", profile_for(uuid.UUID(int=1), extra="x")),
        ("a tenant that isn't a GUID", profile_for(uuid.UUID(int=1), graph_tenant_id="not-a-guid")),
        ("a mailbox that isn't restoretest", profile_for(uuid.UUID(int=1), test_mailbox="alice@contoso.onmicrosoft.com")),
        ("a secret-looking value for the tenant", profile_for(uuid.UUID(int=1), graph_tenant_id="Sentinel-Secret-7f3a")),
    ],
)
async def test_a_document_that_is_not_a_client_profile_is_refused_without_its_values(session, name, document):
    lab = await Lab.make(session)

    with pytest.raises(RepoError) as raised:
        await lab.create(config_json=document)

    assert (raised.value.key, raised.value.reason) == ("config_json", "not a client-profile.v1"), name
    assert str(raised.value) == "config_json: not a client-profile.v1"
    for value in values_of(document):
        if len(value) >= 8:
            assert value not in str(raised.value), (name, value)
    assert await lab.audit_rows() == []


async def test_the_schema_is_checked_before_the_tenant(session):
    """A document that isn't a profile at all never gets to the comparison."""
    lab = await Lab.make(session)

    with pytest.raises(RepoError, match="^config_json: "):
        await lab.create(config_json={"graph_tenant_id": str(lab.client.tenant_id)})


async def test_a_client_that_is_not_the_msp_s_is_no_client(session):
    lab = await Lab.make(session)

    for client_id in (lab.other_client.id, uuid.uuid4()):
        with pytest.raises(RepoError) as raised:
            await lab.create(client_id=client_id, config_json=profile_for(lab.other_client.tenant_id))
        assert (raised.value.key, raised.value.reason) == ("client_id", "no such client")
        assert str(client_id) not in str(raised.value)
    assert await lab.audit_rows() == []
    assert await lab.audit_rows(lab.other_msp.id) == []


async def test_the_database_s_own_refusals_stay_integrity_errors(session):
    """A second connector for one Worker and client: the key's name, for the
    route or the CLI to word (C5.10, C5.13)."""
    lab = await Lab.make(session)
    await lab.create()

    with pytest.raises(IntegrityError) as raised:
        async with session.begin_nested():
            await lab.create()

    assert '"uq_connector_worker_id_client_id"' in str(raised.value.orig)


async def test_a_connector_type_is_the_worker_s_name_rule(session):
    lab = await Lab.make(session)

    connector = await lab.create(type="other_backup")

    assert connector.type == "other_backup"


# --- Update ------------------------------------------------------------------------


async def test_an_update_changes_the_profile_and_writes_its_audit_row(session):
    lab = await Lab.make(session)
    connector = await lab.create()
    changed = profile_for(lab.client.tenant_id, veeam_org_name="renamed.onmicrosoft.com")

    touched = await lab.connectors.update(lab.msp.id, connector.id, changed, ip="10.0.0.2")

    assert touched == 1
    assert (await lab.connectors.get(lab.msp.id, connector.id)).config_json == changed
    assert sorted((row.action, row.target, row.ip) for row in await lab.audit_rows()) == [
        ("connector.create", f"connector:{connector.id}", None),
        ("connector.update", f"connector:{connector.id}", "10.0.0.2"),
    ]


async def test_an_update_to_a_profile_of_another_tenant_or_no_profile_changes_nothing(session):
    lab = await Lab.make(session)
    connector = await lab.create()
    before = dict(connector.config_json)

    with pytest.raises(RepoError, match="^graph_tenant_id: "):
        await lab.connectors.update(lab.msp.id, connector.id, profile_for(uuid.uuid4()))
    with pytest.raises(RepoError, match="^config_json: "):
        await lab.connectors.update(lab.msp.id, connector.id, {"format": "restoreproof.client-profile.v1"})

    assert (await lab.connectors.get(lab.msp.id, connector.id)).config_json == before
    assert [row.action for row in await lab.audit_rows()] == ["connector.create"]


async def test_an_update_of_a_connector_that_is_not_the_msp_s_touches_nothing_and_writes_no_audit_row(session):
    lab = await Lab.make(session)
    connector = await lab.create()

    assert await lab.connectors.update(lab.other_msp.id, connector.id, profile_for(lab.client.tenant_id)) == 0
    assert await lab.connectors.update(lab.msp.id, uuid.uuid4(), profile_for(lab.client.tenant_id)) == 0

    assert [row.action for row in await lab.audit_rows()] == ["connector.create"]
    assert await lab.audit_rows(lab.other_msp.id) == []


# --- Delete ------------------------------------------------------------------------


async def test_a_delete_removes_the_connector_and_writes_its_audit_row(session):
    lab = await Lab.make(session)
    connector = await lab.create()

    assert await lab.connectors.delete(lab.msp.id, connector.id, ip="10.0.0.3") == 1

    assert await lab.connectors.get(lab.msp.id, connector.id) is None
    assert sorted((row.action, row.target, row.ip) for row in await lab.audit_rows()) == [
        ("connector.create", f"connector:{connector.id}", None),
        ("connector.delete", f"connector:{connector.id}", "10.0.0.3"),
    ]


async def test_a_delete_of_nothing_writes_no_audit_row(session):
    lab = await Lab.make(session)
    connector = await lab.create()

    assert await lab.connectors.delete(lab.other_msp.id, connector.id) == 0
    assert await lab.connectors.delete(lab.msp.id, uuid.uuid4()) == 0

    assert [row.action for row in await lab.audit_rows()] == ["connector.create"]
    assert await lab.audit_rows(lab.other_msp.id) == []


async def test_a_connector_a_plan_points_at_is_not_deleted(session):
    lab = await Lab.make(session)
    connector = await lab.create()
    await PlanRepo(session).create(
        lab.msp.id, lab.client.id, connector.id, sample_mail=1, sample_sp=1, sample_od=1, cadence_cron="0 2 * * *"
    )

    with pytest.raises(IntegrityError) as raised:
        async with session.begin_nested():
            await lab.connectors.delete(lab.msp.id, connector.id)

    assert '"fk_test_plan_msp_id_connector_id_client_id_connector"' in str(raised.value.orig)
    assert (await lab.connectors.get(lab.msp.id, connector.id)) is not None


# --- List ---------------------------------------------------------------------------


async def test_list_filters_by_client_and_by_worker(session):
    lab = await Lab.make(session)
    second_client = await ClientRepo(session).create(lab.msp.id, name="second", tenant_id=uuid.uuid4())
    second_worker = await WorkerRepo(session).create(
        lab.msp.id, name="second", public_key_pem=PEM, api_token_hash="b" * 64
    )
    one = await lab.create()
    two = await lab.create(client_id=second_client.id, config_json=profile_for(second_client.tenant_id))
    three = await lab.create(worker_id=second_worker.id)

    assert {c.id for c in await lab.connectors.list(lab.msp.id)} == {one.id, two.id, three.id}
    assert {c.id for c in await lab.connectors.list(lab.msp.id, client_id=lab.client.id)} == {one.id, three.id}
    assert {c.id for c in await lab.connectors.list(lab.msp.id, worker_id=lab.worker.id)} == {one.id, two.id}
    assert [c.id for c in await lab.connectors.list(lab.msp.id, client_id=second_client.id, worker_id=second_worker.id)] == []


async def test_nothing_of_the_profile_reaches_the_audit_row(session):
    lab = await Lab.make(session)
    marker = "restoretest@sentinel-audit-4c1e.onmicrosoft.com"

    connector = await lab.create(config_json=profile_for(lab.client.tenant_id, test_mailbox=marker))
    await lab.connectors.update(lab.msp.id, connector.id, profile_for(lab.client.tenant_id))
    await lab.connectors.delete(lab.msp.id, connector.id)

    for row in await lab.audit_rows():
        for value in (row.action, row.target):
            assert "sentinel" not in value
            assert str(lab.client.tenant_id) not in value

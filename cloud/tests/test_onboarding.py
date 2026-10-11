"""C5.10's logic (docs/decisions.md 2026-10-11, "C5.10 and C5.9", points 1
to 5): the six functions of `app/onboarding.py` over the rolled-back session,
each through the repos, each answering the lines the CLI prints, each refusal
a `RepoError` with no value in it, one audit row per command that changed a
row and none for one refused.
"""

from __future__ import annotations

import datetime as dt
import json
import uuid

import pytest
from sqlalchemy import text

from app import onboarding
from app.auth.tokens import token_hash
from app.cadence import DEFAULT_CADENCE
from app.models import DEFAULT_RETENTION_DAYS
from app.onboarding import (
    create_client,
    create_connector,
    create_msp,
    create_plan,
    create_worker_token,
    read_profile_file,
    revoke_worker,
)
from app.repo.audit import AuditRepo
from app.repo.clients import ClientRepo
from app.repo.connectors import ConnectorRepo
from app.repo.errors import RepoError
from app.repo.install_tokens import InstallTokenRepo
from app.repo.lookup import Lookup
from app.repo.msps import MspRepo
from app.repo.plans import PlanRepo
from app.repo.runs import RunRepo
from app.repo.workers import WorkerRepo
from tests.test_repo_connectors import VALID_PROFILE, profile_for

UTC = dt.timezone.utc
NOW = dt.datetime(2026, 10, 11, 12, 0, 30, tzinfo=UTC)
PEM = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----\n"
TABLES = ("msp", "client", "worker", "connector", "test_plan", "test_run", "install_token", "audit_log")


def a_hash(seed: str) -> str:
    return uuid.uuid5(uuid.NAMESPACE_DNS, seed).hex * 2


@pytest.fixture
def clock(monkeypatch):
    monkeypatch.setattr(onboarding, "now", lambda: NOW)
    return NOW


async def counts(session) -> dict[str, int]:
    return {table: (await session.execute(text(f'SELECT count(*) FROM "{table}"'))).scalar_one() for table in TABLES}


async def audit_actions(session, msp_id) -> list[tuple[str, str]]:
    return sorted((row.action, row.target) for row in await AuditRepo(session).list(msp_id))


class Lab:
    """An MSP with a client and a Worker, made through the functions."""

    @classmethod
    async def make(cls, session) -> "Lab":
        lab = cls()
        lab.session = session
        lab.msp_id = uuid.UUID((await create_msp(session, name="a")).values["msp_id"])
        lab.tenant_id = uuid.uuid4()
        lab.client_id = uuid.UUID((await create_client(session, lab.msp_id, name="contoso", tenant_id=lab.tenant_id)).values["client_id"])
        lab.worker_id = (await WorkerRepo(session).create(
            lab.msp_id, "w", public_key_pem=PEM, key_id=a_hash("k"), api_token_hash=a_hash("t")
        )).id
        lab.other_msp_id = uuid.UUID((await create_msp(session, name="b")).values["msp_id"])
        lab.other_client_id = uuid.UUID((await create_client(session, lab.other_msp_id, name="other", tenant_id=uuid.uuid4())).values["client_id"])
        return lab

    async def connector(self, **changes) -> uuid.UUID:
        values = {"client_id": self.client_id, "worker_id": self.worker_id, "profile": profile_for(self.tenant_id)}
        created = await create_connector(self.session, self.msp_id, **{**values, **changes})
        return uuid.UUID(created.values["connector_id"])

    async def plan(self, default_connector, **changes):
        values = {"client_id": self.client_id, "connector_id": default_connector, "sample_mail": 5, "sample_sp": 3, "sample_od": 2,
                  "cadence_cron": DEFAULT_CADENCE, "enabled": True, "run_now": False}
        return await create_plan(self.session, self.msp_id, **{**values, **changes})


async def refused(session, coro, key: str, reason: str, *values: str) -> RepoError:
    before = await counts(session)
    with pytest.raises(RepoError) as raised:
        async with session.begin_nested():
            await coro
    assert (raised.value.key, raised.value.reason) == (key, reason)
    for value in values:
        assert not value or value not in str(raised.value)
    assert await counts(session) == before
    return raised.value


# --- create_msp ----------------------------------------------------------------------------


async def test_create_msp_makes_the_row_and_its_audit_row(session, clock):
    created = await create_msp(session, name="Contoso MSP")

    assert created.lines == (("msp_id", created.values["msp_id"]),)
    assert created.notes == ()
    msp_id = uuid.UUID(created.values["msp_id"])
    msp = await MspRepo(session).get(msp_id)
    assert (msp.name, msp.retention_days) == ("Contoso MSP", DEFAULT_RETENTION_DAYS)
    assert await audit_actions(session, msp_id) == [("msp.create", f"msp:{msp_id}")]
    (row,) = await AuditRepo(session).list(msp_id)
    assert (row.user_id, row.ip) == (None, None)


async def test_create_msp_takes_retention_days_and_refuses_a_bad_one(session, clock):
    created = await create_msp(session, name="a", retention_days=30)
    assert (await MspRepo(session).get(uuid.UUID(created.values["msp_id"]))).retention_days == 30

    await refused(session, create_msp(session, name="a", retention_days=0), "retention_days", "not positive")


@pytest.mark.parametrize("name", ["", "x" * 129, "a\tb", "a\nb", "a\x00b"])
async def test_a_name_outside_the_rule_is_refused_without_the_name(session, clock, name):
    await refused(session, create_msp(session, name=name), "name", onboarding.NAME_RULE, name)


# --- create_client ---------------------------------------------------------------------------


async def test_create_client_makes_the_row_and_its_audit_row(session, clock):
    lab = await Lab.make(session)
    tenant = uuid.uuid4()

    created = await create_client(session, lab.msp_id, name="fabrikam", tenant_id=tenant, screenshots_enabled=True)

    client_id = uuid.UUID(created.values["client_id"])
    assert created.lines == (("client_id", str(client_id)),)
    client = await ClientRepo(session).get(lab.msp_id, client_id)
    assert (client.name, client.tenant_id, client.screenshots_enabled) == ("fabrikam", tenant, True)
    assert ("client.create", f"client:{client_id}") in await audit_actions(session, lab.msp_id)


async def test_a_second_client_of_one_tenant_in_one_msp_is_refused_and_another_msp_s_is_taken(session, clock):
    lab = await Lab.make(session)

    await refused(
        session, create_client(session, lab.msp_id, name="again", tenant_id=lab.tenant_id),
        "tenant_id", "already a client of this MSP", str(lab.tenant_id),
    )
    assert "client_id" in (await create_client(session, lab.other_msp_id, name="theirs", tenant_id=lab.tenant_id)).values


async def test_a_client_of_an_msp_that_does_not_exist_is_refused(session, clock):
    await refused(session, create_client(session, uuid.uuid4(), name="x", tenant_id=uuid.uuid4()), "msp_id", "no such MSP")


# --- create_worker_token ---------------------------------------------------------------------


async def test_create_worker_token_prints_the_token_once_and_stores_its_hash(session, clock):
    lab = await Lab.make(session)

    created = await create_worker_token(session, lab.msp_id, label="veeam-vm")

    keys = [key for key, _ in created.lines]
    assert keys == ["install_token_id", "expires_at", "install_token"]
    token = created.values["install_token"]
    assert len(token) == 43
    assert created.values["expires_at"] == "2026-10-18T12:00:30Z"
    assert created.notes == (onboarding.SHOWN_ONCE,)
    row = await Lookup(session).find_install_token_by_hash(token_hash(token))
    assert (str(row.id), row.label, row.msp_id, row.created_by) == (created.values["install_token_id"], "veeam-vm", lab.msp_id, None)
    assert row.expires_at == NOW + dt.timedelta(days=7)
    assert ("install_token.create", f"install_token:{row.id}") in await audit_actions(session, lab.msp_id)
    # Nowhere but the one line: not in the audit row, not as the label.
    assert token not in json.dumps(await audit_actions(session, lab.msp_id))
    assert [t.label for t in await InstallTokenRepo(session).list(lab.msp_id)] == ["veeam-vm"]


@pytest.mark.parametrize("label", ["", "x" * 129, "a\tb"])
async def test_a_label_outside_the_rule_is_refused(session, clock, label):
    lab = await Lab.make(session)

    await refused(session, create_worker_token(session, lab.msp_id, label=label), "label", onboarding.NAME_RULE, label)


async def test_a_token_for_an_msp_that_does_not_exist_is_refused(session, clock):
    await refused(session, create_worker_token(session, uuid.uuid4(), label="x"), "msp_id", "no such MSP")


# --- create_connector --------------------------------------------------------------------------


async def test_create_connector_goes_through_the_repo_which_writes_the_audit_row(session, clock):
    lab = await Lab.make(session)

    connector_id = await lab.connector()

    connector = await ConnectorRepo(session).get(lab.msp_id, connector_id)
    assert (connector.client_id, connector.worker_id, connector.type) == (lab.client_id, lab.worker_id, "veeam_m365")
    assert connector.config_json == profile_for(lab.tenant_id)
    actions = await audit_actions(session, lab.msp_id)
    assert actions.count(("connector.create", f"connector:{connector_id}")) == 1


async def test_a_connector_type_is_stored_as_given(session, clock):
    lab = await Lab.make(session)

    connector_id = await lab.connector(type="veeam_m365_v9")

    assert (await ConnectorRepo(session).get(lab.msp_id, connector_id)).type == "veeam_m365_v9"


@pytest.mark.parametrize(
    ("changes", "key", "reason"),
    [
        ({"profile": {"format": "nope"}}, "config_json", "not a client-profile.v1"),
        ({"profile": "text"}, "config_json", "not a client-profile.v1"),
        ({"client_id": uuid.UUID(int=7)}, "client_id", "no such client"),
        ({"worker_id": uuid.UUID(int=7)}, "worker_id", "no such worker"),
    ],
)
async def test_the_repo_s_refusals_come_through_unchanged(session, clock, changes, key, reason):
    lab = await Lab.make(session)

    await refused(session, lab.connector(**changes), key, reason)


async def test_a_profile_naming_another_tenant_is_refused_without_the_tenant(session, clock):
    lab = await Lab.make(session)
    other = uuid.uuid4()

    await refused(session, lab.connector(profile=profile_for(other)), "graph_tenant_id", "not the client's tenant", str(other), str(lab.tenant_id))


async def test_a_client_twice_on_one_worker_is_refused(session, clock):
    lab = await Lab.make(session)
    await lab.connector()

    await refused(session, lab.connector(), "client_id", "already a connector of this Worker")


async def test_another_msp_s_client_is_no_client(session, clock):
    lab = await Lab.make(session)

    await refused(session, lab.connector(client_id=lab.other_client_id), "client_id", "no such client")


# --- read_profile_file ------------------------------------------------------------------------


def test_read_profile_file_reads_json_as_utf8(tmp_path):
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(VALID_PROFILE), encoding="utf-8")

    assert read_profile_file(path) == VALID_PROFILE


@pytest.mark.parametrize(
    ("content", "reason"),
    [
        (None, "not readable"),
        (b"\xff\xfe\x00", "not UTF-8"),
        (b"{not json", "not JSON"),
        (b"", "not JSON"),
    ],
)
def test_a_file_that_is_not_a_profile_is_refused_without_its_path_or_text(tmp_path, content, reason):
    path = tmp_path / "Sentinel-Folder" / "profile.json"
    if content is not None:
        path.parent.mkdir()
        path.write_bytes(content)

    with pytest.raises(RepoError) as raised:
        read_profile_file(path)

    assert (raised.value.key, raised.value.reason) == ("profile_file", reason)
    assert "Sentinel" not in str(raised.value) and "not json" not in str(raised.value)


# --- create_plan -----------------------------------------------------------------------------


async def test_create_plan_makes_the_row_and_its_audit_row(session, clock):
    lab = await Lab.make(session)
    connector_id = await lab.connector()

    created = await lab.plan(connector_id, cadence_cron="*/5 * * * *", enabled=False)

    plan_id = uuid.UUID(created.values["plan_id"])
    assert created.lines == (("plan_id", str(plan_id)),)
    plan = await PlanRepo(session).get(lab.msp_id, plan_id)
    assert (plan.client_id, plan.connector_id, plan.sample_mail, plan.sample_sp, plan.sample_od) == (lab.client_id, connector_id, 5, 3, 2)
    assert (plan.cadence_cron, plan.enabled) == ("*/5 * * * *", False)
    assert ("plan.create", f"plan:{plan_id}") in await audit_actions(session, lab.msp_id)
    assert await RunRepo(session).list(lab.msp_id) == []


async def test_run_now_queues_one_run_made_by_hand(session, clock):
    lab = await Lab.make(session)
    connector_id = await lab.connector()

    created = await lab.plan(connector_id, run_now=True)

    assert [key for key, _ in created.lines] == ["plan_id", "run_id"]
    run = await RunRepo(session).get(lab.msp_id, uuid.UUID(created.values["run_id"]))
    assert (run.state, run.scheduled_for, run.plan_id, run.worker_id, run.connector_id, run.client_id) == (
        "queued", None, uuid.UUID(created.values["plan_id"]), lab.worker_id, connector_id, lab.client_id
    )
    assert ("run.create", f"run:{run.id}") in await audit_actions(session, lab.msp_id)


@pytest.mark.parametrize(
    ("changes", "key", "reason"),
    [
        ({"cadence_cron": "nonsense"}, "cadence_cron", "not a cron expression"),
        ({"cadence_cron": "0 2 1 1 *"}, "cadence_cron", "less than monthly"),
        ({"sample_mail": 101}, "sample_mail", "not 0 to 100"),
        ({"sample_sp": -1}, "sample_sp", "not 0 to 100"),
        ({"sample_od": 101}, "sample_od", "not 0 to 100"),
        ({"sample_mail": 0, "sample_sp": 0, "sample_od": 0}, "sample sizes", "all 0"),
        ({"connector_id": uuid.UUID(int=9)}, "connector_id", "not the client's connector"),
    ],
)
async def test_a_plan_outside_the_rules_is_refused(session, clock, changes, key, reason):
    lab = await Lab.make(session)
    connector_id = await lab.connector()

    await refused(session, lab.plan(connector_id, **changes), key, reason, "nonsense")


async def test_a_plan_on_another_client_s_connector_is_refused(session, clock):
    lab = await Lab.make(session)
    connector_id = await lab.connector()
    second = uuid.UUID((await create_client(session, lab.msp_id, name="second", tenant_id=uuid.uuid4())).values["client_id"])

    await refused(session, lab.plan(connector_id, client_id=second), "connector_id", "not the client's connector")
    # Another MSP's client is no client of this one: the plan's own key to client.
    await refused(session, lab.plan(connector_id, client_id=lab.other_client_id), "client_id", "no such client")


# --- revoke_worker ----------------------------------------------------------------------------


async def test_revoke_worker_sets_revoked_at_once_and_writes_its_audit_row(session, clock):
    lab = await Lab.make(session)

    created = await revoke_worker(session, lab.msp_id, worker_id=lab.worker_id)

    assert created.lines == (("revoked_at", "2026-10-11T12:00:30Z"),)
    assert (await WorkerRepo(session).get(lab.msp_id, lab.worker_id)).revoked_at == NOW
    assert ("worker.revoke", f"worker:{lab.worker_id}") in await audit_actions(session, lab.msp_id)
    await refused(session, revoke_worker(session, lab.msp_id, worker_id=lab.worker_id), "worker_id", "no such Worker or already revoked")


async def test_another_msp_s_worker_and_an_absent_one_are_no_worker(session, clock):
    lab = await Lab.make(session)

    await refused(session, revoke_worker(session, lab.other_msp_id, worker_id=lab.worker_id), "worker_id", "no such Worker or already revoked")
    await refused(session, revoke_worker(session, lab.msp_id, worker_id=uuid.uuid4()), "worker_id", "no such Worker or already revoked")
    assert (await WorkerRepo(session).get(lab.msp_id, lab.worker_id)).revoked_at is None


# --- the module's rules ---------------------------------------------------------------------------


def test_now_is_the_cloud_s_clock_in_utc():
    stamp = onboarding.now()

    assert stamp.tzinfo is not None and stamp.utcoffset() == dt.timedelta(0)
    assert abs((dt.datetime.now(UTC) - stamp).total_seconds()) < 5


def test_an_unknown_integrity_error_is_re_raised(session, clock):
    """`constraint_refusal` answers None for a name outside its table; the
    function re-raises the original, which the CLI prints as `internal`."""
    from sqlalchemy.exc import IntegrityError

    error = IntegrityError("x", {}, Exception('violates "uq_nobody_knows"'))

    assert onboarding.worded(error) is error


async def test_nothing_commits(session, monkeypatch, clock):
    committed = []

    async def commit():
        committed.append(True)

    monkeypatch.setattr(session, "commit", commit)
    lab = await Lab.make(session)
    connector_id = await lab.connector()
    await lab.plan(connector_id, run_now=True)
    await create_worker_token(session, lab.msp_id, label="x")
    await revoke_worker(session, lab.msp_id, worker_id=lab.worker_id)

    assert committed == []

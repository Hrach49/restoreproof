"""C5.10: the database's refusals worded once (docs/decisions.md 2026-10-11,
"C5.10 and C5.9", point 2). `constraint_refusal` reads the constraint's name
out of an `IntegrityError` and answers a `RepoError` from a fixed table, by
name and never a value; the CLI prints it now and the admin routes answer it
as 409 later. The table is held complete against the metadata, and every word
is shown on the database.
"""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from sqlalchemy import CheckConstraint, ForeignKeyConstraint, UniqueConstraint
from sqlalchemy.exc import IntegrityError

from app.models import Base, Client, Connector, Msp, TestPlan, TestRun, Worker
from app.repo.errors import CONSTRAINT_WORDS, RepoError, constraint_refusal
from tests.test_models import PROFILE, a_plan, a_run, add, new_client, new_msp, new_worker
from tests.test_repo_connectors import profile_for

UTC = dt.timezone.utc


class DriverError(Exception):
    """What asyncpg raises: the message, and the constraint's name beside it."""

    def __init__(self, text: str, constraint_name: object) -> None:
        super().__init__(text)
        self.constraint_name = constraint_name


NO_CAUSE = object()


class FakeIntegrityError(IntegrityError):
    """An IntegrityError as the asyncpg dialect raises it: `orig` its own
    error, raised from the driver's, which names the constraint."""

    def __init__(self, text: str, constraint_name: object = NO_CAUSE) -> None:
        orig = Exception(text)
        if constraint_name is not NO_CAUSE:
            orig.__cause__ = DriverError(text, constraint_name)
        super().__init__("INSERT ...", {}, orig)


@pytest.mark.parametrize(
    ("constraint", "key", "reason"),
    [
        ("uq_client_msp_id_tenant_id", "tenant_id", "already a client of this MSP"),
        ("uq_connector_worker_id_client_id", "client_id", "already a connector of this Worker"),
        ("uq_worker_key_id", "public_key_pem", "already registered"),
        ("ck_test_plan_sample_mail_range", "sample_mail", "not 0 to 100"),
        ("ck_test_plan_sample_sp_range", "sample_sp", "not 0 to 100"),
        ("ck_test_plan_sample_od_range", "sample_od", "not 0 to 100"),
        ("ck_test_plan_sample_not_empty", "sample sizes", "all 0"),
        ("fk_test_plan_msp_id_connector_id_client_id_connector", "connector_id", "not the client's connector"),
        ("fk_test_plan_msp_id_client_id_client", "client_id", "no such client"),
        ("ck_msp_retention_days_positive", "retention_days", "not positive"),
        ("uq_test_run_msp_id_plan_id_scheduled_for", "scheduled_for", "a run exists for the period"),
        ("fk_client_msp_id_msp", "msp_id", "no such MSP"),
        ("fk_install_token_msp_id_msp", "msp_id", "no such MSP"),
        ("fk_test_plan_msp_id_msp", "msp_id", "no such MSP"),
    ],
)
def test_a_known_constraint_is_worded_by_its_name(constraint, key, reason):
    error = FakeIntegrityError(
        f'duplicate key value violates unique constraint "{constraint}"\nDETAIL: Key (x)=(secret-value) already exists.',
        constraint,
    )

    refusal = constraint_refusal(error)

    assert isinstance(refusal, RepoError)
    assert (refusal.key, refusal.reason) == (key, reason)
    assert str(refusal) == f"{key}: {reason}"
    assert "secret-value" not in str(refusal)


@pytest.mark.parametrize(
    ("text", "constraint_name"),
    [
        ("", NO_CAUSE),  # no driver error under it
        ('violates unique constraint "uq_something_else"', "uq_something_else"),
        ('constraint "UQ_CLIENT_MSP_ID_TENANT_ID"', "UQ_CLIENT_MSP_ID_TENANT_ID"),
        ("null value in column violates not-null constraint", None),  # a NOT NULL names none
        ("a name that is no text", 7),
        # The message alone names nothing, with or without a driver error.
        ('violates unique constraint "uq_client_msp_id_tenant_id"', NO_CAUSE),
        ('violates unique constraint "uq_client_msp_id_tenant_id"', None),
    ],
)
def test_an_unknown_constraint_is_none_for_the_caller_to_re_raise(text, constraint_name):
    assert constraint_refusal(FakeIntegrityError(text, constraint_name)) is None


def test_a_row_value_that_quotes_a_constraint_s_name_words_nothing():
    """The review's finding 5: the DETAIL quotes the failing row, and a name
    or a label in it may hold a constraint's name in quotes; only the name
    the driver gives is read."""
    text = (
        'null value in column "x" of relation "client" violates not-null constraint\n'
        'DETAIL: Failing row contains (1, My "uq_worker_key_id" MSP, null).'
    )

    assert constraint_refusal(FakeIntegrityError(text, None)) is None
    assert constraint_refusal(FakeIntegrityError(text, "ck_some_later_check")) is None
    # ... and the driver's name decides against the message's.
    worded = constraint_refusal(FakeIntegrityError(text, "uq_client_msp_id_tenant_id"))
    assert str(worded) == "tenant_id: already a client of this MSP"


async def test_a_real_refusal_whose_row_quotes_another_constraint_is_worded_by_its_own(session):
    msp = await new_msp(session)
    tenant = uuid.uuid4()
    await new_client(session, msp, tenant)

    refusal = await _refused(session, Client(msp_id=msp.id, name='My "uq_worker_key_id" client', tenant_id=tenant))

    assert str(refusal) == "tenant_id: already a client of this MSP"


def test_the_table_names_every_constraint_an_onboarding_can_meet():
    """Every unique, CHECK and foreign key of the rows the CLI makes (msp,
    client, worker, connector, test_plan) that a command can reach, and the
    period's unique: in the table, with the names as the metadata has them."""
    named = set()
    for table in (Msp.__table__, Client.__table__, Connector.__table__, TestPlan.__table__):
        for constraint in table.constraints:
            if isinstance(constraint, (UniqueConstraint, CheckConstraint)) and constraint.name:
                named.add(constraint.name)
    expected = {
        name
        for name in named
        # The repo refuses these before the database (ConnectorRepo), or they
        # are the composite keys other tables point at, never met by a create.
        if not name.startswith("uq_") or name in ("uq_client_msp_id_tenant_id", "uq_connector_worker_id_client_id")
    } - {"ck_connector_type_name", "ck_worker_key_id_hex"}
    expected |= {"uq_worker_key_id", "fk_test_plan_msp_id_connector_id_client_id_connector", "fk_test_plan_msp_id_client_id_client", "uq_test_run_msp_id_plan_id_scheduled_for"}
    expected |= {f"fk_{table}_msp_id_msp" for table in ("client", "install_token", "worker", "connector", "test_plan", "test_run")}

    assert set(CONSTRAINT_WORDS) == expected
    all_names = {c.name for t in Base.metadata.tables.values() for c in t.constraints if c.name}
    all_names |= {c.name for t in Base.metadata.tables.values() for c in t.constraints if isinstance(c, ForeignKeyConstraint) and c.name}
    assert set(CONSTRAINT_WORDS) <= all_names
    assert all(word[0] and word[1] for word in CONSTRAINT_WORDS.values())


async def _refused(session, row) -> RepoError:
    with pytest.raises(IntegrityError) as raised:
        async with session.begin_nested():
            session.add(row)
            await session.flush()
    refusal = constraint_refusal(raised.value)
    assert refusal is not None, str(raised.value.orig)
    return refusal


async def test_each_word_is_shown_on_the_database(session):
    msp = await new_msp(session)
    tenant = uuid.uuid4()
    client = await new_client(session, msp, tenant)
    worker = await new_worker(session, msp)
    connector = await add(session, Connector(msp_id=msp.id, client_id=client.id, worker_id=worker.id, config_json=profile_for(tenant)))
    other_client = await new_client(session, msp, uuid.uuid4(), "other")
    plan = await add(session, a_plan(msp, client, connector))
    await add(session, a_run(msp, client, worker, plan, scheduled_for=dt.datetime(2026, 10, 11, 2, tzinfo=UTC)))

    assert str(await _refused(session, Client(msp_id=msp.id, name="twice", tenant_id=tenant))) == "tenant_id: already a client of this MSP"
    assert str(await _refused(session, Connector(msp_id=msp.id, client_id=client.id, worker_id=worker.id, config_json=PROFILE))) == "client_id: already a connector of this Worker"
    assert str(await _refused(session, Worker(msp_id=msp.id, name="k", public_key_pem="x", key_id=worker.key_id, api_token_hash="b" * 64))) == "public_key_pem: already registered"
    assert str(await _refused(session, a_plan(msp, client, connector, sample_mail=101))) == "sample_mail: not 0 to 100"
    assert str(await _refused(session, a_plan(msp, client, connector, sample_sp=-1))) == "sample_sp: not 0 to 100"
    assert str(await _refused(session, a_plan(msp, client, connector, sample_od=101))) == "sample_od: not 0 to 100"
    assert str(await _refused(session, a_plan(msp, client, connector, sample_mail=0, sample_sp=0, sample_od=0))) == "sample sizes: all 0"
    assert str(await _refused(session, a_plan(msp, other_client, connector))) == "connector_id: not the client's connector"
    nobody = Client(id=uuid.uuid4(), msp_id=msp.id, name="x", tenant_id=uuid.uuid4())
    assert str(await _refused(session, a_plan(msp, nobody, connector))) == "client_id: no such client"
    assert str(await _refused(session, Msp(name="m", retention_days=0))) == "retention_days: not positive"
    assert str(await _refused(session, a_run(msp, client, worker, plan, scheduled_for=dt.datetime(2026, 10, 11, 2, tzinfo=UTC)))) == "scheduled_for: a run exists for the period"
    assert str(await _refused(session, Client(msp_id=uuid.uuid4(), name="nobody's", tenant_id=uuid.uuid4()))) == "msp_id: no such MSP"

"""C5.2 (with C5.13's constraints): what the database itself refuses.

Every test runs on the database `alembic upgrade head` built, inside a
transaction that is rolled back. A row the database must refuse is flushed in
a savepoint, and the refusal is held to the constraint that made it.
"""

import datetime as dt
import re
import uuid

import pytest
from sqlalchemy import BigInteger, DateTime, ForeignKeyConstraint, UniqueConstraint, Uuid, text
from sqlalchemy.exc import DBAPIError, IntegrityError, StatementError

from app.models import (
    AuditLog,
    Base,
    Client,
    Connector,
    InstallToken,
    Msp,
    Report,
    TestItem,
    TestPlan,
    TestRun,
    User,
    UtcDateTime,
    Worker,
)

UTC = dt.timezone.utc
TENANT = uuid.UUID("5f0c1d1e-7a11-4c56-9b0e-1c2d3e4f5a6b")
SHA = "ab" * 32
PROFILE = {"format": "restoreproof.client-profile.v1"}


async def add(session, row):
    session.add(row)
    await session.flush()
    return row


async def refused(session, row, constraint: str) -> None:
    """The database refuses `row`, and by `constraint`."""
    with pytest.raises(IntegrityError) as raised:
        async with session.begin_nested():
            session.add(row)
            await session.flush()
    assert f'"{constraint}"' in str(raised.value.orig)


async def new_msp(session, name="msp") -> Msp:
    return await add(session, Msp(name=name))


async def new_client(session, msp, tenant_id=None, name="client") -> Client:
    return await add(
        session, Client(msp_id=msp.id, name=name, tenant_id=tenant_id or uuid.uuid4())
    )


async def new_worker(session, msp, name="worker") -> Worker:
    return await add(
        session,
        Worker(
            msp_id=msp.id,
            name=name,
            public_key_pem="-----BEGIN PUBLIC KEY-----\n",
            key_id=uuid.uuid4().hex * 2,
            api_token_hash=uuid.uuid4().hex,
        ),
    )


def an_install_token(msp, **changes) -> InstallToken:
    values = {
        "msp_id": msp.id,
        "token_hash": uuid.uuid4().hex * 2,
        "expires_at": dt.datetime(2026, 10, 17, tzinfo=UTC),
        "label": "the lab's token",
    }
    return InstallToken(**{**values, **changes})


def a_connector(msp, client, worker, **changes) -> Connector:
    values = {
        "msp_id": msp.id,
        "client_id": client.id,
        "worker_id": worker.id,
        "config_json": PROFILE,
    }
    return Connector(**{**values, **changes})


def a_plan(msp, client, connector, **changes) -> TestPlan:
    values = {
        "msp_id": msp.id,
        "client_id": client.id,
        "connector_id": connector.id,
        "sample_mail": 5,
        "sample_sp": 3,
        "sample_od": 2,
        "cadence_cron": "0 2 * * *",
    }
    return TestPlan(**{**values, **changes})


def a_run(msp, client, worker, plan, **changes) -> TestRun:
    values = {
        "msp_id": msp.id,
        "client_id": client.id,
        "worker_id": worker.id,
        "plan_id": plan.id,
        "connector_id": plan.connector_id,
    }
    return TestRun(**{**values, **changes})


def an_item(msp, run, **changes) -> TestItem:
    values = {
        "msp_id": msp.id,
        "run_id": run.id,
        "position": 0,
        "type": "mail",
        "name": "a subject",
        "expected_kind": "manifest",
    }
    return TestItem(**{**values, **changes})


class World:
    """One MSP with a client, a worker, a connector, a plan and a run."""

    @classmethod
    async def make(cls, session, name="a") -> "World":
        world = cls()
        world.msp = await new_msp(session, name)
        world.client = await new_client(session, world.msp)
        world.worker = await new_worker(session, world.msp)
        world.connector = await add(session, a_connector(world.msp, world.client, world.worker))
        world.plan = await add(session, a_plan(world.msp, world.client, world.connector))
        world.run = await add(session, a_run(world.msp, world.client, world.worker, world.plan))
        world.user = await add(
            session,
            User(msp_id=world.msp.id, email=f"{name}@example.test", password_hash="x", role="admin"),
        )
        return world


# --- The rules every table follows (the metadata, no database) ----------------


def test_every_table_but_msp_has_a_required_msp_id_with_a_key_to_msp():
    for name, table in Base.metadata.tables.items():
        if name == "msp":
            assert "msp_id" not in table.c
            continue
        column = table.c["msp_id"]
        assert column.nullable is False, name
        assert isinstance(column.type, Uuid), name
        assert [key.target_fullname for key in column.foreign_keys if len(key.constraint.columns) == 1] == [
            "msp.id"
        ], name


def test_every_other_foreign_key_is_composite_and_starts_with_msp_id():
    seen = 0
    for name, table in Base.metadata.tables.items():
        for constraint in table.constraints:
            if not isinstance(constraint, ForeignKeyConstraint):
                continue
            if constraint.referred_table.name == "msp":
                continue
            seen += 1
            assert len(constraint.columns) >= 2, (name, constraint.name)
            assert constraint.column_keys[0] == "msp_id", (name, constraint.name)
            assert constraint.elements[0].column.name == "msp_id", (name, constraint.name)
    assert seen == 13


def test_no_foreign_key_cascades_or_sets_null():
    for table in Base.metadata.tables.values():
        for constraint in table.foreign_key_constraints:
            assert constraint.ondelete is None
            assert constraint.onupdate is None


def test_every_primary_key_is_one_uuid_named_id():
    for name, table in Base.metadata.tables.items():
        (key,) = table.primary_key.columns
        assert key.name == "id", name
        assert isinstance(key.type, Uuid), name
        assert key.default is not None and key.server_default is not None, name


def test_every_time_is_a_timestamp_with_time_zone_that_refuses_a_naive_value():
    columns = [column for table in Base.metadata.tables.values() for column in table.columns]
    times = [column for column in columns if isinstance(column.type, UtcDateTime)]

    assert not [column for column in columns if isinstance(column.type, DateTime)]
    assert len(times) == 19
    assert all(column.type.impl.timezone is True for column in times)
    assert {column.name for column in times} >= {"created_at", "last_seen_at", "last_error_at", "expires_at", "at", "tsa_time", "scheduled_for"}


def test_every_table_another_points_at_is_unique_on_msp_id_and_id():
    for table in Base.metadata.tables.values():
        for constraint in table.foreign_key_constraints:
            target = constraint.referred_table
            if target.name == "msp":
                continue
            referred = tuple(element.column.name for element in constraint.elements)
            uniques = {
                tuple(column.name for column in unique.columns)
                for unique in target.constraints
                if unique.__visit_name__ == "unique_constraint"
            }
            assert referred in uniques, (table.name, referred)
            assert referred[:2] == ("msp_id", "id")


# --- Defaults ----------------------------------------------------------------


async def test_an_msp_keeps_three_years_by_default(session):
    msp = await new_msp(session)
    await session.refresh(msp)

    assert msp.retention_days == 1095
    assert isinstance(msp.id, uuid.UUID)
    assert msp.created_at.tzinfo is not None
    assert msp.created_at.utcoffset() == dt.timedelta(0)
    assert abs(dt.datetime.now(UTC) - msp.created_at) < dt.timedelta(minutes=5)


async def test_a_row_inserted_by_hand_gets_its_id_and_defaults_from_the_database(session):
    row = (
        await session.execute(
            text("INSERT INTO msp (name) VALUES ('by hand') RETURNING id, retention_days, created_at")
        )
    ).one()

    assert isinstance(row.id, uuid.UUID)
    assert row.retention_days == 1095
    assert row.created_at.utcoffset() == dt.timedelta(0)


async def test_the_other_defaults(session):
    world = await World.make(session)
    for row in (world.client, world.connector, world.plan, world.run):
        await session.refresh(row)

    assert world.client.screenshots_enabled is False
    assert world.connector.type == "veeam_m365"
    assert world.connector.config_json == PROFILE
    assert world.plan.enabled is True
    assert world.run.state == "queued"
    assert world.run.created_at.utcoffset() == dt.timedelta(0)
    assert (world.run.signature_ok, world.run.tsa_ok, world.run.cleanup_ok) == (None, None, None)
    assert (world.run.bundle_key, world.run.bundle_sha256, world.run.error_code) == (None, None, None)


# --- C5.13: a tenant is unique per MSP ----------------------------------------


async def test_a_second_client_with_the_same_tenant_in_one_msp_is_refused(session):
    msp = await new_msp(session)
    await new_client(session, msp, TENANT, "first")

    await refused(
        session,
        Client(msp_id=msp.id, name="second", tenant_id=TENANT),
        "uq_client_msp_id_tenant_id",
    )


async def test_the_same_tenant_in_another_msp_is_allowed(session):
    first = await new_client(session, await new_msp(session, "a"), TENANT)
    second = await new_client(session, await new_msp(session, "b"), TENANT)

    assert first.tenant_id == second.tenant_id
    assert first.msp_id != second.msp_id


async def test_the_same_tenant_in_the_other_case_is_the_same_tenant(session):
    msp = await new_msp(session)
    await new_client(session, msp, TENANT)

    with pytest.raises(IntegrityError) as raised:
        async with session.begin_nested():
            await session.execute(
                text("INSERT INTO client (msp_id, name, tenant_id) VALUES (:msp, 'upper', :tenant)"),
                {"msp": msp.id, "tenant": uuid.UUID(str(TENANT).upper())},
            )
    assert '"uq_client_msp_id_tenant_id"' in str(raised.value.orig)

    # And as text, the way a hand-written statement would give it.
    with pytest.raises(IntegrityError) as raised:
        async with session.begin_nested():
            await session.execute(
                text(
                    "INSERT INTO client (msp_id, name, tenant_id) "
                    f"VALUES ('{msp.id}', 'upper', '{str(TENANT).upper()}')"
                )
            )
    assert '"uq_client_msp_id_tenant_id"' in str(raised.value.orig)


async def test_a_client_without_a_tenant_is_refused(session):
    msp = await new_msp(session)

    with pytest.raises(IntegrityError) as raised:
        async with session.begin_nested():
            await session.execute(
                text("INSERT INTO client (msp_id, name) VALUES (:msp, 'no tenant')"), {"msp": msp.id}
            )
    assert "tenant_id" in str(raised.value.orig)


async def test_a_tenant_that_is_no_guid_is_refused_by_the_type(session):
    msp = await new_msp(session)

    with pytest.raises(DBAPIError):
        async with session.begin_nested():
            await session.execute(
                text(
                    "INSERT INTO client (msp_id, name, tenant_id) "
                    f"VALUES ('{msp.id}', 'bad', 'contoso.onmicrosoft.com')"
                )
            )


# --- C5.13: a connector is unique per worker and client -----------------------


async def test_a_second_connector_for_one_worker_and_client_is_refused(session):
    world = await World.make(session)

    await refused(
        session,
        a_connector(world.msp, world.client, world.worker, type="other_backup"),
        "uq_connector_worker_id_client_id",
    )


async def test_the_same_client_on_another_worker_is_another_connector(session):
    world = await World.make(session)
    other = await new_worker(session, world.msp, "second worker")

    connector = await add(session, a_connector(world.msp, world.client, other))

    assert connector.id != world.connector.id


@pytest.mark.parametrize(
    "name",
    ["", "Veeam_m365", "veeam-m365", "veeam m365", "veeam.m365", "a" * 65, "veeam_m365\n", "é"],
)
async def test_a_connector_type_outside_the_name_rule_is_refused(session, name):
    msp = await new_msp(session)
    client = await new_client(session, msp)
    worker = await new_worker(session, msp)

    await refused(session, a_connector(msp, client, worker, type=name), "ck_connector_type_name")


@pytest.mark.parametrize("name", ["veeam_m365", "other_backup", "0", "a" * 64, "_"])
async def test_a_connector_type_the_name_rule_takes(session, name):
    msp = await new_msp(session)
    client = await new_client(session, msp)
    worker = await new_worker(session, msp)

    connector = await add(session, a_connector(msp, client, worker, type=name))

    assert connector.type == name


async def test_a_connector_needs_its_profile(session):
    world = await World.make(session)
    other = await new_worker(session, world.msp, "second")

    with pytest.raises(IntegrityError) as raised:
        async with session.begin_nested():
            await session.execute(
                text("INSERT INTO connector (msp_id, client_id, worker_id) VALUES (:m, :c, :w)"),
                {"m": world.msp.id, "c": world.client.id, "w": other.id},
            )
    assert "config_json" in str(raised.value.orig)


# --- No row points at another MSP's row --------------------------------------


async def test_a_connector_cannot_join_one_msp_s_worker_to_another_s_client(session):
    a = await World.make(session, "a")
    b = await World.make(session, "b")

    await refused(
        session, a_connector(a.msp, a.client, b.worker), "fk_connector_msp_id_worker_id_worker"
    )
    await refused(
        session, a_connector(a.msp, b.client, a.worker), "fk_connector_msp_id_client_id_client"
    )
    # Filed under B, with a worker and a client of A's that have no connector
    # yet (or the one-per-pair rule answers first): either key refuses it, and
    # the database names the one it checked first.
    worker = await new_worker(session, a.msp, "second")
    client = await new_client(session, a.msp, name="second")
    with pytest.raises(IntegrityError) as raised:
        async with session.begin_nested():
            session.add(a_connector(b.msp, client, worker))
            await session.flush()
    assert re.search(
        '"fk_connector_msp_id_(worker_id_worker|client_id_client)"', str(raised.value.orig)
    )


async def test_a_plan_cannot_use_another_client_s_connector(session):
    world = await World.make(session)
    other_client = await new_client(session, world.msp, name="other client")

    await refused(
        session,
        a_plan(world.msp, other_client, world.connector),
        "fk_test_plan_msp_id_connector_id_client_id_connector",
    )


async def test_a_plan_cannot_use_another_msp_s_connector(session):
    a = await World.make(session, "a")
    b = await World.make(session, "b")

    await refused(
        session,
        a_plan(a.msp, a.client, b.connector),
        "fk_test_plan_msp_id_connector_id_client_id_connector",
    )


async def test_a_run_cannot_be_filed_under_another_client_than_its_plan_s(session):
    world = await World.make(session)
    other_client = await new_client(session, world.msp, name="other client")

    await refused(
        session,
        a_run(world.msp, other_client, world.worker, world.plan),
        "fk_test_run_msp_id_plan_id_connector_id_client_id_test_plan",
    )


async def test_a_run_cannot_name_a_worker_other_than_its_plan_s_connector_s(session):
    """Finding 3 of the C5.1/C5.2 review: a run's Worker is its plan's
    connector's, not any Worker of the MSP."""
    world = await World.make(session)
    other_worker = await new_worker(session, world.msp, "other worker")

    await refused(
        session,
        a_run(world.msp, world.client, other_worker, world.plan),
        "fk_test_run_msp_id_connector_id_worker_id_connector",
    )


async def test_a_run_cannot_name_another_connector_than_its_plan_s(session):
    world = await World.make(session)
    other_client = await new_client(session, world.msp, name="other client")
    other_connector = await add(session, a_connector(world.msp, other_client, world.worker))

    await refused(
        session,
        a_run(world.msp, world.client, world.worker, world.plan, connector_id=other_connector.id),
        "fk_test_run_msp_id_plan_id_connector_id_client_id_test_plan",
    )


def test_a_run_names_its_connector():
    column = TestRun.__table__.c["connector_id"]

    assert column.nullable is False
    assert isinstance(column.type, Uuid)
    keys = {
        constraint.name
        for constraint in TestRun.__table__.constraints
        if isinstance(constraint, ForeignKeyConstraint)
    }
    assert {
        "fk_test_run_msp_id_connector_id_worker_id_connector",
        "fk_test_run_msp_id_plan_id_connector_id_client_id_test_plan",
    } <= keys
    assert "fk_test_run_msp_id_plan_id_client_id_test_plan" not in keys


async def test_a_run_cannot_name_another_msp_s_worker(session):
    a = await World.make(session, "a")
    b = await World.make(session, "b")

    await refused(
        session, a_run(a.msp, a.client, b.worker, a.plan), "fk_test_run_msp_id_worker_id_worker"
    )


async def test_an_item_a_report_and_an_audit_row_stay_in_their_msp(session):
    a = await World.make(session, "a")
    b = await World.make(session, "b")

    await refused(session, an_item(a.msp, b.run), "fk_test_item_msp_id_run_id_test_run")
    await refused(session, a_report(a.msp, b.client, storage_key="k"), "fk_report_msp_id_client_id_client")
    await refused(
        session,
        AuditLog(msp_id=a.msp.id, user_id=b.user.id, action="connector.create", target="x"),
        "fk_audit_log_msp_id_user_id_user",
    )


async def test_an_msp_id_that_is_no_msp_is_refused(session):
    await refused(
        session,
        Client(msp_id=uuid.uuid4(), name="orphan", tenant_id=TENANT),
        "fk_client_msp_id_msp",
    )


async def test_an_audit_row_needs_no_user(session):
    world = await World.make(session)

    row = await add(
        session, AuditLog(msp_id=world.msp.id, action="plan.create", target=str(world.plan.id))
    )
    await session.refresh(row)

    assert row.user_id is None
    assert row.ip is None
    assert row.at.utcoffset() == dt.timedelta(0)


@pytest.mark.parametrize("ip", ["203.0.113.7", "2001:db8::7"])
async def test_an_audit_row_s_ip_is_read_back_as_the_text_it_was_given(session, ip):
    """The driver's own answer for an `inet` is an `ipaddress` object."""
    world = await World.make(session)

    row = await add(session, AuditLog(msp_id=world.msp.id, action="login", target="-", ip=ip))
    await session.refresh(row)

    assert row.ip == ip
    assert type(row.ip) is str
    kind = await session.execute(text("SELECT pg_typeof(ip)::text FROM audit_log"))
    assert kind.scalar_one() == "inet"


async def test_an_audit_row_s_ip_that_is_no_address_is_refused(session):
    world = await World.make(session)

    with pytest.raises((DBAPIError, StatementError)):
        async with session.begin_nested():
            await add(
                session, AuditLog(msp_id=world.msp.id, action="login", target="-", ip="nowhere")
            )


async def test_nothing_is_deleted_by_deleting_something_else(session):
    world = await World.make(session)
    await add(session, an_item(world.msp, world.run))

    for table, key in (
        ("test_run", world.run.id),
        ("test_plan", world.plan.id),
        ("connector", world.connector.id),
        ("client", world.client.id),
        ("worker", world.worker.id),
        ("msp", world.msp.id),
    ):
        with pytest.raises(IntegrityError) as raised:
            async with session.begin_nested():
                await session.execute(text(f"DELETE FROM {table} WHERE id = :id"), {"id": key})
        # A key that points at this table refused it (several do; the database
        # names the first): by the convention its name ends in the table's.
        assert re.search(f'"fk_[a-z_]+_{table}"', str(raised.value.orig)), table

    count = (await session.execute(text("SELECT count(*) FROM test_item"))).scalar_one()
    assert count == 1


# --- test_run -----------------------------------------------------------------


@pytest.mark.parametrize("state", ["queued", "dispatched", "pass", "fail", "error", "expired"])
async def test_each_state_of_the_list_is_taken(session, state):
    world = await World.make(session)

    run = await add(session, a_run(world.msp, world.client, world.worker, world.plan, state=state))

    assert run.state == state


# `received` (C5.7): the bundle's status is known in the request that receives
# it, so a run goes from dispatched to pass, fail or error and no row is ever
# received; the word is not in the list.
@pytest.mark.parametrize("state", ["", "passed", "Pass", "PASS", "running", "pass ", "error\n", "received"])
async def test_a_state_outside_the_list_is_refused(session, state):
    world = await World.make(session)

    await refused(
        session,
        a_run(world.msp, world.client, world.worker, world.plan, state=state),
        "ck_test_run_state",
    )


@pytest.mark.parametrize(
    "sha",
    ["AB" * 32, "ab" * 31, "ab" * 33, "ab" * 31 + "zz", "", "ab" * 31 + "a\n", " " + "ab" * 31 + "a"],
)
async def test_a_bundle_hash_is_64_lower_case_hex_digits(session, sha):
    world = await World.make(session)

    await refused(
        session,
        a_run(world.msp, world.client, world.worker, world.plan, bundle_sha256=sha),
        "ck_test_run_bundle_sha256_hex",
    )


async def test_a_run_s_later_columns(session):
    world = await World.make(session)
    eastern = dt.timezone(dt.timedelta(hours=5))
    started = dt.datetime(2026, 10, 10, 7, 0, 0, tzinfo=eastern)

    run = await add(
        session,
        a_run(
            world.msp,
            world.client,
            world.worker,
            world.plan,
            state="pass",
            restore_point_at=started,
            started_at=started,
            finished_at=started + dt.timedelta(minutes=4),
            total_ms=240_000,
            bundle_key=f"msp/{world.msp.id}/runs/x/result.json",
            bundle_sha256=SHA,
            signature_ok=True,
            tsa_ok=False,
            tsa_time=started + dt.timedelta(minutes=5),
            cleanup_ok=True,
        ),
    )
    await session.refresh(run)

    # The same moment, back in UTC.
    assert run.started_at == started
    assert run.started_at.utcoffset() == dt.timedelta(0)
    assert run.started_at.hour == 2
    assert (run.signature_ok, run.tsa_ok, run.cleanup_ok) == (True, False, True)
    assert run.total_ms == 240_000
    # C5.7: the token's own time, beside whether it verified.
    assert run.tsa_time == started + dt.timedelta(minutes=5)
    assert run.tsa_time.utcoffset() == dt.timedelta(0)


async def test_a_run_s_tsa_time_is_null_until_a_token_verified(session):
    world = await World.make(session)

    await session.refresh(world.run)

    assert (world.run.tsa_ok, world.run.tsa_time) == (None, None)


async def test_a_time_without_a_zone_is_refused_before_the_driver_sees_it(session):
    """asyncpg would take it as this machine's local time."""
    world = await World.make(session)

    with pytest.raises(StatementError) as raised:
        async with session.begin_nested():
            session.add(
                a_run(
                    world.msp,
                    world.client,
                    world.worker,
                    world.plan,
                    started_at=dt.datetime(2026, 10, 10, 7, 0, 0),
                )
            )
            await session.flush()
    assert isinstance(raised.value.orig, ValueError)
    assert "a time without a zone" in str(raised.value.orig)

    count = (await session.execute(text("SELECT count(*) FROM test_run"))).scalar_one()
    assert count == 1


async def test_a_negative_duration_is_refused(session):
    world = await World.make(session)

    await refused(
        session,
        a_run(world.msp, world.client, world.worker, world.plan, total_ms=-1),
        "ck_test_run_total_ms_not_negative",
    )
    await refused(session, an_item(world.msp, world.run, ms=-1), "ck_test_item_ms_not_negative")


# --- test_plan ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("sample_mail", -1),
        ("sample_mail", 101),
        ("sample_sp", -1),
        ("sample_sp", 101),
        ("sample_od", -1),
        ("sample_od", 101),
    ],
)
async def test_a_sample_size_outside_0_to_100_is_refused(session, column, value):
    world = await World.make(session)
    other = await new_worker(session, world.msp, "second")
    connector = await add(session, a_connector(world.msp, world.client, other))

    await refused(
        session,
        a_plan(world.msp, world.client, connector, **{column: value}),
        f"ck_test_plan_{column}_range",
    )


async def test_a_plan_that_samples_nothing_is_refused(session):
    world = await World.make(session)

    await refused(
        session,
        a_plan(world.msp, world.client, world.connector, sample_mail=0, sample_sp=0, sample_od=0),
        "ck_test_plan_sample_not_empty",
    )


@pytest.mark.parametrize("sizes", [(100, 100, 100), (1, 0, 0), (0, 1, 0), (0, 0, 1)])
async def test_the_sample_sizes_a_job_may_have(session, sizes):
    world = await World.make(session)

    plan = await add(
        session,
        a_plan(
            world.msp,
            world.client,
            world.connector,
            sample_mail=sizes[0],
            sample_sp=sizes[1],
            sample_od=sizes[2],
        ),
    )

    assert (plan.sample_mail, plan.sample_sp, plan.sample_od) == sizes


# --- test_item, report, msp ---------------------------------------------------


async def test_an_item_as_a_result_gives_it(session):
    world = await World.make(session)

    item = await add(
        session,
        an_item(
            world.msp,
            world.run,
            type="sharepoint",
            name="Budget.xlsx",
            expected_kind="manifest",
            expected_sha256=SHA,
            found_sha256=SHA,
            found=True,
            match=True,
            ms=412,
        ),
    )
    unchecked = await add(session, an_item(world.msp, world.run, reason="graph_transient"))
    await session.refresh(unchecked)

    assert (item.found, item.match, item.ms) == (True, True, 412)
    # Not known is null, never false.
    assert (unchecked.found, unchecked.match, unchecked.ms) == (None, None, None)
    assert (unchecked.expected_sha256, unchecked.found_sha256) == (None, None)


async def test_an_item_has_its_position_in_the_result(session):
    """C5.7: the result's `index`, so the rows join to the stored result and
    to items.csv; no unique, since the schema can't hold `index` to its
    position and the Cloud files what the signed result says."""
    world = await World.make(session)

    first = await add(session, an_item(world.msp, world.run, position=0))
    again = await add(session, an_item(world.msp, world.run, position=0, name="another"))
    last = await add(session, an_item(world.msp, world.run, position=2_147_483_647))

    assert (first.position, again.position, last.position) == (0, 0, 2_147_483_647)


async def test_an_item_without_a_position_is_refused(session):
    world = await World.make(session)

    with pytest.raises(IntegrityError) as raised:
        async with session.begin_nested():
            session.add(an_item(world.msp, world.run, position=None))
            await session.flush()
    assert '"position"' in str(raised.value.orig) and "not-null" in str(raised.value.orig)


async def test_a_negative_position_is_refused(session):
    world = await World.make(session)

    await refused(session, an_item(world.msp, world.run, position=-1), "ck_test_item_position_not_negative")


@pytest.mark.parametrize("column", ["expected_sha256", "found_sha256"])
async def test_an_item_s_hash_is_64_lower_case_hex_digits(session, column):
    world = await World.make(session)

    await refused(
        session, an_item(world.msp, world.run, **{column: "AB" * 32}), f"ck_test_item_{column}_hex"
    )
    await refused(
        session, an_item(world.msp, world.run, **{column: "ab" * 31}), f"ck_test_item_{column}_hex"
    )


def a_report(msp, client, **changes) -> Report:
    """C6.4 (docs/decisions.md 2026-10-12, "C6.4", point 1): a final report of
    September with both hashes."""
    values = {
        "msp_id": msp.id,
        "client_id": client.id,
        "period_start": dt.date(2026, 9, 1),
        "period_end": dt.date(2026, 9, 30),
        "storage_key": f"msp/{msp.id}/reports/{client.id}/2026-09.pdf",
        "content_sha256": SHA,
        "file_sha256": "cd" * 32,
        "interim": False,
        "generated_at": dt.datetime(2026, 10, 1, 3, 0, tzinfo=UTC),
    }
    return Report(**{**values, **changes})


@pytest.mark.parametrize("column", ["content_sha256", "file_sha256"])
async def test_a_report_s_two_hashes_are_64_lower_case_hex_digits_each(session, column):
    world = await World.make(session)

    await refused(session, a_report(world.msp, world.client, **{column: "AB" * 32}), f"ck_report_{column}_hex")
    kept = await add(session, a_report(world.msp, world.client))
    await session.refresh(kept)

    assert (kept.content_sha256, kept.file_sha256, kept.interim) == (SHA, "cd" * 32, False)
    assert kept.period_start == dt.date(2026, 9, 1)
    assert kept.generated_at == dt.datetime(2026, 10, 1, 3, 0, tzinfo=UTC)


async def test_a_report_has_no_sha256_column_and_says_whether_it_is_interim(session):
    """`sha256` is gone (point 1); `interim` and `generated_at` are given,
    never defaulted."""
    columns = Report.__table__.c

    assert "sha256" not in columns
    assert columns["interim"].nullable is False and columns["interim"].server_default is None
    assert columns["generated_at"].nullable is False and columns["generated_at"].server_default is None
    world = await World.make(session)
    with pytest.raises(IntegrityError, match="interim"):
        async with session.begin_nested():
            session.add(a_report(world.msp, world.client, interim=None))
            await session.flush()


async def test_a_period_ends_on_or_after_its_start(session):
    world = await World.make(session)

    await refused(session, a_report(world.msp, world.client, period_end=dt.date(2026, 8, 31)), "ck_report_period_order")
    await add(session, a_report(world.msp, world.client, period_end=dt.date(2026, 9, 1)))


async def test_a_period_has_one_final_report_and_any_number_of_interim_ones(session):
    """`uq_report_final_period`: a partial unique on (msp_id, client_id,
    period_start) where not interim. The same period in the other MSP is its
    own; another period of the client is another report."""
    a = await World.make(session, "a")
    b = await World.make(session, "b")
    await add(session, a_report(a.msp, a.client))

    await refused(session, a_report(a.msp, a.client, storage_key="again"), "uq_report_final_period")
    await add(session, a_report(a.msp, a.client, interim=True, storage_key="interim-1"))
    await add(session, a_report(a.msp, a.client, interim=True, storage_key="interim-2"))
    await add(session, a_report(b.msp, b.client))
    await add(session, a_report(a.msp, a.client, period_start=dt.date(2026, 10, 1), period_end=dt.date(2026, 10, 31), storage_key="october"))


async def test_a_storage_key_is_written_once(session):
    world = await World.make(session)
    await add(session, a_report(world.msp, world.client, interim=True))

    await refused(session, a_report(world.msp, world.client, interim=True), "uq_report_storage_key")


@pytest.mark.parametrize("days", [0, -1])
async def test_a_retention_of_no_days_is_refused(session, days):
    await refused(session, Msp(name="short", retention_days=days), "ck_msp_retention_days_positive")


# --- The lookups that come before an MSP is known ------------------------------


async def test_a_worker_s_token_hash_is_unique_across_msps(session):
    a = await World.make(session, "a")
    b = await World.make(session, "b")

    await refused(
        session,
        Worker(
            msp_id=b.msp.id,
            name="copy",
            public_key_pem="-----BEGIN PUBLIC KEY-----\n",
            key_id="d" * 64,
            api_token_hash=a.worker.api_token_hash,
        ),
        "uq_worker_api_token_hash",
    )


async def test_an_install_token_s_hash_is_unique_across_msps(session):
    a = await new_msp(session, "a")
    b = await new_msp(session, "b")
    expires = dt.datetime(2026, 10, 17, tzinfo=UTC)
    token = await add(session, an_install_token(a, token_hash="h" * 64, expires_at=expires))
    await session.refresh(token)

    assert token.used_at is None
    await refused(
        session,
        an_install_token(b, token_hash="h" * 64, expires_at=expires),
        "uq_install_token_token_hash",
    )


async def test_an_email_is_unique_without_regard_to_case_across_msps(session):
    a = await World.make(session, "a")
    b = await new_msp(session, "b")

    await refused(
        session,
        User(msp_id=b.id, email="A@Example.TEST", password_hash="x", role="admin"),
        "uq_user_email_lower",
    )
    assert a.user.email == "a@example.test"


# --- C6.1: the user's role and times; C6.2: the run's recovery time ------------------------


@pytest.mark.parametrize("role", ["owner", "Admin", "", "member "])
async def test_a_role_outside_admin_and_member_is_refused(session, role):
    msp = await new_msp(session)

    await refused(session, User(msp_id=msp.id, email=f"{uuid.uuid4()}@example.test", password_hash="x", role=role), "ck_user_role")


@pytest.mark.parametrize("role", ["admin", "member"])
async def test_a_user_has_the_two_times_from_the_database_s_clock(session, role):
    msp = await new_msp(session)
    user = await add(session, User(msp_id=msp.id, email=f"{uuid.uuid4()}@example.test", password_hash="x", role=role))
    await session.refresh(user)

    assert user.password_changed_at.utcoffset() == dt.timedelta(0)
    assert user.created_at == user.password_changed_at
    assert abs(dt.datetime.now(UTC) - user.created_at) < dt.timedelta(minutes=5)


def test_the_user_s_two_times_are_required_and_the_run_s_recovery_time_is_a_bigint():
    user = User.__table__.c
    run = TestRun.__table__.c

    assert isinstance(user["password_changed_at"].type, UtcDateTime) and not user["password_changed_at"].nullable
    assert isinstance(user["created_at"].type, UtcDateTime) and not user["created_at"].nullable
    assert isinstance(run["recovery_ms"].type, BigInteger) and run["recovery_ms"].nullable


async def test_a_negative_recovery_time_is_refused_and_a_zero_one_taken(session):
    world = await World.make(session)

    await refused(session, a_run(world.msp, world.client, world.worker, world.plan, recovery_ms=-1), "ck_test_run_recovery_ms_not_negative")
    run = await add(session, a_run(world.msp, world.client, world.worker, world.plan, recovery_ms=0))
    await session.refresh(run)
    assert run.recovery_ms == 0


# --- C5.5: the key and the install token ----------------------------------------


async def test_a_worker_s_key_id_is_unique_across_msps(session):
    a = await new_msp(session, "a")
    b = await new_msp(session, "b")
    key_id = "c" * 64
    first = await add(
        session,
        Worker(msp_id=a.id, name="first", public_key_pem="x", key_id=key_id, api_token_hash="1" * 64),
    )

    assert first.key_id == key_id
    await refused(
        session,
        Worker(msp_id=b.id, name="second", public_key_pem="x", key_id=key_id, api_token_hash="2" * 64),
        "uq_worker_key_id",
    )


@pytest.mark.parametrize("key_id", ["C" * 64, "c" * 63, "c" * 65, "", "c" * 63 + "\n", "g" * 64])
async def test_a_key_id_is_64_lower_case_hex_digits(session, key_id):
    msp = await new_msp(session)

    await refused(
        session,
        Worker(msp_id=msp.id, name="w", public_key_pem="x", key_id=key_id, api_token_hash="1" * 64),
        "ck_worker_key_id_hex",
    )


async def test_a_worker_without_a_key_id_is_refused(session):
    msp = await new_msp(session)

    with pytest.raises(IntegrityError) as raised:
        async with session.begin_nested():
            await session.execute(
                text(
                    "INSERT INTO worker (msp_id, name, public_key_pem, api_token_hash) "
                    "VALUES (:m, 'w', 'x', :h)"
                ),
                {"m": msp.id, "h": "1" * 64},
            )
    assert "key_id" in str(raised.value.orig)


async def test_a_worker_may_name_the_install_token_that_made_it_but_only_its_msp_s(session):
    a = await new_msp(session, "a")
    b = await new_msp(session, "b")
    own = await add(session, an_install_token(a))
    other = await add(session, an_install_token(b))

    worker = await add(
        session,
        Worker(
            msp_id=a.id, name="w", public_key_pem="x", key_id="a" * 64, api_token_hash="1" * 64,
            install_token_id=own.id,
        ),
    )
    await session.refresh(worker)

    assert worker.install_token_id == own.id
    await refused(
        session,
        Worker(
            msp_id=a.id, name="w2", public_key_pem="x", key_id="b" * 64, api_token_hash="2" * 64,
            install_token_id=other.id,
        ),
        "fk_worker_msp_id_install_token_id_install_token",
    )
    assert (await new_worker(session, a, "no token")).install_token_id is None


async def test_an_install_token_has_a_label_a_creation_time_and_maybe_its_maker(session):
    world = await World.make(session, "a")
    b = await World.make(session, "b")

    token = await add(session, an_install_token(world.msp, label="the lab", created_by=world.user.id))
    await session.refresh(token)
    assert (token.label, token.created_by) == ("the lab", world.user.id)
    assert token.created_at.utcoffset() == dt.timedelta(0)
    assert abs(dt.datetime.now(UTC) - token.created_at) < dt.timedelta(minutes=5)

    unmade = await add(session, an_install_token(world.msp, label=""))
    await session.refresh(unmade)
    assert unmade.created_by is None

    await refused(
        session,
        an_install_token(world.msp, created_by=b.user.id),
        "fk_install_token_msp_id_created_by_user",
    )
    with pytest.raises(IntegrityError) as raised:
        async with session.begin_nested():
            await session.execute(
                text("INSERT INTO install_token (msp_id, token_hash, expires_at) VALUES (:m, :h, now())"),
                {"m": world.msp.id, "h": "9" * 64},
            )
    assert "label" in str(raised.value.orig)

# --- C5.6: dispatch -------------------------------------------------------------------


async def test_a_run_starts_never_dispatched_with_no_attempt(session):
    world = await World.make(session)
    await session.refresh(world.run)

    assert (world.run.dispatched_at, world.run.attempt) == (None, 0)


async def test_a_dispatched_run_carries_its_time_and_its_count(session):
    world = await World.make(session)
    at = dt.datetime(2026, 10, 10, 12, 0, tzinfo=UTC)

    run = await add(
        session,
        a_run(world.msp, world.client, world.worker, world.plan, state="dispatched", dispatched_at=at, attempt=3),
    )
    await session.refresh(run)

    assert (run.state, run.dispatched_at, run.attempt) == ("dispatched", at, 3)


async def test_a_negative_attempt_is_refused(session):
    world = await World.make(session)

    await refused(
        session,
        a_run(world.msp, world.client, world.worker, world.plan, attempt=-1),
        "ck_test_run_attempt_not_negative",
    )


def test_the_poll_s_index_starts_with_the_tenant():
    indexes = {index.name: [column.name for column in index.columns] for index in TestRun.__table__.indexes}

    assert indexes["ix_test_run_msp_id_worker_id_state_created_at"] == ["msp_id", "worker_id", "state", "created_at"]
    assert indexes["ix_test_run_msp_id_client_id_created_at"] == ["msp_id", "client_id", "created_at"]
    assert all(columns[0] == "msp_id" for columns in indexes.values())


# --- C5.8: the heartbeat's columns ------------------------------------------------------------


def test_the_worker_holds_the_heartbeat_s_three_new_columns():
    columns = Worker.__table__.columns

    assert isinstance(columns["last_error_at"].type, UtcDateTime) and columns["last_error_at"].nullable
    assert isinstance(columns["outbox_depth"].type, BigInteger) and columns["outbox_depth"].nullable
    assert isinstance(columns["uptime_s"].type, BigInteger) and columns["uptime_s"].nullable
    assert all(columns[name].server_default is None for name in ("last_error_at", "outbox_depth", "uptime_s"))


async def test_a_worker_s_heartbeat_columns_are_null_until_a_heartbeat(session):
    msp = await new_msp(session)

    worker = await new_worker(session, msp)
    await session.refresh(worker)

    assert (worker.last_seen_at, worker.last_error, worker.last_error_at) == (None, None, None)
    assert (worker.outbox_depth, worker.uptime_s) == (None, None)


async def test_a_worker_s_heartbeat_columns_take_the_worker_s_values(session):
    msp = await new_msp(session)
    at = dt.datetime(2026, 10, 9, 20, 27, 38, 206000, tzinfo=UTC)

    worker = await add(
        session,
        Worker(
            msp_id=msp.id,
            name="w",
            public_key_pem="x",
            key_id="3" * 64,
            api_token_hash="4" * 64,
            last_error="job_invalid",
            last_error_at=at,
            outbox_depth=2**53 - 1,
            uptime_s=152,
        ),
    )
    await session.refresh(worker)

    assert (worker.last_error, worker.last_error_at, worker.outbox_depth, worker.uptime_s) == ("job_invalid", at, 2**53 - 1, 152)


@pytest.mark.parametrize("column", ["outbox_depth", "uptime_s"])
async def test_a_negative_heartbeat_count_is_refused(session, column):
    msp = await new_msp(session)

    await refused(
        session,
        Worker(msp_id=msp.id, name="w", public_key_pem="x", key_id="5" * 64, api_token_hash="6" * 64, **{column: -1}),
        f"ck_worker_{column}_not_negative",
    )


async def test_a_naive_last_error_at_is_refused_before_the_driver(session):
    msp = await new_msp(session)

    with pytest.raises(StatementError, match="a time without a zone"):
        async with session.begin_nested():
            session.add(
                Worker(
                    msp_id=msp.id,
                    name="w",
                    public_key_pem="x",
                    key_id="7" * 64,
                    api_token_hash="8" * 64,
                    last_error_at=dt.datetime(2026, 10, 9, 20, 27, 38),
                )
            )
            await session.flush()


# --- C5.9: the period a scheduled run is for, and when a plan was made ---------------------


def test_a_run_holds_the_period_it_is_for_and_a_plan_when_it_was_made():
    """docs/decisions.md 2026-10-11, "C5.10 and C5.9", point 8."""
    run_columns = TestRun.__table__.columns
    plan_columns = TestPlan.__table__.columns

    assert isinstance(run_columns["scheduled_for"].type, UtcDateTime) and run_columns["scheduled_for"].nullable
    assert run_columns["scheduled_for"].server_default is None
    assert isinstance(plan_columns["created_at"].type, UtcDateTime) and not plan_columns["created_at"].nullable
    assert plan_columns["created_at"].server_default is not None
    uniques = {
        constraint.name: [column.name for column in constraint.columns]
        for constraint in TestRun.__table__.constraints
        if isinstance(constraint, UniqueConstraint)
    }
    assert uniques["uq_test_run_msp_id_plan_id_scheduled_for"] == ["msp_id", "plan_id", "scheduled_for"]


async def test_a_second_run_of_one_plan_and_period_is_refused(session):
    world = await World.make(session)
    period = dt.datetime(2026, 10, 11, 2, 0, tzinfo=UTC)
    await add(session, a_run(world.msp, world.client, world.worker, world.plan, scheduled_for=period))

    await refused(
        session,
        a_run(world.msp, world.client, world.worker, world.plan, scheduled_for=period),
        "uq_test_run_msp_id_plan_id_scheduled_for",
    )


async def test_another_period_another_plan_or_no_period_is_taken(session):
    world = await World.make(session)
    period = dt.datetime(2026, 10, 11, 2, 0, tzinfo=UTC)
    other_plan = await add(session, a_plan(world.msp, world.client, world.connector, cadence_cron="0 3 * * *"))
    await add(session, a_run(world.msp, world.client, world.worker, world.plan, scheduled_for=period))

    await add(session, a_run(world.msp, world.client, world.worker, world.plan, scheduled_for=period + dt.timedelta(days=1)))
    await add(session, a_run(world.msp, world.client, world.worker, other_plan, scheduled_for=period))
    # Two runs made by hand: nulls are distinct, so the unique is the period rule alone.
    await add(session, a_run(world.msp, world.client, world.worker, world.plan))
    await add(session, a_run(world.msp, world.client, world.worker, world.plan))


async def test_a_plan_s_created_at_is_the_database_s_now(session):
    world = await World.make(session)
    await session.refresh(world.plan)
    (now,) = (await session.execute(text("SELECT now()"))).one()

    assert world.plan.created_at == now
    assert world.plan.created_at.tzinfo is not None

"""C5.2 (with C5.13's constraints): what the database itself refuses.

Every test runs on the database `alembic upgrade head` built, inside a
transaction that is rolled back. A row the database must refuse is flushed in
a savepoint, and the refusal is held to the constraint that made it.
"""

import datetime as dt
import uuid

import pytest
from sqlalchemy import DateTime, ForeignKeyConstraint, Uuid, text
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
            api_token_hash=uuid.uuid4().hex,
        ),
    )


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
    }
    return TestRun(**{**values, **changes})


def an_item(msp, run, **changes) -> TestItem:
    values = {
        "msp_id": msp.id,
        "run_id": run.id,
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
    assert seen == 10


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
    assert len(times) == 11
    assert all(column.type.impl.timezone is True for column in times)
    assert {column.name for column in times} >= {"created_at", "last_seen_at", "expires_at", "at"}


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
    with pytest.raises(IntegrityError):
        async with session.begin_nested():
            await session.execute(
                text(
                    "INSERT INTO client (msp_id, name, tenant_id) "
                    f"VALUES ('{msp.id}', 'upper', '{str(TENANT).upper()}')"
                )
            )


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
    # Filed under B, with A's worker and client: both keys refuse it.
    with pytest.raises(IntegrityError):
        async with session.begin_nested():
            session.add(a_connector(b.msp, a.client, a.worker))
            await session.flush()


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
        "fk_test_run_msp_id_plan_id_client_id_test_plan",
    )


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
    await refused(
        session,
        Report(
            msp_id=a.msp.id,
            client_id=b.client.id,
            period_start=dt.date(2026, 9, 1),
            period_end=dt.date(2026, 9, 30),
            storage_key="k",
            sha256=SHA,
        ),
        "fk_report_msp_id_client_id_client",
    )
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
        with pytest.raises(IntegrityError):
            async with session.begin_nested():
                await session.execute(text(f"DELETE FROM {table} WHERE id = :id"), {"id": key})

    count = (await session.execute(text("SELECT count(*) FROM test_item"))).scalar_one()
    assert count == 1


# --- test_run -----------------------------------------------------------------


@pytest.mark.parametrize(
    "state", ["queued", "dispatched", "received", "pass", "fail", "error", "expired"]
)
async def test_each_state_of_the_list_is_taken(session, state):
    world = await World.make(session)

    run = await add(session, a_run(world.msp, world.client, world.worker, world.plan, state=state))

    assert run.state == state


@pytest.mark.parametrize("state", ["", "passed", "Pass", "PASS", "running", "pass ", "error\n"])
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


@pytest.mark.parametrize("column", ["expected_sha256", "found_sha256"])
async def test_an_item_s_hash_is_64_lower_case_hex_digits(session, column):
    world = await World.make(session)

    await refused(
        session, an_item(world.msp, world.run, **{column: "AB" * 32}), f"ck_test_item_{column}_hex"
    )
    await refused(
        session, an_item(world.msp, world.run, **{column: "ab" * 31}), f"ck_test_item_{column}_hex"
    )


async def test_a_report_s_hash_is_64_lower_case_hex_digits(session):
    world = await World.make(session)

    def report(sha: str) -> Report:
        return Report(
            msp_id=world.msp.id,
            client_id=world.client.id,
            period_start=dt.date(2026, 9, 1),
            period_end=dt.date(2026, 9, 30),
            storage_key="reports/2026-09.pdf",
            sha256=sha,
        )

    await refused(session, report("AB" * 32), "ck_report_sha256_hex")
    kept = await add(session, report(SHA))
    await session.refresh(kept)

    assert kept.period_start == dt.date(2026, 9, 1)
    assert kept.generated_at.utcoffset() == dt.timedelta(0)


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
            api_token_hash=a.worker.api_token_hash,
        ),
        "uq_worker_api_token_hash",
    )


async def test_an_install_token_s_hash_is_unique_across_msps(session):
    a = await new_msp(session, "a")
    b = await new_msp(session, "b")
    expires = dt.datetime(2026, 10, 17, tzinfo=UTC)
    token = await add(session, InstallToken(msp_id=a.id, token_hash="h" * 64, expires_at=expires))
    await session.refresh(token)

    assert token.used_at is None
    await refused(
        session,
        InstallToken(msp_id=b.id, token_hash="h" * 64, expires_at=expires),
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

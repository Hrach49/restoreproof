"""C5.10's Done-when by name, and the Typer layer of `cloud/manage.py`
(docs/decisions.md 2026-10-11, "C5.10 and C5.9", points 1 to 4 and 11): the
commands run through `typer.testing.CliRunner` in a thread (a command's
`asyncio.run` can't share the test loop), against a migrated database of the
test's own, since a command commits.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import json
import re
import sys
import time
import uuid
from pathlib import Path

import httpx
import pytest
import typer
from botocore.stub import ANY, Stubber
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from typer.testing import CliRunner

from app.auth.tokens import token_hash
from app.db import make_session_factory
from app.main import create_app
from app.repo.audit import AuditRepo
from app.repo.clients import ClientRepo
from app.repo.connectors import ConnectorRepo
from app.repo.items import ItemRepo
from app.repo.lookup import Lookup
from app.repo.msps import MspRepo
from app.repo.plans import PlanRepo
from app.repo.reports import ReportRepo
from app.repo.runs import RunRepo
from app.repo.users import UserRepo
from app.repo.workers import WorkerRepo
from app.storage import Storage, make_s3_client
from tests.conftest import make_settings
from tests.test_registration import KEY, KEY_ID
from tests.test_repo_connectors import VALID_PROFILE

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import manage  # noqa: E402

TOKEN_SHAPE = re.compile(r"^[A-Za-z0-9_-]{43}$")
LINE = re.compile(r"^[a-z0-9_]+ \S+$")
runner = CliRunner()


async def cli(*args: str):
    """One command, as a person types it, in a thread of its own."""
    return await asyncio.to_thread(runner.invoke, manage.app, list(args))


def lines(result) -> dict[str, str]:
    out = result.stdout.splitlines()
    assert all(LINE.match(line) for line in out), out
    return dict(line.split(" ", 1) for line in out)


@pytest.fixture
def database(own_database, monkeypatch):
    """The CLI's database for the test: the test's own, through the
    environment as a deployment gives it."""
    monkeypatch.setenv("DATABASE_URL", own_database)
    return own_database


@pytest.fixture
async def rows(database):
    """The rows the CLI made, read back through the repos."""
    engine = create_async_engine(database, connect_args={"server_settings": {"timezone": "UTC"}})

    class Rows:
        def __init__(self):
            self.factory = make_session_factory(engine)

        async def read(self, work):
            async with self.factory() as session, session.begin():
                return await work(session)

    try:
        yield Rows()
    finally:
        await engine.dispose()


@pytest.fixture
def profile_file(tmp_path):
    def write(tenant_id: uuid.UUID, name: str = "profile.json") -> Path:
        path = tmp_path / name
        path.write_text(json.dumps({**VALID_PROFILE, "graph_tenant_id": str(tenant_id)}), encoding="utf-8")
        return path

    return write


async def register(database: str, install_token: str) -> dict:
    """The Worker's registration through the app, as W5.1 will do it, against
    the same database (the real `get_session`, so the rows are committed)."""
    engine = create_async_engine(database, connect_args={"server_settings": {"timezone": "UTC"}})
    application = create_app(make_settings(DATABASE_URL=database))
    application.state.session_factory = make_session_factory(engine)
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=application), base_url="http://test") as client:
            response = await client.post(
                "/v1/workers/register",
                json={"install_token": install_token, "public_key_pem": KEY, "worker_name": "veeam-vm", "version": "0.0.0"},
            )
    finally:
        await engine.dispose()
    assert response.status_code == 201, response.text
    return response.json()


# --- The Done-when, by name --------------------------------------------------------------------


async def test_a_new_msp_with_one_client_and_plan_is_created_in_under_5_minutes_by_cli(database, rows, profile_file):
    tenant = uuid.uuid4()
    started = time.perf_counter()

    msp = lines(await cli("create-msp", "--name", "Contoso MSP"))
    client = lines(await cli("create-client", "--msp-id", msp["msp_id"], "--name", "Fabrikam", "--tenant-id", str(tenant)))
    token = await cli("create-worker-token", "--msp-id", msp["msp_id"], "--label", "veeam-vm")
    registered = await register(database, lines(token)["install_token"])
    connector = lines(await cli(
        "create-connector", "--msp-id", msp["msp_id"], "--client-id", client["client_id"],
        "--worker-id", registered["worker_id"], "--profile-file", str(profile_file(tenant)),
    ))
    plan = lines(await cli(
        "create-plan", "--msp-id", msp["msp_id"], "--client-id", client["client_id"],
        "--connector-id", connector["connector_id"], "--mail", "10", "--sp", "10", "--od", "10",
    ))
    revoked = lines(await cli("revoke-worker", "--msp-id", msp["msp_id"], "--worker-id", registered["worker_id"]))
    elapsed = time.perf_counter() - started

    assert elapsed < 300, elapsed
    msp_id = uuid.UUID(msp["msp_id"])
    assert set(msp) == {"msp_id"} and set(client) == {"client_id"} and set(connector) == {"connector_id"} and set(plan) == {"plan_id"}
    assert set(lines(token)) == {"install_token_id", "expires_at", "install_token"}
    assert TOKEN_SHAPE.match(lines(token)["install_token"])
    assert token.stderr.strip() == manage.onboarding.SHOWN_ONCE
    assert registered["key_id"] == KEY_ID
    assert set(revoked) == {"revoked_at"}

    async def read(session):
        return (
            await MspRepo(session).get(msp_id),
            await ClientRepo(session).get(msp_id, uuid.UUID(client["client_id"])),
            await WorkerRepo(session).get(msp_id, uuid.UUID(registered["worker_id"])),
            await ConnectorRepo(session).get(msp_id, uuid.UUID(connector["connector_id"])),
            await PlanRepo(session).get(msp_id, uuid.UUID(plan["plan_id"])),
            await RunRepo(session).list(msp_id),
            sorted(row.action for row in await AuditRepo(session).list(msp_id)),
            await Lookup(session).find_install_token_by_hash(token_hash(lines(token)["install_token"])),
        )

    msp_row, client_row, worker_row, connector_row, plan_row, runs, actions, token_row = await rows.read(read)
    assert msp_row.name == "Contoso MSP"
    assert (client_row.name, client_row.tenant_id) == ("Fabrikam", tenant)
    assert worker_row.revoked_at is not None and worker_row.key_id == KEY_ID
    assert (connector_row.client_id, connector_row.worker_id) == (client_row.id, worker_row.id)
    assert (plan_row.sample_mail, plan_row.cadence_cron, plan_row.enabled) == (10, "0 2 * * *", True)
    assert runs == []
    assert actions == ["client.create", "connector.create", "install_token.create", "msp.create", "plan.create", "worker.register", "worker.revoke"]
    assert token_row.used_at is not None and token_row.label == "veeam-vm"
    print(f"\nthe six commands took {elapsed:.1f} s")


# --- Failure paths ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("environment", "line"),
    [
        (None, "settings error: DATABASE_URL is missing"),
        ("", "settings error: DATABASE_URL is missing"),
        ("postgresql://not-async", "settings error: DATABASE_URL is not valid"),
    ],
)
async def test_without_a_database_url_the_command_stops_naming_the_variable(monkeypatch, environment, line):
    if environment is None:
        monkeypatch.delenv("DATABASE_URL", raising=False)
    else:
        monkeypatch.setenv("DATABASE_URL", environment)

    result = await cli("create-msp", "--name", "x")

    assert (result.exit_code, result.stdout, result.stderr.strip()) == (1, "", line)


async def test_a_database_that_cannot_be_reached_is_one_line_without_the_driver_s_text(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://Sentinel-User:Sentinel-Password@127.0.0.1:1/none")

    result = await cli("create-msp", "--name", "x")

    assert (result.exit_code, result.stdout, result.stderr.strip()) == (1, "", "database: unreachable")
    assert "Sentinel" not in result.stderr and "127.0.0.1" not in result.stderr


async def test_a_refusal_is_one_line_on_stderr_exit_1_and_nothing_committed(database, rows):
    msp = lines(await cli("create-msp", "--name", "a"))
    tenant = uuid.uuid4()
    await cli("create-client", "--msp-id", msp["msp_id"], "--name", "first", "--tenant-id", str(tenant))

    result = await cli("create-client", "--msp-id", msp["msp_id"], "--name", "second", "--tenant-id", str(tenant).upper())

    assert (result.exit_code, result.stdout, result.stderr.strip()) == (1, "", "tenant_id: already a client of this MSP")
    assert str(tenant) not in result.stderr.lower()
    clients = await rows.read(lambda s: ClientRepo(s).list(uuid.UUID(msp["msp_id"])))
    assert [c.name for c in clients] == ["first"]


@pytest.mark.parametrize(
    "args",
    [
        ("create-msp",),
        ("create-client", "--msp-id", "not-a-uuid", "--name", "x", "--tenant-id", str(uuid.UUID(int=1))),
        ("create-client", "--msp-id", str(uuid.UUID(int=1)), "--name", "x", "--tenant-id", "not-a-guid"),
        ("create-worker-token", "--msp-id", str(uuid.UUID(int=1))),
        ("create-plan", "--msp-id", str(uuid.UUID(int=1)), "--client-id", str(uuid.UUID(int=1)), "--connector-id", str(uuid.UUID(int=1)), "--mail", "x", "--sp", "1", "--od", "1"),
        ("create-user", "--msp-id", str(uuid.UUID(int=1))),
        ("delete-msp",),
        ("generate-report", "--msp-id", str(uuid.UUID(int=1))),
        ("generate-report", "--msp-id", "x", "--client-id", str(uuid.UUID(int=1))),
    ],
)
async def test_a_usage_fault_is_typer_s_exit_2_before_any_database(monkeypatch, args):
    monkeypatch.delenv("DATABASE_URL", raising=False)

    result = await cli(*args)

    assert result.exit_code == 2
    assert result.stdout == ""
    assert "settings error" not in result.stderr


async def test_no_arguments_prints_the_commands(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)

    result = await cli()

    text = result.stdout + result.stderr
    for command in ("create-msp", "create-client", "create-worker-token", "create-connector", "create-plan", "revoke-worker", "create-user", "reset-password", "generate-report"):
        assert command in text


# --- C6.1: create-user and reset-password (docs/decisions.md 2026-10-12, point 12) -------------


PASSWORD = "correct horse battery staple"


async def cli_with_password(password: str, *args: str):
    """The command with the password on standard input (no console under
    the runner, so one line is read); never on the command line."""
    return await asyncio.to_thread(runner.invoke, manage.app, list(args), input=password + "\n")


async def test_create_user_reads_the_password_from_stdin_and_prints_the_id_alone(database, rows):
    msp = lines(await cli("create-msp", "--name", "a"))

    result = await cli_with_password(PASSWORD, "create-user", "--msp-id", msp["msp_id"], "--email", " Admin@Example.test ", "--role", "admin")

    assert result.exit_code == 0, result.stderr
    made = lines(result)
    assert set(made) == {"user_id"} and result.stderr == ""
    assert PASSWORD not in result.stdout + result.stderr
    user = await rows.read(lambda s: UserRepo(s).get(uuid.UUID(msp["msp_id"]), uuid.UUID(made["user_id"])))
    assert (user.email, user.role) == ("Admin@Example.test", "admin")
    assert user.password_hash.startswith("$argon2id$") and PASSWORD not in user.password_hash
    actions = await rows.read(lambda s: AuditRepo(s).list(uuid.UUID(msp["msp_id"])))
    assert [(a.action, a.target, a.user_id, a.ip) for a in actions][-1] == ("user.create", f"user:{made['user_id']}", None, None)


async def test_reset_password_replaces_the_hash_marks_the_change_and_prints_the_time(database, rows):
    msp = lines(await cli("create-msp", "--name", "a"))
    made = lines(await cli_with_password(PASSWORD, "create-user", "--msp-id", msp["msp_id"], "--email", "x@example.test", "--role", "member"))
    before = await rows.read(lambda s: UserRepo(s).get(uuid.UUID(msp["msp_id"]), uuid.UUID(made["user_id"])))

    result = await cli_with_password("another password entirely", "reset-password", "--email", "X@EXAMPLE.TEST")

    assert result.exit_code == 0, result.stderr
    printed = lines(result)
    assert set(printed) == {"user_id", "password_changed_at"} and printed["user_id"] == made["user_id"]
    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", printed["password_changed_at"])
    after = await rows.read(lambda s: UserRepo(s).get(uuid.UUID(msp["msp_id"]), uuid.UUID(made["user_id"])))
    assert after.password_hash != before.password_hash and after.password_changed_at > before.password_changed_at
    actions = await rows.read(lambda s: AuditRepo(s).list(uuid.UUID(msp["msp_id"])))
    assert [a.action for a in actions][-1] == "user.reset_password"


@pytest.mark.parametrize(
    ("password", "args", "line"),
    [
        (PASSWORD, ("create-user", "--msp-id", "{msp}", "--email", "no-at-sign", "--role", "admin"), "email: not an address"),
        (PASSWORD, ("create-user", "--msp-id", "{msp}", "--email", "a@b.test", "--role", "owner"), "role: not admin or member"),
        ("short", ("create-user", "--msp-id", "{msp}", "--email", "a@b.test", "--role", "admin"), "password: not 12 to 1024 characters"),
        (PASSWORD, ("create-user", "--msp-id", str(uuid.UUID(int=9)), "--email", "a@b.test", "--role", "admin"), "msp_id: no such MSP"),
        (PASSWORD, ("reset-password", "--email", "nobody@example.test"), "email: no such user"),
        ("short", ("reset-password", "--email", "a@b.test"), "password: not 12 to 1024 characters"),
    ],
)
async def test_a_user_command_s_refusal_is_one_line_with_nothing_of_the_password(database, rows, password, args, line):
    msp = lines(await cli("create-msp", "--name", "a"))

    result = await cli_with_password(password, *[a.format(msp=msp["msp_id"]) for a in args])

    assert (result.exit_code, result.stdout, result.stderr.strip()) == (1, "", line)
    assert password not in result.stderr
    assert await rows.read(lambda s: UserRepo(s).list(uuid.UUID(msp["msp_id"]))) == []


async def test_the_same_address_twice_in_any_case_is_refused_through_the_cli(database, rows):
    msp = lines(await cli("create-msp", "--name", "a"))
    await cli_with_password(PASSWORD, "create-user", "--msp-id", msp["msp_id"], "--email", "one@example.test", "--role", "admin")

    result = await cli_with_password(PASSWORD, "create-user", "--msp-id", msp["msp_id"], "--email", "ONE@example.test", "--role", "member")

    assert (result.exit_code, result.stdout, result.stderr.strip()) == (1, "", "email: already a user of this Cloud")


def test_the_password_is_never_a_command_line_option():
    for command in manage.app.registered_commands:
        if command.name in ("create-user", "reset-password"):
            import inspect

            assert "password" not in inspect.signature(command.callback).parameters


def test_the_console_path_asks_twice_and_refuses_two_entries_that_differ(monkeypatch):
    answers = iter(["first entry 12", "second entry 12"])
    monkeypatch.setattr(manage.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(manage.getpass, "getpass", lambda prompt: next(answers))

    with pytest.raises(typer.Exit) as raised:
        manage.read_password()
    assert raised.value.exit_code == 1

    answers = iter(["same entry 123", "same entry 123"])
    assert manage.read_password() == "same entry 123"


@pytest.mark.parametrize(
    ("content", "line"),
    [(None, "profile_file: not readable"), (b"\xff\xfe", "profile_file: not UTF-8"), (b"{", "profile_file: not JSON")],
)
async def test_a_profile_file_that_cannot_be_read_is_refused_without_its_path(database, tmp_path, content, line):
    msp = lines(await cli("create-msp", "--name", "a"))
    path = tmp_path / "Sentinel-Folder" / "profile.json"
    if content is not None:
        path.parent.mkdir()
        path.write_bytes(content)

    result = await cli(
        "create-connector", "--msp-id", msp["msp_id"], "--client-id", str(uuid.UUID(int=1)),
        "--worker-id", str(uuid.UUID(int=2)), "--profile-file", str(path),
    )

    assert (result.exit_code, result.stdout, result.stderr.strip()) == (1, "", line)
    assert "Sentinel" not in result.stderr


async def test_a_profile_naming_another_tenant_is_refused_through_the_cli(database, profile_file):
    msp = lines(await cli("create-msp", "--name", "a"))
    client = lines(await cli("create-client", "--msp-id", msp["msp_id"], "--name", "c", "--tenant-id", str(uuid.uuid4())))
    token = lines(await cli("create-worker-token", "--msp-id", msp["msp_id"], "--label", "l"))
    registered = await register(database, token["install_token"])
    other = uuid.uuid4()

    result = await cli(
        "create-connector", "--msp-id", msp["msp_id"], "--client-id", client["client_id"],
        "--worker-id", registered["worker_id"], "--profile-file", str(profile_file(other)),
    )

    assert (result.exit_code, result.stdout, result.stderr.strip()) == (1, "", "graph_tenant_id: not the client's tenant")
    assert str(other) not in result.stderr


@pytest.mark.parametrize(
    ("cron", "line"),
    [("nonsense", "cadence_cron: not a cron expression"), ("0 2 1 1 *", "cadence_cron: less than monthly"), ("0 2 * * * *", "cadence_cron: not a cron expression"),
     ("R 2 * * *", "cadence_cron: not a cron expression"), ("0 0 31 2 *", "cadence_cron: never occurs"),
     ("* * * * *", "cadence_cron: more often than every 5 minutes")],
)
async def test_a_cron_outside_the_rule_is_refused_through_the_cli(database, cron, line):
    msp = lines(await cli("create-msp", "--name", "a"))

    result = await cli(
        "create-plan", "--msp-id", msp["msp_id"], "--client-id", str(uuid.UUID(int=1)), "--connector-id", str(uuid.UUID(int=2)),
        "--mail", "1", "--sp", "1", "--od", "1", "--cron", cron,
    )

    assert (result.exit_code, result.stdout, result.stderr.strip()) == (1, "", line)
    assert cron not in result.stderr


def test_an_error_nobody_foresaw_is_the_internal_line_naming_the_type_alone(monkeypatch, capsys):
    """A refusal the table doesn't word, or anything else raised, is one
    line with the exception's type and nothing of its text."""

    async def fake(url, work):
        raise RuntimeError("Sentinel-Text")

    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://nobody:nothing@127.0.0.1:1/none")
    monkeypatch.setattr(manage, "_in_transaction", fake)

    with pytest.raises(typer.Exit) as raised:
        manage.run(lambda s: None)

    captured = capsys.readouterr()
    assert raised.value.exit_code == 1
    assert (captured.out, captured.err.strip()) == ("", "internal: RuntimeError")


# --- Happy paths beyond the Done-when --------------------------------------------------------------


async def test_the_token_is_on_stdout_once_and_its_hash_nowhere(database, rows):
    msp = lines(await cli("create-msp", "--name", "a"))

    result = await cli("create-worker-token", "--msp-id", msp["msp_id"], "--label", "veeam-vm")

    printed = lines(result)
    token = printed["install_token"]
    assert result.stdout.count(token) == 1
    assert token not in result.stderr and token_hash(token) not in result.stdout + result.stderr
    assert result.stderr.strip() == manage.onboarding.SHOWN_ONCE
    assert printed["expires_at"].endswith("Z")
    row = await rows.read(lambda s: Lookup(s).find_install_token_by_hash(token_hash(token)))
    assert str(row.id) == printed["install_token_id"]


async def test_create_plan_run_now_prints_the_run_and_create_msp_takes_retention(database, rows, profile_file):
    msp = lines(await cli("create-msp", "--name", "a", "--retention-days", "30"))
    tenant = uuid.uuid4()
    client = lines(await cli("create-client", "--msp-id", msp["msp_id"], "--name", "c", "--tenant-id", str(tenant), "--screenshots-enabled"))
    token = lines(await cli("create-worker-token", "--msp-id", msp["msp_id"], "--label", "l"))
    registered = await register(database, token["install_token"])
    connector = lines(await cli(
        "create-connector", "--msp-id", msp["msp_id"], "--client-id", client["client_id"],
        "--worker-id", registered["worker_id"], "--profile-file", str(profile_file(tenant)), "--type", "veeam_m365",
    ))

    plan = lines(await cli(
        "create-plan", "--msp-id", msp["msp_id"], "--client-id", client["client_id"], "--connector-id", connector["connector_id"],
        "--mail", "1", "--sp", "0", "--od", "0", "--cron", "*/5 * * * *", "--disabled", "--run-now",
    ))

    assert list(plan) == ["plan_id", "run_id"]
    msp_id = uuid.UUID(msp["msp_id"])
    async def read(s):
        return (
            await MspRepo(s).get(msp_id), await ClientRepo(s).get(msp_id, uuid.UUID(client["client_id"])),
            await PlanRepo(s).get(msp_id, uuid.UUID(plan["plan_id"])), await RunRepo(s).list(msp_id),
        )

    msp_row, client_row, plan_row, runs = await rows.read(read)
    assert msp_row.retention_days == 30 and client_row.screenshots_enabled is True
    assert (plan_row.cadence_cron, plan_row.enabled) == ("*/5 * * * *", False)
    assert [(str(r.id), r.state, r.scheduled_for) for r in runs] == [(plan["run_id"], "queued", None)]


# --- C6.4: generate-report (docs/decisions.md 2026-10-12, "C6.4", point 7) ------------------------

REPORT_CLOCK = dt.datetime(2026, 10, 12, 9, 30, 0, tzinfo=dt.timezone.utc)
S3_ENV = {"S3_ENDPOINT": "http://127.0.0.1:1", "S3_ACCESS_KEY": "test-access-key", "S3_SECRET_KEY": "test-secret-key", "S3_BUCKET": "test-bucket"}


@pytest.fixture
def report_clock(monkeypatch):
    monkeypatch.setattr(manage.report_generate, "now", lambda: REPORT_CLOCK)
    return REPORT_CLOCK


@pytest.fixture
def bucket(monkeypatch):
    """The CLI's bucket on botocore's Stubber (the real client would reach
    for S3_ENDPOINT): any PDF body is taken and kept."""
    for name, value in S3_ENV.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("SECRET_KEY", raising=False)
    settings = make_settings()
    client = make_s3_client(settings)
    stubber = Stubber(client)
    bodies: list[bytes] = []
    client.meta.events.register("before-parameter-build.s3.PutObject", lambda params, **_kw: bodies.append(params["Body"]))
    storage = Storage(client, settings.s3_bucket)
    monkeypatch.setattr(manage.Storage, "for_writing", staticmethod(lambda _settings: storage))
    stubber.activate()

    class Bucket:
        def expect(self, key: str) -> None:
            stubber.add_response("put_object", {"ETag": '"x"'}, expected_params={"Bucket": "test-bucket", "Key": key, "Body": ANY, "ContentType": "application/pdf"})

        @property
        def bodies(self) -> list[bytes]:
            return bodies

        def done(self) -> None:
            stubber.assert_no_pending_responses()

    yield Bucket()
    stubber.deactivate()


async def a_september(rows, msp_id: str, client_id: str) -> None:
    """A Worker, a connector, a plan and one fail run of September 2026 with
    a missing item, through the repos on the CLI's own database."""

    async def work(s):
        msp, client = uuid.UUID(msp_id), uuid.UUID(client_id)
        worker = await WorkerRepo(s).create(msp, "w", public_key_pem="-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----\n", key_id="a" * 64, api_token_hash="b" * 64)
        tenant = (await ClientRepo(s).get(msp, client)).tenant_id
        connector = await ConnectorRepo(s).create(msp, client, worker.id, {**VALID_PROFILE, "graph_tenant_id": str(tenant)})
        plan = await PlanRepo(s).create(msp, client, connector.id, sample_mail=2, sample_sp=0, sample_od=0, cadence_cron="0 2 * * *", now=REPORT_CLOCK)
        run = await RunRepo(s).create(msp, plan_id=plan.id, client_id=client, connector_id=connector.id, worker_id=worker.id)
        await s.execute(text("UPDATE test_run SET state = 'fail', finished_at = '2026-09-10T02:30:00Z', recovery_ms = 65000 WHERE id = :id"), {"id": run.id})
        await ItemRepo(s).create(msp, run.id, position=0, type="mail", name="RP-CANARY-0003", expected_kind="manifest", found=False, match=False, reason="no restored copy found")

    await rows.read(work)


async def test_generate_report_makes_the_month_s_final_report_and_prints_its_six_lines(database, rows, report_clock, bucket):
    msp = lines(await cli("create-msp", "--name", "a"))
    client = lines(await cli("create-client", "--msp-id", msp["msp_id"], "--name", "contoso", "--tenant-id", str(uuid.uuid4())))
    await a_september(rows, msp["msp_id"], client["client_id"])
    key = f"msp/{msp['msp_id']}/reports/{client['client_id']}/2026-09.pdf"
    bucket.expect(key)

    result = await cli("generate-report", "--msp-id", msp["msp_id"], "--client-id", client["client_id"], "--period", "2026-09")

    assert result.exit_code == 0, result.stderr
    printed = lines(result)
    assert list(printed) == ["report_id", "period", "interim", "storage_key", "content_sha256", "file_sha256"]
    assert (printed["period"], printed["interim"], printed["storage_key"]) == ("2026-09", "false", key)
    bucket.done()
    (pdf,) = bucket.bodies
    assert hashlib.sha256(pdf).hexdigest() == printed["file_sha256"] and pdf.startswith(b"%PDF-")
    msp_id = uuid.UUID(msp["msp_id"])
    (row,) = await rows.read(lambda s: ReportRepo(s).list(msp_id))
    assert (str(row.id), row.content_sha256, row.file_sha256, row.interim, row.generated_at) == (printed["report_id"], printed["content_sha256"], printed["file_sha256"], False, REPORT_CLOCK)
    audit = await rows.read(lambda s: AuditRepo(s).list(msp_id))
    assert [(r.action, r.target, r.user_id, r.ip) for r in audit if r.action == "report.create"] == [("report.create", f"report:{row.id}", None, None)]
    assert result.stderr == ""


async def test_generate_report_s_default_period_is_the_previous_month_of_the_cloud_s_clock(database, rows, report_clock, bucket):
    msp = lines(await cli("create-msp", "--name", "a"))
    client = lines(await cli("create-client", "--msp-id", msp["msp_id"], "--name", "contoso", "--tenant-id", str(uuid.uuid4())))
    await a_september(rows, msp["msp_id"], client["client_id"])
    bucket.expect(f"msp/{msp['msp_id']}/reports/{client['client_id']}/2026-09.pdf")

    result = await cli("generate-report", "--msp-id", msp["msp_id"], "--client-id", client["client_id"])

    assert result.exit_code == 0, result.stderr
    assert lines(result)["period"] == "2026-09"
    bucket.done()


@pytest.mark.parametrize(
    ("period", "line"),
    [
        ("2026-9", "period: not YYYY-MM"),
        ("2026-08", "period: no run in the period"),
        ("2027-01", "period: has not begun"),
    ],
)
async def test_generate_report_s_refusals_are_one_line_and_exit_1_with_nothing_put(database, rows, report_clock, bucket, period, line):
    msp = lines(await cli("create-msp", "--name", "a"))
    client = lines(await cli("create-client", "--msp-id", msp["msp_id"], "--name", "contoso", "--tenant-id", str(uuid.uuid4())))
    await a_september(rows, msp["msp_id"], client["client_id"])

    result = await cli("generate-report", "--msp-id", msp["msp_id"], "--client-id", client["client_id"], "--period", period)

    assert (result.exit_code, result.stdout, result.stderr.strip()) == (1, "", line)
    assert bucket.bodies == []
    assert await rows.read(lambda s: ReportRepo(s).list(uuid.UUID(msp["msp_id"]))) == []


async def test_generate_report_twice_is_the_period_s_refusal_and_another_msp_s_client_is_no_client(database, rows, report_clock, bucket):
    msp = lines(await cli("create-msp", "--name", "a"))
    other = lines(await cli("create-msp", "--name", "b"))
    client = lines(await cli("create-client", "--msp-id", msp["msp_id"], "--name", "contoso", "--tenant-id", str(uuid.uuid4())))
    await a_september(rows, msp["msp_id"], client["client_id"])
    bucket.expect(f"msp/{msp['msp_id']}/reports/{client['client_id']}/2026-09.pdf")
    first = await cli("generate-report", "--msp-id", msp["msp_id"], "--client-id", client["client_id"], "--period", "2026-09")
    assert first.exit_code == 0, first.stderr

    again = await cli("generate-report", "--msp-id", msp["msp_id"], "--client-id", client["client_id"], "--period", "2026-09")
    theirs = await cli("generate-report", "--msp-id", other["msp_id"], "--client-id", client["client_id"], "--period", "2026-09")

    assert (again.exit_code, again.stdout, again.stderr.strip()) == (1, "", "period: already reported")
    assert (theirs.exit_code, theirs.stdout, theirs.stderr.strip()) == (1, "", "client_id: no such client")
    assert len(bucket.bodies) == 1


async def test_generate_report_needs_the_s3_variables_and_no_secret_key_and_stops_before_the_database(monkeypatch, report_clock):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    for name in S3_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("S3_BUCKET", "b")

    result = await cli("generate-report", "--msp-id", str(uuid.UUID(int=1)), "--client-id", str(uuid.UUID(int=2)), "--period", "2026-09")

    assert (result.exit_code, result.stdout, result.stderr.strip()) == (1, "", "settings error: S3_ENDPOINT is missing; S3_ACCESS_KEY is missing; S3_SECRET_KEY is missing")


async def test_generate_report_without_a_database_url_names_it_after_the_s3_variables_pass(monkeypatch, report_clock, bucket):
    monkeypatch.delenv("DATABASE_URL", raising=False)

    result = await cli("generate-report", "--msp-id", str(uuid.UUID(int=1)), "--client-id", str(uuid.UUID(int=2)), "--period", "2026-09")

    assert (result.exit_code, result.stdout, result.stderr.strip()) == (1, "", "settings error: DATABASE_URL is missing")


def test_the_cli_builds_no_statement_and_logs_nothing():
    source = Path(manage.__file__).read_text(encoding="utf-8")

    assert "configure_logging" not in source
    assert "select(" not in source and "session.execute" not in source
    assert "typer.Typer(" in source

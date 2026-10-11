"""C5.10's Done-when by name, and the Typer layer of `cloud/manage.py`
(docs/decisions.md 2026-10-11, "C5.10 and C5.9", points 1 to 4 and 11): the
commands run through `typer.testing.CliRunner` in a thread (a command's
`asyncio.run` can't share the test loop), against a migrated database of the
test's own, since a command commits.
"""

from __future__ import annotations

import asyncio
import json
import re
import sys
import time
import uuid
from pathlib import Path

import httpx
import pytest
import typer
from sqlalchemy.ext.asyncio import create_async_engine
from typer.testing import CliRunner

from app.auth.tokens import token_hash
from app.db import make_session_factory
from app.main import create_app
from app.repo.audit import AuditRepo
from app.repo.clients import ClientRepo
from app.repo.connectors import ConnectorRepo
from app.repo.lookup import Lookup
from app.repo.msps import MspRepo
from app.repo.plans import PlanRepo
from app.repo.runs import RunRepo
from app.repo.workers import WorkerRepo
from tests.conftest import make_settings
from tests.test_registration import KEY, KEY_ID
from tests.test_repo_connectors import VALID_PROFILE

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import manage  # noqa: E402

TOKEN_SHAPE = re.compile(r"^[A-Za-z0-9_-]{43}$")
LINE = re.compile(r"^[a-z_]+ \S+$")
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
    for command in ("create-msp", "create-client", "create-worker-token", "create-connector", "create-plan", "revoke-worker"):
        assert command in text
    assert "create-user" not in text


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


def test_the_cli_builds_no_statement_and_logs_nothing():
    source = Path(manage.__file__).read_text(encoding="utf-8")

    assert "configure_logging" not in source
    assert "select(" not in source and "session.execute" not in source
    assert "typer.Typer(" in source

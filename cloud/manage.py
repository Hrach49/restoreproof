"""The hand-onboarding CLI (C5.10; docs/decisions.md 2026-10-11, "C5.10 and
C5.9", points 1 to 5; docs/onboarding.md). From cloud/:

    uv run python manage.py create-msp --name "Contoso MSP"
    uv run python manage.py create-client --msp-id <uuid> --name Fabrikam --tenant-id <guid>
    uv run python manage.py create-worker-token --msp-id <uuid> --label veeam-vm
    uv run python manage.py create-connector --msp-id <uuid> --client-id <uuid> --worker-id <uuid> --profile-file <path>
    uv run python manage.py create-plan --msp-id <uuid> --client-id <uuid> --connector-id <uuid> --mail 10 --sp 10 --od 10
    uv run python manage.py revoke-worker --msp-id <uuid> --worker-id <uuid>
    uv run python manage.py create-user --msp-id <uuid> --email admin@example.test --role admin
    uv run python manage.py reset-password --email admin@example.test
    uv run python manage.py generate-report --msp-id <uuid> --client-id <uuid> [--period 2026-09]

or `docker compose exec api python manage.py <command> ...` inside the stack.
`DATABASE_URL` alone, read as a migration reads it; no bucket, no SECRET_KEY,
but for `generate-report` (C6.4), which writes the PDF to the bucket and so
reads the five S3 variables too (`storage_settings_from_environment`), still
no SECRET_KEY.
Each command is one transaction, committed when its function returns and
rolled back when it raises; the logic is app/onboarding.py's, over the repos,
and no statement is built here (tests/test_tenant_scope.py holds this file).
Stdout is one `<name> <value>` line per thing made; a refusal is one
`<key>: <reason>` line on stderr, exit 1; a usage fault is Typer's, exit 2.
Nothing is logged, and the one secret ever printed is the install token
`create-worker-token` exists to print, once. A password (C6.1) is read from
the console twice without echo, or from standard input as one line when that
is no console; never from an argument or the environment; printed nowhere.
"""

from __future__ import annotations

import asyncio
import getpass
import sys
import uuid
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Annotated

import typer
from sqlalchemy.ext.asyncio import AsyncSession

from app import onboarding
from app.cadence import DEFAULT_CADENCE
from app.db import make_engine_for_url, make_session_factory
from app.models import DEFAULT_CONNECTOR_TYPE, DEFAULT_RETENTION_DAYS
from app.repo.errors import RepoError
from app.report import data as report_data
from app.report import generate as report_generate
from app.settings import SettingsError, database_url_from_environment, storage_settings_from_environment
from app.storage import Storage

app = typer.Typer(add_completion=False, no_args_is_help=True, help=__doc__.split("\n\n")[0])

Work = Callable[[AsyncSession], Awaitable[onboarding.Created]]

MspId = Annotated[uuid.UUID, typer.Option(help="the MSP's id")]
Email = Annotated[str, typer.Option(help="the user's e-mail address")]

PASSWORDS_DIFFER = "password: the two entries differ"


def read_password() -> str:
    """The password from the console (twice, no echo) or from standard input
    (one line) when that is no console; never an argument."""
    if sys.stdin.isatty():
        first = getpass.getpass("Password: ")
        if getpass.getpass("Again: ") != first:
            _fail(PASSWORDS_DIFFER)
        return first
    return sys.stdin.readline().rstrip("\r\n")


async def _in_transaction(url: str, work: Work) -> onboarding.Created:
    engine = make_engine_for_url(url)
    try:
        async with make_session_factory(engine)() as session, session.begin():
            return await work(session)
    finally:
        await engine.dispose()


def _fail(line: str) -> None:
    typer.echo(line, err=True)
    raise typer.Exit(code=1)


def run(work: Work) -> None:
    """Run one command's work in one transaction and print what it made."""
    try:
        url = database_url_from_environment()
    except SettingsError as error:
        _fail(str(error))
    try:
        created = asyncio.run(_in_transaction(url, work))
    except RepoError as error:
        _fail(str(error))
    except (OSError, TimeoutError):
        _fail("database: unreachable")
    except Exception as error:  # noqa: BLE001 - the one place a command ends; the type alone
        _fail(f"internal: {type(error).__name__}")
    for name, value in created.lines:
        typer.echo(f"{name} {value}")
    for note in created.notes:
        typer.echo(note, err=True)


@app.command("create-msp")
def create_msp(
    name: Annotated[str, typer.Option(help="the MSP's name")],
    retention_days: Annotated[int, typer.Option(help="how long runs are kept")] = DEFAULT_RETENTION_DAYS,
) -> None:
    """Make an MSP; prints msp_id."""
    run(lambda session: onboarding.create_msp(session, name=name, retention_days=retention_days))


@app.command("create-client")
def create_client(
    msp_id: MspId,
    name: Annotated[str, typer.Option(help="the client's name")],
    tenant_id: Annotated[uuid.UUID, typer.Option(help="the client's Microsoft 365 tenant id (a GUID)")],
    screenshots_enabled: Annotated[bool, typer.Option("--screenshots-enabled", help="take a screenshot per run")] = False,
) -> None:
    """Make a client of the MSP, one per tenant; prints client_id."""
    run(
        lambda session: onboarding.create_client(
            session, msp_id, name=name, tenant_id=tenant_id, screenshots_enabled=screenshots_enabled
        )
    )


@app.command("create-worker-token")
def create_worker_token(
    msp_id: MspId,
    label: Annotated[str, typer.Option(help="what the token is for (shown beside the Worker)")],
) -> None:
    """Make an install token for a Worker; prints it once."""
    run(lambda session: onboarding.create_worker_token(session, msp_id, label=label))


@app.command("create-connector")
def create_connector(
    msp_id: MspId,
    client_id: Annotated[uuid.UUID, typer.Option(help="the client's id")],
    worker_id: Annotated[uuid.UUID, typer.Option(help="the Worker's id, from its registration")],
    profile_file: Annotated[Path, typer.Option(help="the client's restoreproof.client-profile.v1 file")],
    type: Annotated[str, typer.Option(help="the connector's type")] = DEFAULT_CONNECTOR_TYPE,
) -> None:
    """Bind the client to the Worker with its profile; prints connector_id."""

    async def work(session: AsyncSession) -> onboarding.Created:
        profile = onboarding.read_profile_file(profile_file)
        return await onboarding.create_connector(
            session, msp_id, client_id=client_id, worker_id=worker_id, profile=profile, type=type
        )

    run(work)


@app.command("create-plan")
def create_plan(
    msp_id: MspId,
    client_id: Annotated[uuid.UUID, typer.Option(help="the client's id")],
    connector_id: Annotated[uuid.UUID, typer.Option(help="the client's connector")],
    mail: Annotated[int, typer.Option(help="mails per run, 0 to 100")],
    sp: Annotated[int, typer.Option(help="SharePoint files per run, 0 to 100")],
    od: Annotated[int, typer.Option(help="OneDrive files per run, 0 to 100")],
    cron: Annotated[str, typer.Option(help="five cron fields, UTC, at least monthly")] = DEFAULT_CADENCE,
    disabled: Annotated[bool, typer.Option("--disabled", help="make the plan disabled")] = False,
    run_now: Annotated[bool, typer.Option("--run-now", help="also queue one run at once")] = False,
) -> None:
    """Make a test plan on the client's connector; prints plan_id (and run_id with --run-now)."""
    run(
        lambda session: onboarding.create_plan(
            session,
            msp_id,
            client_id=client_id,
            connector_id=connector_id,
            sample_mail=mail,
            sample_sp=sp,
            sample_od=od,
            cadence_cron=cron,
            enabled=not disabled,
            run_now=run_now,
        )
    )


@app.command("revoke-worker")
def revoke_worker(
    msp_id: MspId,
    worker_id: Annotated[uuid.UUID, typer.Option(help="the Worker's id")],
) -> None:
    """Revoke a Worker's token from now on; prints revoked_at."""
    run(lambda session: onboarding.revoke_worker(session, msp_id, worker_id=worker_id))


@app.command("create-user")
def create_user(
    msp_id: MspId,
    email: Email,
    role: Annotated[str, typer.Option(help="admin or member")],
) -> None:
    """Make a user of the MSP; the password is asked for; prints user_id."""
    password = read_password()
    run(lambda session: onboarding.create_user(session, msp_id, email=email, role=role, password=password))


@app.command("reset-password")
def reset_password(email: Email) -> None:
    """Give the user a new password (asked for) and end their sessions; prints user_id."""
    password = read_password()
    run(lambda session: onboarding.reset_password(session, email=email, password=password))


@app.command("generate-report")
def generate_report(
    msp_id: MspId,
    client_id: Annotated[uuid.UUID, typer.Option(help="the client's id")],
    period: Annotated[str | None, typer.Option(help="the month, YYYY-MM (UTC); the previous month when not given")] = None,
) -> None:
    """Make the client's PDF report of a month (C6.4) and store it; prints
    report_id, period, interim, storage_key, content_sha256, file_sha256.
    Needs the S3 variables beside DATABASE_URL; the current month gives an
    interim report, a month before it the final one, made once."""
    at = report_generate.now()
    try:
        month = report_data.period_of(period) if period is not None else report_data.previous_month(at.date())
        storage = Storage.for_writing(storage_settings_from_environment())
    except RepoError as error:
        _fail(str(error))
    except SettingsError as error:
        _fail(str(error))
    run(lambda session: report_generate.generate(session, storage, msp_id, client_id, month, now=at))


if __name__ == "__main__":  # pragma: no cover - the process's entry
    sys.exit(app())

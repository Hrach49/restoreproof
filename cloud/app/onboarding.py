"""The hand-onboarding's logic (C5.10; docs/decisions.md 2026-10-11, "C5.10
and C5.9", points 1 to 5): what `cloud/manage.py` runs, one function per
command, each `async` over a session and plain values, each through the
repos (and `issue_install_token`) and building no statement, so the lint of
tests/test_tenant_scope.py holds it as it holds a router. The transaction is
the caller's (`manage.py` commits one per command); nothing here commits.

Each function answers a `Created`: the `<name> <value>` lines the CLI prints,
in order, and the notes it prints on stderr. A refusal is a `RepoError`
naming the key and a fixed reason, never a value: the repos' own, the
database's worded by `constraint_refusal`, or this module's (a name or a
label outside its rule, a profile file that can't be read, a Worker that
isn't there to revoke). One audit row per command that changed a row,
`user_id` and `ip` null (the CLI has no user and no address); `create_connector`
writes none of its own, since `ConnectorRepo.create` writes the repo's.
The admin routes of C6.x can call these the same way.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TypeVar
from uuid import UUID

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import passwords
from app.auth.tokens import issue_install_token
from app.cadence import DEFAULT_CADENCE
from app.models import DEFAULT_CONNECTOR_TYPE, DEFAULT_RETENTION_DAYS, USER_ROLES
from app.repo.audit import AuditRepo
from app.repo.clients import ClientRepo
from app.repo.connectors import ConnectorRepo
from app.repo.errors import RepoError, constraint_refusal
from app.repo.lookup import Lookup
from app.repo.msps import MspRepo
from app.repo.plans import PlanRepo
from app.repo.runs import RunRepo
from app.repo.users import UserRepo
from app.repo.workers import WorkerRepo

# A name or a label: 1 to 128 characters without a control character
# (registration's rule for a Worker's name; the label is shown beside it).
NAME_RULE = "not 1 to 128 characters without a control character"
_NAME = re.compile(r"^[^\x00-\x1f\x7f]{1,128}$")
# C6.1: an address is trimmed, holds one `@` with something on each side, no
# space and no control character, at most a mailbox's 254; stored as typed.
EMAIL_RULE = "not an address"
_EMAIL = re.compile(r"^[^\s@\x00-\x1f\x7f]+@[^\s@\x00-\x1f\x7f]+$")
MAX_EMAIL = 254
ROLE_RULE = "not admin or member"
NO_SUCH_USER = "no such user"

SHOWN_ONCE = "the install token is shown once; the Cloud stores its hash alone"
NO_SUCH_WORKER = "no such Worker or already revoked"
NO_SUCH_CONNECTOR = "not the client's connector"

T = TypeVar("T")


@dataclass(frozen=True)
class Created:
    """What a command prints: `<name> <value>` lines on stdout, notes on stderr."""

    lines: tuple[tuple[str, str], ...]
    notes: tuple[str, ...] = ()
    values: dict[str, str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "values", dict(self.lines))


def now() -> dt.datetime:
    """The Cloud's clock; a test moves it."""
    return dt.datetime.now(dt.timezone.utc)


def _time_text(stamp: dt.datetime) -> str:
    return stamp.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _check_name(key: str, value: str) -> None:
    if not _NAME.fullmatch(value):
        raise RepoError(key, NAME_RULE)


def worded(error: IntegrityError) -> BaseException:
    """The database's refusal as a `RepoError`, or the error itself."""
    refusal = constraint_refusal(error)
    return error if refusal is None else refusal


async def _refused_by_the_database(work: Callable[[], Awaitable[T]]) -> T:
    try:
        return await work()
    except IntegrityError as error:
        raise worded(error) from None


async def _audit(session: AsyncSession, msp_id: UUID, action: str, target: str) -> None:
    await AuditRepo(session).write(msp_id, action, target, user_id=None, ip=None)


async def create_msp(session: AsyncSession, *, name: str, retention_days: int = DEFAULT_RETENTION_DAYS) -> Created:
    _check_name("name", name)
    msp = await _refused_by_the_database(lambda: MspRepo(session).create(name=name, retention_days=retention_days))
    await _audit(session, msp.id, "msp.create", f"msp:{msp.id}")
    return Created((("msp_id", str(msp.id)),))


async def create_client(
    session: AsyncSession, msp_id: UUID, *, name: str, tenant_id: UUID, screenshots_enabled: bool = False
) -> Created:
    _check_name("name", name)
    client = await _refused_by_the_database(
        lambda: ClientRepo(session).create(msp_id, name=name, tenant_id=tenant_id, screenshots_enabled=screenshots_enabled)
    )
    await _audit(session, msp_id, "client.create", f"client:{client.id}")
    return Created((("client_id", str(client.id)),))


async def create_worker_token(session: AsyncSession, msp_id: UUID, *, label: str) -> Created:
    _check_name("label", label)
    token, row = await _refused_by_the_database(
        lambda: issue_install_token(session, msp_id, now(), label=label, created_by=None)
    )
    await _audit(session, msp_id, "install_token.create", f"install_token:{row.id}")
    return Created(
        (("install_token_id", str(row.id)), ("expires_at", _time_text(row.expires_at)), ("install_token", token)),
        notes=(SHOWN_ONCE,),
    )


def read_profile_file(path: Path) -> Any:
    """The profile file as JSON; a refusal names the key and never the path or the text."""
    try:
        raw = Path(path).read_bytes()
    except OSError:
        raise RepoError("profile_file", "not readable") from None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise RepoError("profile_file", "not UTF-8") from None
    try:
        return json.loads(text)
    except ValueError:
        raise RepoError("profile_file", "not JSON") from None


async def create_connector(
    session: AsyncSession,
    msp_id: UUID,
    *,
    client_id: UUID,
    worker_id: UUID,
    profile: Any,
    type: str = DEFAULT_CONNECTOR_TYPE,
) -> Created:
    # The repo holds the profile, the client, the tenant and the Worker in its
    # own order, and writes the audit row.
    connector = await _refused_by_the_database(
        lambda: ConnectorRepo(session).create(msp_id, client_id, worker_id, profile, type, user_id=None, ip=None)
    )
    return Created((("connector_id", str(connector.id)),))


async def create_plan(
    session: AsyncSession,
    msp_id: UUID,
    *,
    client_id: UUID,
    connector_id: UUID,
    sample_mail: int,
    sample_sp: int,
    sample_od: int,
    cadence_cron: str = DEFAULT_CADENCE,
    enabled: bool = True,
    run_now: bool = False,
) -> Created:
    # The repo holds the cadence; the database's key holds the connector to
    # the client (`connector_id: not the client's connector`, an absent one
    # included), worded by `constraint_refusal`.
    at = now()
    plan = await _refused_by_the_database(
        lambda: PlanRepo(session).create(
            msp_id,
            client_id,
            connector_id,
            sample_mail=sample_mail,
            sample_sp=sample_sp,
            sample_od=sample_od,
            cadence_cron=cadence_cron,
            now=at,
            enabled=enabled,
        )
    )
    await _audit(session, msp_id, "plan.create", f"plan:{plan.id}")
    lines: list[tuple[str, str]] = [("plan_id", str(plan.id))]
    if run_now:
        # A run made by hand (no period): the pilot's first test without
        # waiting for the cadence, since the scheduler makes no run for a
        # period that began before the plan was made. The connector exists
        # by the key the plan was just held to; one that is gone all the same
        # is that key's refusal.
        connector = await ConnectorRepo(session).get(msp_id, connector_id)
        if connector is None:
            raise RepoError("connector_id", NO_SUCH_CONNECTOR)
        worker_id = connector.worker_id
        run = await _refused_by_the_database(
            lambda: RunRepo(session).create(
                msp_id, plan_id=plan.id, client_id=client_id, connector_id=connector_id, worker_id=worker_id
            )
        )
        await _audit(session, msp_id, "run.create", f"run:{run.id}")
        lines.append(("run_id", str(run.id)))
    return Created(tuple(lines))


async def revoke_worker(
    session: AsyncSession, msp_id: UUID, *, worker_id: UUID, user_id: UUID | None = None, ip: str | None = None
) -> Created:
    """The CLI's (no user, no address) and the `/workers` page's (C6.2: the
    user and the address on the one `worker.revoke` row)."""
    at = now()
    if await WorkerRepo(session).revoke(msp_id, worker_id, at) == 0:
        raise RepoError("worker_id", NO_SUCH_WORKER)
    await AuditRepo(session).write(msp_id, "worker.revoke", f"worker:{worker_id}", user_id=user_id, ip=ip)
    return Created((("revoked_at", _time_text(at)),))


def check_email(email: str) -> str:
    """The address trimmed, or `email: not an address`."""
    address = email.strip()
    if len(address) > MAX_EMAIL or not _EMAIL.fullmatch(address):
        raise RepoError("email", EMAIL_RULE)
    return address


def _check_password(password: str) -> None:
    reason = passwords.check_password_rule(password)
    if reason is not None:
        raise RepoError("password", reason)


async def create_user(session: AsyncSession, msp_id: UUID, *, email: str, role: str, password: str) -> Created:
    """A user of the MSP (C6.1, point 12): the address, the role and the
    password each held to its rule before any work, the hash made in a
    thread, one audit row `user.create`; the password reaches no line."""
    address = check_email(email)
    if role not in USER_ROLES:
        raise RepoError("role", ROLE_RULE)
    _check_password(password)
    password_hash = await asyncio.to_thread(passwords.hash_password, password)
    user = await _refused_by_the_database(
        lambda: UserRepo(session).create(msp_id, email=address, password_hash=password_hash, role=role)
    )
    await _audit(session, msp_id, "user.create", f"user:{user.id}")
    return Created((("user_id", str(user.id)),))


async def reset_password(session: AsyncSession, *, email: str, password: str) -> Created:
    """A new password for the user of the address (C6.1, point 12): the hash
    replaced and `password_changed_at` set, so every session of the user
    ends; one audit row `user.reset_password` in the user's MSP."""
    address = check_email(email)
    _check_password(password)
    user = await Lookup(session).find_user_by_email(address)
    if user is None:
        raise RepoError("email", NO_SUCH_USER)
    at = now()
    password_hash = await asyncio.to_thread(passwords.hash_password, password)
    await UserRepo(session).set_password_hash(user.msp_id, user.id, password_hash, changed_at=at)
    await _audit(session, user.msp_id, "user.reset_password", f"user:{user.id}")
    return Created((("user_id", str(user.id)), ("password_changed_at", _time_text(at))))

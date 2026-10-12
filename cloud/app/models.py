"""The Cloud's data model (C5.2, with C5.13's constraints).

The rules every table follows (docs/decisions.md 2026-10-10, C5.1 and C5.2,
point 4):

- A primary key is a `uuid` named `id`, made by the model and, for a row
  inserted by hand, by the database.
- Every table but `msp` has `msp_id uuid NOT NULL` with a key to `msp`. Every
  table another one points at is unique on `(msp_id, id)`, and every other
  foreign key is composite and starts with `msp_id`: a row can't point at
  another MSP's row.
- No foreign key cascades or sets null: nothing is deleted by deleting
  something else.
- Every time is a `timestamptz` (`UtcDateTime`). A value without a zone is
  refused here: the driver would take it as the machine's local time.
- The database checks what the Cloud decides (`test_run.state`, a connector's
  name, a plan's sample sizes, a hash's shape). What a Worker's result says
  (`test_item.type`, `expected_kind`, `reason`, `test_run.error_code`) is text:
  `shared/schemas/result.v1.json` is the list of those words.

`app/migrations/versions/0001_initial.py` is written by hand and must agree
with this file; `tests/test_migrations.py` holds the two together.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    MetaData,
    Text,
    TypeDecorator,
    UniqueConstraint,
    Uuid,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# Every constraint and index gets a fixed name, so a test can say which one
# refused a row and a migration can drop it.
NAMING_CONVENTION = {
    "pk": "pk_%(table_name)s",
    "fk": "fk_%(table_name)s_%(column_0_N_name)s_%(referred_table_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
}

# The Worker's connector-name rule (rp::connector::is_connector_name, W4.11).
CONNECTOR_TYPE_RULE = "^[a-z0-9_]{1,64}$"
DEFAULT_CONNECTOR_TYPE = "veeam_m365"

# No `received` (C5.7): the bundle's status is known in the request that
# receives it, so a run goes from dispatched to pass, fail or error in one
# statement and no row is ever "received".
RUN_STATES = ("queued", "dispatched", "pass", "fail", "error", "expired")

# A SHA-256 as the Worker writes it: 64 lower-case hex digits.
SHA256_RULE = "^[0-9a-f]{64}$"

DEFAULT_RETENTION_DAYS = 1095


class UtcDateTime(TypeDecorator):
    """A `timestamptz` that takes only a time with a zone.

    asyncpg doesn't refuse a naive datetime: it reads it as the local time of
    the machine the app runs on. So the model refuses it before the driver
    sees it.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: dt.datetime | None, dialect: Any) -> dt.datetime | None:
        if value is not None and value.utcoffset() is None:
            raise ValueError("a time without a zone: give an aware UTC datetime")
        return value


class InetText(TypeDecorator):
    """An `inet` read back as the text it was given.

    asyncpg answers an `inet` with an `ipaddress` object, whatever the engine
    it runs under was told; the model's `str` is then true of every engine.
    """

    impl = INET
    cache_ok = True

    def process_result_value(self, value: Any, dialect: Any) -> str | None:
        return None if value is None else str(value)


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


def _id() -> Mapped[uuid.UUID]:
    return mapped_column(
        Uuid, primary_key=True, default=uuid.uuid4, server_default=text("gen_random_uuid()")
    )


def _msp_id() -> Mapped[uuid.UUID]:
    return mapped_column(Uuid, ForeignKey("msp.id"), nullable=False)


def _time(*, nullable: bool = True, default_now: bool = False) -> Mapped[Any]:
    return mapped_column(
        UtcDateTime,
        nullable=nullable,
        server_default=func.now() if default_now else None,
    )


def _sha256_check(column: str) -> CheckConstraint:
    return CheckConstraint(f"{column} ~ '{SHA256_RULE}'", name=f"{column}_hex")


def _same_msp(columns: tuple[str, ...], target: str, referred: tuple[str, ...]) -> ForeignKeyConstraint:
    """A key to `target` that starts with `msp_id` on both sides."""
    return ForeignKeyConstraint(
        ["msp_id", *columns], [f"{target}.msp_id", *(f"{target}.{name}" for name in referred)]
    )


class Msp(Base):
    __tablename__ = "msp"
    __table_args__ = (CheckConstraint("retention_days > 0", name="retention_days_positive"),)

    id: Mapped[uuid.UUID] = _id()
    name: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[dt.datetime] = _time(nullable=False, default_now=True)
    retention_days: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default=text(str(DEFAULT_RETENTION_DAYS))
    )


# C6.1: what a user may do (docs/decisions.md 2026-10-12, "C6.1, C6.2 and
# C6.3", points 3 and 22): a member reads and downloads, an admin also revokes
# a Worker and reads /audit.
USER_ROLES = ("admin", "member")


class User(Base):
    __tablename__ = "user"
    __table_args__ = (
        UniqueConstraint("msp_id", "id"),
        # The login form has no MSP (C6.1): one address, whatever its case.
        Index("uq_user_email_lower", func.lower(text("email")), unique=True),
        CheckConstraint("role IN (" + ", ".join(f"'{role}'" for role in USER_ROLES) + ")", name="role"),
    )

    id: Mapped[uuid.UUID] = _id()
    msp_id: Mapped[uuid.UUID] = _msp_id()
    email: Mapped[str] = mapped_column(Text, nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[str] = mapped_column(Text, nullable=False)
    # C6.1: a session cookie signed before this time is no session, so a
    # password reset ends every session of the user (point 5).
    password_changed_at: Mapped[dt.datetime] = _time(nullable=False, default_now=True)
    created_at: Mapped[dt.datetime] = _time(nullable=False, default_now=True)


class Client(Base):
    __tablename__ = "client"
    __table_args__ = (
        UniqueConstraint("msp_id", "id"),
        # C5.13: a tenant is one client of an MSP. A uuid, so the same tenant
        # in the other case is the same tenant.
        UniqueConstraint("msp_id", "tenant_id"),
    )

    id: Mapped[uuid.UUID] = _id()
    msp_id: Mapped[uuid.UUID] = _msp_id()
    name: Mapped[str] = mapped_column(Text, nullable=False)
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    screenshots_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )


class Worker(Base):
    __tablename__ = "worker"
    __table_args__ = (
        # C5.5: which install token made this Worker; null for one made any other way.
        _same_msp(("install_token_id",), "install_token", ("id",)),
        UniqueConstraint("msp_id", "id"),
        # C5.4 finds a Worker by its token's hash alone, before any MSP is known.
        UniqueConstraint("api_token_hash"),
        # C5.5: a public key is registered once, across all MSPs. The key's id
        # is the SHA-256 of its SubjectPublicKeyInfo DER (signature.v1.json),
        # canonical bytes where the PEM text is not.
        UniqueConstraint("key_id"),
        _sha256_check("key_id"),
        # C5.8: the heartbeat's two counts are never negative.
        CheckConstraint("outbox_depth >= 0", name="outbox_depth_not_negative"),
        CheckConstraint("uptime_s >= 0", name="uptime_s_not_negative"),
    )

    id: Mapped[uuid.UUID] = _id()
    msp_id: Mapped[uuid.UUID] = _msp_id()
    name: Mapped[str] = mapped_column(Text, nullable=False)
    # The one serialisation of the key (C5.5): the library's three-line PEM.
    public_key_pem: Mapped[str] = mapped_column(Text, nullable=False)
    key_id: Mapped[str] = mapped_column(Text, nullable=False)
    api_token_hash: Mapped[str] = mapped_column(Text, nullable=False)
    install_token_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    version: Mapped[str | None] = mapped_column(Text)
    # C5.8: the heartbeat's columns. `last_seen_at` is the Cloud's clock at
    # the heartbeat; the rest are the Worker's own words, null until the first
    # heartbeat and null again when the Worker says so (a restarted service
    # has no error since its start).
    last_seen_at: Mapped[dt.datetime | None] = _time()
    last_error: Mapped[str | None] = mapped_column(Text)
    last_error_at: Mapped[dt.datetime | None] = _time()
    outbox_depth: Mapped[int | None] = mapped_column(BigInteger)
    uptime_s: Mapped[int | None] = mapped_column(BigInteger)
    revoked_at: Mapped[dt.datetime | None] = _time()


class Connector(Base):
    __tablename__ = "connector"
    __table_args__ = (
        _same_msp(("client_id",), "client", ("id",)),
        _same_msp(("worker_id",), "worker", ("id",)),
        UniqueConstraint("msp_id", "id"),
        # What test_plan's key points at: a plan is on its own client's connector.
        UniqueConstraint("msp_id", "id", "client_id"),
        # What test_run's key points at: a run's Worker is its connector's.
        UniqueConstraint("msp_id", "id", "worker_id"),
        # C5.13: one connector per Worker and client.
        UniqueConstraint("worker_id", "client_id"),
        CheckConstraint(f"type ~ '{CONNECTOR_TYPE_RULE}'", name="type_name"),
    )

    id: Mapped[uuid.UUID] = _id()
    msp_id: Mapped[uuid.UUID] = _msp_id()
    client_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    worker_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    type: Mapped[str] = mapped_column(
        Text, nullable=False, server_default=text(f"'{DEFAULT_CONNECTOR_TYPE}'")
    )
    # A client-profile.v1 (shared/schemas/client-profile.v1.json). That it names
    # the client's tenant is the repository layer's to hold (C5.13).
    config_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)


class TestPlan(Base):
    __test__ = False  # a model, not a pytest class
    __tablename__ = "test_plan"
    __table_args__ = (
        _same_msp(("client_id",), "client", ("id",)),
        _same_msp(("connector_id", "client_id"), "connector", ("id", "client_id")),
        UniqueConstraint("msp_id", "id"),
        # What test_run's key points at: a run is filed under its plan's client
        # and on its plan's connector.
        UniqueConstraint("msp_id", "id", "connector_id", "client_id"),
        # The Worker's job rule (W4.8 J3): 0 to 100 each, not all 0.
        CheckConstraint("sample_mail BETWEEN 0 AND 100", name="sample_mail_range"),
        CheckConstraint("sample_sp BETWEEN 0 AND 100", name="sample_sp_range"),
        CheckConstraint("sample_od BETWEEN 0 AND 100", name="sample_od_range"),
        CheckConstraint("sample_mail + sample_sp + sample_od > 0", name="sample_not_empty"),
    )

    id: Mapped[uuid.UUID] = _id()
    msp_id: Mapped[uuid.UUID] = _msp_id()
    client_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    connector_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    sample_mail: Mapped[int] = mapped_column(Integer, nullable=False)
    sample_sp: Mapped[int] = mapped_column(Integer, nullable=False)
    sample_od: Mapped[int] = mapped_column(Integer, nullable=False)
    # C5.9: five fields, UTC, at least monthly; held by PlanRepo.create
    # (app/cadence.py), not by the database.
    cadence_cron: Mapped[str] = mapped_column(Text, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    # C5.9: the scheduler makes no run for a period that began before the plan.
    created_at: Mapped[dt.datetime] = _time(nullable=False, default_now=True)


class TestRun(Base):
    __test__ = False  # a model, not a pytest class
    __tablename__ = "test_run"
    __table_args__ = (
        _same_msp(("client_id",), "client", ("id",)),
        _same_msp(("worker_id",), "worker", ("id",)),
        # A run's connector is its plan's, and its Worker is that connector's:
        # it can only name its plan's connector's Worker (C5.3, finding 3).
        _same_msp(("plan_id", "connector_id", "client_id"), "test_plan", ("id", "connector_id", "client_id")),
        _same_msp(("connector_id", "worker_id"), "connector", ("id", "worker_id")),
        UniqueConstraint("msp_id", "id"),
        # C5.9: one run per plan and cron period. Nulls are distinct, so a run
        # made by hand (no period) never collides: the unique is the period
        # rule alone, and two ticks or two scheduler processes make one run.
        UniqueConstraint("msp_id", "plan_id", "scheduled_for"),
        CheckConstraint(
            "state IN (" + ", ".join(f"'{state}'" for state in RUN_STATES) + ")", name="state"
        ),
        CheckConstraint("total_ms >= 0", name="total_ms_not_negative"),
        CheckConstraint("recovery_ms >= 0", name="recovery_ms_not_negative"),
        CheckConstraint("attempt >= 0", name="attempt_not_negative"),
        _sha256_check("bundle_sha256"),
        Index(None, "msp_id", "client_id", "created_at"),
        # The poll (C5.6): a Worker's oldest queued runs, one index walk.
        Index(None, "msp_id", "worker_id", "state", "created_at"),
    )

    id: Mapped[uuid.UUID] = _id()
    msp_id: Mapped[uuid.UUID] = _msp_id()
    client_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    worker_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    plan_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    connector_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    state: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'queued'"))
    # C5.9: the start of the cron period the scheduler made this run for;
    # null for a run made by hand (RunRepo.create, create-plan --run-now).
    scheduled_for: Mapped[dt.datetime | None] = _time()
    # C5.6: the last dispatch's time, and how many times the run was handed to
    # its Worker. C5.7's `RunRepo.receive` moves a run that was handed out to
    # its bundle's pass, fail or error.
    dispatched_at: Mapped[dt.datetime | None] = _time()
    attempt: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    restore_point_at: Mapped[dt.datetime | None] = _time()
    started_at: Mapped[dt.datetime | None] = _time()
    finished_at: Mapped[dt.datetime | None] = _time()
    total_ms: Mapped[int | None] = mapped_column(BigInteger)
    # C6.2: `timings.spans.recovery.ms`, restore start to last item verified
    # (W3.2); the pages' and C6.4's "recovery time". Null as `total_ms` is.
    recovery_ms: Mapped[int | None] = mapped_column(BigInteger)
    bundle_key: Mapped[str | None] = mapped_column(Text)
    bundle_sha256: Mapped[str | None] = mapped_column(Text)
    # Null is "not known yet", never false.
    signature_ok: Mapped[bool | None] = mapped_column(Boolean)
    tsa_ok: Mapped[bool | None] = mapped_column(Boolean)
    # C5.7: the token's own time (genTime, UTC, whole seconds), set with tsa_ok.
    tsa_time: Mapped[dt.datetime | None] = _time()
    cleanup_ok: Mapped[bool | None] = mapped_column(Boolean)
    error_code: Mapped[str | None] = mapped_column(Text)
    error_message: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[dt.datetime] = _time(nullable=False, default_now=True)


class TestItem(Base):
    __test__ = False  # a model, not a pytest class
    __tablename__ = "test_item"
    __table_args__ = (
        _same_msp(("run_id",), "test_run", ("id",)),
        CheckConstraint("ms >= 0", name="ms_not_negative"),
        CheckConstraint("position >= 0", name="position_not_negative"),
        _sha256_check("expected_sha256"),
        _sha256_check("found_sha256"),
        Index(None, "msp_id", "run_id"),
    )

    id: Mapped[uuid.UUID] = _id()
    msp_id: Mapped[uuid.UUID] = _msp_id()
    run_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    # C5.7: the item's `index` in the result, which items.csv and the status's
    # failed_items name it by. No unique: the Cloud files what the signed
    # result says.
    position: Mapped[int] = mapped_column(Integer, nullable=False)
    type: Mapped[str] = mapped_column(Text, nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    expected_kind: Mapped[str] = mapped_column(Text, nullable=False)
    expected_sha256: Mapped[str | None] = mapped_column(Text)
    found_sha256: Mapped[str | None] = mapped_column(Text)
    # Null for an item that couldn't be checked: not known, never false.
    found: Mapped[bool | None] = mapped_column(Boolean)
    match: Mapped[bool | None] = mapped_column(Boolean)
    reason: Mapped[str | None] = mapped_column(Text)
    ms: Mapped[int | None] = mapped_column(BigInteger)


class Report(Base):
    __tablename__ = "report"
    __table_args__ = (
        _same_msp(("client_id",), "client", ("id",)),
        _sha256_check("sha256"),
    )

    id: Mapped[uuid.UUID] = _id()
    msp_id: Mapped[uuid.UUID] = _msp_id()
    client_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    period_start: Mapped[dt.date] = mapped_column(Date, nullable=False)
    period_end: Mapped[dt.date] = mapped_column(Date, nullable=False)
    storage_key: Mapped[str] = mapped_column(Text, nullable=False)
    sha256: Mapped[str] = mapped_column(Text, nullable=False)
    generated_at: Mapped[dt.datetime] = _time(nullable=False, default_now=True)


class AuditLog(Base):
    __tablename__ = "audit_log"
    __table_args__ = (_same_msp(("user_id",), "user", ("id",)),)

    id: Mapped[uuid.UUID] = _id()
    msp_id: Mapped[uuid.UUID] = _msp_id()
    # Null for what the admin CLI or the scheduler did.
    user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    action: Mapped[str] = mapped_column(Text, nullable=False)
    target: Mapped[str] = mapped_column(Text, nullable=False)
    ip: Mapped[str | None] = mapped_column(InetText)
    at: Mapped[dt.datetime] = _time(nullable=False, default_now=True)


class InstallToken(Base):
    __tablename__ = "install_token"
    __table_args__ = (
        # C5.5: who made the token; null for the CLI, as audit_log.user_id is.
        _same_msp(("created_by",), "user", ("id",)),
        # What worker.install_token_id points at.
        UniqueConstraint("msp_id", "id"),
        # C5.4 finds a token by its hash alone, before any MSP is known.
        UniqueConstraint("token_hash"),
    )

    id: Mapped[uuid.UUID] = _id()
    msp_id: Mapped[uuid.UUID] = _msp_id()
    token_hash: Mapped[str] = mapped_column(Text, nullable=False)
    # What the MSP admin typed when the token was made (C5.5). A token names
    # no client: a Worker is an MSP's, and connectors bind clients later.
    label: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[dt.datetime] = _time(nullable=False, default_now=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    expires_at: Mapped[dt.datetime] = _time(nullable=False)
    used_at: Mapped[dt.datetime | None] = _time()

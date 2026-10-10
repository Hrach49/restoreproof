"""The initial schema: the eleven tables of C5.2 with C5.13's constraints.

Written by hand and frozen: it imports nothing from app.models, so a later
change to a model never changes what this migration builds. Every constraint
and index is named here in full (`op.f`), following the models' convention.
tests/test_migrations.py holds this file and the models together.

Revision ID: 0001
Revises:
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

SHA256_RULE = "^[0-9a-f]{64}$"

# In the order they are made; dropped in reverse.
TABLES = (
    "msp",
    "user",
    "client",
    "install_token",
    "worker",
    "audit_log",
    "connector",
    "report",
    "test_plan",
    "test_run",
    "test_item",
)


def _id() -> sa.Column:
    return sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False)


def _msp_id() -> sa.Column:
    return sa.Column("msp_id", sa.Uuid(), nullable=False)


def _uuid(name: str, *, nullable: bool = False) -> sa.Column:
    return sa.Column(name, sa.Uuid(), nullable=nullable)


def _text(name: str, *, nullable: bool = False, default: str | None = None) -> sa.Column:
    server_default = None if default is None else sa.text(f"'{default}'")
    return sa.Column(name, sa.Text(), server_default=server_default, nullable=nullable)


def _time(name: str, *, nullable: bool = True, default_now: bool = False) -> sa.Column:
    return sa.Column(
        name,
        sa.DateTime(timezone=True),
        server_default=sa.text("now()") if default_now else None,
        nullable=nullable,
    )


def _boolean(name: str, *, nullable: bool = True, default: str | None = None) -> sa.Column:
    server_default = None if default is None else sa.text(default)
    return sa.Column(name, sa.Boolean(), server_default=server_default, nullable=nullable)


def _pk(table: str) -> sa.PrimaryKeyConstraint:
    return sa.PrimaryKeyConstraint("id", name=op.f(f"pk_{table}"))


def _fk_msp(table: str) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(["msp_id"], ["msp.id"], name=op.f(f"fk_{table}_msp_id_msp"))


def _fk(table: str, columns: tuple[str, ...], target: str, referred: tuple[str, ...]) -> sa.ForeignKeyConstraint:
    """A key to `target` that starts with `msp_id` on both sides."""
    local = ("msp_id", *columns)
    return sa.ForeignKeyConstraint(
        list(local),
        [f"{target}.msp_id", *(f"{target}.{name}" for name in referred)],
        name=op.f(f"fk_{table}_{'_'.join(local)}_{target}"),
    )


def _unique(table: str, *columns: str) -> sa.UniqueConstraint:
    return sa.UniqueConstraint(*columns, name=op.f(f"uq_{table}_{'_'.join(columns)}"))


def _check(table: str, name: str, condition: str) -> sa.CheckConstraint:
    return sa.CheckConstraint(condition, name=op.f(f"ck_{table}_{name}"))


def _sha256(table: str, column: str) -> sa.CheckConstraint:
    return _check(table, f"{column}_hex", f"{column} ~ '{SHA256_RULE}'")


def upgrade() -> None:
    op.create_table(
        "msp",
        _id(),
        _text("name"),
        _time("created_at", nullable=False, default_now=True),
        sa.Column("retention_days", sa.Integer(), server_default=sa.text("1095"), nullable=False),
        _pk("msp"),
        _check("msp", "retention_days_positive", "retention_days > 0"),
    )

    op.create_table(
        "user",
        _id(),
        _msp_id(),
        _text("email"),
        _text("password_hash"),
        _text("role"),
        _pk("user"),
        _fk_msp("user"),
        _unique("user", "msp_id", "id"),
    )
    op.create_index("uq_user_email_lower", "user", [sa.text("lower(email)")], unique=True)

    op.create_table(
        "client",
        _id(),
        _msp_id(),
        _text("name"),
        _uuid("tenant_id"),
        _boolean("screenshots_enabled", nullable=False, default="false"),
        _pk("client"),
        _fk_msp("client"),
        _unique("client", "msp_id", "id"),
        _unique("client", "msp_id", "tenant_id"),
    )

    op.create_table(
        "install_token",
        _id(),
        _msp_id(),
        _text("token_hash"),
        _text("label"),
        _time("created_at", nullable=False, default_now=True),
        _uuid("created_by", nullable=True),
        _time("expires_at", nullable=False),
        _time("used_at"),
        _pk("install_token"),
        _fk_msp("install_token"),
        _fk("install_token", ("created_by",), "user", ("id",)),
        _unique("install_token", "msp_id", "id"),
        _unique("install_token", "token_hash"),
    )

    op.create_table(
        "worker",
        _id(),
        _msp_id(),
        _text("name"),
        _text("public_key_pem"),
        _text("key_id"),
        _text("api_token_hash"),
        _uuid("install_token_id", nullable=True),
        _text("version", nullable=True),
        _time("last_seen_at"),
        _text("last_error", nullable=True),
        _time("revoked_at"),
        _pk("worker"),
        _fk_msp("worker"),
        _fk("worker", ("install_token_id",), "install_token", ("id",)),
        _unique("worker", "msp_id", "id"),
        _unique("worker", "api_token_hash"),
        _unique("worker", "key_id"),
        _sha256("worker", "key_id"),
    )

    op.create_table(
        "audit_log",
        _id(),
        _msp_id(),
        _uuid("user_id", nullable=True),
        _text("action"),
        _text("target"),
        sa.Column("ip", postgresql.INET(), nullable=True),
        _time("at", nullable=False, default_now=True),
        _pk("audit_log"),
        _fk_msp("audit_log"),
        _fk("audit_log", ("user_id",), "user", ("id",)),
    )

    op.create_table(
        "connector",
        _id(),
        _msp_id(),
        _uuid("client_id"),
        _uuid("worker_id"),
        _text("type", default="veeam_m365"),
        sa.Column("config_json", postgresql.JSONB(), nullable=False),
        _pk("connector"),
        _fk_msp("connector"),
        _fk("connector", ("client_id",), "client", ("id",)),
        _fk("connector", ("worker_id",), "worker", ("id",)),
        _unique("connector", "msp_id", "id"),
        _unique("connector", "msp_id", "id", "client_id"),
        _unique("connector", "msp_id", "id", "worker_id"),
        _unique("connector", "worker_id", "client_id"),
        _check("connector", "type_name", "type ~ '^[a-z0-9_]{1,64}$'"),
    )

    op.create_table(
        "report",
        _id(),
        _msp_id(),
        _uuid("client_id"),
        sa.Column("period_start", sa.Date(), nullable=False),
        sa.Column("period_end", sa.Date(), nullable=False),
        _text("storage_key"),
        _text("sha256"),
        _time("generated_at", nullable=False, default_now=True),
        _pk("report"),
        _fk_msp("report"),
        _fk("report", ("client_id",), "client", ("id",)),
        _sha256("report", "sha256"),
    )

    op.create_table(
        "test_plan",
        _id(),
        _msp_id(),
        _uuid("client_id"),
        _uuid("connector_id"),
        sa.Column("sample_mail", sa.Integer(), nullable=False),
        sa.Column("sample_sp", sa.Integer(), nullable=False),
        sa.Column("sample_od", sa.Integer(), nullable=False),
        _text("cadence_cron"),
        _boolean("enabled", nullable=False, default="true"),
        _pk("test_plan"),
        _fk_msp("test_plan"),
        _fk("test_plan", ("client_id",), "client", ("id",)),
        _fk("test_plan", ("connector_id", "client_id"), "connector", ("id", "client_id")),
        _unique("test_plan", "msp_id", "id"),
        _unique("test_plan", "msp_id", "id", "connector_id", "client_id"),
        _check("test_plan", "sample_mail_range", "sample_mail BETWEEN 0 AND 100"),
        _check("test_plan", "sample_sp_range", "sample_sp BETWEEN 0 AND 100"),
        _check("test_plan", "sample_od_range", "sample_od BETWEEN 0 AND 100"),
        _check("test_plan", "sample_not_empty", "sample_mail + sample_sp + sample_od > 0"),
    )

    op.create_table(
        "test_run",
        _id(),
        _msp_id(),
        _uuid("client_id"),
        _uuid("worker_id"),
        _uuid("plan_id"),
        _uuid("connector_id"),
        _text("state", default="queued"),
        _time("restore_point_at"),
        _time("started_at"),
        _time("finished_at"),
        sa.Column("total_ms", sa.BigInteger(), nullable=True),
        _text("bundle_key", nullable=True),
        _text("bundle_sha256", nullable=True),
        _boolean("signature_ok"),
        _boolean("tsa_ok"),
        _boolean("cleanup_ok"),
        _text("error_code", nullable=True),
        _text("error_message", nullable=True),
        _time("created_at", nullable=False, default_now=True),
        _pk("test_run"),
        _fk_msp("test_run"),
        _fk("test_run", ("client_id",), "client", ("id",)),
        _fk("test_run", ("worker_id",), "worker", ("id",)),
        _fk("test_run", ("plan_id", "connector_id", "client_id"), "test_plan", ("id", "connector_id", "client_id")),
        _fk("test_run", ("connector_id", "worker_id"), "connector", ("id", "worker_id")),
        _unique("test_run", "msp_id", "id"),
        _check(
            "test_run",
            "state",
            "state IN ('queued', 'dispatched', 'received', 'pass', 'fail', 'error', 'expired')",
        ),
        _check("test_run", "total_ms_not_negative", "total_ms >= 0"),
        _sha256("test_run", "bundle_sha256"),
    )
    op.create_index(
        op.f("ix_test_run_msp_id_client_id_created_at"),
        "test_run",
        ["msp_id", "client_id", "created_at"],
    )

    op.create_table(
        "test_item",
        _id(),
        _msp_id(),
        _uuid("run_id"),
        _text("type"),
        _text("name"),
        _text("expected_kind"),
        _text("expected_sha256", nullable=True),
        _text("found_sha256", nullable=True),
        _boolean("found"),
        _boolean("match"),
        _text("reason", nullable=True),
        sa.Column("ms", sa.BigInteger(), nullable=True),
        _pk("test_item"),
        _fk_msp("test_item"),
        _fk("test_item", ("run_id",), "test_run", ("id",)),
        _check("test_item", "ms_not_negative", "ms >= 0"),
        _sha256("test_item", "expected_sha256"),
        _sha256("test_item", "found_sha256"),
    )
    op.create_index(op.f("ix_test_item_msp_id_run_id"), "test_item", ["msp_id", "run_id"])


def downgrade() -> None:
    # A table's indexes and constraints go with it.
    for table in reversed(TABLES):
        op.drop_table(table)

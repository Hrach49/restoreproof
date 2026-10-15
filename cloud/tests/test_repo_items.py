"""C5.7: `ItemRepo` by itself (docs/decisions.md 2026-10-10, C5.7, point 12):
a row per item of a result, with its `position`, written in one statement by
`create_many`, listed in the result's order.
"""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from sqlalchemy import event, text

from app.repo.items import ItemRepo, ItemRow
from app.repo.runs import RunRepo
from tests.test_repo_runs import NOW, UTC, Queue


def item(position: int, **changes) -> ItemRow:
    values = dict(
        position=position,
        type="mail",
        name=f"subject {position}",
        expected_kind="fields",
        expected_sha256=None,
        found_sha256=None,
        found=True,
        match=True,
        reason=None,
        ms=1200,
    )
    return ItemRow(**{**values, **changes})


async def a_run(session):
    q = await Queue.make(session)
    return q, await q.run(created_at=NOW)


async def test_create_takes_the_position_and_list_answers_by_position_then_id(session):
    q, run = await a_run(session)
    items = ItemRepo(session)

    second = await items.create(q.msp.id, run.id, position=1, type="sharepoint", name="b.docx", expected_kind="metadata")
    first = await items.create(
        q.msp.id, run.id, position=0, type="mail", name="a", expected_kind="manifest", expected_sha256="ab" * 32
    )
    also_first = await items.create(q.msp.id, run.id, position=0, type="onedrive", name="c.pdf", expected_kind="manifest")

    listed = await items.list(q.msp.id, run.id)
    assert [row.id for row in listed] == sorted([first.id, also_first.id]) + [second.id]
    assert [row.position for row in listed] == [0, 0, 1]


@pytest.mark.parametrize("count", [0, 1, 6])
async def test_create_many_writes_every_row_in_one_statement_and_none_for_none(session, test_engine, count):
    q, run = await a_run(session)
    rows = [item(i, match=i % 2 == 0, reason=None if i % 2 == 0 else "no restored copy found") for i in range(count)]
    counted: list[str] = []

    def record(_conn, _cursor, statement, _params, _context, _executemany):
        counted.append(statement.strip().split()[0].upper())

    event.listen(test_engine.sync_engine, "before_cursor_execute", record)
    try:
        written = await ItemRepo(session).create_many(q.msp.id, run.id, rows)
    finally:
        event.remove(test_engine.sync_engine, "before_cursor_execute", record)

    assert written == count
    assert counted == (["INSERT"] if count else [])
    listed = await ItemRepo(session).list(q.msp.id, run.id)
    assert [(row.position, row.name, row.match, row.reason, row.ms) for row in listed] == [
        (r.position, r.name, r.match, r.reason, r.ms) for r in rows
    ]
    assert all(row.msp_id == q.msp.id and row.run_id == run.id for row in listed)


async def test_create_many_files_every_column_of_the_row(session):
    q, run = await a_run(session)
    row = item(
        3,
        type="onedrive",
        name="Übersicht.docx",
        expected_kind="manifest",
        expected_sha256="ab" * 32,
        found=False,
        match=False,
        reason="no restored copy found",
        ms=None,
    )

    assert await ItemRepo(session).create_many(q.msp.id, run.id, [row]) == 1

    (stored,) = await ItemRepo(session).list(q.msp.id, run.id)
    for column in ItemRow.__dataclass_fields__:
        assert getattr(stored, column) == getattr(row, column), column


# --- C6.4: the month's items (docs/decisions.md 2026-10-12, "C6.4", point 5) --------------------

OCT = dt.datetime(2026, 10, 1, tzinfo=UTC)
NOV = dt.datetime(2026, 11, 1, tzinfo=UTC)


async def a_month(session):
    """A pass with three matched items of three types, a fail with a missing
    mail, a mismatched file and a matched one, an error with an item nobody
    checked, an expired run with an item (none should have one, but the read
    counts what is there), a queued run with an item (no test, but the
    month's since the C6.4 review's finding 2: a run with no result yet), a
    run of last month, and the other MSP's run of this month."""
    q = await Queue.make(session)
    b = await Queue.make(session, "b")
    items = ItemRepo(session)

    async def run(state, at, other=False):
        row = await q.run(created_at=at, state=state, other=other)
        await session.execute(text("UPDATE test_run SET finished_at = :f WHERE id = :id"), {"f": at if state in ("pass", "fail", "error") else None, "id": row.id})
        return row

    passed = await run("pass", dt.datetime(2026, 10, 2, tzinfo=UTC))
    await items.create_many(q.msp.id, passed.id, [
        item(0), item(1, type="sharepoint", name="a.docx", expected_kind="backup_content"), item(2, type="onedrive", name="b.pdf", expected_kind="metadata"),
        item(3, type="onedrive", name="c.pdf", expected_kind="backup_content"),
    ])
    failed = await run("fail", dt.datetime(2026, 10, 3, tzinfo=UTC))
    await items.create_many(q.msp.id, failed.id, [
        item(0, name="gone", found=False, match=False, reason="no restored copy found"),
        item(1, type="sharepoint", name="changed.docx", expected_kind="backup_content", found=True, match=False, reason="hash differs"),
        item(2, type="sharepoint", name="fine.docx", expected_kind="manifest"),
    ])
    errored = await run("error", dt.datetime(2026, 10, 4, tzinfo=UTC))
    await items.create_many(q.msp.id, errored.id, [item(0, name="unchecked", found=None, match=None, reason=None)])
    expired = await run("expired", dt.datetime(2026, 10, 5, tzinfo=UTC))
    await items.create_many(q.msp.id, expired.id, [item(0, name="odd")])
    queued = await run("queued", dt.datetime(2026, 10, 6, tzinfo=UTC))
    await items.create_many(q.msp.id, queued.id, [item(0, name="not a test", match=False)])
    old = await run("fail", dt.datetime(2026, 9, 6, tzinfo=UTC))
    await items.create_many(q.msp.id, old.id, [item(0, name="last month", match=False)])
    theirs = await b.run(created_at=dt.datetime(2026, 10, 3, tzinfo=UTC), state="fail")
    await session.execute(text("UPDATE test_run SET finished_at = created_at WHERE id = :id"), {"id": theirs.id})
    await items.create_many(b.msp.id, theirs.id, [item(0, name="theirs", match=False)])
    return q, b, passed, failed, errored, expired, queued


async def test_counts_by_type_in_period_counts_the_month_s_runs_items_per_run_type_and_kind(session):
    """C6.8 (docs/decisions.md 2026-10-15, point 1): grouped by the expected
    kind too, so the report knows what each test compared from one read."""
    q, b, passed, failed, errored, expired, queued = await a_month(session)

    counts = await ItemRepo(session).counts_by_type_in_period(q.msp.id, q.client.id, start=OCT, end=NOV)

    # The last number counts the items compared: found, with `match` known
    # (the C6.8 code review's finding 1): the missing mail and the item
    # nobody checked were not.
    assert [(c.run_id, c.type, c.expected_kind, c.count, c.compared) for c in counts] == [
        (passed.id, "mail", "fields", 1, 1), (passed.id, "onedrive", "backup_content", 1, 1),
        (passed.id, "onedrive", "metadata", 1, 1), (passed.id, "sharepoint", "backup_content", 1, 1),
        (failed.id, "mail", "fields", 1, 0), (failed.id, "sharepoint", "backup_content", 1, 1),
        (failed.id, "sharepoint", "manifest", 1, 1),
        (errored.id, "mail", "fields", 1, 0),
        (expired.id, "mail", "fields", 1, 1),
        (queued.id, "mail", "fields", 1, 1),
    ]
    assert await ItemRepo(session).counts_by_type_in_period(q.msp.id, b.client.id, start=OCT, end=NOV) == []
    assert await ItemRepo(session).counts_by_type_in_period(b.msp.id, q.client.id, start=OCT, end=NOV) == []


async def test_unmatched_in_period_answers_the_failed_and_errored_runs_items_that_did_not_match(session):
    """By run (the month's order) then position; a matched item, a queued
    run's, an expired run's, last month's and the other MSP's never."""
    q, b, passed, failed, errored, expired, queued = await a_month(session)

    rows = await ItemRepo(session).unmatched_in_period(q.msp.id, q.client.id, start=OCT, end=NOV)

    assert [(row.run_id, row.position, row.name, row.found, row.match, row.reason) for row in rows] == [
        (failed.id, 0, "gone", False, False, "no restored copy found"),
        (failed.id, 1, "changed.docx", True, False, "hash differs"),
        (errored.id, 0, "unchecked", None, None, None),
    ]
    assert await ItemRepo(session).unmatched_in_period(q.msp.id, b.client.id, start=OCT, end=NOV) == []
    assert await ItemRepo(session).unmatched_in_period(b.msp.id, q.client.id, start=OCT, end=NOV) == []


@pytest.mark.parametrize("method", ["counts_by_type_in_period", "unmatched_in_period"])
async def test_the_month_s_item_reads_are_one_statement_each_and_refuse_a_naive_edge(session, test_engine, method):
    q, *_ = await a_month(session)
    statements: list[str] = []

    def record(_conn, _cursor, statement, _params, _context, _executemany):
        statements.append(statement.strip().split()[0].upper())

    event.listen(test_engine.sync_engine, "before_cursor_execute", record)
    try:
        await getattr(ItemRepo(session), method)(q.msp.id, q.client.id, start=OCT, end=NOV)
    finally:
        event.remove(test_engine.sync_engine, "before_cursor_execute", record)

    assert statements == ["SELECT"]
    with pytest.raises(ValueError, match="without a zone"):
        await getattr(ItemRepo(session), method)(q.msp.id, q.client.id, start=dt.datetime(2026, 10, 1), end=NOV)


async def test_create_many_takes_the_caller_s_msp_and_run_never_the_row_s(session):
    q, run = await a_run(session)
    other = await q.run(created_at=NOW)

    await ItemRepo(session).create_many(q.msp.id, run.id, [item(0)])

    assert await ItemRepo(session).list(q.msp.id, other.id) == []
    assert await ItemRepo(session).list(uuid.uuid4(), run.id) == []
    assert len(await ItemRepo(session).list(q.msp.id, run.id)) == 1
    assert await RunRepo(session).get(q.msp.id, run.id) is not None

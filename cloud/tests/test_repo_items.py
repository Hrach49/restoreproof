"""C5.7: `ItemRepo` by itself (docs/decisions.md 2026-10-10, C5.7, point 12):
a row per item of a result, with its `position`, written in one statement by
`create_many`, listed in the result's order.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import event

from app.repo.items import ItemRepo, ItemRow
from app.repo.runs import RunRepo
from tests.test_repo_runs import NOW, Queue


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


async def test_create_many_takes_the_caller_s_msp_and_run_never_the_row_s(session):
    q, run = await a_run(session)
    other = await q.run(created_at=NOW)

    await ItemRepo(session).create_many(q.msp.id, run.id, [item(0)])

    assert await ItemRepo(session).list(q.msp.id, other.id) == []
    assert await ItemRepo(session).list(uuid.uuid4(), run.id) == []
    assert len(await ItemRepo(session).list(q.msp.id, run.id)) == 1
    assert await RunRepo(session).get(q.msp.id, run.id) is not None

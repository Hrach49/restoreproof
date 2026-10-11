"""C5.9: a plan's cadence (docs/decisions.md 2026-10-11, "C5.10 and C5.9",
points 6 and 7). `parse` holds the text to five fields and to croniter;
`check_monthly` to at least monthly (from every day's start in the 400 days
after `now`, the next occurrence is within 31 days); `due_at` is the latest
occurrence at or before `now`, the start of the period that is current.
"""

from __future__ import annotations

import datetime as dt

import pytest

from app import cadence
from app.cadence import CadenceError, check_monthly, check_spacing, due_at, parse

UTC = dt.timezone.utc
NOW = dt.datetime(2026, 10, 11, 12, 0, 30, tzinfo=UTC)


def at(*args) -> dt.datetime:
    return dt.datetime(*args, tzinfo=UTC)


# --- parse: five fields, then croniter -------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "",
        " ",
        "nonsense",
        "0 2 * *",  # four fields
        "0 2 * * * *",  # six: croniter would take seconds
        "0 0 2 * * *",
        "@daily",  # croniter takes it; the Cloud's form is five fields
        "60 2 * * *",
        "0 24 * * *",
        "0 2 32 * *",
        "0 2 * 13 *",
        "0 2 * * 8",
        "0  2 * * *",  # two spaces: not five space-separated fields
        " 0 2 * * *",
        "0 2 * * *\n",
        "0 2 * * *; DROP TABLE test_plan",
        "a b c d e",
        # croniter's random field: a new value for every reader, so no period
        # would have one start (the review's finding 1).
        "R 2 * * *",
        "r 2 * * *",
        "0 R * * *",
        "0 2 R * *",
        "R(0-5) 2 * * *",
        "0 2 R(1-5) * *",
        "0 2 * * R",
        "0,R 2 * * *",
    ],
)
def test_a_text_that_is_not_a_five_field_cron_is_refused(text):
    with pytest.raises(CadenceError) as raised:
        parse(text)

    assert raised.value.reason == cadence.NOT_A_CRON
    assert str(raised.value) == cadence.NOT_A_CRON
    assert text.strip() not in str(raised.value) or text.strip() == ""


@pytest.mark.parametrize("text", ["0 2 * * *", "*/5 * * * *", "0 2 1 * *", "0 2 L * *", "0 2 * * 1", "30 23 */3 * *", "0 2 1 */2 *", "0 2 1 1 *"])
def test_a_five_field_cron_is_parsed(text):
    assert parse(text).text == text


@pytest.mark.parametrize("text", ["0 2 * MAR FRI", "0 2 * apr,mar thu", "0 2 * * fri", "0 2 * JAN-DEC *"])
def test_a_name_with_an_r_in_it_is_no_random_field(text):
    assert parse(text).text == text


def test_two_readers_of_one_cadence_agree_on_the_period(monkeypatch):
    """What the random field broke: `due_at` is one value however often it
    is asked, for every form `parse` takes."""
    for text in ["0 2 * * *", "*/5 * * * *", "0 2 L * *", "0 2 * MAR FRI"]:
        assert len({due_at(parse(text), NOW) for _ in range(20)}) == 1


# --- a cron no date can meet ------------------------------------------------------------


@pytest.mark.parametrize("text", ["0 0 31 2 *", "0 2 30 2 *", "0 2 31 4,6 *"])
def test_a_cron_that_never_occurs_is_refused_with_its_own_word(text):
    """croniter takes it and then can't walk it (the review's finding 2):
    a `CadenceError`, never croniter's own error."""
    cron = parse(text)

    for work in (
        lambda: check_monthly(cron, NOW),
        lambda: due_at(cron, NOW),
        lambda: cron.next_after(NOW),
        lambda: cron.previous_before(NOW),
    ):
        with pytest.raises(CadenceError) as raised:
            work()
        assert raised.value.reason == cadence.NEVER_OCCURS == "never occurs"
        assert raised.value.__cause__ is None and raised.value.__suppress_context__


# --- check_spacing: at most every five minutes -------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "*/5 * * * *",  # the tick itself: the Done-when's cron
        "0 2 * * *",
        "0,5 2 * * *",
        "0,58 2 * * *",  # 58 and 0 of one hour alone: 58 minutes apart
        "58 23 * * *",
        "0,58 2,4 * * *",  # hours that never follow each other
        "55 * * * *",
        "0,30 * * * *",
        "0 2 L * *",
    ],
)
def test_a_cron_no_finer_than_five_minutes_passes(text):
    check_spacing(parse(text))


@pytest.mark.parametrize(
    "text",
    [
        "* * * * *",  # every minute (the review's finding 4)
        "*/1 * * * *",
        "*/2 * * * *",
        "*/4 * * * *",
        "0,4 2 * * *",  # two minutes of one hour, four apart
        "0-10 2 * * *",
        "0,58 * * * *",  # 58 and the next hour's 0
        "0,58 2,3 * * *",
        "0,58 0,23 * * *",  # 23:58 and 00:00
        "*/7 * * * *",  # 56 and the next hour's 0
    ],
)
def test_a_cron_finer_than_five_minutes_is_refused(text):
    with pytest.raises(CadenceError) as raised:
        check_spacing(parse(text))

    assert raised.value.reason == cadence.TOO_OFTEN == "more often than every 5 minutes"


def test_the_floor_is_the_scheduler_s_tick():
    from app.scheduler import TICK_S

    assert cadence.MIN_PERIOD == dt.timedelta(seconds=TICK_S) == dt.timedelta(minutes=5)


# --- check_monthly ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    ["0 2 * * *", "*/5 * * * *", "0 2 1 * *", "0 2 15 * *", "0 2 L * *", "0 2 * * 1", "0 2 28 * *", "0 2 1,15 * *"],
)
def test_a_cron_that_fires_at_least_monthly_passes(text):
    check_monthly(parse(text), NOW)


@pytest.mark.parametrize(
    "text",
    [
        "0 2 31 * *",  # 58 days from February
        "0 2 30 * *",  # February has no 30th
        "0 2 1 */2 *",  # bi-monthly
        "0 2 1 1 *",  # yearly
        "0 2 29 2 *",  # a leap day
        "0 2 1 1,7 *",
    ],
)
def test_a_cron_that_can_skip_a_month_is_refused(text):
    with pytest.raises(CadenceError) as raised:
        check_monthly(parse(text), NOW)

    assert raised.value.reason == cadence.LESS_THAN_MONTHLY


def test_the_bound_is_31_days_from_a_day_s_start():
    """A gap of exactly 31 days between occurrences passes (the 1st of
    every month: from Jan 2's start, Feb 1 02:00 is 30 days and 2 hours);
    the rule's constants are what the entry says."""
    assert cadence.MONTHLY_BOUND == dt.timedelta(days=31)
    assert cadence.MONTHLY_SPAN_DAYS == 400
    check_monthly(parse("0 2 1 * *"), at(2026, 1, 1))
    # 2026-01-01 00:00 → from 2026-01-02 the next is 2026-02-01 00:00: 30 days.
    check_monthly(parse("0 0 1 * *"), at(2026, 1, 1))


def test_the_rule_walks_400_day_starts_from_now(monkeypatch):
    seen = []
    original = cadence.Cadence.next_after

    def spy(self, start):
        seen.append(start)
        return original(self, start)

    monkeypatch.setattr(cadence.Cadence, "next_after", spy)
    check_monthly(parse("0 2 * * *"), NOW)

    assert len(seen) == 400
    assert seen[0] == at(2026, 10, 11)
    assert seen[-1] == at(2026, 10, 11) + dt.timedelta(days=399)
    assert all(start.hour == 0 and start.minute == 0 and start.second == 0 for start in seen)


# --- due_at: the latest occurrence at or before now -----------------------------------------


@pytest.mark.parametrize(
    ("text", "now", "due"),
    [
        ("0 2 * * *", at(2026, 10, 11, 2, 0, 0), at(2026, 10, 11, 2, 0)),  # at the occurrence itself
        ("0 2 * * *", at(2026, 10, 11, 2, 0, 0, 500000), at(2026, 10, 11, 2, 0)),  # half a second after
        ("0 2 * * *", at(2026, 10, 11, 1, 59, 59), at(2026, 10, 10, 2, 0)),  # a second before
        ("0 2 * * *", at(2026, 10, 11, 23, 59), at(2026, 10, 11, 2, 0)),
        ("*/5 * * * *", at(2026, 10, 11, 12, 7, 30), at(2026, 10, 11, 12, 5)),
        ("*/5 * * * *", at(2026, 10, 11, 12, 5, 0), at(2026, 10, 11, 12, 5)),
        ("*/5 * * * *", at(2026, 10, 11, 0, 0, 0), at(2026, 10, 11, 0, 0)),
        ("0 2 1 * *", at(2026, 11, 1, 1, 0), at(2026, 10, 1, 2, 0)),  # across a month's end
        ("0 2 1 * *", at(2026, 11, 1, 2, 0), at(2026, 11, 1, 2, 0)),
        ("0 2 L * *", at(2026, 3, 1, 0, 0), at(2026, 2, 28, 2, 0)),
    ],
)
def test_due_at_is_the_latest_occurrence_at_or_before_now(text, now, due):
    assert due_at(parse(text), now) == due


def test_due_at_answers_an_aware_utc_time():
    due = due_at(parse("0 2 * * *"), NOW)

    assert due.tzinfo is not None and due.utcoffset() == dt.timedelta(0)


def test_due_at_refuses_a_naive_now():
    with pytest.raises(ValueError):
        due_at(parse("0 2 * * *"), dt.datetime(2026, 10, 11, 12, 0))


def test_next_after_is_strictly_after():
    cron = parse("0 2 * * *")

    assert cron.next_after(at(2026, 10, 11, 2, 0)) == at(2026, 10, 12, 2, 0)
    assert cron.next_after(at(2026, 10, 11, 1, 59)) == at(2026, 10, 11, 2, 0)


def test_the_default_cadence_is_the_guide_s_daily_two_o_clock():
    assert cadence.DEFAULT_CADENCE == "0 2 * * *"
    check_monthly(parse(cadence.DEFAULT_CADENCE), NOW)

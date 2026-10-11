"""A plan's cadence (C5.9; docs/decisions.md 2026-10-11, "C5.10 and C5.9",
points 6 and 7): what `test_plan.cadence_cron` may say and when a period starts.

A cadence is exactly five space-separated cron fields, read in UTC and nothing
else, parsed by croniter (so `L`, ranges, steps and lists are what croniter
takes); croniter's six-field form with seconds and its `@daily` words are
refused, so there is one form, and so is croniter's random `R` (a field
croniter draws anew for every reader, so no two would agree on a period's
start). A cron no date can meet (`0 0 31 2 *`) is one croniter takes and then
can't walk: `never occurs`, here and not croniter's own error. A cadence is at
most every `MIN_PERIOD` (the scheduler's tick: a finer period could get no run
of its own), held on the minute and hour fields: two minutes of one hour less
than five apart, or the last of an hour and the first of the next when the
hours can follow each other. A cadence is at least monthly: from the start
of every day in the 400 days after `now` (a leap year and every month's length
covered), the next occurrence is within 31 days; a cron that skips a month
(`0 2 31 * *`, `0 2 1 */2 *`, `0 2 1 1 *`) is refused where the plan is made,
since C6.4's monthly report wants a run in every period it covers.

`due_at` is the latest occurrence at or before `now`: the start of the period
that is current, which `test_run.scheduled_for` names and the unique
`uq_test_run_msp_id_plan_id_scheduled_for` holds to one run.

Strict (100% line and branch): this decides whether a run is made.
"""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass

from croniter import CroniterBadDateError, croniter

DEFAULT_CADENCE = "0 2 * * *"

NOT_A_CRON = "not a cron expression"
LESS_THAN_MONTHLY = "less than monthly"
NEVER_OCCURS = "never occurs"
TOO_OFTEN = "more often than every 5 minutes"

# The scheduler's tick (`app.scheduler.TICK_S`; a test holds the two equal).
MIN_PERIOD = dt.timedelta(minutes=5)

MONTHLY_BOUND = dt.timedelta(days=31)
MONTHLY_SPAN_DAYS = 400

_FIVE_FIELDS = re.compile(r"^\S+( \S+){4}$")
# croniter's random field, `R` or `R(1-5)`: an `r` that is no letter of a name.
_RANDOM = re.compile(r"(?<![a-z])r(?![a-z])", re.IGNORECASE)
_UTC = dt.timezone.utc


class CadenceError(ValueError):
    """A cadence that is refused; the text holds the reason and never the cadence."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class Cadence:
    text: str

    def next_after(self, start: dt.datetime) -> dt.datetime:
        """The first occurrence strictly after `start`."""
        try:
            return croniter(self.text, start).get_next(dt.datetime)
        except CroniterBadDateError:
            raise CadenceError(NEVER_OCCURS) from None

    def previous_before(self, start: dt.datetime) -> dt.datetime:
        """The last occurrence strictly before `start`."""
        try:
            return croniter(self.text, start).get_prev(dt.datetime)
        except CroniterBadDateError:
            raise CadenceError(NEVER_OCCURS) from None

    def minutes_and_hours(self) -> tuple[list[int], list[int]]:
        """The minutes of an hour and the hours of a day the cron names."""
        minutes, hours = croniter(self.text).expanded[:2]
        return (
            list(range(60)) if minutes == ["*"] else sorted(minutes),
            list(range(24)) if hours == ["*"] else sorted(hours),
        )


def parse(text: str) -> Cadence:
    """The cadence, or `CadenceError(NOT_A_CRON)`."""
    if not _FIVE_FIELDS.fullmatch(text) or _RANDOM.search(text) or not croniter.is_valid(text):
        raise CadenceError(NOT_A_CRON)
    return Cadence(text)


def _aware(now: dt.datetime) -> dt.datetime:
    if now.utcoffset() is None:
        raise ValueError("a time without a zone: give an aware UTC datetime")
    return now.astimezone(_UTC)


def check_spacing(cadence: Cadence) -> None:
    """Refuse a cadence whose occurrences can be less than `MIN_PERIOD` apart:
    by the minute and hour fields alone, so a pair the day fields would keep
    apart (23:58 and 00:00 on days that never follow) is refused too."""
    minutes, hours = cadence.minutes_and_hours()
    gaps = [later - earlier for earlier, later in zip(minutes, minutes[1:])]
    if any((hour + 1) % 24 in hours for hour in hours):
        gaps.append(minutes[0] + 60 - minutes[-1])
    if any(dt.timedelta(minutes=gap) < MIN_PERIOD for gap in gaps):
        raise CadenceError(TOO_OFTEN)


def check_monthly(cadence: Cadence, now: dt.datetime) -> None:
    """Refuse a cadence that can leave a day's start more than 31 days from
    its next occurrence, in the 400 days after `now`."""
    day = _aware(now).replace(hour=0, minute=0, second=0, microsecond=0)
    for _ in range(MONTHLY_SPAN_DAYS):
        if cadence.next_after(day) - day > MONTHLY_BOUND:
            raise CadenceError(LESS_THAN_MONTHLY)
        day += dt.timedelta(days=1)


def due_at(cadence: Cadence, now: dt.datetime) -> dt.datetime:
    """The latest occurrence at or before `now`: croniter's previous is
    strictly before, so the occurrence at `now` itself is the next one
    after that previous when it is not past `now`."""
    now = _aware(now)
    previous = cadence.previous_before(now)
    following = cadence.next_after(previous)
    return following if following <= now else previous

"""C6.1's limiter (docs/decisions.md 2026-10-12, "C6.1, C6.2 and C6.3",
point 7): five attempts a minute per key on a sliding window, every attempt
counted, the sixth refused with the seconds to wait, the table bounded."""

from __future__ import annotations

import pytest

from app.auth.login_limiter import MAX_ATTEMPTS, MAX_KEYS, WINDOW_S, LoginLimiter


class Clock:
    def __init__(self, at: float = 1000.0):
        self.at = at

    def __call__(self) -> float:
        return self.at


def test_the_constants_are_the_entry_s():
    assert (WINDOW_S, MAX_ATTEMPTS, MAX_KEYS) == (60.0, 5, 10_000)


def test_five_attempts_pass_and_the_sixth_is_refused_with_the_seconds_to_wait():
    clock = Clock()
    limiter = LoginLimiter(clock)

    answers = [limiter.attempt(["email:a"]) for _ in range(5)]
    clock.at += 10
    sixth = limiter.attempt(["email:a"])

    assert answers == [None] * 5
    assert sixth == 50


def test_a_refused_attempt_is_not_counted_and_the_window_slides():
    clock = Clock()
    limiter = LoginLimiter(clock)
    for _ in range(5):
        limiter.attempt(["email:a"])
        clock.at += 5  # attempts at 1000, 1005, 1010, 1015, 1020; now 1025

    assert limiter.attempt(["email:a"]) == 35
    clock.at = 1059.9
    assert limiter.attempt(["email:a"]) == 1
    clock.at = 1060.0
    assert limiter.attempt(["email:a"]) is None  # the first fell out at 60 s exactly: one slot free
    assert limiter.attempt(["email:a"]) == 5  # 1005 + 60 - 1060


def test_the_wait_is_at_least_one_second():
    clock = Clock()
    limiter = LoginLimiter(clock)
    for _ in range(5):
        limiter.attempt(["ip:x"])
    clock.at += 59.9

    assert limiter.attempt(["ip:x"]) == 1


def test_either_key_refuses_and_the_longer_wait_wins():
    clock = Clock()
    limiter = LoginLimiter(clock)
    for _ in range(5):
        limiter.attempt(["ip:x", "email:a"])
    clock.at += 30
    for _ in range(4):
        limiter.attempt(["email:b"])
    limiter.attempt(["email:c", "ip:y"])

    assert limiter.attempt(["ip:x", "email:zz"]) == 30  # the IP alone refuses
    assert limiter.attempt(["ip:z", "email:a"]) == 30  # the address alone refuses
    assert limiter.attempt(["ip:z", "email:b"]) is None  # the fifth under b
    assert limiter.attempt(["ip:z", "email:b"]) == 60
    clock.at += 20
    assert limiter.attempt(["ip:x", "email:b"]) == 40  # x waits 10, b waits 40


def test_a_refused_attempt_counts_under_no_key():
    clock = Clock()
    limiter = LoginLimiter(clock)
    for _ in range(5):
        limiter.attempt(["ip:x"])

    assert limiter.attempt(["ip:x", "email:fresh"]) == 60
    for _ in range(5):
        assert limiter.attempt(["email:fresh"]) is None  # nothing was recorded under it
    assert limiter.attempt(["email:fresh"]) == 60


def test_the_table_is_bounded_and_the_least_recently_touched_key_goes_first():
    clock = Clock()
    limiter = LoginLimiter(clock, max_keys=3)
    for key in ("a", "b", "c"):
        limiter.attempt([key])
    limiter.attempt(["a"])  # a touched again: b is now the oldest

    limiter.attempt(["d"])

    assert len(limiter) == 3
    for _ in range(4):
        limiter.attempt(["b"])
    assert limiter.attempt(["b"]) is None  # b started afresh: this is its fifth
    assert limiter.attempt(["b"]) == 60


def test_the_default_clock_and_bounds_are_the_module_s(monkeypatch):
    limiter = LoginLimiter(Clock())

    assert (limiter._window_s, limiter._max_attempts, limiter._max_keys) == (WINDOW_S, MAX_ATTEMPTS, MAX_KEYS)


@pytest.mark.parametrize("keys", [[], ()])
def test_no_key_is_never_refused_and_records_nothing(keys):
    limiter = LoginLimiter(Clock())

    assert limiter.attempt(keys) is None
    assert len(limiter) == 0

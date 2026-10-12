"""The login limiter (C6.1; docs/decisions.md 2026-10-12, "C6.1, C6.2 and
C6.3", point 7): five attempts a minute per key, a sliding window in the
process's memory on a clock the caller gives. Every `POST /login` counts,
right or wrong: the sixth inside the window for any of its keys is refused
before any password work. The table is bounded: past `MAX_KEYS` keys the one
least recently touched is dropped. The count is per process and lost at a
restart (C7.2 owns a shared store).

Guarded at 100% line and branch (tools/check_coverage.py).
"""

from __future__ import annotations

import math
from collections import OrderedDict
from collections.abc import Callable, Iterable

WINDOW_S = 60.0
MAX_ATTEMPTS = 5
MAX_KEYS = 10_000


class LoginLimiter:
    def __init__(self, clock: Callable[[], float], *, window_s: float = WINDOW_S, max_attempts: int = MAX_ATTEMPTS, max_keys: int = MAX_KEYS) -> None:
        self._clock = clock
        self._window_s = window_s
        self._max_attempts = max_attempts
        self._max_keys = max_keys
        self._attempts: OrderedDict[str, list[float]] = OrderedDict()

    def attempt(self, keys: Iterable[str]) -> int | None:
        """Count one attempt under every key, or refuse it: the seconds to wait
        (at least 1) when any key has had its attempts inside the window, else
        None with the attempt recorded under each key."""
        now = self._clock()
        keys = list(keys)
        retry_after: float | None = None
        for key in keys:
            recent = self._recent(key, now)
            if len(recent) >= self._max_attempts:
                wait = recent[0] + self._window_s - now
                retry_after = wait if retry_after is None else max(retry_after, wait)
        if retry_after is not None:
            return max(1, math.ceil(retry_after))
        for key in keys:
            self._recent(key, now).append(now)
            self._attempts.move_to_end(key)
        while len(self._attempts) > self._max_keys:
            self._attempts.popitem(last=False)
        return None

    def _recent(self, key: str, now: float) -> list[float]:
        """The key's attempts inside the window, the older ones dropped."""
        stamps = self._attempts.setdefault(key, [])
        kept = [stamp for stamp in stamps if stamp > now - self._window_s]
        stamps[:] = kept
        return stamps

    def __len__(self) -> int:
        return len(self._attempts)

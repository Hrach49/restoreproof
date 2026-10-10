"""A repo's own refusal: the key it is about and a fixed reason, never a value."""

from __future__ import annotations


class RepoError(Exception):
    def __init__(self, key: str, reason: str) -> None:
        super().__init__(f"{key}: {reason}")
        self.key = key
        self.reason = reason

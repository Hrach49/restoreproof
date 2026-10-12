"""Passwords (C6.1; docs/decisions.md 2026-10-12, "C6.1, C6.2 and C6.3",
point 2): Argon2id by argon2-cffi under the library's defaults (RFC 9106's
second profile: 64 MiB, 3 passes, 4 lanes). `verify_password` answers false
for a wrong password and for a text that is no hash, never an exception; an
unknown address is verified against `unknown_hash()`, so a known and an
unknown address cost the same work. The two run in a thread at the route
(they are CPU work of about 100 ms); nothing here touches the loop. The
password rule is held where a password is set (the CLI), not at login.

Guarded at 100% line and branch (tools/check_coverage.py).
"""

from __future__ import annotations

import secrets
from functools import lru_cache

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

MIN_PASSWORD_CHARACTERS = 12
MAX_PASSWORD_CHARACTERS = 1024
PASSWORD_RULE = f"not {MIN_PASSWORD_CHARACTERS} to {MAX_PASSWORD_CHARACTERS} characters"

_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """True when `password` is the one `password_hash` was made from."""
    try:
        return _hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    """True for a hash made under other parameters than today's."""
    return _hasher.check_needs_rehash(password_hash)


@lru_cache(maxsize=1)
def unknown_hash() -> str:
    """One hash of a password nobody knows, made once: what an unknown
    address is verified against."""
    return hash_password(secrets.token_urlsafe(32))


def check_password_rule(password: str) -> str | None:
    """The reason a password is refused, or None."""
    if not MIN_PASSWORD_CHARACTERS <= len(password) <= MAX_PASSWORD_CHARACTERS:
        return PASSWORD_RULE
    return None

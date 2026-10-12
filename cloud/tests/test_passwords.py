"""C6.1's hashes (docs/decisions.md 2026-10-12, "C6.1, C6.2 and C6.3", point
2): Argon2id under the library's defaults, a wrong password and a text that
is no hash both false, the unknown hash made once, the rule's bounds."""

from __future__ import annotations

import argon2
import pytest

from app.auth import passwords
from app.auth.passwords import (
    MAX_PASSWORD_CHARACTERS,
    MIN_PASSWORD_CHARACTERS,
    PASSWORD_RULE,
    check_password_rule,
    hash_password,
    needs_rehash,
    unknown_hash,
    verify_password,
)

PASSWORD = "correct horse battery staple"


def test_the_hash_is_argon2id_under_the_library_s_defaults():
    made = hash_password(PASSWORD)

    assert made.startswith("$argon2id$")
    parameters = argon2.extract_parameters(made)
    defaults = argon2.PasswordHasher()
    assert (parameters.time_cost, parameters.memory_cost, parameters.parallelism) == (defaults.time_cost, defaults.memory_cost, defaults.parallelism)
    assert (parameters.memory_cost, parameters.time_cost, parameters.parallelism) == (65536, 3, 4)
    assert made != hash_password(PASSWORD)  # a salt each
    assert not needs_rehash(made)


def test_the_right_password_verifies_and_a_wrong_one_does_not():
    made = hash_password(PASSWORD)

    assert verify_password(made, PASSWORD) is True
    assert verify_password(made, PASSWORD + " ") is False
    assert verify_password(made, "") is False


@pytest.mark.parametrize("text", ["", "x", "$argon2id$v=19$m=65536,t=3,p=4$", "$argon2id$v=19$m=65536,t=3,p=4$AAAA$AAAA", "not a hash at all"])
def test_a_text_that_is_no_hash_is_false_never_an_exception(text):
    assert verify_password(text, PASSWORD) is False


def test_a_hash_under_older_parameters_needs_a_rehash_and_still_verifies():
    older = argon2.PasswordHasher(time_cost=1, memory_cost=8, parallelism=1).hash(PASSWORD)

    assert verify_password(older, PASSWORD) is True
    assert needs_rehash(older) is True


def test_the_unknown_hash_is_made_once_and_verifies_nothing():
    first = unknown_hash()

    assert unknown_hash() is first
    assert first.startswith("$argon2id$")
    assert verify_password(first, "") is False
    assert verify_password(first, PASSWORD) is False


@pytest.mark.parametrize(
    ("password", "reason"),
    [
        ("", PASSWORD_RULE),
        ("x" * (MIN_PASSWORD_CHARACTERS - 1), PASSWORD_RULE),
        ("x" * MIN_PASSWORD_CHARACTERS, None),
        ("x" * MAX_PASSWORD_CHARACTERS, None),
        ("x" * (MAX_PASSWORD_CHARACTERS + 1), PASSWORD_RULE),
        ("é" * MIN_PASSWORD_CHARACTERS, None),
    ],
)
def test_the_rule_is_the_length_alone(password, reason):
    assert check_password_rule(password) == reason


def test_the_bounds_are_the_entry_s():
    assert (MIN_PASSWORD_CHARACTERS, MAX_PASSWORD_CHARACTERS) == (12, 1024)
    assert PASSWORD_RULE == "not 12 to 1024 characters"
    assert passwords._hasher.type is argon2.Type.ID

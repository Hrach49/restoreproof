"""C5.5: the public key a Worker registers (docs/decisions.md 2026-10-10,
"C5.5 and C5.6", point 2).

`read_key_file` is the key-file rule of the W4.3 review, held row by row to
shared/testdata/signing-v1/key-files.json and to verify_bundle.py's own
reader; `registered_key` then refuses a non-canonical encoding and a
small-order point (tests/registration-keys.json), and answers the one stored
form: the library's three-line PEM and the key's id.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app.auth.public_keys import DER_PREFIX, RegisteredKey, read_key_file, registered_key
from tests.test_verify_bundle import KEY_FILES, KEY_FILES_FILE, file_bytes, key_id_of_row, vb

REGISTRATION_KEYS = json.loads(
    (Path(__file__).resolve().parent / "registration-keys.json").read_bytes().decode("utf-8")
)
ACCEPTED = REGISTRATION_KEYS["accepted"]
REFUSED = REGISTRATION_KEYS["refused"]
P = 2**255 - 19


def pem_of(raw_hex: str) -> str:
    """The library's own PEM of the key's SubjectPublicKeyInfo."""
    der = DER_PREFIX + bytes.fromhex(raw_hex)
    body = base64.b64encode(der).decode("ascii")
    return f"-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----\n"


# --- The key-file rule: the 46 rows, as the script reads them --------------------------


def test_the_prefix_is_the_library_s():
    assert DER_PREFIX == bytes.fromhex("302a300506032b6570032100")
    assert len(DER_PREFIX) == 12


@pytest.mark.parametrize("row", KEY_FILES, ids=lambda row: row["name"])
def test_each_key_file_is_read_or_refused_as_both_verifiers_do(row):
    raw = file_bytes(row)
    der = read_key_file(raw)
    script = vb.public_key_from_pem(raw)

    if not row["accepted"]:
        assert der is None
        assert script is None
        return
    assert der is not None and script is not None
    assert der == script.der
    assert len(der) == 44 and der.startswith(DER_PREFIX)
    assert hashlib.sha256(der).hexdigest() == key_id_of_row(row)


def test_the_reader_takes_bytes_only():
    assert read_key_file("not bytes") is None  # type: ignore[arg-type]
    assert read_key_file(b"") is None


# --- registered_key: the two refusals beyond the rule ------------------------------------


@pytest.mark.parametrize("row", ACCEPTED, ids=lambda row: row["name"])
def test_a_key_the_cloud_accepts(row):
    key = registered_key(pem_of(row["raw"]))

    assert isinstance(key, RegisteredKey)
    assert key.key_id == row["key_id"]
    assert key.pem == pem_of(row["raw"])
    assert key.der == DER_PREFIX + bytes.fromhex(row["raw"])


@pytest.mark.parametrize("row", REFUSED, ids=lambda row: row["name"])
def test_a_small_order_or_non_canonical_key_is_refused_though_the_file_rule_takes_it(row):
    pem = pem_of(row["raw"])

    assert read_key_file(pem.encode("ascii")) is not None  # a well-formed key file
    assert registered_key(pem) is None


def test_the_fourteen_encodings_are_the_eight_points_and_their_other_six():
    assert len(REFUSED) == 14
    assert len({row["raw"] for row in REFUSED}) == 14
    y_values = {int.from_bytes(bytes.fromhex(row["raw"]), "little") & (2**255 - 1) for row in REFUSED}
    assert sum(1 for y in y_values if y >= P) == 2  # p and p + 1, each in two sign forms
    assert sum(1 for row in REFUSED if row["why"] == "non_canonical") == 4
    assert sum(1 for row in REFUSED if row["why"] == "small_order") == 10


def test_the_library_itself_refuses_none_of_the_eight_canonical_small_order_keys():
    """Why the list exists: the library takes them, and under the identity key
    it verifies a forged signature."""
    for row in REFUSED:
        if row["why"] == "small_order" and not row["name"].endswith("sign-set"):
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(row["raw"]))
    identity = Ed25519PublicKey.from_public_bytes(bytes.fromhex(REFUSED[0]["raw"]))
    identity.verify(bytes.fromhex(REFUSED[0]["raw"]) + bytes(32), b"any message at all")


@pytest.mark.parametrize("y", [P, P + 1, 2**255 - 1])
def test_a_y_at_or_above_p_is_refused_whatever_the_point(y):
    raw = y.to_bytes(32, "little")

    assert registered_key(pem_of(raw.hex())) is None


def test_a_y_just_below_p_passes_the_canonical_rule():
    raw = (P - 1).to_bytes(32, "little")  # the point of order 2: refused by the list, not the rule
    assert registered_key(pem_of(raw.hex())) is None
    raw = (P - 2).to_bytes(32, "little")  # no such point need exist: the rule passes it
    assert registered_key(pem_of(raw.hex())) is not None


# --- One stored form -------------------------------------------------------------------------


def test_every_accepted_layout_is_stored_as_one_text_under_one_key_id():
    accepted = [row for row in KEY_FILES if row["accepted"] and row["name"] != "small-order-identity-key"]
    keys = [registered_key(file_bytes(row).decode("utf-8")) for row in accepted]

    assert len(accepted) == 10
    assert all(key is not None for key in keys)
    assert {key.pem for key in keys} == {pem_of(ACCEPTED[0]["raw"])}
    assert {key.key_id for key in keys} == {KEY_FILES_FILE["accepted_key_id"]}


def test_the_stored_form_is_the_library_s_own_serialisation():
    raw = bytes.fromhex(ACCEPTED[0]["raw"])
    library = Ed25519PublicKey.from_public_bytes(raw).public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )

    assert registered_key(pem_of(raw.hex())).pem.encode("ascii") == library


def test_the_identity_key_s_id_is_the_vectors_but_the_key_is_refused():
    identity = pem_of(REFUSED[0]["raw"])

    assert hashlib.sha256(read_key_file(identity.encode("ascii"))).hexdigest() == KEY_FILES_FILE["identity_key_id"]
    assert registered_key(identity) is None


@pytest.mark.parametrize("text", ["", " ", "\ud800", "-----BEGIN PUBLIC KEY-----\n\n-----END PUBLIC KEY-----\n"])
def test_a_string_that_is_no_key_file_is_refused(text):
    assert registered_key(text) is None

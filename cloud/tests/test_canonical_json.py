"""The result's canonical form, canonical-json-v1 (docs/decisions.md 2026-10-04,
W4.1 point 4), from the Cloud's side: for every accepted vector in
shared/testdata/canonical-json-v1.json, Python's one-line dump gives the bytes
the Worker's rp::canonical_json gives (worker/tests/canonical_json_test.cpp runs
the same file). The refusing canonicaliser comes with verify_bundle.py (W4.3),
so the rejects are only checked for their shape here.
"""

import hashlib
import json
from pathlib import Path

import pytest


def shared_dir() -> Path:
    """The repo's shared/ folder: the first one, walking up from this file, that
    holds testdata. Also found from mutmut's copy under cloud/mutants/."""
    for folder in Path(__file__).resolve().parents:
        if (folder / "shared" / "testdata").is_dir():
            return folder / "shared"
    raise FileNotFoundError("no shared/testdata above " + str(Path(__file__).resolve()))


VECTORS_PATH = shared_dir() / "testdata" / "canonical-json-v1.json"
VECTORS = json.loads(VECTORS_PATH.read_bytes().decode("utf-8"))
CASES = VECTORS["cases"]
REJECTS = VECTORS["rejects"]


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def test_vectors_file_names_this_form():
    assert VECTORS["form"] == "canonical-json-v1"


def test_vectors_file_is_lf_and_ascii():
    # .gitattributes keeps it LF, so both builds read the same bytes.
    raw = VECTORS_PATH.read_bytes()
    assert b"\r" not in raw
    assert raw.isascii()


def test_vectors_file_covers_every_required_case():
    # The same list as worker/tests/canonical_json_test.cpp.
    names = [entry["name"] for entry in CASES + REJECTS]
    required = {
        "empty-object", "empty-array", "empty-string", "true", "false", "null",
        "literals-in-containers", "empty-containers-nested", "whitespace-removed", "key-order",
        "key-order-nested", "key-prefixes", "keys-escaped", "array-order-kept", "control-characters",
        "control-characters-each", "del", "slash", "quote", "backslash", "latin-e-acute",
        "combining-not-composed", "line-separator-u2028", "paragraph-separator-u2029",
        "bom-in-string", "astral", "nested-arrays-of-strings", "integer-zero", "integer-minus-one",
        "integer-max", "integer-min", "integers", "result-shaped",
        "float", "float-fraction", "float-exponent", "float-nested", "integer-two-to-the-53",
        "integer-minus-two-to-the-53", "integer-out-of-range-nested", "non-ascii-key",
        "non-ascii-key-nested",
    }
    assert required <= set(names)
    assert len(names) == len(set(names)), "case names must be unique"


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_accepted_case(case):
    expected = case["canonical"].encode("utf-8")
    assert canonical(case["input"]) == expected
    assert hashlib.sha256(expected).hexdigest() == case["sha256"]
    # The canonical text is a fixed point.
    assert canonical(json.loads(expected)) == expected


@pytest.mark.parametrize("reject", REJECTS, ids=[r["name"] for r in REJECTS])
def test_reject_is_json_text_with_a_known_reason(reject):
    json.loads(reject["input_text"])
    assert reject["reason"] in {"float", "integer_out_of_range", "non_ascii_key"}

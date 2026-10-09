"""restoreproof.client-profile.v1's schema (W4.10, docs/decisions.md 2026-10-09,
points 1 and 8), from the Cloud's side: shared/schemas/client-profile.v1.json
is a valid JSON Schema 2020-12 in the shared subset, and Python's validator
judges every document of shared/testdata/client-profile-v1/ as the file says,
which is how the Worker's rp::parse_client_profile judges them
(worker/tests/client_profile_test.cpp runs the same file), but for the cases
the file marks `code_refuses`: a control character in veeam_org_name, tenant
text the schema holds to a length alone and the Worker's reader refuses.
"""

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from test_result_schema import patched, shared_dir

SCHEMA_PATH = shared_dir() / "schemas" / "client-profile.v1.json"
VECTORS_DIR = shared_dir() / "testdata" / "client-profile-v1"
SCHEMA = json.loads(SCHEMA_PATH.read_bytes().decode("utf-8"))
CASES_FILE = json.loads((VECTORS_DIR / "cases.json").read_bytes().decode("utf-8"))
BASE_PATH = VECTORS_DIR / CASES_FILE["base"]
BASE = json.loads(BASE_PATH.read_bytes().decode("utf-8"))
CASES = CASES_FILE["cases"]
VALIDATOR = Draft202012Validator(SCHEMA)

FORMAT = "restoreproof.client-profile.v1"
KEYS = [
    "format",
    "veeam_org_name",
    "graph_tenant_id",
    "graph_client_id",
    "test_mailbox",
    "test_site_id",
    "test_library_id",
    "test_onedrive_drive_id",
    "test_onedrive_folder_id",
]


def test_the_schema_is_a_valid_2020_12_schema_in_the_shared_subset():
    assert SCHEMA["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    Draft202012Validator.check_schema(SCHEMA)
    # Every key required, no other allowed, the format a constant (point 1).
    assert sorted(SCHEMA["required"]) == sorted(KEYS)
    assert sorted(SCHEMA["properties"]) == sorted(KEYS)
    assert SCHEMA["additionalProperties"] is False
    assert SCHEMA["properties"]["format"] == {"const": FORMAT}
    # No format keyword: the shapes are patterns (W4.1 point 3).
    assert "format" not in json.dumps(SCHEMA["properties"]["graph_tenant_id"])


def test_the_schema_file_is_lf():
    assert b"\r" not in SCHEMA_PATH.read_bytes()


def test_the_base_profile_is_valid_and_its_own_canonical_text():
    assert CASES_FILE["format"] == FORMAT
    assert BASE["format"] == FORMAT
    assert list(VALIDATOR.iter_errors(BASE)) == []
    raw = BASE_PATH.read_bytes()
    text = json.dumps(BASE, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    assert raw == text.encode("utf-8")


def test_the_cases_are_pinned_and_code_refuses_marks_valid_ones_only():
    # The counts worker/tests/client_profile_test.cpp pins, held here too.
    assert len(CASES) == 104
    assert sum(1 for case in CASES if case["valid"]) == 18
    assert sum(1 for case in CASES if not case["valid"]) == 86
    assert sum(1 for case in CASES if case.get("code_refuses")) == 2
    assert all(case["valid"] for case in CASES if case.get("code_refuses"))
    assert len({case["name"] for case in CASES}) == len(CASES)
    assert "float" not in {type(value).__name__ for value in _values(CASES)}


def _values(value):
    if isinstance(value, dict):
        for member in value.values():
            yield from _values(member)
    elif isinstance(value, list):
        for member in value:
            yield from _values(member)
    else:
        yield value


@pytest.mark.parametrize("case", CASES, ids=[case["name"] for case in CASES])
def test_each_case_is_judged_as_the_file_says(case):
    document = patched(BASE, case["patch"])
    errors = list(VALIDATOR.iter_errors(document))
    assert (errors == []) == case["valid"], [error.message for error in errors]


def test_the_profile_holds_ids_only_and_no_secret_shaped_key():
    # Point 10: a profile is IDs, a name and an address; no key of it looks
    # like a secret (config.json's own markers).
    markers = ("password", "secret", "token", "key", "pfx", "credential")
    for key in KEYS:
        assert not any(marker in key for marker in markers if marker != "key"), key

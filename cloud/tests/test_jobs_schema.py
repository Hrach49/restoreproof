"""restoreproof.jobs.v1's schema (W4.10, docs/decisions.md 2026-10-09, points 2
and 8), from the Cloud's side: shared/schemas/jobs.v1.json is a valid JSON
Schema 2020-12 in the shared subset whose job's `client` refers to
client-profile.v1.json beside it, and Python's validator judges every document
of shared/testdata/jobs-v1/ as the file says, which is how the Worker's
rp::parse_jobs judges them (worker/tests/service_jobs_test.cpp runs the same
file), but for the cases the file marks `code_refuses`: a run_id the schema's
pattern allows and no folder can carry.
"""

import json

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from test_result_schema import patched, shared_dir

SCHEMA_PATH = shared_dir() / "schemas" / "jobs.v1.json"
PROFILE_SCHEMA_PATH = shared_dir() / "schemas" / "client-profile.v1.json"
VECTORS_DIR = shared_dir() / "testdata" / "jobs-v1"
SCHEMA = json.loads(SCHEMA_PATH.read_bytes().decode("utf-8"))
PROFILE_SCHEMA = json.loads(PROFILE_SCHEMA_PATH.read_bytes().decode("utf-8"))
CASES_FILE = json.loads((VECTORS_DIR / "cases.json").read_bytes().decode("utf-8"))
BASE_PATH = VECTORS_DIR / CASES_FILE["base"]
BASE = json.loads(BASE_PATH.read_bytes().decode("utf-8"))
CASES = CASES_FILE["cases"]
# The job's client is the profile schema, found by the relative $ref through
# the two schemas' $id.
REGISTRY = Registry().with_resource(PROFILE_SCHEMA["$id"], Resource.from_contents(PROFILE_SCHEMA))
VALIDATOR = Draft202012Validator(SCHEMA, registry=REGISTRY)

FORMAT = "restoreproof.jobs.v1"
JOB_KEYS = [
    "run_id",
    "client_id",
    "client",
    "sample_mail",
    "sample_sp",
    "sample_od",
    "restore_point",
    "screenshots_enabled",
    "canary_cursor",
]


def test_the_schema_is_a_valid_2020_12_schema_that_refers_to_the_profile():
    assert SCHEMA["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    Draft202012Validator.check_schema(SCHEMA)
    assert SCHEMA["properties"]["format"] == {"const": FORMAT}
    assert SCHEMA["properties"]["jobs"]["maxItems"] == 5
    job = SCHEMA["$defs"]["job"]
    assert sorted(job["properties"]) == sorted(JOB_KEYS)
    assert sorted(job["required"]) == sorted(key for key in JOB_KEYS if key != "canary_cursor")
    assert job["additionalProperties"] is False
    # One copy of the profile's rules: the job's client is the profile schema.
    assert job["properties"]["client"] == {"$ref": "client-profile.v1.json"}
    assert PROFILE_SCHEMA["$id"].endswith("/client-profile.v1.json")


def test_the_schema_file_is_lf():
    assert b"\r" not in SCHEMA_PATH.read_bytes()


def test_the_base_document_is_valid_and_its_own_canonical_text():
    assert CASES_FILE["format"] == FORMAT
    assert BASE["format"] == FORMAT
    assert list(VALIDATOR.iter_errors(BASE)) == []
    raw = BASE_PATH.read_bytes()
    text = json.dumps(BASE, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    assert raw == text.encode("utf-8")


def test_the_cases_are_pinned_and_code_refuses_marks_valid_ones_only():
    # The counts worker/tests/service_jobs_test.cpp pins, held here too.
    assert len(CASES) == 72
    assert sum(1 for case in CASES if case["valid"]) == 17
    assert sum(1 for case in CASES if not case["valid"]) == 55
    assert sum(1 for case in CASES if case.get("code_refuses")) == 3
    assert all(case["valid"] for case in CASES if case.get("code_refuses"))
    assert len({case["name"] for case in CASES}) == len(CASES)


@pytest.mark.parametrize("case", CASES, ids=[case["name"] for case in CASES])
def test_each_case_is_judged_as_the_file_says(case):
    document = patched(BASE, case["patch"])
    errors = list(VALIDATOR.iter_errors(document))
    assert (errors == []) == case["valid"], [error.message for error in errors]


def test_a_job_without_a_profile_is_no_job_whatever_else_it_has():
    # Point 2: the profile is required; there is no fallback to a config.
    document = patched(BASE, [{"op": "remove", "path": "/jobs/0/client"}])
    assert [error.message for error in VALIDATOR.iter_errors(document)] == [
        "'client' is a required property"
    ]

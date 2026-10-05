"""restoreproof.result.v1's schema (docs/decisions.md 2026-10-04, W4.1 points 2
and 3), from the Cloud's side: shared/schemas/result.v1.json is a valid JSON
Schema 2020-12, and Python's validator judges every document of
shared/testdata/result-v1/ as the file says, which is how the Worker's C++
validator judges them (worker/tests/result_schema_test.cpp runs the same
file). The Cloud reads the schema by path; there is no copy.
"""

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator


def shared_dir() -> Path:
    """The repo's shared/ folder: the first one, walking up from this file, that
    holds schemas. Also found from mutmut's copy under cloud/mutants/."""
    for folder in Path(__file__).resolve().parents:
        if (folder / "shared" / "schemas").is_dir():
            return folder / "shared"
    raise FileNotFoundError("no shared/schemas above " + str(Path(__file__).resolve()))


SCHEMA_PATH = shared_dir() / "schemas" / "result.v1.json"
VECTORS_DIR = shared_dir() / "testdata" / "result-v1"
SCHEMA = json.loads(SCHEMA_PATH.read_bytes().decode("utf-8"))
CASES_FILE = json.loads((VECTORS_DIR / "cases.json").read_bytes().decode("utf-8"))
BASE_PATH = VECTORS_DIR / CASES_FILE["base"]
BASE = json.loads(BASE_PATH.read_bytes().decode("utf-8"))
CASES = CASES_FILE["cases"]
VALIDATOR = Draft202012Validator(SCHEMA)


def patched(document, patch):
    """`document` with an RFC 6902 patch of add, remove and replace applied."""
    result = copy.deepcopy(document)
    for step in patch:
        parts = [part.replace("~1", "/").replace("~0", "~") for part in step["path"].split("/")[1:]]
        if not parts:
            assert step["op"] == "replace"
            result = copy.deepcopy(step["value"])
            continue
        parent = result
        for part in parts[:-1]:
            parent = parent[int(part)] if isinstance(parent, list) else parent[part]
        last = parts[-1]
        if isinstance(parent, list):
            index = len(parent) if last == "-" else int(last)
            if step["op"] == "add":
                parent.insert(index, copy.deepcopy(step["value"]))
            elif step["op"] == "remove":
                del parent[index]
            else:
                assert step["op"] == "replace"
                parent[index] = copy.deepcopy(step["value"])
        elif step["op"] == "remove":
            del parent[last]
        else:
            assert step["op"] in ("add", "replace")
            # RFC 6902: a replaced member must be there.
            assert step["op"] == "add" or last in parent
            parent[last] = copy.deepcopy(step["value"])
    return result


def test_the_patch_helper_applies_add_remove_and_replace():
    document = {"a": {"b": [1, 2, 3]}, "c": 1, "d/e": 0}
    patch = [
        {"op": "add", "path": "/a/b/-", "value": 4},
        {"op": "add", "path": "/a/b/0", "value": 0},
        {"op": "remove", "path": "/a/b/1"},
        {"op": "replace", "path": "/a/b/1", "value": "two"},
        {"op": "replace", "path": "/c", "value": None},
        {"op": "add", "path": "/x", "value": {"y": 1}},
        {"op": "remove", "path": "/d~1e"},
    ]
    assert patched(document, patch) == {"a": {"b": [0, "two", 3, 4]}, "c": None, "x": {"y": 1}}
    # The document handed in is left as it was.
    assert document == {"a": {"b": [1, 2, 3]}, "c": 1, "d/e": 0}
    assert patched(document, [{"op": "replace", "path": "", "value": []}]) == []
    with pytest.raises(AssertionError):
        patched(document, [{"op": "replace", "path": "/missing", "value": 1}])
    with pytest.raises(KeyError):
        patched(document, [{"op": "remove", "path": "/missing"}])


def test_the_schema_is_a_valid_2020_12_schema():
    assert SCHEMA["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    Draft202012Validator.check_schema(SCHEMA)


def test_the_schema_file_is_lf():
    # .gitattributes keeps it LF: the bytes the Worker embeds on Windows.
    assert b"\r" not in SCHEMA_PATH.read_bytes()


def test_the_base_document_is_valid():
    assert CASES_FILE["format"] == "restoreproof.result.v1"
    assert BASE["format"] == "restoreproof.result.v1"
    assert list(VALIDATOR.iter_errors(BASE)) == []


def test_the_base_document_is_its_own_canonical_text():
    # canonical-json-v1 (tests/test_canonical_json.py): what the Worker wrote.
    raw = BASE_PATH.read_bytes()
    text = json.dumps(BASE, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    assert raw == text.encode("utf-8")


def test_the_cases_are_both_kinds_and_none_holds_a_float():
    # Python reads 1.0 as an integer and the Worker's validator doesn't, so
    # the shared cases hold none (W4.1 point 3).
    # The counts worker/tests/result_schema_test.cpp pins, held here too: a
    # case dropped from cases.json is noticed on this side as well.
    assert len(CASES) == 183
    assert sum(1 for case in CASES if case["valid"]) == 45
    assert sum(1 for case in CASES if not case["valid"]) == 138
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
def test_each_case_validates_as_it_says(case):
    document = patched(BASE, case["patch"])
    errors = list(VALIDATOR.iter_errors(document))
    assert (errors == []) == case["valid"]

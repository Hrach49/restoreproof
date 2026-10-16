"""The profile the script prints (W7.0, decision point 8): restoreproof.client-profile.v1 from what
was read back, sorted keys, LF; the script's own schema copy equal to the shared one; its
Test-Json and Python's jsonschema judging every shared case alike."""

import copy
import json

import jsonschema
import pytest

from pwsh import REPO_DIR, SETUP_DIR, SHARED_SCHEMA, evaluate, ps, ps_string

SCHEMA_COPY = SETUP_DIR / "client-profile.v1.json"
CASES = REPO_DIR / "shared" / "testdata" / "client-profile-v1" / "cases.json"
VALUES = {
    "VeeamOrgName": "contoso.onmicrosoft.com",
    "TenantId": "AAAAAAAA-2222-3333-4444-555555555555",
    "ClientId": "BBBBBBBB-2222-3333-4444-555555555555",
    "Mailbox": "restoretest@contoso.onmicrosoft.com",
    "SiteId": "contoso.sharepoint.com,aaaaaaaa-0000-0000-0000-000000000001,aaaaaaaa-0000-0000-0000-000000000002",
    "LibraryDriveId": "b!library",
    "DriveId": "b!onedrive",
    "FolderId": "01FOLDER",
}


def schema() -> dict:
    return json.loads(SHARED_SCHEMA.read_text(encoding="utf-8"))


def test_the_scripts_schema_copy_is_the_shared_one():
    assert SCHEMA_COPY.read_bytes() == SHARED_SCHEMA.read_bytes()


@pytest.fixture(scope="module")
def made():
    args = " ".join(f"-{k} {ps(v)}" for k, v in VALUES.items())
    (text,) = evaluate([f"ConvertTo-ProfileJson (New-ClientProfile {args})"])
    return text


def test_the_profile_is_valid_and_holds_what_was_read(made):
    profile = json.loads(made)
    jsonschema.validate(profile, schema())
    assert profile == {
        "format": "restoreproof.client-profile.v1",
        "graph_client_id": "bbbbbbbb-2222-3333-4444-555555555555",
        "graph_tenant_id": "aaaaaaaa-2222-3333-4444-555555555555",
        "test_library_id": "b!library",
        "test_mailbox": "restoretest@contoso.onmicrosoft.com",
        "test_onedrive_drive_id": "b!onedrive",
        "test_onedrive_folder_id": "01FOLDER",
        "test_site_id": VALUES["SiteId"],
        "veeam_org_name": "contoso.onmicrosoft.com",
    }


def test_the_profile_text_is_sorted_lf_and_ends_in_one_newline(made):
    assert "\r" not in made
    assert made.endswith("}\n") and not made.endswith("\n\n")
    keys = list(json.loads(made).keys())
    assert keys == sorted(keys)


def apply(document: dict, patch: list) -> dict:
    """RFC 6902's add, replace and remove on top-level keys, the shared cases' only ones."""
    document = copy.deepcopy(document)
    for op in patch:
        key = op["path"].lstrip("/")
        assert "/" not in key, op
        if op["op"] == "remove":
            document.pop(key, None)
        else:
            document[key] = op["value"]
    return document


def cases():
    data = json.loads(CASES.read_text(encoding="utf-8"))
    base = json.loads((CASES.parent / data["base"]).read_text(encoding="utf-8"))
    return [(c["name"], apply(base, c["patch"])) for c in data["cases"]]


@pytest.fixture(scope="module")
def test_json_says():
    rows = [
        f"Test-Json -Json {ps_string(json.dumps(doc, ensure_ascii=False))} -SchemaFile {ps_string(SCHEMA_COPY)} -ErrorAction SilentlyContinue"
        for _, doc in cases()
    ]
    return evaluate(rows)


@pytest.mark.parametrize("index", range(len(cases())), ids=[name for name, _ in cases()])
def test_test_json_and_jsonschema_agree(test_json_says, index):
    _, doc = cases()[index]
    valid = jsonschema.Draft202012Validator(schema()).is_valid(doc)
    assert test_json_says[index] is valid

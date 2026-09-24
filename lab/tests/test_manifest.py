import copy
import hashlib
import json

import pytest
from jsonschema import Draft202012Validator

from seeder import MANIFEST_SCHEMA_PATH, tenant
from seeder.catalog import canary_files, canary_mails
from seeder.manifest import (
    RULES,
    SCHEMA_ID,
    ManifestError,
    dumps_manifest,
    file_entry,
    find_secret_words,
    iso_utc,
    load_manifest,
    mail_entry,
    sha256_hex,
    validate_manifest,
    write_manifest,
)
from seeder.normalize import body_sha256
from tests.manifest_factory import make_manifest

MAIL = canary_mails()[0]
SP_FILE = canary_files()[0]  # rp-canary-01.pdf, SharePoint
OD_FILE = canary_files()[10]  # rp-canary-11.pdf, OneDrive
FIRST_FILE = 20  # index of rp-canary-01.pdf in entries


# --- iso_utc -------------------------------------------------------------------------

@pytest.mark.parametrize(
    "value",
    [
        "",
        "garbage",
        "2026-09-25",
        "2026-09-25T10:00:00",  # no time zone
        "2026-09-25 10:00:00Z",
        "2026-13-01T10:00:00Z",
        "2026-02-30T10:00:00Z",
        "2026-09-25T25:00:00Z",
        "2026-09-25T10:00:00.Z",
        "2026-09-25T10:00:00+0200",
        "2026-09-25T10:00:00Z trailing",
    ],
)
def test_iso_utc_rejects_garbage(value):
    with pytest.raises(ValueError):
        iso_utc(value)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2026-09-25T10:00:00Z", "2026-09-25T10:00:00Z"),
        ("2026-09-25T10:00:00.1234567Z", "2026-09-25T10:00:00Z"),
        ("2026-09-25T10:00:59.9999999Z", "2026-09-25T10:00:59Z"),  # truncated, not rounded
        ("2026-09-25T10:00:00+00:00", "2026-09-25T10:00:00Z"),
        ("2026-09-25T10:00:00+02:00", "2026-09-25T08:00:00Z"),
        ("2026-09-25T23:30:00-01:00", "2026-09-26T00:30:00Z"),
        ("2026-09-25T10:00:00.5+02:00", "2026-09-25T08:00:00Z"),
    ],
)
def test_iso_utc(value, expected):
    assert iso_utc(value) == expected


def test_sha256_hex():
    assert sha256_hex(b"abc") == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


# --- entry builders --------------------------------------------------------------------

def test_mail_entry_fields():
    entry = mail_entry(
        MAIL,
        sender="hrachyaharutyunyan@restoreprooflab.onmicrosoft.com",
        folder="Inbox",
        sent_at="2026-09-25T10:00:00.1234567Z",
        received_at="2026-09-25T12:00:05+02:00",
        internet_message_id="<a@b>",
        graph_message_id="AAk=",
        body_readback=MAIL.body.replace("\r\n", "\n") + "\n",
    )
    assert entry == {
        "id": "RP-CANARY-0001",
        "kind": "mail",
        "subject": "RP-CANARY-0001",
        "sender": "hrachyaharutyunyan@restoreprooflab.onmicrosoft.com",
        "recipient": tenant.ALICE_UPN,
        "location": {"mailbox": tenant.ALICE_UPN, "folder": "Inbox"},
        "sent_at": "2026-09-25T10:00:00Z",
        "received_at": "2026-09-25T10:00:05Z",
        "internet_message_id": "<a@b>",
        "graph_message_id": "AAk=",
        "body_content_type": "text",
        "body_normalization": "text-v1",
        "body_sha256": body_sha256(MAIL.body),
        "sent_body_sha256": body_sha256(MAIL.body),
        "body_readback_exact": False,
    }


def test_mail_entry_readback_exact_when_identical():
    entry = mail_entry(
        MAIL, sender=MAIL.sender, folder="Inbox", sent_at="2026-09-25T10:00:00Z",
        received_at="2026-09-25T10:00:00Z", internet_message_id="<a@b>",
        graph_message_id="x", body_readback=MAIL.body,
    )
    assert entry["body_readback_exact"] is True


def test_sharepoint_file_entry_fields():
    entry = file_entry(
        SP_FILE, folder_id="01PARENT", drive_item_id="01ITEM",
        last_modified_at="2026-09-25T10:00:00.5Z", local_bytes=b"abc", stored_bytes=b"abcd",
    )
    assert entry == {
        "id": "rp-canary-01.pdf",
        "kind": "sharepoint_file",
        "name": "rp-canary-01.pdf",
        "file_type": "pdf",
        "location": {
            "site_id": tenant.SHAREPOINT_SITE_ID,
            "list_id": tenant.SHAREPOINT_LIST_ID,
            "drive_id": tenant.SHAREPOINT_DRIVE_ID,
            "folder_id": "01PARENT",
            "folder_path": "/",
        },
        "drive_item_id": "01ITEM",
        "uploaded_by": tenant.ADMIN_UPN,
        "last_modified_at": "2026-09-25T10:00:00Z",
        "local_sha256": hashlib.sha256(b"abc").hexdigest(),
        "local_size": 3,
        "stored_sha256": hashlib.sha256(b"abcd").hexdigest(),
        "stored_size": 4,
        "stored_matches_local": False,
        "content_rule": "bytes",
        "content_sha256": hashlib.sha256(b"abcd").hexdigest(),
    }


@pytest.mark.parametrize("file_type", ["docx", "xlsx"])
def test_office_entry_hashes_content_parts_so_a_sharepoint_rewrite_matches(file_type):
    from seeder.catalog import canary_files
    from seeder.office import office_content_sha256
    from tests.office_fakes import office_zip, sharepoint_rewrite

    f = next(c for c in canary_files() if c.file_type == file_type and c.kind == "sharepoint_file")
    local = office_zip(file_type, "hello")
    stored = sharepoint_rewrite(local)
    entry = file_entry(
        f, folder_id="01PARENT", drive_item_id="01ITEM",
        last_modified_at="2026-09-25T10:00:00Z", local_bytes=local, stored_bytes=stored,
    )
    assert entry["stored_matches_local"] is False
    assert entry["content_rule"] == "office-v1"
    assert entry["content_sha256"] == office_content_sha256(local, file_type)
    assert entry["content_sha256"] == office_content_sha256(stored, file_type)


def test_office_entry_whose_stored_bytes_are_not_a_package_is_an_error():
    from seeder.catalog import canary_files
    from seeder.office import OfficeContentError
    from tests.office_fakes import office_zip

    f = next(c for c in canary_files() if c.file_type == "docx")
    with pytest.raises(OfficeContentError):
        file_entry(
            f, folder_id="01PARENT", drive_item_id="01ITEM", last_modified_at="2026-09-25T10:00:00Z",
            local_bytes=office_zip("docx", "x"), stored_bytes=b"<html>error page</html>",
        )


def test_onedrive_file_entry_location():
    entry = file_entry(
        OD_FILE, folder_id=tenant.ONEDRIVE_FOLDER_ID, drive_item_id="01ITEM",
        last_modified_at="2026-09-25T10:00:00Z", local_bytes=b"abc", stored_bytes=b"abc",
    )
    assert entry["kind"] == "onedrive_file"
    assert entry["uploaded_by"] == tenant.ALICE_UPN
    assert entry["location"] == {
        "user": tenant.ALICE_UPN,
        "drive_id": tenant.ONEDRIVE_DRIVE_ID,
        "folder_id": tenant.ONEDRIVE_FOLDER_ID,
        "folder_path": "/RestoreTest",
    }
    assert entry["stored_matches_local"] is True


# --- schema and validation -------------------------------------------------------------

def test_schema_file_is_a_valid_draft_2020_12_schema():
    schema = json.loads(MANIFEST_SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["properties"]["schema"]["const"] == SCHEMA_ID


def test_every_schema_property_is_documented():
    schema = json.loads(MANIFEST_SCHEMA_PATH.read_text(encoding="utf-8"))
    missing = []

    def walk(node, path):
        if isinstance(node, dict):
            for name, sub in node.get("properties", {}).items():
                if "description" not in sub or "title" not in sub:
                    missing.append(f"{path}/{name}")
            for key, sub in node.items():
                walk(sub, f"{path}/{key}")
        elif isinstance(node, list):
            for i, sub in enumerate(node):
                walk(sub, f"{path}/{i}")

    walk(schema, "")
    assert missing == []


def test_valid_fake_manifest_passes():
    manifest = make_manifest()
    validate_manifest(manifest)
    Draft202012Validator(
        json.loads(MANIFEST_SCHEMA_PATH.read_text(encoding="utf-8"))
    ).validate(manifest)
    assert len(manifest["entries"]) == 40
    assert manifest["schema"] == SCHEMA_ID
    assert manifest["rules"] == RULES
    assert manifest["tenant"] == tenant.TENANT_DOMAIN
    assert manifest["tenant_id"] == tenant.TENANT_ID


def test_fake_manifest_has_both_stored_matches_local_values():
    values = {e["stored_matches_local"] for e in make_manifest()["entries"] if "name" in e}
    assert values == {True, False}


def _drop_last(m):
    m["entries"].pop()


def _add_extra(m):
    m["entries"].append(copy.deepcopy(m["entries"][-1]))


def _set(index, key, value):
    def mutate(m):
        m["entries"][index][key] = value
    return mutate


def _del(index, key):
    def mutate(m):
        del m["entries"][index][key]
    return mutate


def _swap(i, j):
    def mutate(m):
        e = m["entries"]
        e[i], e[j] = e[j], e[i]
    return mutate


def _duplicate(m):
    m["entries"][1] = copy.deepcopy(m["entries"][0])


def _top(key, value):
    def mutate(m):
        m[key] = value
    return mutate


def _location(index, key, value):
    def mutate(m):
        m["entries"][index]["location"][key] = value
    return mutate


def _file_as_onedrive(m):
    # rp-canary-01.pdf dressed as a complete, schema-valid OneDrive entry
    e = m["entries"][FIRST_FILE]
    e["kind"] = "onedrive_file"
    e["location"] = {
        "user": tenant.ALICE_UPN, "drive_id": "d", "folder_id": "f", "folder_path": "/RestoreTest",
    }


def _stored_equal_but_flag_false(m):
    e = m["entries"][FIRST_FILE]
    e["stored_sha256"], e["stored_size"] = e["local_sha256"], e["local_size"]
    e["stored_matches_local"] = False


def _exact_but_hashes_differ(m):
    e = m["entries"][0]
    e["body_readback_exact"] = True
    e["body_sha256"] = "0" * 64


MUTATIONS = [
    ("39-entries", _drop_last, "40"),
    ("41-entries", _add_extra, "40"),
    ("missing-field", _del(0, "body_sha256"), "body_sha256"),
    ("missing-file-field", _del(FIRST_FILE, "stored_size"), "stored_size"),
    ("extra-field", _set(0, "access", "x"), "access"),
    ("extra-top-level-field", _top("note", "x"), "note"),
    ("bad-hash", _set(0, "body_sha256", "abc"), "body_sha256"),
    ("uppercase-hash", _set(FIRST_FILE, "local_sha256", "A" * 64), "local_sha256"),
    ("bad-date-format", _set(0, "sent_at", "2026-09-25 10:00:00"), "sent_at"),
    ("bad-date-value", _set(0, "received_at", "2026-13-01T10:00:00Z"), "received_at"),
    ("bad-seeded-at", _top("seeded_at", "yesterday"), "seeded_at"),
    ("wrong-kind", _set(0, "kind", "email"), "RP-CANARY-0001"),
    ("wrong-schema-id", _top("schema", "seed-manifest.v2"), "seed-manifest.v1"),
    ("wrong-order-mails", _swap(0, 1), "RP-CANARY-0001"),
    ("wrong-order-files", _swap(FIRST_FILE, FIRST_FILE + 1), "rp-canary-01.pdf"),
    ("files-before-mails", _swap(0, FIRST_FILE), "RP-CANARY-0001"),
    ("duplicate-id", _duplicate, "duplicate"),
    ("stored-matches-local-true", _set(FIRST_FILE + 1, "stored_matches_local", True), "stored_matches_local"),
    ("stored-matches-local-false", _stored_equal_but_flag_false, "stored_matches_local"),
    ("kind-not-catalog", _file_as_onedrive, "sharepoint_file"),
    ("subject-not-id", _set(0, "subject", "RP-CANARY-0002"), "subject"),
    ("name-not-id", _set(FIRST_FILE, "name", "rp-canary-02.pdf"), "name"),
    ("file-type-not-extension", _set(FIRST_FILE, "file_type", "docx"), "file_type"),
    ("mailbox-not-recipient", _location(0, "mailbox", tenant.BOB_UPN), "mailbox"),
    ("readback-exact-but-hash-differs", _exact_but_hashes_differ, "body_readback_exact"),
    ("negative-size", _set(FIRST_FILE, "local_size", -1), "local_size"),
    ("wrong-normalization", _set(0, "body_normalization", "text-v2"), "text-v1"),
    ("secret-word", _set(0, "graph_message_id", "Bearer abc"), "bearer"),
    ("missing-content-rule", _del(FIRST_FILE, "content_rule"), "content_rule"),
    ("unknown-content-rule", _set(FIRST_FILE, "content_rule", "office-v2"), "content_rule"),
    ("office-type-with-bytes-rule", _set(FIRST_FILE + 1, "content_rule", "bytes"), "content_rule"),
    ("pdf-with-office-rule", _set(FIRST_FILE, "content_rule", "office-v1"), "content_rule"),
    ("bytes-content-hash-not-stored", _set(FIRST_FILE, "content_sha256", "0" * 64), "content_sha256"),
]


@pytest.mark.parametrize(
    ("mutate", "fragment"), [m[1:] for m in MUTATIONS], ids=[m[0] for m in MUTATIONS]
)
def test_invalid_manifest_is_rejected(mutate, fragment):
    manifest = make_manifest()
    mutate(manifest)
    with pytest.raises(ManifestError) as info:
        validate_manifest(manifest)
    assert fragment.lower() in str(info.value).lower()


def test_error_names_entry_and_expected_vs_actual():
    manifest = make_manifest()
    _swap(0, 1)(manifest)
    with pytest.raises(ManifestError) as info:
        validate_manifest(manifest)
    message = str(info.value)
    assert "expected RP-CANARY-0001" in message and "got RP-CANARY-0002" in message


def test_count_error_says_expected_and_actual():
    manifest = make_manifest()
    _drop_last(manifest)
    with pytest.raises(ManifestError) as info:
        validate_manifest(manifest)
    assert "39" in str(info.value) and "40" in str(info.value)


def test_schema_error_names_entry_id():
    manifest = make_manifest()
    _set(FIRST_FILE + 3, "local_sha256", "A" * 64)(manifest)
    with pytest.raises(ManifestError) as info:
        validate_manifest(manifest)
    assert "rp-canary-04.txt" in str(info.value)


def test_non_dict_manifest_is_rejected():
    with pytest.raises(ManifestError):
        validate_manifest([])  # type: ignore[arg-type]


# --- secret words ------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("text", "found"),
    [
        ("an access_token here", ["token"]),
        ("PASSWORD=1", ["password"]),
        ("client_Secret", ["secret"]),
        ("Authorization: Bearer x", ["bearer"]),
        ("token and secret", ["token", "secret"]),
    ],
)
def test_find_secret_words_flags_injected_words(text, found):
    assert sorted(find_secret_words(text)) == sorted(found)


def test_fake_manifest_contains_no_secret_words():
    assert find_secret_words(dumps_manifest(make_manifest())) == []


def test_write_refuses_manifest_with_secret_word(tmp_path):
    manifest = make_manifest()
    manifest["entries"][0]["graph_message_id"] = "password123"
    path = tmp_path / "seed-manifest.json"
    with pytest.raises(ManifestError, match="password"):
        write_manifest(path, manifest)
    assert not path.exists()


# --- serialisation ---------------------------------------------------------------------

def test_dumps_manifest_format():
    manifest = make_manifest()
    manifest["entries"][0]["location"]["folder"] = "Boîte de réception"
    text = dumps_manifest(manifest)
    assert text == json.dumps(manifest, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    assert text.endswith("}\n") and not text.endswith("\n\n")
    assert "Boîte de réception" in text
    assert '\n  "entries": [\n    {\n      "body_content_type"' in text  # sorted, 2 spaces


def test_write_manifest_writes_lf_utf8_and_round_trips(tmp_path):
    manifest = make_manifest()
    manifest["entries"][0]["location"]["folder"] = "Boîte de réception"
    path = tmp_path / "seed-manifest.json"
    write_manifest(path, manifest)
    data = path.read_bytes()
    assert b"\r\n" not in data and b"\r" not in data
    assert not data.startswith(b"\xef\xbb\xbf")
    assert data.decode("utf-8") == dumps_manifest(manifest)
    assert load_manifest(path) == manifest


def test_write_manifest_validates_first(tmp_path):
    manifest = make_manifest()
    manifest["entries"].pop()
    path = tmp_path / "seed-manifest.json"
    with pytest.raises(ManifestError):
        write_manifest(path, manifest)
    assert not path.exists()


def test_load_manifest_missing_file_says_run_seed(tmp_path):
    with pytest.raises(ManifestError, match="python -m seeder seed"):
        load_manifest(tmp_path / "nope.json")


@pytest.mark.parametrize("content", [b"{not json", b"[1, 2]", b"\xff\xfe"])
def test_load_manifest_rejects_unreadable_content(tmp_path, content):
    path = tmp_path / "seed-manifest.json"
    path.write_bytes(content)
    with pytest.raises(ManifestError):
        load_manifest(path)

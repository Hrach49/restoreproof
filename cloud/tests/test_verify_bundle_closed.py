"""The auditor's verifier over a run folder the Worker's service closed
afterwards (W4.8, docs/decisions.md 2026-10-08, points 7 and 15):
shared/testdata/signing-v1/closed-folder.json is one such folder as texts, a
run whose process ended after a restore request and before its result was
written. The Worker's rp::Signer::verify_folder says `verified` for it
(worker/tests/worker_body_test.cpp); so must shared/tools/verify_bundle.py,
with the schema that knows the code `interrupted`. The key is RFC 8032's
published test key 1, not a secret.
"""

import hashlib
import json

from test_verify_bundle import (
    KEYS,
    SCHEMAS_DIR,
    SIGNING_DIR,
    pem_file,
    public_key,
    run_main,
    schemas,  # noqa: F401 - the fixture
    vb,
)

CLOSED = json.loads((SIGNING_DIR / "closed-folder.json").read_bytes().decode("utf-8"))


def write_closed(folder):
    folder.mkdir()
    for name, text in CLOSED["files"].items():
        (folder / name).write_bytes(text.encode("utf-8"))
    return folder


def test_the_vector_is_a_folder_without_a_result_of_its_own_run():
    result = json.loads(CLOSED["files"]["result.json"])
    status = result["status"]
    assert (status["status"], status["error_code"], status["restore_sent"]) == ("error", "interrupted", True)
    assert status["counts"] == {"failed": 0, "items": 0, "unchecked": 0, "verified": 0}
    for step in ("ended_at", "sample", "expected", "restore", "check", "cleanup"):
        assert result[step] is None
    assert all(span is None for span in result["timings"]["spans"].values())
    assert [entry["name"] for entry in result["attachments"]] == ["items.csv", "veeam-session.log"]
    assert sorted(CLOSED["files"]) == ["items.csv", "result.json", "signature.json", "veeam-session.log"]
    assert CLOSED["files"]["veeam-session.log"] == ""


def test_its_hash_and_key_are_the_files_own():
    result = CLOSED["files"]["result.json"].encode("utf-8")
    assert hashlib.sha256(result).hexdigest() == CLOSED["bundle_sha256"]
    assert KEYS[CLOSED["key"]]["key_id"] == CLOSED["key_id"]
    assert vb.canonical_fault(result) is None


def test_a_closed_folder_is_verified(tmp_path, schemas):  # noqa: F811
    folder = write_closed(tmp_path / "run")
    verdict = vb.verify_folder(folder, public_key(CLOSED["key"]), schemas)
    assert verdict.word == "verified"
    assert verdict.bundle_sha256 == CLOSED["bundle_sha256"]
    assert verdict.key_id == CLOSED["key_id"]


def test_main_prints_the_line_the_worker_prints(tmp_path, capsys):
    folder = write_closed(tmp_path / "run")
    code, out, err = run_main(
        capsys, folder, "--public-key", pem_file(tmp_path, CLOSED["key"]), "--schemas", SCHEMAS_DIR
    )
    assert code == 0
    assert out == f"verified {CLOSED['bundle_sha256']} key {CLOSED['key_id']} timestamp none\n"
    assert err == "note: not timestamped\n"


def test_one_changed_byte_of_its_result_is_not_verified(tmp_path, schemas):  # noqa: F811
    folder = write_closed(tmp_path / "run")
    text = CLOSED["files"]["result.json"].replace('"restore_sent":true', '"restore_sent":false')
    assert text != CLOSED["files"]["result.json"]
    (folder / "result.json").write_bytes(text.encode("utf-8"))
    assert vb.verify_folder(folder, public_key(CLOSED["key"]), schemas).word == "hash_mismatch"

"""The auditor's verifier, shared/tools/verify_bundle.py, over a run folder
(docs/decisions.md 2026-10-05, W4.3 points 5 and 6): for every folder of
shared/testdata/signing-v1/cases.json it gives the word the Worker's
rp::Signer::verify_folder gives (worker/tests/signer_test.cpp runs the same
file), which is what "the two verifiers agree" means offline. Beside the cases:
RFC 8032's tests byte for byte, the two test keys' PEM and key_id, the order of
the checks, the lines `main` prints and its exit codes.

The script is one self-contained file outside any package, so it is loaded by
path. The keys here are RFC 8032's published test keys, not secrets.
"""

import base64
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, x25519


def shared_dir() -> Path:
    """The repo's shared/ folder: the first one, walking up from this file, that
    holds testdata. Also found from mutmut's copy under cloud/mutants/."""
    for folder in Path(__file__).resolve().parents:
        if (folder / "shared" / "testdata").is_dir():
            return folder / "shared"
    raise FileNotFoundError("no shared/testdata above " + str(Path(__file__).resolve()))


def load_verify_bundle():
    path = shared_dir() / "tools" / "verify_bundle.py"
    spec = importlib.util.spec_from_file_location("verify_bundle", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


vb = load_verify_bundle()

SCHEMAS_DIR = shared_dir() / "schemas"
SIGNING_DIR = shared_dir() / "testdata" / "signing-v1"


def load_json(name: str):
    return json.loads((SIGNING_DIR / name).read_bytes().decode("utf-8"))


KEYS = {key["name"]: key for key in load_json("keys.json")["keys"]}
ED25519_TESTS = load_json("ed25519.json")["tests"]
BUNDLE = load_json("bundle.json")
CASES_FILE = load_json("cases.json")
CASES = {case["name"]: case for case in CASES_FILE["cases"]}
FAILING = [case for case in CASES_FILE["cases"] if case["expect"] != "verified"]
VERIFYING = [case for case in CASES_FILE["cases"] if case["expect"] == "verified"]
KEY_FILES_FILE = load_json("key-files.json")
KEY_FILES = KEY_FILES_FILE["key_files"]

# How many cases expect each word: what worker/tests/signer_test.cpp pins too,
# so a case dropped from cases.json is noticed on this side as well.
CASES_PER_WORD = {
    "verified": 1,
    "result_unreadable": 1,
    "result_not_canonical": 12,
    "result_schema": 1,
    "attachment_twice": 1,
    "screenshot_missing": 1,
    "signature_file": 10,
    "hash_mismatch": 2,
    "wrong_key": 2,
    "signature_invalid": 4,
    "attachment_missing": 1,
    "attachment_size": 1,
    "attachment_hash": 1,
}

VERIFIED_LINE = f"verified {BUNDLE['bundle_sha256']} key {BUNDLE['key_id']}\n"

# The thirteen words of the entry's point 5, `verified` and the failures in the
# checks' order.
FAILURE_WORDS = [
    "result_unreadable",
    "result_not_canonical",
    "result_schema",
    "attachment_twice",
    "screenshot_missing",
    "signature_file",
    "hash_mismatch",
    "wrong_key",
    "signature_invalid",
    "attachment_missing",
    "attachment_size",
    "attachment_hash",
]


def file_bytes(change: dict) -> bytes:
    if "text" in change:
        return change["text"].encode("utf-8")
    return base64.b64decode(change["base64"], validate=True)


def write_folder(folder: Path, *changes: dict) -> Path:
    """bundle.json's files in a new folder, then each change map applied as
    cases.json says: null removes, text and base64 replace."""
    folder.mkdir()
    for name, text in BUNDLE["files"].items():
        (folder / name).write_bytes(text.encode("utf-8"))
    for change in changes:
        for name, to in change.items():
            if to is None:
                (folder / name).unlink()
            else:
                (folder / name).write_bytes(file_bytes(to))
    return folder


def public_key(name: str = "rfc8032-test-1"):
    key = vb.public_key_from_pem(KEYS[name]["public_key_pem"].encode("ascii"))
    assert key is not None
    return key


def pem_file(tmp_path: Path, name: str = "rfc8032-test-1") -> Path:
    path = tmp_path / f"{name}.pem"
    path.write_bytes(KEYS[name]["public_key_pem"].encode("ascii"))
    return path


@pytest.fixture(scope="module")
def schemas():
    return vb.load_schemas(SCHEMAS_DIR)


def run_main(capsys, *argv) -> tuple[int, str, str]:
    code = vb.main([str(arg) for arg in argv])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


# --- the shared cases: failures first ----------------------------------------


def test_cases_file_is_about_this_bundle_and_these_keys():
    assert CASES_FILE["bundle"] == "bundle.json"
    assert CASES_FILE["keys"] == "keys.json"
    assert len(CASES) == len(CASES_FILE["cases"]), "a case name twice"
    assert FAILING and VERIFYING


def test_the_cases_are_the_38_and_so_many_of_each_word():
    assert len(CASES_FILE["cases"]) == 38
    assert sum(CASES_PER_WORD.values()) == 38
    assert Counter(case["expect"] for case in CASES_FILE["cases"]) == CASES_PER_WORD
    assert (len(FAILING), len(VERIFYING)) == (37, 1)


@pytest.mark.parametrize("case", FAILING, ids=lambda case: case["name"])
def test_each_failing_case_gets_its_word(case, tmp_path, schemas):
    folder = write_folder(tmp_path / "run", case["files"])
    verdict = vb.verify_folder(folder, public_key(case["public_key"]), schemas)
    assert verdict.word == case["expect"]
    # A failure names no hash, no key and no note.
    assert verdict.bundle_sha256 == ""
    assert verdict.key_id == ""
    assert verdict.notes == ()


@pytest.mark.parametrize("case", VERIFYING, ids=lambda case: case["name"])
def test_each_verifying_case_is_verified(case, tmp_path, schemas):
    folder = write_folder(tmp_path / "run", case["files"])
    verdict = vb.verify_folder(folder, public_key(case["public_key"]), schemas)
    assert verdict.word == "verified"
    assert verdict.bundle_sha256 == BUNDLE["bundle_sha256"]
    assert verdict.key_id == BUNDLE["key_id"]
    assert verdict.notes == ()


def test_the_vectors_expect_exactly_the_words_the_script_can_answer():
    expected = {case["expect"] for case in CASES_FILE["cases"]}
    assert expected == set(vb.WORDS) | {vb.VERIFIED}


def test_the_words_are_the_entrys_in_the_checks_order():
    assert vb.VERIFIED == "verified"
    assert list(vb.WORDS) == FAILURE_WORDS


@pytest.mark.parametrize(
    "name",
    [
        "result-removed",
        "result-bom",
        "result-unknown-status",
        "signature-removed",
        "result-check-item-one-digit",
        "untouched-the-second-key-given",
        "signature-s-plus-l",
        "forgery-result-changed-hash-computed-again",
        "attachment-one-byte-changed",
    ],
)
def test_main_prints_not_verified_and_the_word_and_exits_1(name, tmp_path, capsys):
    case = CASES[name]
    folder = write_folder(tmp_path / "run", case["files"])
    code, out, err = run_main(
        capsys, folder, "--public-key", pem_file(tmp_path, case["public_key"]), "--schemas", SCHEMAS_DIR
    )
    assert out == f"not verified: {case['expect']}\n"
    assert err == ""
    assert code == 1


# --- the order of the checks: the first failure wins --------------------------


@pytest.mark.parametrize(
    ("first", "second", "key"),
    [
        ("result-removed", "signature-removed", "rfc8032-test-1"),
        ("result-not-json", "signature-removed", "rfc8032-test-1"),
        ("result-unknown-status", "signature-removed", "rfc8032-test-1"),
        ("result-attachment-listed-twice", "signature-removed", "rfc8032-test-1"),
        ("result-captured-without-screenshot", "signature-removed", "rfc8032-test-1"),
        ("signature-removed", "attachment-removed", "rfc8032-test-1"),
        ("signature-not-json", "result-expected-item-hash-one-digit", "rfc8032-test-1"),
        ("result-expected-item-hash-one-digit", "untouched-the-second-key-given", "rfc8032-test-2"),
        ("result-expected-item-hash-one-digit", "signature-one-bit-changed", "rfc8032-test-1"),
        ("signature-of-the-second-key", "attachment-removed", "rfc8032-test-1"),
        ("signature-one-bit-changed", "attachment-removed", "rfc8032-test-1"),
        # items.csv is listed before veeam-session.log.
        ("attachment-one-byte-changed", "attachment-removed", "rfc8032-test-1"),
    ],
)
def test_an_earlier_check_answers_before_a_later_one(first, second, key, tmp_path, schemas):
    folder = write_folder(tmp_path / "run", CASES[second]["files"], CASES[first]["files"])
    verdict = vb.verify_folder(folder, public_key(key), schemas)
    assert verdict.word == CASES[first]["expect"]


def test_the_key_id_is_checked_before_the_signature(tmp_path, schemas):
    # The second key's signature and key_id: under the first key it is the
    # wrong key, though the signature is no signature of the first key either.
    folder = write_folder(tmp_path / "run", CASES["signature-of-the-second-key"]["files"])
    assert vb.verify_folder(folder, public_key("rfc8032-test-1"), schemas).word == "wrong_key"
    # And under the second key, whose signature it is, the folder verifies.
    verdict = vb.verify_folder(folder, public_key("rfc8032-test-2"), schemas)
    assert verdict.word == "verified"
    assert verdict.key_id == KEYS["rfc8032-test-2"]["key_id"]


# --- what the cases don't hold -----------------------------------------------


def test_a_result_over_the_size_limit_is_unreadable_and_one_at_it_is_read(tmp_path, schemas):
    assert vb.MAX_RESULT_FILE_BYTES == 16 * 1024 * 1024  # rp::kMaxResultFileBytes
    folder = write_folder(tmp_path / "run")
    (folder / "result.json").write_bytes(b" " * (vb.MAX_RESULT_FILE_BYTES + 1))
    assert vb.verify_folder(folder, public_key(), schemas).word == "result_unreadable"
    (folder / "result.json").write_bytes(b" " * vb.MAX_RESULT_FILE_BYTES)
    assert vb.verify_folder(folder, public_key(), schemas).word == "result_not_canonical"


def test_a_result_that_is_a_folder_is_unreadable(tmp_path, schemas):
    folder = write_folder(tmp_path / "run", {"result.json": None})
    (folder / "result.json").mkdir()
    assert vb.verify_folder(folder, public_key(), schemas).word == "result_unreadable"


def test_an_empty_result_is_not_canonical(tmp_path, schemas):
    folder = write_folder(tmp_path / "run", {"result.json": {"text": ""}})
    assert vb.verify_folder(folder, public_key(), schemas).word == "result_not_canonical"


def test_a_signature_file_over_its_size_limit_is_signature_file(tmp_path, schemas):
    assert vb.MAX_SIGNATURE_FILE_BYTES == 4096  # rp::kMaxSignatureFileBytes
    folder = write_folder(tmp_path / "run")
    signature = (folder / "signature.json").read_bytes()
    (folder / "signature.json").write_bytes(signature + b" " * 4096)
    assert vb.verify_folder(folder, public_key(), schemas).word == "signature_file"


@pytest.mark.parametrize(
    "text",
    [
        "[]",
        "null",
        "{}",
        '{"algorithm":"ed25519"}',
        '"restoreproof.signature.v1"',
    ],
)
def test_a_canonical_signature_file_that_is_not_its_five_keys(text, tmp_path, schemas):
    folder = write_folder(tmp_path / "run", {"signature.json": {"text": text}})
    assert vb.verify_folder(folder, public_key(), schemas).word == "signature_file"


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("algorithm", "Ed25519"),
        ("format", "restoreproof.signature.v2"),
        ("bundle_sha256", BUNDLE["bundle_sha256"][:63]),
        ("key_id", BUNDLE["key_id"] + "0"),
        ("key_id", None),
        ("signature", 7),
        ("signature", ""),
    ],
)
def test_a_signature_file_with_one_value_of_another_shape(key, value, tmp_path, schemas):
    document = json.loads(BUNDLE["files"]["signature.json"])
    document[key] = value
    text = vb.canonical_json(document).decode("utf-8")
    folder = write_folder(tmp_path / "run", {"signature.json": {"text": text}})
    assert vb.verify_folder(folder, public_key(), schemas).word == "signature_file"


def test_an_attachment_longer_than_listed_is_attachment_size(tmp_path, schemas):
    folder = write_folder(tmp_path / "run")
    with (folder / "items.csv").open("ab") as file:
        file.write(b"2,\"onedrive\",\"a third\"\n")
    assert vb.verify_folder(folder, public_key(), schemas).word == "attachment_size"


def test_an_attachment_that_is_a_folder_is_missing(tmp_path, schemas):
    folder = write_folder(tmp_path / "run", {"veeam-session.log": None})
    (folder / "veeam-session.log").mkdir()
    assert vb.verify_folder(folder, public_key(), schemas).word == "attachment_missing"


def test_a_file_the_result_does_not_list_is_a_note_never_a_failure(tmp_path, schemas):
    folder = write_folder(tmp_path / "run")
    (folder / "manifest.json").write_bytes(b"{}")
    (folder / "a-token.tsr").write_bytes(b"\x00")
    (folder / "sub").mkdir()
    verdict = vb.verify_folder(folder, public_key(), schemas)
    assert verdict.word == "verified"
    assert verdict.notes == ("a-token.tsr", "manifest.json", "sub")


def test_a_failed_folder_has_no_notes(tmp_path, schemas):
    folder = write_folder(tmp_path / "run", CASES["attachment-removed"]["files"])
    (folder / "manifest.json").write_bytes(b"{}")
    verdict = vb.verify_folder(folder, public_key(), schemas)
    assert verdict.word == "attachment_missing"
    assert verdict.notes == ()


def test_the_public_key_is_never_taken_from_the_folder(tmp_path, schemas):
    # The second key's whole signature, and its PEM beside it: the caller's key
    # decides, the PEM in the folder is one more unlisted file.
    folder = write_folder(tmp_path / "run", CASES["signature-of-the-second-key"]["files"])
    for name in ("public-key.pem", "public_key.pem", "key.pem"):
        (folder / name).write_bytes(KEYS["rfc8032-test-2"]["public_key_pem"].encode("ascii"))
    assert vb.verify_folder(folder, public_key("rfc8032-test-1"), schemas).word == "wrong_key"


def test_the_result_is_checked_as_canonical_before_the_schema_sees_it(tmp_path):
    # Python's `integer` takes 1.0: with a schema that takes anything, the float
    # is still refused, and as not canonical.
    lax = tmp_path / "schemas"
    lax.mkdir()
    (lax / "result.v1.json").write_bytes(b"{}")
    (lax / "signature.v1.json").write_bytes((SCHEMAS_DIR / "signature.v1.json").read_bytes())
    folder = write_folder(tmp_path / "run", CASES["result-float-1.0"]["files"])
    verdict = vb.verify_folder(folder, public_key(), vb.load_schemas(lax))
    assert verdict.word == "result_not_canonical"


def test_a_folder_that_cannot_be_listed_is_not_a_verdict(tmp_path, schemas):
    with pytest.raises(vb.SetupError):
        vb.verify_folder(tmp_path / "not-there", public_key(), schemas)


# --- the lines of main, and exit 0 --------------------------------------------


def test_main_prints_the_verified_line_and_exits_0(tmp_path, capsys):
    folder = write_folder(tmp_path / "run")
    code, out, err = run_main(capsys, folder, "--public-key", pem_file(tmp_path), "--schemas", SCHEMAS_DIR)
    assert out == VERIFIED_LINE
    assert re.fullmatch(r"verified [0-9a-f]{64} key [0-9a-f]{64}\n", out)
    assert err == ""
    assert code == 0


def test_main_finds_the_schemas_beside_the_script_by_default(tmp_path, capsys):
    folder = write_folder(tmp_path / "run")
    code, out, err = run_main(capsys, folder, "--public-key", pem_file(tmp_path))
    assert (code, out, err) == (0, VERIFIED_LINE, "")
    assert vb.default_schemas_dir() == SCHEMAS_DIR


def test_main_notes_each_unlisted_file_on_stderr(tmp_path, capsys):
    folder = write_folder(tmp_path / "run")
    (folder / "manifest.json").write_bytes(b"{}")
    (folder / "tsa-token.tsr").write_bytes(b"\x00")
    code, out, err = run_main(capsys, folder, "--public-key", pem_file(tmp_path), "--schemas", SCHEMAS_DIR)
    assert out == VERIFIED_LINE
    assert err == (
        "note: not listed in the result: manifest.json\n"
        "note: not listed in the result: tsa-token.tsr\n"
    )
    assert code == 0


def test_a_note_shows_an_odd_file_name_in_ascii(tmp_path, capsys):
    folder = write_folder(tmp_path / "run")
    (folder / "bericht-ü.txt").write_bytes(b"")
    code, out, err = run_main(capsys, folder, "--public-key", pem_file(tmp_path), "--schemas", SCHEMAS_DIR)
    assert (code, out) == (0, VERIFIED_LINE)
    assert err == "note: not listed in the result: bericht-\\xfc.txt\n"


# The Worker's rule for a name in a note (worker/src/signer_command.cpp,
# `printable`): printable ASCII but the backslash as it is, anything else by its
# code point in lower-case hex, \xNN below U+0100, \uNNNN below U+10000,
# \UNNNNNNNN above; a surrogate without its pair is a code point of its own.
@pytest.mark.parametrize(
    ("name", "printed"),
    [
        ("items (2).csv", "items (2).csv"),
        (" ~", " ~"),
        ("a\\b", "a\\x5cb"),
        ("a\tb", "a\\x09b"),
        ("a\nb", "a\\x0ab"),
        ("a\rb", "a\\x0db"),
        ("\x00\x1f\x7f", "\\x00\\x1f\\x7f"),
        ("\x80\xa0\xff", "\\x80\\xa0\\xff"),
        ("bericht-\u00fc.txt", "bericht-\\xfc.txt"),
        ("\u0100\u65e5\uffff", "\\u0100\\u65e5\\uffff"),
        ("\U00010000\U0001f600\U0010ffff", "\\U00010000\\U0001f600\\U0010ffff"),
        ("x\udc80y", "x\\udc80y"),
        ("\ud800", "\\ud800"),
        # A high and a low one side by side, each without its pair in the name
        # as the folder gave it: never joined into one character.
        ("\ud83d" + "\ude00", "\\ud83d\\ude00"),
        ("\udfff\ud800", "\\udfff\\ud800"),
    ],
)
def test_a_name_is_printed_by_the_workers_rule(name, printed):
    assert vb._printable(name) == printed
    assert printed.isascii() and printed.isprintable()


def test_the_notes_for_odd_names_are_the_workers_lines_in_code_point_order(tmp_path, capsys):
    # The line `rpworker signer verify` prints for each of these names, and in
    # its order: by code point, so U+FF01 before U+1F600 (UTF-16 order would
    # put the surrogate pair first) and the lone surrogate U+DC80 between.
    folder = write_folder(tmp_path / "run")
    names = ["\U0001f600.bin", "x\udc80y", "\u65e5\u672c.txt", "bericht-\u00fc.txt", "\udc80", "\uff01"]
    for name in names:
        try:
            # Windows keeps a lone surrogate in a name; elsewhere it stands for
            # the byte 0x80 (surrogateescape), which the listing gives back.
            (folder / name).write_bytes(b"")
        except (OSError, ValueError):  # pragma: no cover - a file system that has no such name
            pytest.skip("this file system takes no such name")
    assert sorted(os.listdir(folder))[-5:] == [
        "x\udc80y", "\u65e5\u672c.txt", "\udc80", "\uff01", "\U0001f600.bin",
    ]
    code, out, err = run_main(capsys, folder, "--public-key", pem_file(tmp_path), "--schemas", SCHEMAS_DIR)
    assert (code, out) == (0, VERIFIED_LINE)
    assert err == (
        "note: not listed in the result: bericht-\\xfc.txt\n"
        "note: not listed in the result: x\\udc80y\n"
        "note: not listed in the result: \\u65e5\\u672c.txt\n"
        "note: not listed in the result: \\udc80\n"
        "note: not listed in the result: \\uff01\n"
        "note: not listed in the result: \\U0001f600.bin\n"
    )
    assert err.isascii()


def test_no_output_line_uses_a_banned_word(tmp_path, capsys):
    lines = []
    for name in ("untouched", "signature-one-bit-changed"):
        folder = write_folder(tmp_path / name, CASES[name]["files"])
        _, out, err = run_main(capsys, folder, "--public-key", pem_file(tmp_path), "--schemas", SCHEMAS_DIR)
        lines.append(out + err)
    text = " ".join(lines + list(vb.WORDS) + [vb.__doc__]).lower()
    for banned in ("certified", "guarantee", "fully recoverable", "accepted by insurers"):
        assert banned not in text


# --- exit 2: never a verdict --------------------------------------------------


def assert_no_verdict(code: int, out: str, err: str) -> None:
    assert code == 2
    assert out == ""
    assert "verified" not in err
    assert err.startswith(("error: ", "usage: "))


def test_a_missing_folder_is_exit_2(tmp_path, capsys):
    code, out, err = run_main(
        capsys, tmp_path / "not-there", "--public-key", pem_file(tmp_path), "--schemas", SCHEMAS_DIR
    )
    assert_no_verdict(code, out, err)
    assert err == "error: the folder can't be opened\n"


def test_a_file_given_as_the_folder_is_exit_2(tmp_path, capsys):
    folder = write_folder(tmp_path / "run")
    code, out, err = run_main(
        capsys, folder / "result.json", "--public-key", pem_file(tmp_path), "--schemas", SCHEMAS_DIR
    )
    assert_no_verdict(code, out, err)
    assert err == "error: the folder can't be opened\n"


def test_an_empty_folder_argument_is_exit_2_never_the_working_folder(tmp_path, capsys, monkeypatch):
    folder = write_folder(tmp_path / "run")
    key_file = pem_file(tmp_path)
    monkeypatch.chdir(folder)
    # The working folder itself verifies when it is named.
    assert run_main(capsys, ".", "--public-key", key_file, "--schemas", SCHEMAS_DIR) == (0, VERIFIED_LINE, "")
    code, out, err = run_main(capsys, "", "--public-key", key_file)
    assert_no_verdict(code, out, err)
    assert err == "error: the folder can't be opened\n"
    code, out, err = run_main(capsys, "", "--public-key", key_file, "--schemas", SCHEMAS_DIR)
    assert_no_verdict(code, out, err)
    assert err == "error: the folder can't be opened\n"


def test_verify_folder_takes_no_empty_folder_as_the_working_folder(tmp_path, schemas, monkeypatch):
    monkeypatch.chdir(write_folder(tmp_path / "run"))
    assert vb.verify_folder(".", public_key(), schemas).word == "verified"
    assert vb.verify_folder(Path("."), public_key(), schemas).word == "verified"
    with pytest.raises(vb.SetupError):
        vb.verify_folder("", public_key(), schemas)


def test_an_empty_public_key_value_is_exit_2(tmp_path, capsys, monkeypatch):
    folder = write_folder(tmp_path / "run")
    monkeypatch.chdir(tmp_path)
    read = []
    real = vb._read_file
    monkeypatch.setattr(vb, "_read_file", lambda path, limit: (read.append(path.name), real(path, limit))[1])
    code, out, err = run_main(capsys, folder, "--public-key", "", "--schemas", SCHEMAS_DIR)
    assert_no_verdict(code, out, err)
    assert err == "error: --public-key: the file can't be read\n"
    assert read == ["result.v1.json", "signature.v1.json"]  # no file was tried as the key


def test_an_empty_schemas_value_is_exit_2_never_the_working_folders_schemas(tmp_path, capsys, monkeypatch):
    folder = write_folder(tmp_path / "run")
    key_file = pem_file(tmp_path)
    here = tmp_path / "schemas-here"
    here.mkdir()
    for name in ("result.v1.json", "signature.v1.json"):
        (here / name).write_bytes((SCHEMAS_DIR / name).read_bytes())
    monkeypatch.chdir(here)
    assert run_main(capsys, folder, "--public-key", key_file, "--schemas", ".") == (0, VERIFIED_LINE, "")
    code, out, err = run_main(capsys, folder, "--public-key", key_file, "--schemas", "")
    assert_no_verdict(code, out, err)
    assert err == "error: --schemas: the folder can't be opened\n"
    with pytest.raises(vb.SetupError):
        vb.load_schemas("")


def test_a_folder_that_lists_and_cannot_be_read_from_is_exit_2_never_a_verdict(tmp_path, capsys, monkeypatch):
    # What Python 3.14 does on Windows for `<folder> ` (a trailing space): the
    # listing of that name succeeds and no file under it opens. Faked, so it
    # holds on every interpreter: a listing that answers for a name nothing
    # can be read under.
    folder = write_folder(tmp_path / "run")
    real_listdir = os.listdir
    asked = []

    def listing(path="."):
        asked.append(str(path))
        return real_listdir(folder)

    monkeypatch.setattr(vb.os, "listdir", listing)
    code, out, err = run_main(
        capsys, tmp_path / "another-name", "--public-key", pem_file(tmp_path), "--schemas", SCHEMAS_DIR
    )
    monkeypatch.undo()
    assert_no_verdict(code, out, err)
    assert err == "error: the folder can't be opened\n"
    assert asked == []  # not even listed


def test_the_listing_and_every_read_use_the_one_resolved_folder(tmp_path, schemas, monkeypatch):
    folder = write_folder(tmp_path / "run")
    (tmp_path / "other").mkdir()
    given = tmp_path / "other" / ".." / "run"
    # On Windows in the extended-length form, which has no 260-character limit.
    resolved = extended(folder.resolve(strict=True))
    listed, opened = [], []
    real_listdir, real_open = os.listdir, open

    def listing(path="."):
        listed.append(str(path))
        return real_listdir(path)

    def opening(path, *args, **kwargs):
        opened.append(str(path))
        return real_open(path, *args, **kwargs)

    key = public_key()
    monkeypatch.setattr(vb.os, "listdir", listing)
    monkeypatch.setattr(vb, "open", opening, raising=False)
    verdict = vb.verify_folder(given, key, schemas)
    monkeypatch.undo()
    assert verdict.word == "verified"
    assert listed == [resolved]
    names = ["result.json", "signature.json", "items.csv", "veeam-session.log"]
    assert opened == [os.path.join(resolved, name) for name in names]


def test_a_folder_given_with_a_trailing_space_never_gets_a_failing_verdict(tmp_path, capsys):
    # Windows opens `run ` as `run`; elsewhere there is no such folder. Either
    # the one resolved folder is verified or nothing is: never `not verified`
    # for a complete folder (which the listing and the reads of Python 3.14 on
    # Windows, each asked with the name as given, would end in).
    folder = write_folder(tmp_path / "run")
    code, out, err = run_main(capsys, str(folder) + " ", "--public-key", pem_file(tmp_path), "--schemas", SCHEMAS_DIR)
    if code == 0:
        assert (out, err) == (VERIFIED_LINE, "")
    else:
        assert_no_verdict(code, out, err)
        assert err == "error: the folder can't be opened\n"


def test_a_folder_that_resolves_and_cannot_be_listed_is_exit_2(tmp_path, capsys, monkeypatch):
    folder = write_folder(tmp_path / "run")

    def refuse(_path="."):
        raise PermissionError("no")

    monkeypatch.setattr(vb.os, "listdir", refuse)
    code, out, err = run_main(capsys, folder, "--public-key", pem_file(tmp_path), "--schemas", SCHEMAS_DIR)
    monkeypatch.undo()
    assert_no_verdict(code, out, err)
    assert err == "error: the folder can't be opened\n"


def rsa_pem() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def other_pems() -> dict[str, bytes]:
    test_1 = KEYS["rfc8032-test-1"]["public_key_pem"].encode("ascii")
    test_2 = KEYS["rfc8032-test-2"]["public_key_pem"].encode("ascii")
    spki = serialization.PublicFormat.SubjectPublicKeyInfo
    pem = serialization.Encoding.PEM
    private = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(KEYS["rfc8032-test-1"]["seed_hex"]))
    return {
        "empty": b"",
        "not-pem": b"this is not a key\n",
        "rsa": rsa_pem(),
        "p-256": ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(pem, spki),
        "x25519": x25519.X25519PrivateKey.generate().public_key().public_bytes(pem, spki),
        "the-private-key": private.private_bytes(
            pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ),
        "two-blocks": test_1 + test_2,
        "text-before-the-block": b"the Worker's key:\n" + test_1,
        "text-after-the-block": test_1 + b"that was it\n",
        "a-nul-in-it": test_1.replace(b"\n", b"\x00\n", 1),
        "a-broken-body": test_1.replace(b"MCow", b"!!!!"),
        "a-cut-body": test_1.replace(b"URo=", b""),
        "not-utf8": b"\xff\xfe" + test_1,
    }


OTHER_PEMS = other_pems()


@pytest.mark.parametrize("name", sorted(OTHER_PEMS))
def test_a_key_file_that_is_not_one_ed25519_public_key_is_exit_2(name, tmp_path, capsys):
    assert vb.public_key_from_pem(OTHER_PEMS[name]) is None
    folder = write_folder(tmp_path / "run")
    key_file = tmp_path / "key.pem"
    key_file.write_bytes(OTHER_PEMS[name])
    code, out, err = run_main(capsys, folder, "--public-key", key_file, "--schemas", SCHEMAS_DIR)
    assert_no_verdict(code, out, err)
    assert err == "error: --public-key: not an Ed25519 public key in PEM\n"


# --- key-files.json: one rule for a public key file in both verifiers ---------


def test_the_key_files_are_the_46_and_11_are_keys():
    assert KEY_FILES_FILE["keys"] == "keys.json"
    assert KEY_FILES_FILE["accepted_key_id"] == KEYS["rfc8032-test-1"]["key_id"]
    assert len(KEY_FILES) == 46
    assert len({row["name"] for row in KEY_FILES}) == 46, "a name twice"
    assert sum(1 for row in KEY_FILES if row["accepted"]) == 11
    assert sum(1 for row in KEY_FILES if not row["accepted"]) == 35
    for row in KEY_FILES:
        assert sorted(row) in (["accepted", "name", "text"], ["accepted", "base64", "name"]), row["name"]
        assert type(row["accepted"]) is bool
    assert [row["name"] for row in KEY_FILES if "base64" in row] == ["utf16-le-with-bom"]
    # The identity key's ID is its own DER's, as the rule writes it.
    identity = bytes.fromhex("302a300506032b6570032100") + b"\x01" + bytes(31)
    assert hashlib.sha256(identity).hexdigest() == KEY_FILES_FILE["identity_key_id"]


def key_id_of_row(row: dict) -> str:
    return KEY_FILES_FILE["identity_key_id" if row["name"] == "small-order-identity-key" else "accepted_key_id"]


@pytest.mark.parametrize("row", KEY_FILES, ids=lambda row: row["name"])
def test_each_key_file_is_taken_or_refused_as_the_worker_does(row):
    key = vb.public_key_from_pem(file_bytes(row))
    if not row["accepted"]:
        assert key is None
        return
    assert key is not None
    assert key.key_id == key_id_of_row(row)
    # The file's own 44 bytes, never a re-encoding.
    assert len(key.der) == 44
    assert key.der[:12].hex() == "302a300506032b6570032100"
    assert hashlib.sha256(key.der).hexdigest() == key.key_id


@pytest.mark.parametrize("row", KEY_FILES, ids=lambda row: row["name"])
def test_each_key_file_through_main(row, tmp_path, capsys):
    folder = write_folder(tmp_path / "run")
    key_file = tmp_path / "key.pem"
    key_file.write_bytes(file_bytes(row))
    code, out, err = run_main(capsys, folder, "--public-key", key_file, "--schemas", SCHEMAS_DIR)
    if not row["accepted"]:
        assert_no_verdict(code, out, err)
        assert err == "error: --public-key: not an Ed25519 public key in PEM\n"
    elif key_id_of_row(row) == BUNDLE["key_id"]:
        assert (code, out, err) == (0, VERIFIED_LINE, "")
    else:  # a key, and not the bundle's
        assert (code, out, err) == (1, "not verified: wrong_key\n", "")


def test_the_library_is_not_asked_about_a_file_the_rule_refuses(monkeypatch):
    asked = []
    real = vb.Ed25519PublicKey.from_public_bytes

    class Watched:
        @staticmethod
        def from_public_bytes(data):
            asked.append(bytes(data))
            return real(data)

    monkeypatch.setattr(vb, "Ed25519PublicKey", Watched)
    for row in KEY_FILES:
        key = vb.public_key_from_pem(file_bytes(row))
        assert (key is not None) == row["accepted"], row["name"]
    # Asked once per accepted file, and only for the 32 bytes after the prefix.
    assert len(asked) == 11
    assert all(len(raw) == 32 for raw in asked)
    assert not hasattr(vb, "serialization")  # no PEM or DER reader of the library


def test_a_key_the_library_refuses_is_no_key(monkeypatch):
    class Refusing:
        @staticmethod
        def from_public_bytes(_data):
            raise ValueError("no")

    monkeypatch.setattr(vb, "Ed25519PublicKey", Refusing)
    assert vb.public_key_from_pem(KEYS["rfc8032-test-1"]["public_key_pem"].encode("ascii")) is None


def test_a_key_file_that_is_not_there_is_exit_2(tmp_path, capsys):
    folder = write_folder(tmp_path / "run")
    code, out, err = run_main(capsys, folder, "--public-key", tmp_path / "no.pem", "--schemas", SCHEMAS_DIR)
    assert_no_verdict(code, out, err)
    assert err == "error: --public-key: the file can't be read\n"


def test_a_key_file_with_white_space_around_its_block_is_the_key(tmp_path):
    pem = KEYS["rfc8032-test-1"]["public_key_pem"].encode("ascii")
    for text in (pem, b"\r\n \t" + pem + b"\n\n", pem.replace(b"\n", b"\r\n"), pem.rstrip(b"\n")):
        key = vb.public_key_from_pem(text)
        assert key is not None
        assert key.key_id == KEYS["rfc8032-test-1"]["key_id"]


def test_a_missing_schema_folder_is_exit_2(tmp_path, capsys):
    folder = write_folder(tmp_path / "run")
    code, out, err = run_main(
        capsys, folder, "--public-key", pem_file(tmp_path), "--schemas", tmp_path / "no-schemas"
    )
    assert_no_verdict(code, out, err)
    assert err == "error: --schemas: result.v1.json can't be read\n"


@pytest.mark.parametrize("missing", ["result.v1.json", "signature.v1.json"])
def test_one_schema_not_found_is_exit_2_never_a_skipped_check(missing, tmp_path, capsys):
    schemas_dir = tmp_path / "schemas"
    schemas_dir.mkdir()
    for name in ("result.v1.json", "signature.v1.json"):
        if name != missing:
            (schemas_dir / name).write_bytes((SCHEMAS_DIR / name).read_bytes())
    folder = write_folder(tmp_path / "run")
    code, out, err = run_main(capsys, folder, "--public-key", pem_file(tmp_path), "--schemas", schemas_dir)
    assert_no_verdict(code, out, err)
    assert err == f"error: --schemas: {missing} can't be read\n"


@pytest.mark.parametrize(
    "content",
    [b"this is not JSON", b"[]", b'{"type":"no-such-type"}', b'{"type":"object","type":"object"}', b"\xff"],
)
def test_a_schema_file_that_is_not_a_schema_is_exit_2(content, tmp_path, capsys):
    schemas_dir = tmp_path / "schemas"
    schemas_dir.mkdir()
    (schemas_dir / "result.v1.json").write_bytes((SCHEMAS_DIR / "result.v1.json").read_bytes())
    (schemas_dir / "signature.v1.json").write_bytes(content)
    folder = write_folder(tmp_path / "run")
    code, out, err = run_main(capsys, folder, "--public-key", pem_file(tmp_path), "--schemas", schemas_dir)
    assert_no_verdict(code, out, err)
    assert err == "error: --schemas: signature.v1.json isn't a JSON Schema\n"


@pytest.mark.parametrize("failure", [RuntimeError("boom"), KeyError("attachments"), KeyboardInterrupt(), MemoryError()])
def test_anything_unexpected_inside_main_is_exit_2(failure, tmp_path, capsys, monkeypatch):
    def fail(*_args, **_kwargs):
        raise failure

    monkeypatch.setattr(vb, "verify_folder", fail)
    folder = write_folder(tmp_path / "run")
    code, out, err = run_main(capsys, folder, "--public-key", pem_file(tmp_path), "--schemas", SCHEMAS_DIR)
    assert_no_verdict(code, out, err)
    assert err == f"error: unexpected failure ({type(failure).__name__})\n"


@pytest.mark.parametrize("name", ["untouched", "signature-one-bit-changed"])
def test_a_verdict_that_cannot_be_printed_is_exit_2(name, tmp_path, capsys, monkeypatch):
    class LostStream:
        def write(self, _text):
            raise OSError("the pipe is closed")

        def flush(self):
            raise OSError("the pipe is closed")

    folder = write_folder(tmp_path / "run", CASES[name]["files"])
    key_file = pem_file(tmp_path)
    monkeypatch.setattr(vb.sys, "stdout", LostStream())
    code = vb.main([str(folder), "--public-key", str(key_file), "--schemas", str(SCHEMAS_DIR)])
    monkeypatch.undo()
    assert code == 2
    assert capsys.readouterr().err == "error: unexpected failure (OSError)\n"


def test_verify_checks_the_two_files_bytes_without_a_folder(schemas):
    result = BUNDLE["files"]["result.json"].encode("utf-8")
    signature = BUNDLE["files"]["signature.json"].encode("utf-8")
    assert vb.verify(result, signature, public_key(), schemas) == vb.Verification(
        "verified", BUNDLE["bundle_sha256"], BUNDLE["key_id"], ()
    )
    assert vb.verify(result, None, public_key(), schemas).word == "signature_file"
    assert vb.verify(result + b"\n", signature, public_key(), schemas).word == "result_not_canonical"
    assert vb.verify(result, signature, public_key("rfc8032-test-2"), schemas).word == "wrong_key"


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["folder"],
        ["--public-key", "key.pem"],
        ["folder", "--public-key"],
        ["folder", "another", "--public-key", "key.pem"],
        ["folder", "--public-key", "key.pem", "--no-such-flag"],
        # No abbreviation of a flag.
        ["folder", "--public", "key.pem"],
    ],
)
def test_a_usage_error_is_exit_2(argv, capsys):
    code, out, err = run_main(capsys, *argv)
    assert_no_verdict(code, out, err)
    assert err.startswith("usage: verify_bundle.py")


# --- ed25519.json: RFC 8032 section 7.1, byte for byte -------------------------


def test_the_rfc_tests_are_the_three():
    assert [test["name"] for test in ED25519_TESTS] == ["rfc8032-test-1", "rfc8032-test-2", "rfc8032-test-3"]


@pytest.mark.parametrize("test", ED25519_TESTS, ids=lambda test: test["name"])
def test_each_rfc_8032_signature_is_reproduced_and_accepted(test):
    private = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(test["seed_hex"]))
    public = private.public_key()
    raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert raw.hex() == test["public_key_hex"]
    message = bytes.fromhex(test["message_hex"])
    signature = private.sign(message)
    assert signature.hex() == test["signature_hex"]
    public.verify(signature, message)  # raises when it isn't one
    # And through the script's own key: the same answer, and no to one bit less.
    pem = public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    key = vb.public_key_from_pem(pem)
    assert key.accepts(signature, message) is True
    changed = bytes([signature[0] ^ 1]) + signature[1:]
    assert key.accepts(changed, message) is False


# --- keys.json: the PEM and the key_id from the seed ---------------------------


def test_the_two_test_keys_are_rfc_8032s_first_two():
    assert sorted(KEYS) == ["rfc8032-test-1", "rfc8032-test-2"]
    for test in ED25519_TESTS[:2]:
        assert KEYS[test["name"]]["seed_hex"] == test["seed_hex"]


@pytest.mark.parametrize("name", sorted(KEYS))
def test_each_test_keys_texts_come_from_its_seed(name):
    entry = KEYS[name]
    private = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(entry["seed_hex"]))
    pkcs8 = private.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    assert len(pkcs8) == 48
    assert pkcs8[:16].hex() == "302e020100300506032b657004220420"
    assert base64.b64encode(pkcs8).decode("ascii") == entry["private_pkcs8_base64"]
    public = private.public_key()
    pem = public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert pem.decode("ascii") == entry["public_key_pem"]
    der = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert len(der) == 44
    assert hashlib.sha256(der).hexdigest() == entry["key_id"]
    # The script derives the same from the PEM alone.
    key = vb.public_key_from_pem(entry["public_key_pem"].encode("ascii"))
    assert key.der == der
    assert key.key_id == entry["key_id"]


# --- bundle.json as it is -----------------------------------------------------


def test_the_bundle_verifies_as_it_is(tmp_path, schemas):
    folder = write_folder(tmp_path / "run")
    assert sorted(path.name for path in folder.iterdir()) == [
        "items.csv", "result.json", "signature.json", "veeam-session.log",
    ]
    verdict = vb.verify_folder(folder, public_key(BUNDLE["key"]), schemas)
    assert verdict == vb.Verification("verified", BUNDLE["bundle_sha256"], BUNDLE["key_id"], ())


def test_the_bundles_hash_is_its_result_files_own_sha256():
    result = BUNDLE["files"]["result.json"].encode("utf-8")
    assert hashlib.sha256(result).hexdigest() == BUNDLE["bundle_sha256"]
    assert vb.is_canonical(result)
    assert BUNDLE["key_id"] == KEYS[BUNDLE["key"]]["key_id"]


def test_the_bundles_signature_file_is_canonical_valid_and_over_the_raw_digest(schemas):
    raw = BUNDLE["files"]["signature.json"].encode("utf-8")
    assert vb.is_canonical(raw)
    document = json.loads(raw)
    assert schemas.signature.is_valid(document)
    assert list(document) == ["algorithm", "bundle_sha256", "format", "key_id", "signature"]
    assert document["bundle_sha256"] == BUNDLE["bundle_sha256"]
    signature = base64.b64decode(document["signature"], validate=True)
    assert len(signature) == 64
    digest = bytes.fromhex(BUNDLE["bundle_sha256"])
    key = public_key(BUNDLE["key"])
    assert key.accepts(signature, digest) is True
    # The message is the 32 raw bytes, not their 64 hex characters.
    assert key.accepts(signature, BUNDLE["bundle_sha256"].encode("ascii")) is False
    # Ed25519 is deterministic: the test key gives this signature again.
    private = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(KEYS[BUNDLE["key"]]["seed_hex"]))
    assert private.sign(digest) == signature


def test_the_vector_files_are_lf():
    # .gitattributes keeps them LF, so both builds read the same bytes.
    for name in ("keys.json", "ed25519.json", "bundle.json", "cases.json", "key-files.json"):
        assert b"\r" not in (SIGNING_DIR / name).read_bytes(), name


# --- the code review of 2026-10-06: where the two verifiers answered differently,
# --- or a failure of the script read as a verdict ------------------------------

SCRIPT = shared_dir() / "tools" / "verify_bundle.py"


def extended(path) -> str:
    """`path` as Windows takes it whatever its length; as it is elsewhere."""
    return "\\\\?\\" + str(path) if os.name == "nt" else str(path)


@pytest.mark.parametrize(
    "argv",
    [
        ["--public-key", "{other}", "--public-key", "{key}", "--schemas", "{schemas}"],
        ["--public-key", "{key}", "--public-key", "{other}", "--schemas", "{schemas}"],
        ["--public-key", "{key}", "--public-key", "{key}", "--schemas", "{schemas}"],
        ["--public-key", "{key}", "--schemas", "{lax}", "--schemas", "{schemas}"],
        ["--public-key", "{key}", "--schemas", "{schemas}", "--schemas", "{lax}"],
        ["--public-key", "{key}", "--schemas", "{schemas}", "--schemas", "{schemas}"],
    ],
)
def test_an_option_given_twice_is_a_usage_error_never_the_last_one(argv, tmp_path, capsys):
    # argparse keeps the last value of a repeated option: a caller that puts its
    # own key first and passes further arguments on would have it replaced, and
    # a folder signed with the other key would read `verified`. The Worker
    # refuses a second --public-key with its usage line.
    folder = write_folder(tmp_path / "run")
    lax = tmp_path / "lax"
    lax.mkdir()
    (lax / "result.v1.json").write_bytes(b"{}")
    (lax / "signature.v1.json").write_bytes(b"{}")
    values = {
        "key": str(pem_file(tmp_path)),
        "other": str(pem_file(tmp_path, "rfc8032-test-2")),
        "schemas": str(SCHEMAS_DIR),
        "lax": str(lax),
    }
    code, out, err = run_main(capsys, folder, *[arg.format(**values) for arg in argv])
    assert_no_verdict(code, out, err)
    assert err.startswith("usage: verify_bundle.py")
    assert "given more than once" in err


@pytest.mark.parametrize("name", [" ", "  ", "...", ". ", ".. ", ". .", "./ ", ".\\...", "../run/ "])
def test_a_folder_name_of_blanks_or_dots_is_exit_2_never_the_folder_above_it(name, tmp_path, capsys, monkeypatch):
    # Windows drops blanks and dots at the end of a path, so each of these
    # would be the working folder or the one above it: a verdict about a folder
    # the caller never named. Both are signed folders here, so a wrong reading
    # of the name would verify.
    outer = write_folder(tmp_path / "run")
    inner = write_folder(outer / "run")
    key_file = pem_file(tmp_path)
    monkeypatch.chdir(inner)
    assert run_main(capsys, ".", "--public-key", key_file, "--schemas", SCHEMAS_DIR) == (0, VERIFIED_LINE, "")
    code, out, err = run_main(capsys, name, "--public-key", key_file, "--schemas", SCHEMAS_DIR)
    assert_no_verdict(code, out, err)
    assert err == "error: the folder can't be opened\n"
    with pytest.raises(vb.SetupError):
        vb.verify_folder(name, public_key(), vb.load_schemas(SCHEMAS_DIR))


def test_the_working_folder_and_the_one_above_are_still_named_by_their_dots(tmp_path, capsys, monkeypatch):
    outer = write_folder(tmp_path / "run")
    inner = write_folder(outer / "run")
    key_file = pem_file(tmp_path)
    monkeypatch.chdir(inner)
    for name in (".", "./", "../run", "..\\run" if os.name == "nt" else "../run/"):
        assert run_main(capsys, name, "--public-key", key_file, "--schemas", SCHEMAS_DIR) == (0, VERIFIED_LINE, "")
    code, out, err = run_main(capsys, "..", "--public-key", key_file, "--schemas", SCHEMAS_DIR)
    assert (code, out, err) == (0, VERIFIED_LINE, "note: not listed in the result: run\n")


@pytest.mark.parametrize(
    ("name", "stored_as", "word"),
    [
        ("items.csv", "ITEMS.CSV", "attachment_missing"),
        ("veeam-session.log", "Veeam-Session.log", "attachment_missing"),
        ("result.json", "RESULT.JSON", "result_unreadable"),
        ("signature.json", "Signature.json", "signature_file"),
    ],
)
def test_a_file_under_another_case_of_its_name_is_not_that_file(name, stored_as, word, tmp_path, capsys):
    # A file system that ignores case opens ITEMS.CSV for items.csv; one that
    # doesn't has no items.csv. The folder's own list of names decides, so the
    # word is the same on both, and the Worker's: never `verified` beside a
    # note that the same file isn't listed.
    folder = write_folder(tmp_path / "run")
    os.rename(folder / name, folder / stored_as)
    assert stored_as in os.listdir(folder)
    assert name not in os.listdir(folder)
    code, out, err = run_main(capsys, folder, "--public-key", pem_file(tmp_path), "--schemas", SCHEMAS_DIR)
    assert (code, out, err) == (1, f"not verified: {word}\n", "")
    assert vb.verify_folder(folder, public_key(), vb.load_schemas(SCHEMAS_DIR)).notes == ()


def test_a_file_the_folder_does_not_list_is_not_read(tmp_path, schemas, monkeypatch):
    folder = write_folder(tmp_path / "run")
    names = [name for name in os.listdir(folder) if name != "items.csv"]
    read = []
    real = vb._read_file
    monkeypatch.setattr(vb.os, "listdir", lambda _path=".": list(names))
    monkeypatch.setattr(vb, "_read_file", lambda path, limit: (read.append(path.name), real(path, limit))[1])
    verdict = vb.verify_folder(folder, public_key(), schemas)
    monkeypatch.undo()
    assert verdict.word == "attachment_missing"
    assert read == ["result.json", "signature.json"]


def test_a_folder_whose_files_are_past_260_characters_is_verified_like_any_other(tmp_path, capsys):
    # rpworker.exe opened no file past MAX_PATH and called an intact folder
    # `attachment_missing`; the script did the same where Windows' long paths
    # are switched off. Both read the folder through its extended path now.
    deep = tmp_path / "deep"
    while len(str(deep)) < 245:
        deep = deep / "twenty-characters-ab"
    os.makedirs(extended(deep))
    try:
        for name, text in BUNDLE["files"].items():
            with open(os.path.join(extended(deep), name), "wb") as file:
                file.write(text.encode("utf-8"))
        assert len(str(deep / "items.csv")) > 260
        key_file = pem_file(tmp_path)
        assert run_main(capsys, deep, "--public-key", key_file, "--schemas", SCHEMAS_DIR) == (0, VERIFIED_LINE, "")
        os.remove(os.path.join(extended(deep), "veeam-session.log"))
        assert run_main(capsys, deep, "--public-key", key_file, "--schemas", SCHEMAS_DIR) == (
            1,
            "not verified: attachment_missing\n",
            "",
        )
    finally:
        shutil.rmtree(extended(tmp_path / "deep"), ignore_errors=True)


@pytest.mark.skipif(os.name != "nt", reason="the extended-length form is Windows'")
@pytest.mark.parametrize(
    ("full", "expected"),
    [
        ("C:\\runs\\one", "\\\\?\\C:\\runs\\one"),
        ("C:/runs//one/", "\\\\?\\C:\\runs\\one"),
        ("C:\\runs\\two\\..\\one", "\\\\?\\C:\\runs\\one"),
        ("\\\\server\\share\\runs\\one", "\\\\?\\UNC\\server\\share\\runs\\one"),
        ("\\\\?\\C:\\runs\\one", "\\\\?\\C:\\runs\\one"),
        ("\\\\?\\UNC\\server\\share\\runs", "\\\\?\\UNC\\server\\share\\runs"),
        ("\\\\.\\C:\\runs\\one", "\\\\.\\C:\\runs\\one"),
    ],
)
def test_a_windows_path_in_its_extended_form(full, expected):
    assert vb._extended(full) == expected


@pytest.mark.parametrize("missing", ["cryptography", "jsonschema"])
def test_the_script_without_one_of_its_packages_is_exit_2_never_a_verdicts_exit_code(missing, tmp_path):
    # Run with plain `python` and not `uv run`, the import fails; Python's own
    # exit status for a traceback is 1, which is "not verified".
    folder = write_folder(tmp_path / "run")
    runner = (
        "import runpy, sys\n"
        f"sys.modules[{missing!r}] = None\n"
        "sys.argv = sys.argv[1:]\n"
        "runpy.run_path(sys.argv[0], run_name='__main__')\n"
    )
    done = subprocess.run(
        [sys.executable, "-c", runner, str(SCRIPT), str(folder), "--public-key", str(pem_file(tmp_path))],
        capture_output=True,
        timeout=120,
        check=False,
    )
    err = done.stderr.decode("utf-8").replace("\r\n", "\n")
    assert done.returncode == 2
    assert done.stdout == b""
    assert err == f"error: a package the script needs isn't installed ({missing}); run it with `uv run`\n"


def test_the_script_as_a_module_without_a_package_is_an_import_error_not_an_exit(monkeypatch):
    monkeypatch.setitem(sys.modules, "jsonschema", None)
    with pytest.raises(ImportError):
        load_verify_bundle()


@pytest.mark.parametrize("name", ["untouched", "signature-one-bit-changed"])
def test_the_script_whose_stdout_is_gone_exits_2_not_pythons_120(name, tmp_path):
    # main() returns 2 when the verdict can't be flushed, but the text stays in
    # stdout's buffer: the interpreter's own flush at exit failed again and
    # made the exit status 120, outside the script's 0, 1 and 2.
    folder = write_folder(tmp_path / "run", CASES[name]["files"])
    read_end, write_end = os.pipe()
    os.close(read_end)  # nobody reads: every write to the pipe fails
    try:
        done = subprocess.run(
            [sys.executable, str(SCRIPT), str(folder), "--public-key", str(pem_file(tmp_path))],
            stdout=write_end,
            stderr=subprocess.PIPE,
            timeout=120,
            check=False,
        )
    finally:
        os.close(write_end)
    err = done.stderr.decode("utf-8").replace("\r\n", "\n")
    assert done.returncode == 2
    assert err in ("error: unexpected failure (OSError)\n", "error: unexpected failure (BrokenPipeError)\n")


@pytest.mark.parametrize(("name", "code"), [("untouched", 0), ("signature-one-bit-changed", 1)])
def test_the_script_run_as_a_program_exits_with_its_verdicts_code(name, code, tmp_path):
    folder = write_folder(tmp_path / "run", CASES[name]["files"])
    done = subprocess.run(
        [sys.executable, str(SCRIPT), str(folder), "--public-key", str(pem_file(tmp_path))],
        capture_output=True,
        timeout=120,
        check=False,
    )
    assert done.returncode == code
    assert done.stderr == b""
    out = done.stdout.decode("utf-8").replace("\r\n", "\n")
    assert out == (VERIFIED_LINE if code == 0 else "not verified: signature_invalid\n")

"""The auditor's verifier and the timestamp (W4.4, docs/decisions.md 2026-10-06
W4.4, point 5): shared/tools/verify_bundle.py over the cases of
shared/testdata/timestamp-v1/, which the Worker's `rpworker signer verify
--tsa-ca` answers alike (worker/tests/timestamp_verify_test.cpp). The tokens
are the test-only TSA's; its keys are published in keys.json and no secret.
"""

import base64
import datetime as dt
import hashlib
import json
import re

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from test_verify_bundle import (
    BUNDLE,
    SCHEMAS_DIR,
    VERIFIED_LINE,
    pem_file,
    public_key,
    run_main,
    schemas,  # noqa: F401 - the fixture
    shared_dir,
    vb,
    write_folder,
)

TIMESTAMP_DIR = shared_dir() / "testdata" / "timestamp-v1"
TSA_KEYS = json.loads((TIMESTAMP_DIR / "keys.json").read_bytes())
CASES_FILE = json.loads((TIMESTAMP_DIR / "cases.json").read_bytes())
CASES = CASES_FILE["cases"]
BY_NAME = {case["name"]: case for case in CASES}
FAILING = [case for case in CASES if case["expect"] != "verified"]
VERIFYING = [case for case in CASES if case["expect"] == "verified"]
STAMPED_AT = "2026-10-06T12:00:00Z"
DIGEST = bytes.fromhex(BUNDLE["bundle_sha256"])
GOOD_TOKEN = base64.b64decode(BY_NAME["token"]["files"]["timestamp.tst"]["base64"])
NOT_STAMPED = "note: not timestamped\n"
UNCHECKED = "note: timestamp.tst was not checked: no --tsa-ca\n"


def tsa_ca(name: str | None) -> bytes | None:
    if name is None:
        return None
    if name == "both_roots":
        return (TSA_KEYS["other_root_pem"] + TSA_KEYS["root_pem"]).encode("ascii")
    key = "tsa_certificate_pem" if name == "tsa_certificate" else f"{name}_pem"
    return TSA_KEYS[key].encode("ascii")


def ca_file(tmp_path, name: str = "root"):
    path = tmp_path / f"tsa-{name}.pem"
    path.write_bytes(tsa_ca(name))
    return path


def stamped_folder(tmp_path):
    return write_folder(tmp_path / "run", BY_NAME["token"]["files"])


def mixed_ca(parts: str) -> bytes:
    """A CA file of the named parts, "root+key": the test root, a block of
    another label, the root under its old label, half a block, a comment."""
    root = TSA_KEYS["root_pem"]
    text = {
        "root": root,
        "key": "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
        "old label": root.replace("BEGIN CERTIFICATE", "BEGIN X509 CERTIFICATE").replace(
            "END CERTIFICATE", "END X509 CERTIFICATE"
        ),
        "half": root[: len(root) // 2],
        "comment": "the test root\n",
    }
    return "".join(text[part] for part in parts.split("+")).encode("ascii")


# --- the shared cases: failures first ----------------------------------------


def test_the_cases_are_about_the_signing_bundle_and_the_published_test_tsa():
    assert CASES_FILE["bundle"] == "../signing-v1/bundle.json"
    assert CASES_FILE["keys"] == "keys.json"
    assert len(CASES) == 23
    assert len(BY_NAME) == 23
    per_word = {}
    for case in CASES:
        per_word[case["expect"]] = per_word.get(case["expect"], 0) + 1
    assert per_word == {
        "timestamp_file": 7,
        "timestamp_mismatch": 3,
        "timestamp_invalid": 5,
        "attachment_hash": 1,
        "verified": 7,
    }
    assert {case["timestamp"] for case in VERIFYING} == {"none", "unchecked", STAMPED_AT}
    assert "never a secret" in TSA_KEYS["description"]


@pytest.mark.parametrize("case", FAILING, ids=lambda case: case["name"])
def test_each_failing_timestamp_case_gets_its_word(case, tmp_path, schemas):  # noqa: F811
    folder = write_folder(tmp_path / "run", case["files"])
    verdict = vb.verify_folder(folder, public_key(case["public_key"]), schemas, tsa_ca(case["tsa_ca"]))
    assert verdict.word == case["expect"]
    assert verdict.bundle_sha256 == ""
    assert verdict.timestamp == "none"
    assert verdict.notes == ()


@pytest.mark.parametrize("case", VERIFYING, ids=lambda case: case["name"])
def test_each_verifying_timestamp_case_has_its_third_field(case, tmp_path, schemas):  # noqa: F811
    folder = write_folder(tmp_path / "run", case["files"])
    verdict = vb.verify_folder(folder, public_key(case["public_key"]), schemas, tsa_ca(case["tsa_ca"]))
    assert verdict.word == vb.VERIFIED
    assert verdict.bundle_sha256 == BUNDLE["bundle_sha256"]
    assert verdict.timestamp == case["timestamp"]
    # timestamp.tst is the folder's own file, never a note.
    assert "timestamp.tst" not in verdict.notes


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_main_answers_each_timestamp_case_with_the_workers_line_note_and_code(case, tmp_path, capsys):
    folder = write_folder(tmp_path / "run", case["files"])
    argv = [folder, "--public-key", pem_file(tmp_path), "--schemas", SCHEMAS_DIR]
    if case["tsa_ca"] is not None:
        argv += ["--tsa-ca", ca_file(tmp_path, case["tsa_ca"])]
    code, out, err = run_main(capsys, *argv)
    if case["expect"] != "verified":
        assert (code, out, err) == (1, f"not verified: {case['expect']}\n", "")
        return
    field = case["timestamp"]
    assert code == 0
    assert out == f"verified {BUNDLE['bundle_sha256']} key {BUNDLE['key_id']} timestamp {field}\n"
    other_name = "note: not listed in the result: TIMESTAMP.TST\n" if "TIMESTAMP.TST" in case["files"] else ""
    assert err == {"none": other_name + NOT_STAMPED, "unchecked": UNCHECKED}.get(field, "")


def test_the_words_are_the_workers_sixteen_with_the_timestamps_three_last():
    assert vb.WORDS[-3:] == ("timestamp_file", "timestamp_mismatch", "timestamp_invalid")
    assert len(vb.WORDS) == 15  # and `verified`
    assert {case["expect"] for case in FAILING} - {"attachment_hash"} == set(vb.WORDS[-3:])


def test_the_unstamped_folders_line_ends_timestamp_none():
    assert VERIFIED_LINE.endswith(" timestamp none\n")


# --- more failure paths -----------------------------------------------------------


def test_a_token_that_is_a_folder_is_timestamp_file(tmp_path, schemas):  # noqa: F811
    folder = write_folder(tmp_path / "run")
    (folder / "timestamp.tst").mkdir()
    assert vb.verify_folder(folder, public_key(), schemas, tsa_ca("root")).word == "timestamp_file"


def test_a_token_at_the_size_limit_is_read_and_one_byte_more_is_not(tmp_path, schemas, monkeypatch):  # noqa: F811
    folder = stamped_folder(tmp_path)
    monkeypatch.setattr(vb, "MAX_TIMESTAMP_FILE_BYTES", len(GOOD_TOKEN))
    assert vb.verify_folder(folder, public_key(), schemas, tsa_ca("root")).word == vb.VERIFIED
    monkeypatch.setattr(vb, "MAX_TIMESTAMP_FILE_BYTES", len(GOOD_TOKEN) - 1)
    assert vb.verify_folder(folder, public_key(), schemas, tsa_ca("root")).word == "timestamp_file"
    assert vb.MAX_TIMESTAMP_FILE_BYTES == len(GOOD_TOKEN) - 1


def test_the_size_limit_is_the_workers():
    assert vb.MAX_TIMESTAMP_FILE_BYTES == 64 * 1024
    assert vb.TIMESTAMP_FILE == "timestamp.tst"


def test_the_timestamp_is_checked_last_and_not_read_before(tmp_path, schemas, monkeypatch):  # noqa: F811
    folder = write_folder(tmp_path / "run", {"signature.json": None, "timestamp.tst": {"text": "x"}})
    read = []
    real = vb._read_file
    monkeypatch.setattr(vb, "_read_file", lambda path, limit: (read.append(path.name), real(path, limit))[1])
    assert vb.verify_folder(folder, public_key(), schemas, tsa_ca("root")).word == "signature_file"
    assert "timestamp.tst" not in read


def test_a_ca_that_holds_no_certificate_verifies_no_token(tmp_path, schemas):  # noqa: F811
    folder = stamped_folder(tmp_path)
    assert vb.verify_folder(folder, public_key(), schemas, b"not a certificate").word == "timestamp_invalid"


def test_a_library_failure_inside_the_tokens_check_is_timestamp_invalid_never_a_crash(tmp_path, schemas, monkeypatch):  # noqa: F811
    folder = stamped_folder(tmp_path)

    def broken(*_):
        raise ValueError("unsupported")

    monkeypatch.setattr(vb, "_signature_holds", broken)
    assert vb.verify_folder(folder, public_key(), schemas, tsa_ca("root")).word == "timestamp_invalid"


# --- the signer's certificate ---------------------------------------------------------


def make_certificate(*, eku: list | None, critical: bool = True, key_usage: x509.KeyUsage | None = None):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "a test certificate (not a secret)")])
    now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(7)
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=3650))
    )
    if eku is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=critical)
    if key_usage is not None:
        builder = builder.add_extension(key_usage, critical=True)
    return builder.sign(key, hashes.SHA256())


def usage(**flags) -> x509.KeyUsage:
    names = (
        "digital_signature content_commitment key_encipherment data_encipherment key_agreement "
        "key_cert_sign crl_sign encipher_only decipher_only"
    ).split()
    return x509.KeyUsage(**{name: flags.get(name, False) for name in names})


STAMPING = ExtendedKeyUsageOID.TIME_STAMPING


@pytest.mark.parametrize(
    ("name", "certificate", "expected"),
    [
        ("critical-time-stamping-alone", make_certificate(eku=[STAMPING]), True),
        (
            "with-digital-signature",
            make_certificate(eku=[STAMPING], key_usage=usage(digital_signature=True)),
            True,
        ),
        (
            "with-content-commitment",
            make_certificate(eku=[STAMPING], key_usage=usage(content_commitment=True)),
            True,
        ),
        ("no-extended-key-usage", make_certificate(eku=None), False),
        ("not-critical", make_certificate(eku=[STAMPING], critical=False), False),
        ("another-usage-beside-it", make_certificate(eku=[STAMPING, ExtendedKeyUsageOID.CODE_SIGNING]), False),
        ("another-usage-alone", make_certificate(eku=[ExtendedKeyUsageOID.SERVER_AUTH]), False),
        (
            "key-usage-without-signing",
            make_certificate(eku=[STAMPING], key_usage=usage(key_encipherment=True)),
            False,
        ),
    ],
)
def test_a_signer_must_be_a_timestamping_certificate_and_nothing_else(name, certificate, expected):
    # No shared vector can hold these: OpenSSL's own responder refuses to sign
    # with such a certificate, and its verifier applies the same rule
    # (X509_PURPOSE_TIMESTAMP_SIGN).
    assert vb._is_timestamp_signer(certificate) is expected


def test_the_published_test_tsa_certificate_is_a_timestamping_certificate():
    certificate = x509.load_pem_x509_certificate(TSA_KEYS["tsa_certificate_pem"].encode("ascii"))
    assert vb._is_timestamp_signer(certificate) is True
    root = x509.load_pem_x509_certificate(TSA_KEYS["root_pem"].encode("ascii"))
    assert vb._is_timestamp_signer(root) is False


# --- a real TSA's token ------------------------------------------------------------------


def digicert_fixture():
    path = shared_dir().parent / "worker" / "tests" / "fixtures" / "tsa" / "digicert-granted.json"
    return json.loads(path.read_bytes())


def digicert_token() -> bytes:
    """The token of the recorded answer: the response is a SEQUENCE of the
    status (30 03 02 01 00) and the token, behind a four-byte header."""
    response = base64.b64decode(digicert_fixture()["body_base64"])
    assert response[:2] == b"\x30\x82" and response[4:9] == bytes.fromhex("3003020100")
    return response[9:]


def test_digicerts_recorded_token_verifies_under_the_pinned_root_and_no_other():
    token = digicert_token()
    assert len(token) == 5998
    digest = bytes.fromhex("95927ce66252fd1a6aba11094a8991a591f73391ec0b5a2e27fa15c502666479")
    root = (shared_dir() / "tsa" / "tsa-ca.pem").read_bytes()
    assert hashlib.sha256(x509.load_pem_x509_certificate(root).public_bytes(serialization.Encoding.DER)).hexdigest() == (
        "552f7bdcf1a7af9e6ce672017f4f12abf77240c78e761ac203d1d9d20ac89988"
    )
    assert vb.check_timestamp(token, digest, root) == ("verified", "2026-10-06T13:29:05Z")
    assert vb.check_timestamp(token, digest, None) == ("verified", "unchecked")
    assert vb.check_timestamp(token, digest, tsa_ca("root")) == ("timestamp_invalid", "")
    assert vb.check_timestamp(token, bytes(32), root) == ("timestamp_mismatch", "")
    # The whole response is no token.
    assert vb.check_timestamp(base64.b64decode(digicert_fixture()["body_base64"]), digest, root) == (
        "timestamp_file",
        "",
    )


def test_check_timestamp_on_the_test_tsas_token():
    assert vb.check_timestamp(GOOD_TOKEN, DIGEST, tsa_ca("root")) == ("verified", STAMPED_AT)
    assert vb.check_timestamp(GOOD_TOKEN, DIGEST, tsa_ca("other_root")) == ("timestamp_invalid", "")
    assert vb.check_timestamp(GOOD_TOKEN, DIGEST, None) == ("verified", "unchecked")
    assert vb.check_timestamp(b"", DIGEST, tsa_ca("root")) == ("timestamp_file", "")


# --- the command ----------------------------------------------------------------------------


def test_main_prints_the_tokens_time_as_the_third_field(tmp_path, capsys):
    folder = stamped_folder(tmp_path)
    code, out, err = run_main(
        capsys, folder, "--public-key", pem_file(tmp_path), "--schemas", SCHEMAS_DIR, "--tsa-ca", ca_file(tmp_path)
    )
    assert (code, err) == (0, "")
    assert out == f"verified {BUNDLE['bundle_sha256']} key {BUNDLE['key_id']} timestamp {STAMPED_AT}\n"
    assert re.fullmatch(r"verified [0-9a-f]{64} key [0-9a-f]{64} timestamp \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\n", out)


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (None, "--tsa-ca: the file can't be read"),
        (b"", "--tsa-ca: no certificate in PEM"),
        (b"not a certificate\n", "--tsa-ca: no certificate in PEM"),
        (b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", "--tsa-ca: no certificate in PEM"),
        # Every block is a certificate, as for the Worker: a block of another
        # label, or one that is cut off, and the file is no CA file.
        ("root+key", "--tsa-ca: no certificate in PEM"),
        ("key+root", "--tsa-ca: no certificate in PEM"),
        ("root+old label", "--tsa-ca: no certificate in PEM"),
        ("root+half", "--tsa-ca: no certificate in PEM"),
    ],
)
def test_a_tsa_ca_file_that_cannot_be_one_is_exit_2_never_a_verdict(content, message, tmp_path, capsys):
    folder = stamped_folder(tmp_path)
    ca = tmp_path / "ca.pem"
    if content is not None:
        ca.write_bytes(mixed_ca(content) if isinstance(content, str) else content)
    code, out, err = run_main(
        capsys, folder, "--public-key", pem_file(tmp_path), "--schemas", SCHEMAS_DIR, "--tsa-ca", ca
    )
    assert (code, out, err) == (2, "", f"error: {message}\n")


@pytest.mark.parametrize("parts", ["root+key", "key+root", "root+old label", "root+half"])
def test_a_ca_text_with_a_block_that_is_no_certificate_verifies_no_token(parts):
    assert vb.check_timestamp(GOOD_TOKEN, DIGEST, mixed_ca(parts)) == ("timestamp_invalid", "")


def test_text_outside_the_blocks_of_a_ca_file_is_a_comment(tmp_path, capsys):
    assert vb.check_timestamp(GOOD_TOKEN, DIGEST, mixed_ca("comment+root+comment")) == ("verified", STAMPED_AT)
    ca = tmp_path / "ca.pem"
    ca.write_bytes(mixed_ca("comment+root+comment"))
    code, _, err = run_main(
        capsys, stamped_folder(tmp_path), "--public-key", pem_file(tmp_path), "--schemas", SCHEMAS_DIR, "--tsa-ca", ca
    )
    assert (code, err) == (0, "")


def test_an_empty_tsa_ca_value_is_exit_2(tmp_path, capsys):
    folder = stamped_folder(tmp_path)
    code, out, err = run_main(
        capsys, folder, "--public-key", pem_file(tmp_path), "--schemas", SCHEMAS_DIR, "--tsa-ca", ""
    )
    assert (code, out, err) == (2, "", "error: --tsa-ca: the file can't be read\n")


def test_tsa_ca_given_twice_is_a_usage_error(tmp_path, capsys):
    folder = stamped_folder(tmp_path)
    ca = ca_file(tmp_path)
    code, out, err = run_main(
        capsys, folder, "--public-key", pem_file(tmp_path), "--tsa-ca", ca_file(tmp_path, "other_root"), "--tsa-ca", ca
    )
    assert code == 2
    assert out == ""
    assert "argument --tsa-ca: given more than once" in err


def test_the_ca_never_comes_from_the_folder(tmp_path, capsys):
    # A CA file inside the folder is one more unlisted file, and the token stays unchecked.
    folder = stamped_folder(tmp_path)
    (folder / "tsa-ca.pem").write_bytes(tsa_ca("root"))
    code, out, err = run_main(capsys, folder, "--public-key", pem_file(tmp_path), "--schemas", SCHEMAS_DIR)
    assert code == 0
    assert out.endswith(" timestamp unchecked\n")
    assert err == "note: not listed in the result: tsa-ca.pem\n" + UNCHECKED


# --- one bit changed anywhere in the token ---------------------------------------------------


def test_one_bit_changed_anywhere_in_the_token_verifies_only_where_the_worker_says():
    # The Worker wrote the list (worker/tests/timestamp_verify_test.cpp): the
    # bytes no signature covers. At every other offset the token is refused by
    # both; which of the three words it gets is not held equal.
    changes = CASES_FILE["one_bit_changes"]
    assert changes["of"] == "token"
    assert changes["token_bytes"] == len(GOOD_TOKEN)
    still_verified = []
    for at in range(len(GOOD_TOKEN)):
        changed = bytearray(GOOD_TOKEN)
        changed[at] ^= 0x01
        word, _ = vb.check_timestamp(bytes(changed), DIGEST, tsa_ca("root"))
        assert word in ("verified", "timestamp_file", "timestamp_mismatch", "timestamp_invalid")
        if word == "verified":
            still_verified.append(at)
    assert still_verified == changes["still_verified"]
    assert len(still_verified) < 20

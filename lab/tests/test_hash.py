import hashlib

import pytest

from seeder import CANARY_DIR, MANIFEST_PATH
from seeder.manifest import ManifestError, check_hashes, dumps_manifest, run_hash, write_manifest
from tests.manifest_factory import fake_file_bytes, make_canary_dir, make_manifest

FIRST_FILE = 20


@pytest.fixture
def lab(tmp_path):
    canary = make_canary_dir(tmp_path)
    manifest_path = tmp_path / "seed-manifest.json"
    write_manifest(manifest_path, make_manifest())
    return manifest_path, canary


def _run(manifest_path, canary):
    lines: list[str] = []
    code = run_hash(manifest_path, canary, out=lines.append)
    return code, "\n".join(lines)


def _rewrite(manifest_path, mutate):
    """Change the manifest on disk without the validation write_manifest does."""
    manifest = make_manifest()
    mutate(manifest)
    manifest_path.write_text(dumps_manifest(manifest), encoding="utf-8", newline="\n")


# --- failure paths ----------------------------------------------------------------------

def test_missing_manifest_exits_2_and_says_run_seed(tmp_path):
    code, output = _run(tmp_path / "seed-manifest.json", make_canary_dir(tmp_path))
    assert code == 2
    assert "python -m seeder seed" in output


def test_unreadable_manifest_exits_2(lab):
    manifest_path, canary = lab
    manifest_path.write_bytes(b"{broken")
    code, _ = _run(manifest_path, canary)
    assert code == 2


def test_manifest_with_39_entries_fails(lab):
    manifest_path, canary = lab
    _rewrite(manifest_path, lambda m: m["entries"].pop())
    code, output = _run(manifest_path, canary)
    assert code != 0
    assert "39" in output and "40" in output


def test_flipped_byte_names_file_and_both_hashes(lab):
    manifest_path, canary = lab
    path = canary / "rp-canary-04.txt"
    original = path.read_bytes()
    tampered = bytes([original[0] ^ 0x01]) + original[1:]
    path.write_bytes(tampered)
    code, output = _run(manifest_path, canary)
    assert code == 1
    fail_lines = [line for line in output.splitlines() if line.startswith("FAIL")]
    assert len(fail_lines) == 1
    assert "rp-canary-04.txt" in fail_lines[0]
    assert hashlib.sha256(original).hexdigest() in fail_lines[0]
    assert hashlib.sha256(tampered).hexdigest() in fail_lines[0]
    assert "39/40" in output


def test_office_content_hash_that_the_local_file_does_not_reproduce_fails(lab):
    # 02 is a SharePoint docx: its content_sha256 (office-v1) must be what the committed
    # file's content parts hash to, since SharePoint only rewrites the package around them.
    manifest_path, canary = lab

    def tamper(m):
        e = m["entries"][FIRST_FILE + 1]
        e["content_sha256"] = "0" * 64

    _rewrite(manifest_path, tamper)
    code, output = _run(manifest_path, canary)
    assert code == 1
    line = next(line for line in output.splitlines() if "rp-canary-02.docx" in line)
    assert line.startswith("FAIL") and "content_sha256" in line and "office-v1" in line


def test_office_ok_line_shows_the_content_hash(lab):
    manifest_path, canary = lab
    code, output = _run(manifest_path, canary)
    assert code == 0
    line = next(line for line in output.splitlines() if "rp-canary-02.docx" in line)
    assert "content_sha256" in line and "office-v1" in line


def test_changed_size_is_reported(lab):
    manifest_path, canary = lab
    (canary / "rp-canary-05.png").write_bytes(fake_file_bytes("rp-canary-05.png") + b"x")
    code, output = _run(manifest_path, canary)
    assert code == 1
    assert "local_size differs" in output


def test_missing_file_is_named(lab):
    manifest_path, canary = lab
    (canary / "rp-canary-18.xlsx").unlink()
    code, output = _run(manifest_path, canary)
    assert code == 1
    fail = [line for line in output.splitlines() if line.startswith("FAIL")]
    assert len(fail) == 1 and "rp-canary-18.xlsx" in fail[0] and "missing" in fail[0]


def test_tampered_sent_body_hash_fails(lab):
    manifest_path, canary = lab

    def tamper(m):
        m["entries"][3]["sent_body_sha256"] = "0" * 64
        m["entries"][3]["body_readback_exact"] = False

    _rewrite(manifest_path, tamper)
    code, output = _run(manifest_path, canary)
    assert code == 1
    fail = [line for line in output.splitlines() if line.startswith("FAIL")]
    assert len(fail) == 1 and "RP-CANARY-0004" in fail[0] and "sent_body_sha256" in fail[0]
    assert "0" * 64 in fail[0]


def test_recipient_not_catalog_fails(lab):
    manifest_path, canary = lab

    def tamper(m):
        e = m["entries"][0]
        e["recipient"] = e["location"]["mailbox"] = "bob@RestoreProofLab.onmicrosoft.com"

    _rewrite(manifest_path, tamper)
    code, output = _run(manifest_path, canary)
    assert code == 1
    assert "recipient differs" in output and "RP-CANARY-0001" in output


def test_check_hashes_raises_on_missing_manifest(tmp_path):
    with pytest.raises(ManifestError):
        check_hashes(tmp_path / "none.json", tmp_path)


def test_check_hashes_lists_problems(lab):
    manifest_path, canary = lab
    (canary / "rp-canary-01.pdf").unlink()
    (canary / "rp-canary-02.docx").write_bytes(b"changed")
    problems = check_hashes(manifest_path, canary)
    assert {p.split(":")[0] for p in problems} == {"rp-canary-01.pdf", "rp-canary-02.docx"}
    assert problems[0].startswith("rp-canary-01.pdf") and problems[1].startswith("rp-canary-02.docx")


# --- happy path ---------------------------------------------------------------------------

def test_good_manifest_and_dir_pass(lab):
    manifest_path, canary = lab
    code, output = _run(manifest_path, canary)
    assert code == 0
    lines = output.splitlines()
    assert len([line for line in lines if line.startswith("ok    ")]) == 40
    assert lines[-1] == "40/40 entries reproduce the manifest hashes"
    assert check_hashes(manifest_path, canary) == []


def test_ok_line_format(lab):
    manifest_path, canary = lab
    _, output = _run(manifest_path, canary)
    digest = hashlib.sha256(fake_file_bytes("rp-canary-01.pdf")).hexdigest()
    assert f"ok    rp-canary-01.pdf   local_sha256 {digest}" in output.splitlines()


@pytest.mark.skipif(not MANIFEST_PATH.exists(), reason="lab/seed-manifest.json not seeded yet")
def test_committed_manifest_reproduces():
    lines: list[str] = []
    assert run_hash(MANIFEST_PATH, CANARY_DIR, out=lines.append) == 0, "\n".join(lines)

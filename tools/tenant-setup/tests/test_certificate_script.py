"""New-WorkerGraphCertificate.ps1 (W7.0, decision point 4), against a fake rpworker, refusals
first: a vault that already holds the certificate is left alone; the PFX opens with its password
under OpenSSL's rules with AES-256-CBC and SHA-256 and nothing older; the values reach rpworker
on stdin alone and appear in no output and no argument."""

import base64
import datetime
import json
import re
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12

from pwsh import CERT_SCRIPT, TESTS_DIR, ps_string, run

NAMES = ("graph_cert_pfx_base64", "graph_cert_password")
# A service no machine has: -Replace proceeds as with the Worker's service stopped.
NO_SERVICE = "rp-test-no-such-service"
# DER encodings of the OIDs that matter, tag and length included.
AES_256_CBC = bytes.fromhex("060960864801650304012a")
HMAC_SHA256 = bytes.fromhex("06082a864886f70d0209")
SHA256 = bytes.fromhex("0609608648016503040201")
PBES2 = bytes.fromhex("06092a864886f70d01050d")
LEGACY = {
    "pbeWithSHAAnd3-KeyTripleDES-CBC": bytes.fromhex("060a2a864886f70d010c0103"),
    "pbeWithSHAAnd40BitRC2-CBC": bytes.fromhex("060a2a864886f70d010c0106"),
    "pbeWithSHAAnd128BitRC4": bytes.fromhex("060a2a864886f70d010c0101"),
}


class FakeWorker:
    def __init__(self, folder: Path):
        self.folder = folder
        self.cmd = folder / "rpworker.cmd"
        self.cmd.write_text(f'@"{sys.executable}" "{TESTS_DIR / "fake_rpworker.py"}" %*\r\n', encoding="ascii")

    def vault(self) -> dict:
        path = self.folder / "vault.json"
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}

    def set_vault(self, values: dict):
        (self.folder / "vault.json").write_text(json.dumps(values), encoding="utf-8")

    def flag(self, name: str):
        (self.folder / name).write_text("", encoding="ascii")

    def argv(self) -> list[list[str]]:
        log = self.folder / "argv.log"
        return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()] if log.exists() else []

    def run(self, *extra: str):
        import os

        os.environ["RP_FAKE_DIR"] = str(self.folder)
        args = " ".join(extra)
        return run(f"& {ps_string(CERT_SCRIPT)} -Worker {ps_string(self.cmd)} {args}")


@pytest.fixture
def worker(tmp_path):
    return FakeWorker(tmp_path)


def said(stderr: str) -> str:
    """pwsh's error text as one line: its colours dropped and its wrapped lines joined."""
    text = re.sub(r"\x1b\[[0-9;]*m", "", stderr)
    return re.sub(r"\s*\n\s*\|\s*", " ", text)


def sets(worker) -> list[str]:
    return [a[2] for a in worker.argv() if a[:2] == ["vault", "set"]]


# ---- refusals first ----------------------------------------------------------------------------


@pytest.mark.parametrize("held", [["graph_cert_pfx_base64"], ["graph_cert_password"], list(NAMES)])
def test_a_vault_that_holds_the_certificate_is_left_alone(worker, held):
    worker.set_vault({name: "x" for name in held})
    result = worker.run()
    assert result.returncode != 0
    assert "already holds" in result.stderr and "-Replace" in result.stderr
    assert sets(worker) == []
    assert worker.vault() == {name: "x" for name in held}


def test_a_vault_list_that_fails_otherwise_stops_it(worker):
    worker.cmd.write_text("@echo vault error: the vault can't be read 1>&2\r\n@exit /b 1\r\n", encoding="ascii")
    result = worker.run()
    assert result.returncode != 0
    assert "vault list failed" in result.stderr and "Nothing was made" in result.stderr


def test_a_failed_password_set_says_the_pfx_is_alone(worker):
    worker.flag("fail-set-graph_cert_password")
    result = worker.run()
    assert result.returncode != 0
    assert "without its password" in result.stderr
    assert sets(worker) == ["graph_cert_pfx_base64", "graph_cert_password"]


def test_a_failed_password_set_on_replace_says_the_old_password_is_left(worker):
    """The vault holds the new PFX with the old password, and the message says so (review finding 8)."""
    worker.set_vault({"graph_cert_pfx_base64": "old", "graph_cert_password": "old"})
    worker.flag("fail-set-graph_cert_password")
    result = worker.run("-Replace", "-ServiceName", NO_SERVICE)
    assert result.returncode != 0
    assert "with the old certificate's password, which doesn't open it" in said(result.stderr)
    assert "without its password" not in said(result.stderr)


def test_replace_while_the_service_runs_is_refused(worker):
    """Between the two sets a running service would read the new PFX with the old password."""
    worker.set_vault({"graph_cert_pfx_base64": "old", "graph_cert_password": "old"})
    # EventLog runs on every Windows machine.
    result = worker.run("-Replace", "-ServiceName", "EventLog")
    assert result.returncode != 0
    assert "The EventLog service is Running: stop it first" in said(result.stderr) and "Nothing was made" in said(result.stderr)
    assert sets(worker) == []
    assert worker.vault() == {"graph_cert_pfx_base64": "old", "graph_cert_password": "old"}


def test_a_failed_pfx_set_sets_nothing_else(worker):
    worker.flag("fail-set-graph_cert_pfx_base64")
    result = worker.run()
    assert result.returncode != 0
    assert sets(worker) == ["graph_cert_pfx_base64"]


# ---- the certificate ---------------------------------------------------------------------------


@pytest.fixture
def made(worker):
    result = worker.run()
    assert result.returncode == 0, result.stderr + result.stdout
    return worker, result


def test_both_values_are_set_and_the_worker_reads_them(made):
    worker, result = made
    assert sets(worker) == list(NAMES)
    assert ["graph", "certificate"] in worker.argv()
    assert "made the Worker's Graph certificate: thumbprint " in result.stdout


def test_the_pfx_opens_with_its_password_and_holds_the_key_and_certificate(made):
    worker, _ = made
    vault = worker.vault()
    key, cert, extra = pkcs12.load_key_and_certificates(
        base64.b64decode(vault["graph_cert_pfx_base64"], validate=True), vault["graph_cert_password"].encode("ascii")
    )
    assert isinstance(key, rsa.RSAPrivateKey) and key.key_size == 2048
    assert key.public_key().public_numbers() == cert.public_key().public_numbers()
    assert cert.subject.rfc4514_string() == "CN=RestoreProof Worker"
    now = datetime.datetime.now(datetime.timezone.utc)
    assert cert.not_valid_before_utc < now
    assert datetime.timedelta(days=729) < cert.not_valid_after_utc - now < datetime.timedelta(days=732)
    assert extra == []
    assert len(base64.b64decode(vault["graph_cert_password"])) == 32


def test_the_pfx_uses_aes_256_and_sha_256_and_no_legacy_cipher(made):
    worker, _ = made
    der = base64.b64decode(worker.vault()["graph_cert_pfx_base64"])
    assert PBES2 in der and AES_256_CBC in der and HMAC_SHA256 in der and SHA256 in der
    for name, oid in LEGACY.items():
        assert oid not in der, name


def test_no_secret_is_an_argument_or_printed(made):
    worker, result = made
    vault = worker.vault()
    pfx = vault["graph_cert_pfx_base64"]
    password = vault["graph_cert_password"]
    argv = json.dumps(worker.argv())
    for secret in (pfx, pfx[:40], password):
        assert secret not in argv
        assert secret not in result.stdout
        assert secret not in result.stderr
    # Nothing was written beside the fake's own files.
    assert sorted(p.name for p in worker.folder.iterdir()) == ["argv.log", "rpworker.cmd", "vault.json"]


def test_replace_makes_a_new_certificate(worker):
    worker.set_vault({"graph_cert_pfx_base64": "old", "graph_cert_password": "old"})
    result = worker.run("-Replace", "-ServiceName", NO_SERVICE)
    assert result.returncode == 0, result.stderr
    assert worker.vault()["graph_cert_password"] != "old"


def test_a_vault_not_made_yet_is_an_empty_one(worker):
    worker.flag("missing-vault")
    result = worker.run("-VaultPath", ps_string(str(worker.folder / "new-vault.bin")))
    assert result.returncode == 0, result.stderr
    assert sets(worker) == list(NAMES)
    assert all("--vault" in a for a in worker.argv())


# ---- the real Worker ---------------------------------------------------------------------------

REAL_WORKER = TESTS_DIR.parents[2] / "worker" / "build" / "dev" / "rpworker.exe"


@pytest.mark.worker
def test_the_real_worker_opens_the_pfx_it_is_given(tmp_path):
    """The PFX goes through the Worker's own OpenSSL loader (graph certificate), on a vault of
    the test's own: the ciphers and the password encoding are the ones the Worker reads."""
    assert REAL_WORKER.exists(), f"build the Worker first (cmake --build --preset dev in worker\\): {REAL_WORKER}"
    vault = tmp_path / "vault.bin"
    result = run(
        f"& {ps_string(CERT_SCRIPT)} -Worker {ps_string(REAL_WORKER)} -VaultPath {ps_string(vault)}"
    )
    assert result.returncode == 0, result.stderr + result.stdout
    assert "made the Worker's Graph certificate: thumbprint " in result.stdout
    listed = run(f"& {ps_string(REAL_WORKER)} vault list --vault {ps_string(vault)}")
    assert listed.stdout.split() == ["graph_cert_pfx_base64", "graph_cert_password"]
    again = run(f"& {ps_string(CERT_SCRIPT)} -Worker {ps_string(REAL_WORKER)} -VaultPath {ps_string(vault)}")
    assert again.returncode != 0 and "already holds" in again.stderr

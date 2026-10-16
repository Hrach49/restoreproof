"""The two Worker commands the installer leans on, against the built rpworker.exe on a vault of
the test's own (W7.1): `signer new-key` makes a key straight into the vault and prints its public
half alone; `vault grant` takes the service account by SID with no service installed. Marked
`worker`: CI deselects it; run it locally with the Worker built."""

import subprocess

import pytest

from pwsh import WORKER_EXE, ps_string, run_json, with_module

pytestmark = pytest.mark.worker


def rpworker(*args: str, stdin: str | None = None) -> subprocess.CompletedProcess:
    assert WORKER_EXE.exists(), f"build the Worker first: {WORKER_EXE}"
    return subprocess.run([str(WORKER_EXE), *args], input=stdin, capture_output=True, text=True, encoding="utf-8")


def test_new_key_makes_the_key_into_the_vault_and_grant_takes_a_sid_of_no_service(tmp_path):
    vault = tmp_path / "vault.bin"
    assert rpworker("vault", "set", "veeam_username", "--vault", str(vault), stdin="DESKTOP\\rp-veeam\n").returncode == 0

    made = rpworker("signer", "new-key", "--vault", str(vault))
    assert made.returncode == 0, made.stderr
    assert made.stdout.startswith("-----BEGIN PUBLIC KEY-----\n") and made.stdout.endswith("-----END PUBLIC KEY-----\n")
    assert made.stderr.splitlines()[0] == f"set signing_key_base64 in {vault}"
    assert made.stderr.splitlines()[1].startswith("key ") and len(made.stderr.splitlines()[1]) == 68
    assert "PRIVATE" not in made.stdout + made.stderr
    listed = rpworker("vault", "list", "--vault", str(vault))
    assert listed.stdout.splitlines() == ["veeam_username", "signing_key_base64"]
    assert rpworker("signer", "public-key", "--vault", str(vault)).stdout == made.stdout

    again = rpworker("signer", "new-key", "--vault", str(vault))
    assert again.returncode == 1 and "already holds signing_key_base64" in again.stderr and again.stdout == ""

    sid = run_json(with_module("Get-ServiceSid -ServiceName 'rp-test-w71-no-such-service'"))
    granted = rpworker("vault", "grant", sid, "--vault", str(vault))
    assert granted.returncode == 0, granted.stderr
    assert granted.stdout == f"granted read on {vault} to {sid}\n"
    acl = subprocess.run(["icacls", str(vault)], capture_output=True, text=True, check=True).stdout
    assert f"*{sid}:(R)" in acl or sid in acl

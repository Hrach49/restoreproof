"""Install-RestoreProofWorker.ps1 as a whole, against tests/fake_rpworker.py and
tests/FakeMachine.psm1 on a temporary root (W7.1, docs/decisions.md 2026-10-16 point 9):
refusals first, each before anything after its step; then the first run's writes and their
order, the ACLs read back, every secret on stdin alone; a second run with `changes: 0`;
-WhatIf writing nothing; a registered Worker asked no token."""

import base64
import ctypes
import json
import os
import subprocess
from pathlib import Path

import pytest

from fake_rpworker import KEY_ID, THUMBPRINT, WORKER_ID
from install_lab import (ANSWERS, PASSWORD, SERVICE, TOKEN, USERNAME, InstallLab, acl_lines, assert_no_secret,
                         assert_no_secret_argument, current_user_sid, explicit_rules, lines, self_signed, sha1_hex)
from pwsh import ps_string, run, run_json, with_module

SERVICE_SID = None


def service_sid() -> str:
    global SERVICE_SID
    if SERVICE_SID is None:
        SERVICE_SID = run_json(with_module(f"Get-ServiceSid -ServiceName '{SERVICE}'"))
    return SERVICE_SID


# --- refusals, before anything after the step ---------------------------------------------


def test_not_elevated_stops_before_anything(tmp_path):
    lab = InstallLab(tmp_path, elevated=False)
    result = lab.run()
    assert result.returncode != 0
    assert "problem: run this from an elevated PowerShell" in result.stderr
    assert lab.argv() == []
    assert not lab.root.exists() and not lab.program.exists()


def test_an_old_powershell_stops_before_anything(tmp_path):
    lab = InstallLab(tmp_path, ps_version="7.3.12")
    result = lab.run()
    assert result.returncode != 0
    assert "PowerShell 7.4 or later is needed (this is 7.3.12)" in result.stderr
    assert lab.argv() == [] and not lab.root.exists()


def test_a_package_without_the_exe_stops_before_anything(tmp_path):
    lab = InstallLab(tmp_path)
    (lab.package / "rpworker.exe").unlink()
    result = lab.run()
    assert result.returncode != 0
    assert "no rpworker.exe in" in result.stderr
    assert lab.argv() == [] and not lab.root.exists()


def test_a_service_from_another_exe_stops_before_anything(tmp_path):
    lab = InstallLab(tmp_path, installed_service={"pathName": '"C:\\elsewhere\\rpworker.exe" service run', "state": "Running"})
    result = lab.run()
    assert result.returncode != 0
    assert "installed with another command line" in result.stderr and "W7.3" in result.stderr
    assert lab.argv() == [] and not lab.program.exists()


def test_veeam_elsewhere_is_asked_and_without_a_console_stops(tmp_path):
    lab = InstallLab(tmp_path, veeam_here=False)
    result = lab.run()
    assert result.returncode != 0
    assert "note: Veeam Backup for Microsoft 365 (its REST service) is not on this machine" in result.stdout
    assert "give -AllowRemoteVeeam" in result.stderr
    assert lab.argv() == []


def test_veeam_elsewhere_with_allow_remote_grants_no_key_file(tmp_path):
    lab = InstallLab(tmp_path, veeam_here=False)
    result = lab.run("-AllowRemoteVeeam")
    assert result.returncode == 0, result.stderr
    out = lines(result)
    assert "note: Veeam is on another machine: no organisation certificate key file is granted here" in out
    assert not any("Get-CertificateKeyFile" in line for line in lab.machine_log())
    assert not any("read on the key file" in line for line in out)
    assert lab.marker("service-started")


def test_a_config_that_fails_the_check_stops_unless_replace(tmp_path):
    lab = InstallLab(tmp_path)
    lab.root.mkdir()
    (lab.root / "config.json").write_text('{"cloud_url": "http://nope"}', encoding="utf-8")
    result = lab.run()
    assert result.returncode != 0
    assert "fails rpworker config check (config error: cloud_url" in result.stderr and "-Replace" in result.stderr
    assert "vault list" not in lab.commands()
    assert lab.config() == {"cloud_url": "http://nope"}, "the operator's file is never rewritten unasked"
    # -Replace writes a new one from the answers, which passes the check.
    result = lab.run("-Replace")
    assert result.returncode == 0, result.stderr
    assert lab.config()["cloud_url"] == "https://cloud.example.invalid"
    assert f"change: wrote {lab.root / 'config.json'}" in lines(result)


def test_a_vault_set_that_fails_stops_and_the_next_run_asks_only_what_is_missing(tmp_path):
    lab = InstallLab(tmp_path, flags=("fail-set-veeam_password",))
    result = lab.run()
    assert result.returncode != 0
    assert "rpworker vault set veeam_password failed: vault error: veeam_password couldn't be set" in result.stderr
    assert lab.vault() == {"veeam_username": USERNAME}
    assert "signer new-key" not in lab.commands() and not lab.marker("service-installed")
    assert_no_secret(result.stdout + result.stderr)
    lab.unflag("fail-set-veeam_password")
    before = len(lab.argv())
    result = lab.run()
    assert result.returncode == 0, result.stderr
    sets = [a for a in lab.argv()[before:] if a[:2] == ["vault", "set"]]
    assert [a[2] for a in sets] == ["veeam_password", "cloud_install_token", "graph_cert_pfx_base64", "graph_cert_password"]
    assert "ok: veeam_username is in the vault" in lines(result)


def test_veeam_list_failing_stops_before_the_service_is_installed(tmp_path):
    lab = InstallLab(tmp_path, flags=("fail-veeam-list",))
    result = lab.run()
    assert result.returncode != 0
    assert "rpworker veeam list failed: veeam error: Veeam POST /v8/token: HTTP 401" in result.stderr
    assert not lab.marker("service-installed") and "cloud register" not in " ".join(lab.commands())
    # The vault was filled and the key and certificate made: the next run keeps them.
    assert set(lab.vault()) == {"veeam_username", "veeam_password", "cloud_install_token", "signing_key_base64", "graph_cert_pfx_base64", "graph_cert_password"}


def test_a_certificate_without_a_key_file_is_a_problem_line_and_the_install_goes_on(tmp_path):
    lab = InstallLab(tmp_path, key_files={})
    result = lab.run()
    assert result.returncode == 0, result.stderr
    assert f"problem: RestoreProofLab.onmicrosoft.com: certificate {THUMBPRINT} has no private key file on this machine" in result.stdout
    assert lab.marker("service-started")
    assert "organisation certificates granted:" not in result.stdout


def test_a_refused_install_token_is_removed_and_the_run_stops(tmp_path):
    lab = InstallLab(tmp_path, flags=("register-401",))
    result = lab.run()
    assert result.returncode != 0
    assert "the Cloud refused the install token (unknown, used or expired); it was removed from the vault" in result.stderr
    assert "cloud_install_token" not in lab.vault()
    assert lab.marker("service-installed") and not lab.marker("service-started")
    assert_no_secret(result.stdout + result.stderr)
    # The next run asks for a new token and registers.
    lab.unflag("register-401")
    result = lab.run(answers={"cloud_install_token": "Sentinel-Install-Token-2nd-" + "x" * 20})
    assert result.returncode == 0, result.stderr
    assert "cloud_api_token" in lab.vault()
    assert f"worker {WORKER_ID} key {KEY_ID}" in lines(result)


def test_a_cloud_not_reached_keeps_the_install_token(tmp_path):
    lab = InstallLab(tmp_path, flags=("register-503",))
    result = lab.run()
    assert result.returncode != 0
    assert "rpworker cloud register failed: cloud register: the Cloud couldn't be reached" in result.stderr
    assert lab.vault()["cloud_install_token"] == TOKEN
    assert not lab.marker("service-started")


def test_a_service_start_that_fails_stops_and_the_next_run_starts_it(tmp_path):
    lab = InstallLab(tmp_path, flags=("fail-service-start",))
    result = lab.run()
    assert result.returncode != 0
    assert "rpworker service start failed: service error: the service RestoreProof stopped while starting" in result.stderr
    assert "cloud_api_token" in lab.vault()
    lab.unflag("fail-service-start")
    lab.machine["installedService"] = {"pathName": f'"{lab.program / "rpworker.exe"}" service run', "state": "Stopped"}
    lab.write_machine()
    result = lab.run(urls=False, answers=None)
    assert result.returncode == 0, result.stderr
    out = lines(result)
    assert [line for line in out if line.startswith("change: ")] == ["change: rpworker service start (started RestoreProof)"]
    assert "changes: 1" in out


# --- Veeam's certificate (point 5) --------------------------------------------------------


def test_veeams_own_certificate_is_pinned(tmp_path):
    lab = InstallLab(tmp_path)
    result = lab.run()
    assert result.returncode == 0, result.stderr
    config = lab.config()
    assert config["veeam_ca_file"] == str(lab.root / "veeam-rest.pem")
    assert config["veeam_cert_sha256"] == __import__("hashlib").sha256(lab.veeam_der).hexdigest().upper()
    pem = (lab.root / "veeam-rest.pem").read_text(encoding="ascii")
    assert base64.b64decode("".join(pem.splitlines()[1:-1])) == lab.veeam_der
    assert "ok: it is this machine's own (LocalMachine\\My, with its key): pinned" in result.stdout
    assert "Veeam's certificate: CN=Veeam Software, thumbprint " + sha1_hex(lab.veeam_der) in result.stdout


def test_a_certificate_the_windows_store_trusts_is_not_pinned(tmp_path):
    lab = InstallLab(tmp_path, remote={"inLocalStoreWithKey": False, "chainsToStore": True, "namesHost": True})
    result = lab.run()
    assert result.returncode == 0, result.stderr
    assert "veeam_ca_file" not in lab.config() and "veeam_cert_sha256" not in lab.config()
    assert not (lab.root / "veeam-rest.pem").exists()
    assert "ok: it chains to the Windows certificate store and names the host: nothing to pin" in result.stdout


def test_a_certificate_of_another_machine_needs_confirming(tmp_path):
    lab = InstallLab(tmp_path, veeam_here=False, remote={"inLocalStoreWithKey": False, "chainsToStore": False, "namesHost": False})
    result = lab.run("-AllowRemoteVeeam")
    assert result.returncode != 0
    assert "Veeam's certificate was not confirmed" in result.stderr
    assert lab.config() is None
    result = lab.run("-AllowRemoteVeeam", "-VeeamThumbprint 'AC32 20B5 8A2B 4C43 8DA1 3816 C2DD 1E25 D1F7 83A7'")
    assert result.returncode != 0, "another thumbprint doesn't confirm it"
    thumb = sha1_hex(lab.veeam_der)
    spaced = " ".join(thumb[i:i + 4] for i in range(0, 40, 4)).lower()
    result = lab.run("-AllowRemoteVeeam", f"-VeeamThumbprint '{spaced}'")
    assert result.returncode == 0, result.stderr
    assert "ok: thumbprint confirmed: pinned" in result.stdout
    assert lab.config()["veeam_cert_sha256"] == __import__("hashlib").sha256(lab.veeam_der).hexdigest().upper()


def test_a_certificate_file_given_by_hand_is_pinned_without_a_probe(tmp_path):
    lab = InstallLab(tmp_path, remote=None)
    der = self_signed("Veeam Software by hand")
    pem_file = tmp_path / "given.pem"
    pem_file.write_text("-----BEGIN CERTIFICATE-----\n" + base64.b64encode(der).decode() + "\n-----END CERTIFICATE-----\n", encoding="ascii")
    result = lab.run(f"-VeeamCertificateFile '{pem_file}'")
    assert result.returncode == 0, result.stderr
    assert not any("Get-RemoteCertificate" in line for line in lab.machine_log())
    assert lab.config()["veeam_cert_sha256"] == __import__("hashlib").sha256(der).hexdigest().upper()
    assert base64.b64decode("".join((lab.root / "veeam-rest.pem").read_text().splitlines()[1:-1])) == der


def test_a_veeam_that_cant_be_reached_stops_before_the_config(tmp_path):
    lab = InstallLab(tmp_path, remote=None)
    result = lab.run()
    assert result.returncode != 0
    assert "could not be reached for its certificate" in result.stderr
    assert lab.config() is None and "vault list" not in lab.commands()


def test_a_cloud_ca_file_is_copied_beside_the_config(tmp_path):
    lab = InstallLab(tmp_path)
    der = self_signed("Caddy Local Authority")
    ca = tmp_path / "root.crt"
    ca.write_text("-----BEGIN CERTIFICATE-----\n" + base64.b64encode(der).decode() + "\n-----END CERTIFICATE-----\n", encoding="ascii")
    result = lab.run(f"-CloudCaFile '{ca}'")
    assert result.returncode == 0, result.stderr
    assert lab.config()["cloud_ca_file"] == str(lab.root / "cloud-ca.pem")
    assert (lab.root / "cloud-ca.pem").read_bytes() == ca.read_bytes()


# --- the first run, whole (point 9) ----------------------------------------------------------


def test_the_first_run_does_the_twelve_steps_in_order_and_puts_no_secret_anywhere_but_stdin(tmp_path):
    lab = InstallLab(tmp_path)
    result = lab.run()
    assert result.returncode == 0, result.stderr
    out = lines(result)
    sid = service_sid()

    # The order of what the Worker was asked.
    commands = lab.commands()
    assert commands[0] == "--version"
    assert commands[1] == f"config check --config {lab.root / 'config.json'}"
    assert commands[2] == "vault list"
    assert commands[3:6] == ["vault set veeam_username", "vault set veeam_password", "vault set cloud_install_token"]
    assert commands[6] == f"vault grant {sid}"
    assert commands[7] == "signer new-key"
    # New-WorkerGraphCertificate.ps1's own calls
    assert commands[8] == "vault list"
    assert commands[9:11] == ["vault set graph_cert_pfx_base64", "vault set graph_cert_password"]
    assert commands[11] == "graph certificate"
    assert commands[12] == f"veeam list --config {lab.root / 'config.json'}"
    assert commands[13] == "service install"
    assert commands[14] == "cloud register --name fake-host-worker"
    assert commands[15] == "service start"
    assert len(commands) == 16
    assert_no_secret_argument(lab)
    assert_no_secret(result.stdout + result.stderr)
    assert lab.vault()["veeam_username"] == USERNAME
    assert lab.vault()["veeam_password"] == PASSWORD
    assert "cloud_install_token" not in lab.vault() and lab.vault()["cloud_api_token"].startswith("FAKE-API-TOKEN-")
    assert (lab.fake / "registered-name.txt").read_text() == "fake-host-worker"

    # The files.
    assert (lab.program / "rpworker.exe").read_bytes() == (lab.package / "rpworker.exe").read_bytes()
    assert (lab.program / "fake.dll").read_bytes() == (lab.package / "fake.dll").read_bytes()
    assert not (lab.program / "README.txt").exists()
    for name in ("state", "runs", "outbox", "sent", "failed", "logs"):
        assert (lab.root / name).is_dir()
    config = lab.config()
    assert list(config) == ["cloud_url", "veeam_url", "veeam_ca_file", "veeam_cert_sha256"]
    assert config["cloud_url"] == "https://cloud.example.invalid" and config["veeam_url"] == "https://veeam.example.invalid:4443"
    raw = (lab.root / "config.json").read_bytes()
    assert not raw.startswith(b"\xef\xbb\xbf") and b"\r" not in raw

    # The ACLs: the root protected with exactly SYSTEM, Administrators, the test's own account
    # and the service account (read and execute); each service folder with Modify for the
    # account on top of what it inherits; nothing for Users.
    root = explicit_rules(lab.root)
    assert root["protected"] is True
    by_sid = {r["sid"]: r for r in root["rules"]}
    assert set(by_sid) == {"S-1-5-18", "S-1-5-32-544", current_user_sid(), sid}
    assert by_sid[sid]["rights"] == "ReadAndExecute, Synchronize" and by_sid[sid]["type"] == "Allow"
    assert by_sid[sid]["inherit"] == "ContainerInherit, ObjectInherit" and by_sid[sid]["propagation"] == "None"
    assert by_sid["S-1-5-18"]["rights"] == "FullControl" and by_sid["S-1-5-32-544"]["rights"] == "FullControl"
    assert "S-1-5-32-545" not in acl_lines(lab.root) and "BUILTIN\\Users" not in acl_lines(lab.root)
    for name in ("state", "runs", "outbox", "sent", "failed", "logs"):
        sub = explicit_rules(lab.root / name)
        assert sub["protected"] is False
        own = [r for r in sub["rules"] if r["sid"] == sid]
        assert len(own) == 1 and own[0]["rights"] == "Modify, Synchronize" and own[0]["inherit"] == "ContainerInherit, ObjectInherit"
    # The key file: read for the account.
    assert f"*{sid}:(R)" in acl_lines(lab.key_file) or sid in acl_lines(lab.key_file)
    assert (lab.fake / "granted.log").read_text().splitlines() == [sid]

    # The lines.
    changes = [line for line in out if line.startswith("change: ")]
    assert changes[0] == f"change: copied rpworker.exe to {lab.program}" or changes[0] == f"change: copied fake.dll to {lab.program}"
    assert any(line.startswith("change: ACL of " + str(lab.root)) for line in changes)
    assert f"change: wrote {lab.root / 'config.json'}" in changes
    assert "change: rpworker vault set veeam_password" in changes
    assert f"change: rpworker signer new-key (key {KEY_ID})" in changes
    assert any(line.startswith("change: New-WorkerGraphCertificate.ps1 (thumbprint ") for line in changes)
    assert f"change: RestoreProofLab.onmicrosoft.com: read on the key file of {THUMBPRINT} granted to {sid}" in changes
    assert any(line.startswith("change: rpworker service install (installed RestoreProof") for line in changes)
    assert f"change: rpworker cloud register (worker {WORKER_ID})" in changes
    assert "change: rpworker service start (started RestoreProof)" in changes
    assert f"changes: {len(changes)}" in out
    assert f"worker {WORKER_ID} key {KEY_ID}" in out
    assert f"organisation certificates granted: {THUMBPRINT}" in out
    assert any(line.startswith("installed in ") and line.endswith(" s (from the last answer typed)") for line in out)
    assert any(line.startswith(f"next: rpworker graph certificate > worker-graph.pem") and f"--worker-id {WORKER_ID}" in line for line in out)


def test_the_second_run_changes_nothing_and_asks_nothing(tmp_path):
    lab = InstallLab(tmp_path)
    assert lab.run().returncode == 0
    lab.machine["installedService"] = {"pathName": f'"{lab.program / "rpworker.exe"}" service run', "state": "Running"}
    lab.write_machine()
    before = len(lab.argv())
    result = lab.run(urls=False, answers=None)
    assert result.returncode == 0, result.stderr
    out = lines(result)
    assert "changes: 0" in out
    assert not any(line.startswith("change: ") for line in out)
    after = lab.commands()[before:]
    assert after == ["--version", f"config check --config {lab.root / 'config.json'}", "vault list", f"vault grant {service_sid()}",
                     f"veeam list --config {lab.root / 'config.json'}", "service start"]
    assert f"ok: service {SERVICE} is installed from {lab.program / 'rpworker.exe'}" in out
    assert f"ok: {lab.root / 'config.json'} (kept; its values are not asked again)" in out
    assert "ok: cloud_api_token is in the vault (registered already)" in out
    assert "ok: signing_key_base64 is in the vault" in out and "ok: the Graph certificate is in the vault" in out
    assert "ok: rpworker service install" in out and "ok: RestoreProof is already running" in out
    assert f"ok: RestoreProofLab.onmicrosoft.com: read on the key file of {THUMBPRINT}" in out


def test_whatif_writes_nothing(tmp_path):
    lab = InstallLab(tmp_path)
    result = lab.run(whatif=True)
    assert result.returncode == 0, result.stderr
    out = lines(result)
    assert not lab.root.exists() and not lab.program.exists()
    # The tests' Worker is there whether copied or not: its two reads run, nothing that writes.
    assert lab.commands() == ["--version", "vault list"]
    assert any(line.startswith("would: copy rpworker.exe to ") for line in out)
    assert any(line.startswith(f"would: make {lab.root} and set its ACL") for line in out)
    assert any(line.startswith("would: write ") and "veeam_cert_sha256" in line for line in out)
    assert "would: rpworker vault set veeam_password" in out and "would: rpworker signer new-key" in out
    assert "would: rpworker service install" in out and "would: rpworker cloud register" in out and "would: rpworker service start" in out
    assert "changes: 0" in out
    assert_no_secret(result.stdout + result.stderr)


def test_a_registered_worker_is_asked_for_no_token(tmp_path):
    lab = InstallLab(tmp_path, vault={"veeam_username": USERNAME, "veeam_password": PASSWORD, "cloud_api_token": "FAKE-API-TOKEN-kept",
                                      "signing_key_base64": "FAKE-SIGNING-KEY", "graph_cert_pfx_base64": "x", "graph_cert_password": "y"})
    (lab.root / "state").mkdir(parents=True)
    (lab.root / "state" / "worker.json").write_text(json.dumps({"worker_id": WORKER_ID, "key_id": KEY_ID}), encoding="utf-8")
    result = lab.run(answers=None)
    assert result.returncode == 0, result.stderr
    out = lines(result)
    assert f"ok: registered with the Cloud as worker {WORKER_ID}" in out
    assert "cloud register" not in " ".join(lab.commands()) and "vault set" not in " ".join(lab.commands())
    assert lab.vault()["cloud_api_token"] == "FAKE-API-TOKEN-kept"
    assert f"worker {WORKER_ID} key {KEY_ID}" in out


def test_a_root_with_the_inherited_acl_and_hand_made_folders_is_tightened(tmp_path):
    lab = InstallLab(tmp_path)
    lab.root.mkdir()
    (lab.root / "runs" / "old-run").mkdir(parents=True)
    (lab.root / "runs" / "old-run" / "result.json").write_text("{}", encoding="utf-8")
    result = lab.run()
    assert result.returncode == 0, result.stderr
    assert (lab.root / "runs" / "old-run" / "result.json").read_text() == "{}"
    assert explicit_rules(lab.root)["protected"] is True
    assert any(r["sid"] == service_sid() for r in explicit_rules(lab.root / "runs")["rules"])


def test_a_stub_dll_in_the_package_is_copied_and_a_changed_one_is_refused_while_installed(tmp_path):
    lab = InstallLab(tmp_path)
    assert lab.run().returncode == 0
    lab.machine["installedService"] = {"pathName": f'"{lab.program / "rpworker.exe"}" service run', "state": "Running"}
    lab.write_machine()
    (lab.package / "rpworker.exe").write_bytes(b"MZ a newer worker")
    result = lab.run(urls=False, answers=None)
    assert result.returncode != 0
    assert "differs from the package's while the service is installed from it; an upgrade in place is W7.3's" in result.stderr
    assert (lab.program / "rpworker.exe").read_bytes() != b"MZ a newer worker"


# --- the W7.1 code review's fixes ------------------------------------------------------------

ELEVATED = bool(ctypes.windll.shell32.IsUserAnAdmin())
# Giving a folder to Users and reading a SACL need an elevated test run (CI's runner is).
needs_elevation = pytest.mark.skipif(not ELEVATED, reason="sets another owner and reads a SACL: run the tests elevated")


def owner_of(path: Path) -> str:
    return run_json(f"(Get-Acl -LiteralPath {ps_string(path)}).GetOwner([Security.Principal.SecurityIdentifier]).Value")


def test_a_first_install_passes_the_config_check_before_the_vault_is_made(tmp_path):
    # Finding 1: `config check` ends on the missing vault's line before step 5 makes it.
    lab = InstallLab(tmp_path)
    result = lab.run()
    assert result.returncode == 0, result.stderr
    out = lines(result)
    assert "ok: rpworker config check" in out
    assert "vault set veeam_username" in lab.commands()


@needs_elevation
def test_a_root_a_local_user_owns_is_given_to_administrators(tmp_path):
    # Finding 2: the owner keeps WRITE_DAC whatever the DACL says.
    lab = InstallLab(tmp_path)
    (lab.root / "runs").mkdir(parents=True)
    for path in (lab.root, lab.root / "runs"):
        subprocess.run(["icacls", str(path), "/setowner", "*S-1-5-32-545", "/Q"], check=True, capture_output=True)
        assert owner_of(path) == "S-1-5-32-545"
    result = lab.run()
    assert result.returncode == 0, result.stderr
    assert owner_of(lab.root) == "S-1-5-32-544" and owner_of(lab.root / "runs") == "S-1-5-32-544"
    assert f"/setowner *S-1-5-32-544 /Q (owned by S-1-5-32-545)" in result.stdout
    # The second run finds nothing to change in the folders.
    assert not any(line.startswith("change: ACL of") for line in lines(lab.run(urls=False, answers=None)))


@needs_elevation
def test_a_config_a_local_user_owns_is_never_kept(tmp_path):
    # Finding 2: a config.json planted before the install names where the secrets go.
    lab = InstallLab(tmp_path)
    lab.root.mkdir()
    planted = lab.root / "config.json"
    planted.write_text('{"cloud_url": "https://attacker.example.invalid", "veeam_url": "https://attacker.example.invalid:4443"}', encoding="utf-8")
    subprocess.run(["icacls", str(planted), "/setowner", "*S-1-5-32-545", "/Q"], check=True, capture_output=True)
    result = lab.run(urls=False)
    assert result.returncode != 0
    assert "is there and is owned by S-1-5-32-545, not by SYSTEM, Administrators or this account" in result.stderr
    assert "-Replace" in result.stderr and "vault set" not in " ".join(lab.commands())
    result = lab.run("-Replace")
    assert result.returncode == 0, result.stderr
    assert lab.config()["cloud_url"] == "https://cloud.example.invalid"
    assert owner_of(planted) != "S-1-5-32-545"
    assert explicit_rules(planted)["rules"] == [], "the new file has its folder's rules alone"


@needs_elevation
def test_the_audit_entries_of_a_key_file_are_kept(tmp_path):
    # Finding 3: Set-Acl, elevated, wrote the SACL back without them.
    lab = InstallLab(tmp_path)
    audit = (
        f"$p = {ps_string(lab.key_file)}\n"
        "$acl = Get-Acl -LiteralPath $p -Audit\n"
        "$acl.AddAuditRule([Security.AccessControl.FileSystemAuditRule]::new([Security.Principal.SecurityIdentifier]'S-1-1-0', 'Read', 'Success'))\n"
        "Set-Acl -LiteralPath $p -AclObject $acl\n"
    )
    assert run(audit).returncode == 0
    count = f"@((Get-Acl -LiteralPath {ps_string(lab.key_file)} -Audit).GetAuditRules($true, $false, [Security.Principal.SecurityIdentifier])).Count"
    assert run_json(count) == 1
    result = lab.run()
    assert result.returncode == 0, result.stderr
    assert service_sid() in acl_lines(lab.key_file)
    assert run_json(count) == 1


def test_half_a_graph_certificate_is_made_again(tmp_path):
    # Finding 6: New-WorkerGraphCertificate.ps1 failed after the PFX was set.
    lab = InstallLab(tmp_path, vault={"veeam_username": USERNAME, "veeam_password": PASSWORD, "cloud_install_token": TOKEN,
                                      "signing_key_base64": "FAKE-SIGNING-KEY", "graph_cert_pfx_base64": "only-the-pfx"})
    result = lab.run(answers=None)
    assert result.returncode == 0, result.stderr
    out = lines(result)
    assert "note: the vault holds half the Graph certificate (one of graph_cert_pfx_base64 and graph_cert_password): it is made again" in out
    assert any(line.startswith("change: New-WorkerGraphCertificate.ps1 (thumbprint ") for line in out)
    assert "ok: the Graph certificate is in the vault" not in out
    vault = lab.vault()
    assert vault["graph_cert_pfx_base64"] != "only-the-pfx" and vault["graph_cert_password"]
    assert "graph certificate" in lab.commands(), "the new PFX opened with its password"


def test_a_wrong_veeam_password_is_corrected_by_running_again_with_replace(tmp_path):
    # Finding 7: the second run asked nothing and stopped on the same line.
    lab = InstallLab(tmp_path, flags=("fail-veeam-list",))
    result = lab.run(answers={**ANSWERS, "veeam_password": "Sentinel-Wrong-Password-1"})
    assert result.returncode != 0
    assert "run the installer again with -Replace to give them again" in result.stderr
    lab.unflag("fail-veeam-list")
    before = len(lab.argv())
    result = lab.run("-Replace", answers={"veeam_password": PASSWORD}, urls=True)
    assert result.returncode == 0, result.stderr
    sets = [a[2] for a in lab.argv()[before:] if a[:2] == ["vault", "set"]]
    assert sets == ["veeam_username", "veeam_password"]
    assert lab.vault()["veeam_password"] == PASSWORD
    assert "signer new-key" not in " ".join(lab.commands()[before:]), "the key is kept"
    assert lab.marker("service-started")


def test_a_url_given_again_unlike_the_kept_config_stops_and_names_replace(tmp_path):
    lab = InstallLab(tmp_path)
    assert lab.run().returncode == 0
    result = lab.run("-CloudUrl 'https://other.example.invalid'", urls=False, answers=None)
    assert result.returncode != 0
    assert "has cloud_url https://cloud.example.invalid, not https://other.example.invalid: give -Replace to write the new one." in result.stderr
    assert lab.config()["cloud_url"] == "https://cloud.example.invalid"


def test_replace_on_a_running_service_stops_it_so_the_start_takes_the_new_config(tmp_path):
    lab = InstallLab(tmp_path)
    assert lab.run().returncode == 0 and lab.marker("service-started")
    lab.machine["installedService"] = {"pathName": f'"{lab.program / "rpworker.exe"}" service run', "state": "Running"}
    lab.write_machine()
    before = len(lab.argv())
    result = lab.run("-Replace", "-VeeamUrl 'https://veeam2.example.invalid:4443'", "-CloudUrl 'https://cloud.example.invalid'",
                     urls=False, answers={"veeam_password": PASSWORD})
    assert result.returncode == 0, result.stderr
    assert lab.config()["veeam_url"] == "https://veeam2.example.invalid:4443"
    after = lab.commands()[before:]
    assert after[-2:] == ["service stop", "service start"]
    out = lines(result)
    assert "change: rpworker service stop (stopped RestoreProof in 0.4 s), so the start takes the new config and account" in out
    assert "change: rpworker service start (started RestoreProof)" in out


def test_a_second_run_without_changes_does_not_stop_the_service(tmp_path):
    lab = InstallLab(tmp_path)
    assert lab.run().returncode == 0
    lab.machine["installedService"] = {"pathName": f'"{lab.program / "rpworker.exe"}" service run', "state": "Running"}
    lab.write_machine()
    lab.run(urls=False, answers=None)
    assert "service stop" not in lab.commands()


def test_a_registration_whose_answer_was_lost_makes_a_new_key_and_registers(tmp_path):
    # Finding 8: the Cloud holds this key (a 201 that never arrived): 409 on every token.
    lab = InstallLab(tmp_path, flags=("cloud-holds-key",))
    result = lab.run()
    assert result.returncode == 0, result.stderr
    commands = lab.commands()
    i = commands.index("cloud register --name fake-host-worker")
    assert commands[i:i + 3] == ["cloud register --name fake-host-worker", "signer new-key --replace", "cloud register --name fake-host-worker"]
    assert "cloud_api_token" in lab.vault() and "cloud_install_token" not in lab.vault()
    assert lab.vault()["signing_key_base64"] != (lab.fake / "cloud-held-key.txt").read_text(encoding="utf-8")
    out = lines(result)
    assert any(line.startswith(f"change: rpworker signer new-key --replace (key {KEY_ID}): the Cloud already held this Worker's old key") and
               "revoke it (manage.py revoke-worker)" in line for line in out)
    assert f"worker {WORKER_ID} key {KEY_ID}" in out
    assert_no_secret(result.stdout + result.stderr)


def test_a_worker_registered_with_another_cloud_stops_and_says_how_to_move(tmp_path):
    lab = InstallLab(tmp_path)
    assert lab.run().returncode == 0
    (lab.root / "state" / "worker.json").write_text(
        json.dumps({"worker_id": WORKER_ID, "key_id": KEY_ID, "cloud_url": "https://cloud.example.invalid"}), encoding="utf-8")
    result = lab.run("-Replace", "-CloudUrl 'https://other.example.invalid'", "-VeeamUrl 'https://veeam.example.invalid:4443'",
                     urls=False, answers={"veeam_password": PASSWORD})
    assert result.returncode != 0
    assert ("this Worker is registered with https://cloud.example.invalid" in result.stderr and
            "rpworker vault remove cloud_api_token" in result.stderr)

"""Uninstall-RestoreProofWorker.ps1 as a whole, against tests/fake_rpworker.py and
tests/FakeMachine.psm1 on a temporary root (W7.3, docs/decisions.md 2026-10-19 point 4):
refusals first, each with nothing removed; then the order of the Worker's calls, every file of
the list overwritten and gone, what is left and named, -Full, -WhatIf, the Cloud not reached,
the flush failing, a held file."""

from pathlib import Path

from fake_rpworker import THUMBPRINT, WORKER_ID
from install_lab import SCRIPTS, SERVICE, InstallLab, assert_no_secret, lines

OUTBOX_LIST = (
    "RUN              QUEUED                ATTEMPTS  NEXT                  LAST_ERROR          TIMESTAMP\n"
    "w73-queued-1     2026-10-19T11:56:44Z  2         2026-10-19T12:40:10Z  upload_unreachable  timestamped\n"
    "1 queued, 0 sent, 0 failed\n"
)


def installed_lab(tmp_path, **kw) -> InstallLab:
    """A Worker the installer put there, running, with a run folder in each of the service's
    folders, a log, a lab folder of someone's own and a worker.json."""
    lab = InstallLab(tmp_path, **kw)
    assert lab.run().returncode == 0, "the install"
    lab.installed()
    for name in ("runs", "outbox", "sent", "failed"):
        folder = lab.root / name / f"{name}-run-1"
        folder.mkdir()
        (folder / "result.json").write_text('{"format":"restoreproof.result.v1"}', encoding="ascii")
        (folder / "items.csv").write_text("index,name\n", encoding="ascii")
    (lab.root / "state" / "worker.json").write_text(f'{{"worker_id":"{WORKER_ID}","key_id":"x","cloud_url":"https://cloud.example.invalid","format":"restoreproof.worker.v1","registered_at":"2026-10-19T00:00:00Z"}}', encoding="ascii")
    (lab.root / "state" / "jobs.json").write_text("{}", encoding="ascii")
    (lab.root / "vault.bin").write_bytes(b"not a vault, a stand-in for the DPAPI blob " + b"x" * 100)
    (lab.root / "logs" / "worker.log").write_text("2026-10-19 service running\n", encoding="ascii")
    (lab.root / "logs" / "worker.1.log").write_text("old\n", encoding="ascii")
    (lab.root / "w48").mkdir()
    (lab.root / "w48" / "kept.txt").write_text("a lab's own folder", encoding="ascii")
    return lab


def present(root: Path) -> set:
    return {p.name for p in root.iterdir()} if root.exists() else set()


# --- refusals, nothing removed --------------------------------------------------------------


def test_not_elevated_stops_before_anything(tmp_path):
    lab = installed_lab(tmp_path)
    lab.machine["elevated"] = False
    lab.write_machine()
    before = len(lab.argv())
    result = lab.uninstall()
    assert result.returncode != 0 and "run this from an elevated PowerShell" in result.stderr
    assert lab.commands()[before:] == [] and (lab.root / "vault.bin").exists() and lab.program.exists()


def test_a_service_from_another_exe_is_refused_with_nothing_removed(tmp_path):
    lab = installed_lab(tmp_path)
    lab.machine["installedService"] = {"pathName": '"C:\\elsewhere\\rpworker.exe" service run', "state": "Running"}
    lab.write_machine()
    before = len(lab.argv())
    result = lab.uninstall()
    assert result.returncode != 0
    assert "runs \"C:\\elsewhere\\rpworker.exe\" service run, not" in result.stderr and "neither" not in result.stderr
    assert "rpworker service stop, then rpworker service uninstall by hand first" in result.stderr
    assert "Nothing was removed; the Worker is installed as it was (stopped, when this ran past step 3" in result.stderr
    assert lab.commands()[before:] == [] and (lab.root / "vault.bin").exists() and lab.program.exists() and lab.entry() is not None


def test_a_run_that_never_ends_stops_the_uninstall_with_the_service_installed(tmp_path):
    lab = installed_lab(tmp_path, run_in_progress=True)
    before = len(lab.argv())
    result = lab.uninstall("-WaitMinutes 0.05")
    assert result.returncode != 0
    assert "run fake-run-1 is still in progress after 0.05 min (before the stop)" in result.stderr
    assert "waiting: run fake-run-1 in progress for 0 min (before the stop; up to 0.05 min)" in result.stdout
    assert lab.commands()[before:] == [] and lab.marker("service-started") and lab.marker("service-installed")
    assert (lab.root / "vault.bin").exists() and lab.program.exists() and lab.overwritten() == []


def test_a_record_the_stop_still_caught_restarts_the_service_once_and_waits(tmp_path):
    lab = installed_lab(tmp_path)
    lab.flag("record-after-stop")
    before = len(lab.argv())
    result = lab.uninstall()
    assert result.returncode == 0, result.stderr
    out = lines(result)
    assert "note: a run was taken as the service stopped: it is started once more so its own recovery closes the run, waits for Veeam and cleans the restore targets" in out
    commands = lab.commands()[before:]
    assert commands[:3] == ["service stop", "service start", "service stop"]
    assert "ok: started RestoreProof" in out and not lab.marker("service-installed")


def test_a_record_that_stays_after_the_restart_stops_with_the_service_stopped_and_nothing_removed(tmp_path):
    lab = installed_lab(tmp_path)
    lab.flag("record-after-stop")
    lab.flag("fail-service-start")
    before = len(lab.argv())
    result = lab.uninstall()
    assert result.returncode != 0
    assert "rpworker service start failed" in result.stderr and "state\\running.json is still there" in result.stderr
    assert lab.commands()[before:] == ["service stop", "service start"]
    assert lab.marker("service-installed") and (lab.root / "vault.bin").exists() and lab.program.exists()


def test_a_service_uninstall_that_fails_stops_with_nothing_removed(tmp_path):
    lab = installed_lab(tmp_path)
    lab.flag("fail-service-uninstall")
    before = len(lab.argv())
    result = lab.uninstall()
    assert result.returncode != 0
    assert "rpworker service uninstall failed: service error: the service RestoreProof is marked for deletion" in result.stderr
    assert "Nothing was removed; the Worker is installed as it was (stopped" in result.stderr
    assert (lab.root / "vault.bin").exists() and lab.program.exists() and lab.overwritten() == [] and lab.entry() is not None
    # Nothing was told or undone: the Cloud not yet, the key file's entry still there.
    assert not lab.marker("revoked") and "cloud_api_token" in lab.vault()
    after = " ".join(lab.commands()[before:])
    assert "cloud revoke" not in after and "veeam list" not in after


def test_a_service_installed_from_an_exe_that_is_gone_is_refused_with_the_sc_lines(tmp_path):
    lab = installed_lab(tmp_path)
    import shutil
    shutil.rmtree(lab.program)
    before = len(lab.argv())
    result = lab.uninstall(worker=lab.program / "rpworker.exe")
    assert result.returncode != 0
    assert f"is installed from {lab.program / 'rpworker.exe'}, which is gone, so rpworker can't stop or uninstall it: sc stop {SERVICE}, then sc delete {SERVICE}, then run this again" in result.stderr
    assert lab.commands()[before:] == [] and (lab.root / "vault.bin").exists() and lab.entry() is not None and lab.overwritten() == []


# --- the whole, in order --------------------------------------------------------------------


def test_the_uninstall_does_the_steps_in_order_overwrites_the_data_and_leaves_the_log(tmp_path):
    lab = installed_lab(tmp_path)
    (lab.fake / "outbox-list.txt").write_text(OUTBOX_LIST, encoding="ascii")
    key_file = lab.key_file
    before = len(lab.argv())
    result = lab.uninstall()
    assert result.returncode == 0, result.stderr
    out = lines(result)
    config = lab.root / "config.json"
    # The service goes before the Cloud is told and the key files are touched (the review's finding 4).
    assert lab.commands()[before:] == [
        "service stop", "vault list", f"outbox flush --config {config} --outbox {lab.root}", f"outbox list --outbox {lab.root}",
        "service uninstall", f"cloud revoke --config {config}", f"veeam list --config {config}",
    ]
    assert f"ok: rpworker 0.1.0 at {lab.program / 'rpworker.exe'}" in out
    assert "change: rpworker service stop (stopped RestoreProof in 0.4 s)" in out
    assert "ok: rpworker outbox flush: 0 queued, 1 sent, 0 failed" in out
    assert "ok: the outbox holds no run that never reached the Cloud" in out
    assert f"change: rpworker cloud revoke (revoked worker {WORKER_ID})" in out and lab.marker("revoked")
    assert f"change: RestoreProofLab.onmicrosoft.com: the account's entry taken off the key file of {THUMBPRINT}" in " ".join(out)
    assert "change: rpworker service uninstall (uninstalled RestoreProof)" in out and not lab.marker("service-installed")
    # The data: vault.bin and every file of the five folders overwritten (the fake records each), then gone.
    overwritten = {Path(p).relative_to(lab.root).as_posix() for p in lab.overwritten()}
    assert overwritten == {
        "vault.bin", "state/worker.json", "state/jobs.json",
        "runs/runs-run-1/result.json", "runs/runs-run-1/items.csv", "outbox/outbox-run-1/result.json", "outbox/outbox-run-1/items.csv",
        "sent/sent-run-1/result.json", "sent/sent-run-1/items.csv", "failed/failed-run-1/result.json", "failed/failed-run-1/items.csv",
    }
    assert present(lab.root) == {"logs", "w48"}
    assert (lab.root / "logs" / "worker.log").read_text(encoding="ascii") == "2026-10-19 service running\n"
    assert (lab.root / "w48" / "kept.txt").exists() and f"note: {lab.root / 'w48'} left: not the installer's" in out
    assert f"change: {lab.root / 'vault.bin'} overwritten once and deleted" in out
    assert f"change: {config} deleted" in out
    assert not lab.program.exists() and f"change: {lab.program} removed" in out
    assert lab.entry() is None and "change: the Apps & features entry removed" in out
    assert f"left: {lab.root / 'logs'} (the service's log; -Full removes it and the folder)" in out
    assert any(line.startswith("vault.bin and the run folders: each file overwritten once, then deleted (no erasure is guaranteed on an SSD") for line in out)
    assert any(line.startswith("next: the Worker's Graph certificate stays as a credential") for line in out)
    assert not any(line.startswith("next: revoke this Worker in the Cloud") for line in out)
    assert "securely" not in result.stdout.lower()
    changes = [line for line in out if line.startswith("change: ")]
    assert f"changes: {len(changes)}" in out
    assert key_file.exists()
    assert_no_secret(result.stdout + result.stderr)


def test_full_removes_the_log_and_the_folder_whole(tmp_path):
    lab = installed_lab(tmp_path)
    result = lab.uninstall("-Full")
    assert result.returncode == 0, result.stderr
    out = lines(result)
    assert not lab.root.exists() and not lab.program.exists()
    assert f"change: {lab.root / 'logs'} removed" in out and f"change: {lab.root} removed" in out
    assert not any("left: not the installer's" in line for line in out) and not any(line.startswith("left: ") for line in out)


def test_whatif_removes_nothing_and_runs_nothing_that_writes(tmp_path):
    lab = installed_lab(tmp_path, run_in_progress=True)
    before = len(lab.argv())
    result = lab.uninstall(whatif=True)
    assert result.returncode == 0, result.stderr
    out = lines(result)
    # The three reads run (the version through the machine module); nothing that writes.
    assert lab.commands()[before:] == ["vault list", f"outbox list --outbox {lab.root}", f"veeam list --config {lab.root / 'config.json'}"]
    assert any(line.startswith("would: icacls ") and "/remove:g" in line for line in out)
    assert "would: wait for run fake-run-1 to end (before the stop)" in out and "would: rpworker service stop" in out
    assert "would: rpworker outbox flush" in out and "would: rpworker cloud revoke" in out and "would: rpworker service uninstall" in out
    assert out.index("would: rpworker service uninstall") < out.index("would: rpworker cloud revoke")
    assert f"would: overwrite once and delete {lab.root / 'vault.bin'}" in out and f"would: remove {lab.program}" in out
    assert "would: remove the Apps & features entry" in out
    assert (lab.root / "vault.bin").exists() and lab.program.exists() and lab.entry() is not None and lab.overwritten() == []
    assert lab.marker("service-installed") and lab.marker("service-started") and "changes: 0" in out


def test_unsent_runs_are_named_and_go_with_the_folder(tmp_path):
    lab = installed_lab(tmp_path)
    lab.flag("fail-outbox-flush")
    (lab.fake / "outbox-list.txt").write_text(OUTBOX_LIST, encoding="ascii")
    result = lab.uninstall()
    assert result.returncode == 0, result.stderr
    out = lines(result)
    assert "ok: rpworker outbox flush: 1 queued, 0 sent, 0 failed" in out
    assert "note: 1 run(s) never reached the Cloud and go with the folder: w73-queued-1" in out
    assert not (lab.root / "outbox").exists()


def test_a_cloud_not_reached_names_the_revoke_by_hand_and_goes_on(tmp_path):
    lab = installed_lab(tmp_path)
    lab.flag("revoke-503")
    result = lab.uninstall()
    assert result.returncode == 0, result.stderr
    out = lines(result)
    assert any(line.startswith("note: the Cloud wasn't reached (cloud revoke: the Cloud couldn't be reached") and f"manage.py revoke-worker --worker-id {WORKER_ID}, or the Workers page" in line for line in out)
    assert f"next: revoke this Worker in the Cloud: manage.py revoke-worker --worker-id {WORKER_ID}, or the Workers page" in out
    assert not lab.marker("revoked") and not lab.program.exists() and not (lab.root / "vault.bin").exists()


def test_a_token_the_cloud_no_longer_knows_is_ok(tmp_path):
    lab = installed_lab(tmp_path)
    lab.flag("revoke-401")
    result = lab.uninstall()
    assert result.returncode == 0, result.stderr
    out = lines(result)
    assert "ok: cloud revoke: the Cloud doesn't know this token (revoked already, or never this Cloud's); it was removed from the vault" in out
    assert not any(line.startswith("next: revoke this Worker") for line in out)


def test_a_worker_never_registered_is_not_sent_and_not_revoked(tmp_path):
    lab = installed_lab(tmp_path)
    lab.set_vault({k: v for k, v in lab.vault().items() if k != "cloud_api_token"})
    result = lab.uninstall()
    assert result.returncode == 0, result.stderr
    out = lines(result)
    assert "note: no API token in the vault: nothing of the outbox is sent" in out
    assert any(line.startswith("note: no API token in the vault: the Cloud isn't told; revoke this Worker in the Cloud") for line in out)
    assert "outbox flush" not in " ".join(lab.commands()) and "cloud revoke" not in " ".join(lab.commands())


def test_veeam_list_failing_leaves_the_key_file_entries_named(tmp_path):
    lab = installed_lab(tmp_path)
    lab.flag("fail-veeam-list")
    result = lab.uninstall()
    assert result.returncode == 0, result.stderr
    out = lines(result)
    assert any(line.startswith("note: rpworker veeam list failed: veeam error: Veeam POST /v8/token: HTTP 401") and "/remove:g *S-1-5-80-" in line for line in out)
    assert not lab.program.exists()


def test_a_held_file_is_one_problem_line_and_the_rest_goes_and_exit_1(tmp_path):
    lab = installed_lab(tmp_path)
    lab.machine["unremovable"] = ["worker.json"]
    lab.write_machine()
    result = lab.uninstall()
    assert result.returncode == 1
    out = lines(result)
    assert any(line.startswith(f"problem: {lab.root / 'state' / 'worker.json'} couldn't be overwritten and deleted (fake:") for line in out)
    assert (lab.root / "state" / "worker.json").exists() and not (lab.root / "state" / "jobs.json").exists()
    assert not (lab.root / "vault.bin").exists() and not lab.program.exists() and "problems: 1" in out


def test_a_held_file_keeps_the_root_under_full(tmp_path):
    lab = installed_lab(tmp_path)
    lab.machine["unremovable"] = ["vault.bin"]
    lab.write_machine()
    result = lab.uninstall("-Full")
    assert result.returncode == 1
    assert (lab.root / "vault.bin").exists() and lab.root.exists()
    assert f"problem: {lab.root} kept: a file in it couldn't be removed (above)" in lines(result)


def test_no_service_and_no_exe_still_removes_the_files(tmp_path):
    lab = installed_lab(tmp_path)
    lab.machine["installedService"] = None
    lab.write_machine()
    import shutil
    shutil.rmtree(lab.program)
    before = len(lab.argv())
    result = lab.uninstall(worker=lab.program / "rpworker.exe")
    assert result.returncode == 0, result.stderr
    out = lines(result)
    assert lab.commands()[before:] == []
    assert any(line.startswith("note: no rpworker at ") and "the files are removed" in line for line in out)
    assert f"ok: no service {SERVICE} to uninstall" in out and f"ok: no {lab.program}" in out
    assert not (lab.root / "vault.bin").exists() and present(lab.root) == {"logs", "w48"}


def test_a_second_uninstall_finds_nothing_and_changes_nothing(tmp_path):
    lab = installed_lab(tmp_path)
    assert lab.uninstall().returncode == 0
    lab.machine["installedService"] = None
    lab.write_machine()
    result = lab.uninstall(worker=lab.program / "rpworker.exe")
    assert result.returncode == 0, result.stderr
    assert "changes: 0" in lines(result)


def test_the_scripts_in_the_program_folder_are_the_packages(tmp_path):
    lab = installed_lab(tmp_path)
    for name in SCRIPTS:
        assert (lab.program / name).exists()
    assert lab.uninstall().returncode == 0
    assert not lab.program.exists()

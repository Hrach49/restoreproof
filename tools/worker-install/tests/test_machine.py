"""WorkerMachine.psm1's real reads and writes that a temporary folder can show (W7.3, W7.4):
the overwrite-then-delete (through -KeepFile, so the bytes are read back), an exe's version,
the run record. The registry entry and the key files are the live Done-when's."""

import os
import subprocess
import sys

import pytest

from pwsh import MACHINE_MODULE, TESTS_DIR, ps_string, run, run_json


def with_machine(command: str) -> str:
    return f"Import-Module {ps_string(MACHINE_MODULE)} -Force\n{command}"


def test_remove_file_overwritten_writes_other_bytes_of_the_same_length_then_deletes(tmp_path):
    original = b"the vault's DPAPI blob stands in for this " + os.urandom(5000)
    path = tmp_path / "vault.bin"
    path.write_bytes(original)
    run_json(with_machine(f"Remove-FileOverwritten -Path {ps_string(path)} -Within {ps_string(tmp_path)} -KeepFile; 'done'"))
    after = path.read_bytes()
    assert len(after) == len(original)
    assert after != original
    # No 64-byte window of the original survives.
    for i in range(0, len(original) - 64, 64):
        assert original[i:i + 64] not in after
    run_json(with_machine(f"Remove-FileOverwritten -Path {ps_string(path)} -Within {ps_string(tmp_path)}; 'done'"))
    assert not path.exists()


def test_remove_file_overwritten_on_an_empty_file_deletes_it(tmp_path):
    path = tmp_path / "empty.bin"
    path.write_bytes(b"")
    run_json(with_machine(f"Remove-FileOverwritten -Path {ps_string(path)} -Within {ps_string(tmp_path)}; 'done'"))
    assert not path.exists()


def test_remove_file_overwritten_throws_for_a_held_file_and_leaves_it(tmp_path):
    path = tmp_path / "held.bin"
    path.write_bytes(b"held " * 100)
    with path.open("rb") as held:  # a reader without delete sharing, as a tailing tool is
        result = run(with_machine(f"try {{ Remove-FileOverwritten -Path {ps_string(path)} -Within {ps_string(tmp_path)}; 'removed' }} catch {{ 'refused: ' + $_.Exception.Message }}"))
        assert result.returncode == 0, result.stderr
        assert "refused: " in result.stdout
        held.read()
    assert path.read_bytes() == b"held " * 100


def refused(command: str) -> str:
    """The message a call threw, or 'removed'."""
    result = run(with_machine(f"try {{ {command}; 'removed' }} catch {{ 'refused: ' + $_.Exception.Message }}"))
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def test_a_hard_link_to_a_file_elsewhere_is_not_overwritten(tmp_path):
    # The service account can make a hard link in runs\ to a file it can't write; the elevated
    # uninstall must never write through it (the W7.3 review's second pass, CWE-59).
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    target = elsewhere / "system.dat"
    target.write_bytes(b"someone else's file " * 50)
    root = tmp_path / "root"
    (root / "runs").mkdir(parents=True)
    link = root / "runs" / "link.bin"
    os.link(target, link)
    message = refused(f"Remove-FileOverwritten -Path {ps_string(link)} -Within {ps_string(root)}")
    assert message == "refused: has 2 names (a hard link): not overwritten"
    assert target.read_bytes() == b"someone else's file " * 50 and link.exists()


def test_a_junction_on_the_way_is_not_followed(tmp_path):
    # runs\ turned into a junction to another folder after the uninstall looked.
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    target = elsewhere / "result.json"
    target.write_bytes(b"not the Worker's " * 50)
    root = tmp_path / "root"
    root.mkdir()
    subprocess.run(["cmd", "/c", "mklink", "/J", str(root / "runs"), str(elsewhere)], capture_output=True, check=True)
    message = refused(f"Remove-FileOverwritten -Path {ps_string(root / 'runs' / 'result.json')} -Within {ps_string(root)}")
    assert message == "refused: is reached through a junction or a symbolic link: not overwritten"
    assert target.read_bytes() == b"not the Worker's " * 50


def test_a_symbolic_link_to_a_file_is_not_followed(tmp_path):
    elsewhere = tmp_path / "elsewhere.dat"
    elsewhere.write_bytes(b"kept " * 50)
    root = tmp_path / "root"
    root.mkdir()
    link = root / "vault.bin"
    try:
        os.symlink(elsewhere, link)
    except OSError:
        pytest.skip("no right to make a symbolic link (neither elevated nor in developer mode)")
    message = refused(f"Remove-FileOverwritten -Path {ps_string(link)} -Within {ps_string(root)}")
    assert message == "refused: is reached through a junction or a symbolic link: not overwritten"
    assert elsewhere.read_bytes() == b"kept " * 50


def test_a_path_outside_within_is_refused(tmp_path):
    path = tmp_path / "a.bin"
    path.write_bytes(b"x")
    (tmp_path / "root").mkdir()
    assert refused(f"Remove-FileOverwritten -Path {ps_string(path)} -Within {ps_string(tmp_path / 'root')}").startswith("refused: not under ")
    assert path.exists()


def test_get_worker_version_reads_the_exes_first_line_and_refuses_what_isnt_a_version(tmp_path):
    cmd = tmp_path / "rpworker.cmd"
    cmd.write_text(f'@"{sys.executable}" "{TESTS_DIR / "fake_rpworker.py"}" %*\r\n', encoding="ascii")
    env = f"$env:RP_FAKE_DIR = {ps_string(tmp_path)}\n"
    assert run_json(with_machine(env + f"Get-WorkerVersion -Exe {ps_string(cmd)}")) == "0.1.0"
    bad = tmp_path / "bad.cmd"
    bad.write_text("@echo not a version\r\n", encoding="ascii")
    result = run(with_machine(f"try {{ Get-WorkerVersion -Exe {ps_string(bad)} }} catch {{ 'refused: ' + $_.Exception.Message }}"))
    assert "refused: " in result.stdout and "--version failed: not a version" in result.stdout
    failing = tmp_path / "failing.cmd"
    failing.write_text("@echo 0.1.0\r\n@exit /b 1\r\n", encoding="ascii")
    result = run(with_machine(f"try {{ Get-WorkerVersion -Exe {ps_string(failing)} }} catch {{ 'refused: ' + $_.Exception.Message }}"))
    assert "refused: " in result.stdout


def test_get_run_record_reads_the_run_id_and_nothing_without_a_record(tmp_path):
    (tmp_path / "state").mkdir()
    assert run_json(with_machine(f"if ($null -eq (Get-RunRecord -Root {ps_string(tmp_path)})) {{ 'none' }}")) == "none"
    (tmp_path / "state" / "running.json").write_text('{"format":"restoreproof.running.v1","run_id":"7cc849e8-run","taken_at":"x"}', encoding="ascii")
    assert run_json(with_machine(f"(Get-RunRecord -Root {ps_string(tmp_path)}).RunId")) == "7cc849e8-run"
    (tmp_path / "state" / "running.json").write_text("not json", encoding="ascii")
    assert run_json(with_machine(f"(Get-RunRecord -Root {ps_string(tmp_path)}).RunId")) == "?"
    (tmp_path / "state" / "running.json").write_text('{"run_id":"../evil name"}', encoding="ascii")
    assert run_json(with_machine(f"(Get-RunRecord -Root {ps_string(tmp_path)}).RunId")) == "?"

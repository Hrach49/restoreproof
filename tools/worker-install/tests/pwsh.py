"""Runs PowerShell 7 for the tests of tools/worker-install (W7.1), as tools/tenant-setup's pwsh.py does.

The scripts under test are PowerShell, so a machine without `pwsh` can't test them: the tests
fail there, never skip. Each call is one `pwsh -NoProfile -NonInteractive` process; a test that
checks many rows evaluates them all in one call and reads one JSON document back.
"""

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
SETUP_DIR = TESTS_DIR.parent
REPO_DIR = SETUP_DIR.parent.parent
MODULE = SETUP_DIR / "RestoreProofWorker.psm1"
MACHINE_MODULE = SETUP_DIR / "WorkerMachine.psm1"
SCRIPT = SETUP_DIR / "Install-RestoreProofWorker.ps1"
UNINSTALL_SCRIPT = SETUP_DIR / "Uninstall-RestoreProofWorker.ps1"
CERT_SCRIPT = REPO_DIR / "tools" / "tenant-setup" / "New-WorkerGraphCertificate.ps1"
FAKE_MACHINE = TESTS_DIR / "FakeMachine.psm1"
WORKER_EXE = REPO_DIR / "worker" / "build" / "dev" / "rpworker.exe"

# What every command starts with: strict, and an error stops it.
PRELUDE = "Set-StrictMode -Version Latest\n$ErrorActionPreference = 'Stop'\n"
# Marks the line the JSON document starts on, so host output before it is ignored.
MARK = "--- json ---"


def pwsh_exe() -> str:
    exe = shutil.which("pwsh")
    assert exe, "PowerShell 7 (pwsh) is not on PATH: the tenant setup scripts can't be tested without it"
    return exe


def ps_string(text: str) -> str:
    """A single-quoted PowerShell string literal."""
    return "'" + str(text).replace("'", "''") + "'"


def run(command: str, *, timeout: int = 180, cwd: Path | None = None) -> subprocess.CompletedProcess:
    """Runs `command` as a script file (a block spanning lines needs a file, not stdin)."""
    with tempfile.TemporaryDirectory(prefix="rp-tenant-test-") as folder:
        path = Path(folder) / "command.ps1"
        # A BOM, so Windows PowerShell's habits never matter: pwsh reads it as UTF-8 either way.
        path.write_text(PRELUDE + command, encoding="utf-8-sig")
        return subprocess.run(
            [pwsh_exe(), "-NoProfile", "-NonInteractive", "-File", str(path)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=timeout,
            cwd=cwd or folder,
        )


def run_json(command: str, *, timeout: int = 180) -> object:
    """Runs `command`, whose last output is one object, and returns it as JSON.

    The command's output is collected into $__result and written after MARK; anything printed
    with Write-Host before it is ignored. A failure raises with pwsh's stderr."""
    wrapped = (
        f"$__result = & {{\n{command}\n}}\n"
        "[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)\n"
        f"'{MARK}'\n"
        "ConvertTo-Json -InputObject $__result -Depth 50 -Compress\n"
    )
    result = run(wrapped, timeout=timeout)
    assert result.returncode == 0, f"pwsh failed ({result.returncode}):\n{result.stderr}\n{result.stdout}"
    out = result.stdout
    assert MARK in out, f"no JSON from pwsh:\n{out}\n{result.stderr}"
    return json.loads(out.split(MARK, 1)[1])


def evaluate(rows: list[str], *, setup: str = "") -> list:
    """Each of `rows` (a PowerShell expression) evaluated with the module imported, in one pwsh.

    A row's value is what it returns ($null as None, one value as itself, several as a list), or
    {"throws": <message>} when it throws."""
    body = "\n".join(
        f"try {{ $__v = @(& {{ {row} }}); $__out.Add([pscustomobject]@{{ ok = $true; v = $__v }}) }} "
        f"catch {{ $__out.Add([pscustomobject]@{{ ok = $false; v = \"$($_.Exception.Message)\" }}) }}"
        for row in rows
    )
    results = run_json(with_module(f"{setup}\n$__out = [System.Collections.Generic.List[object]]::new()\n{body}\n,@($__out)"))
    values = []
    for result in results:
        if not result["ok"]:
            values.append({"throws": result["v"]})
            continue
        v = result["v"] or []
        values.append(None if len(v) == 0 else v[0] if len(v) == 1 else v)
    return values


def with_module(command: str) -> str:
    """`command` with the module imported."""
    return f"Import-Module {ps_string(MODULE)} -Force\n{command}"


def ps(value) -> str:
    """A PowerShell expression for a JSON value: a hashtable, a list, a string, a bool, $null."""
    if value is None:
        return "$null"
    if isinstance(value, bool):
        return "$true" if value else "$false"
    if isinstance(value, list):
        return f"@(ConvertFrom-Json -AsHashtable -InputObject {ps_string(json.dumps(value))})"
    if isinstance(value, dict):
        return f"(ConvertFrom-Json -AsHashtable -InputObject {ps_string(json.dumps(value))})"
    return ps_string(value)

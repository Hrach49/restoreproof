"""lab/entra/new-worker-app.ps1 (L1.5): its constants agree with seeder/tenant.py and the checker,
it parses, and the PFX password only ever reaches the calls that need it."""

import re
import shutil
import subprocess

import pytest

from seeder import LAB_DIR, tenant, worker_app

SCRIPT = LAB_DIR / "entra" / "new-worker-app.ps1"


def script_text() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def constant(name: str) -> str:
    match = re.search(rf"^\${name}\s*=\s*'([^']*)'", script_text(), re.MULTILINE)
    assert match, f"${name} = '...' not found in {SCRIPT.name}"
    return match.group(1)


@pytest.mark.parametrize(
    "name, value",
    [
        ("TenantId", tenant.TENANT_ID),
        ("AdminUpn", tenant.ADMIN_UPN),
        ("RestoreTestUpn", tenant.RESTORETEST_UPN),
        ("AliceUpn", tenant.ALICE_UPN),
        ("SiteId", tenant.SHAREPOINT_SITE_ID),
        ("OneDriveDriveId", tenant.ONEDRIVE_DRIVE_ID),
        ("OneDriveTargetFolderId", tenant.ONEDRIVE_TARGET_FOLDER_ID),
        ("CredTarget", worker_app.CREDENTIAL_TARGET),
        ("PfxName", worker_app.PFX_NAME),
        ("AppName", "RestoreProof Worker"),
    ],
)
def test_constants_match_the_checker(name, value):
    assert constant(name) == value


def test_graph_roles_are_the_checkers_expected_roles():
    match = re.search(r"^\$GraphRoles\s*=\s*@\(([^)]*)\)", script_text(), re.MULTILINE)
    assert match
    assert set(re.findall(r"'([^']+)'", match.group(1))) == worker_app.EXPECTED_ROLES


def test_the_canary_locations_are_never_named():
    # The script grants on RestoreTarget only; the canary library and folder must not appear.
    text = script_text()
    assert tenant.ONEDRIVE_FOLDER_ID not in text
    assert tenant.SHAREPOINT_DRIVE_ID not in text
    assert tenant.SHAREPOINT_LIST_ID not in text


def test_grants_are_read_only():
    roles = re.findall(r"roles\s*=\s*@\(([^)]*)\)", script_text())
    assert roles, "no roles = @(...) in the script"
    assert all(r.strip() == "'read'" for r in roles), roles
    assert "Application Mail.ReadWrite" not in script_text()


def test_the_password_only_reaches_credential_manager_the_pfx_export_and_load():
    allowed = (
        r"^\s*\$password\s*=\s*\[RpWorkerCred\]::Read\(\$CredTarget\)",
        r"^\s*\$password\s*=\s*\[Convert\]::ToBase64String\(",
        r"^\s*\[RpWorkerCred\]::Write\(\$CredTarget, \$CredUser, \$password\)",
        r"^\s*\$secure\s*=\s*ConvertTo-SecureString\s+\$password\s+-AsPlainText\s+-Force",
        r"^\s*\$x509\s*=\s*\[Security\.Cryptography\.X509Certificates\.X509Certificate2\]::new\(\$PfxPath, \$password,",
        r"^\s*if \(\$haveFile -and -not \$password\)",
        r"^\s*Remove-Variable password, secure",
    )
    for number, line in enumerate(script_text().splitlines(), 1):
        if re.search(r"\$password\b", line, re.IGNORECASE) and not line.lstrip().startswith("#"):
            assert any(re.search(p, line) for p in allowed), f"line {number} uses $password: {line.strip()}"


def test_no_transcript_and_nothing_secret_is_written_out():
    text = script_text()
    assert "Start-Transcript" not in text
    assert not re.search(r"(Write-\w+|Out-\w+)[^\n]*\$(password|secure)\b", text, re.IGNORECASE)
    assert "Export-Clixml" not in text


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell 7 not installed")
def test_script_parses():
    command = (
        "$e = $null; $null = [System.Management.Automation.Language.Parser]::ParseFile("
        f"'{SCRIPT}', [ref]$null, [ref]$e); $e | ForEach-Object {{ $_.ToString() }}; exit $e.Count"
    )
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", command], capture_output=True, text=True, timeout=120
    )
    assert result.returncode == 0, result.stdout + result.stderr

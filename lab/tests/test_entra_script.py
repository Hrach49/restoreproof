"""lab/entra/new-worker-app.ps1 (L1.5): its constants agree with seeder/tenant.py and the checker,
it parses, and the PFX password only ever reaches the calls that need it."""

import re
import shutil
import subprocess
import sys
import uuid

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
        r"^\s*\$password\s*=\s*\[RpWorkerCredential\]::Read\(\$CredTarget\)",
        r"^\s*\$password\s*=\s*\[Convert\]::ToBase64String\(",
        r"^\s*\[RpWorkerCredential\]::Write\(\$CredTarget, \$CredUser, \$password\)",
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


def run_pwsh(command: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", command], capture_output=True, text=True, timeout=120
    )


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell 7 not installed")
def test_a_consent_on_another_api_is_removed_under_strict_mode():
    # The removal loop runs with stubs, as the script does: a consent on Exchange Online has no
    # Graph role to name it, and reading .value off nothing used to throw before the DELETE.
    command = f"""
        Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'
        $ast = [System.Management.Automation.Language.Parser]::ParseFile('{SCRIPT}', [ref]$null, [ref]$null)
        $loop = $ast.Find({{ param($n) $n -is [System.Management.Automation.Language.ForEachStatementAst] -and
            $n.Variable.VariablePath.UserPath -eq 'extra' -and $n.Condition.Extent.Text -like '$assigned*' }}, $true)
        function Invoke-Graph {{ param($Method, $Path) "$Method $Path" | Out-Host }}
        function Done {{ param($Text) "done: $Text" | Out-Host }}
        $spId = 'sp'
        $graphSp = [pscustomobject]@{{ id = 'graph'; appRoles = @([pscustomobject]@{{ id = 'r1'; value = 'Sites.Selected' }}) }}
        $roleIds = @{{ 'Sites.Selected' = 'r1' }}
        $assigned = @(
            [pscustomobject]@{{ id = 'keep'; resourceId = 'graph'; appRoleId = 'r1'; resourceDisplayName = 'Microsoft Graph' }},
            [pscustomobject]@{{ id = 'exo'; resourceId = 'exchange'; appRoleId = 'dc890d15'; resourceDisplayName = 'Office 365 Exchange Online' }})
        . ([scriptblock]::Create($loop.Extent.Text))
    """
    result = run_pwsh(command)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "DELETE servicePrincipals/sp/appRoleAssignments/exo" in result.stdout
    assert "Office 365 Exchange Online role dc890d15" in result.stdout
    assert "appRoleAssignments/keep" not in result.stdout


def test_exchange_module_is_new_enough_for_disable_wam():
    # Connect-ExchangeOnline -DisableWAM exists from ExchangeOnlineManagement 3.7.2 on.
    text = script_text()
    assert "-DisableWAM" in text
    match = re.search(r"Import-Module ExchangeOnlineManagement -MinimumVersion ([\d.]+)", text)
    assert match
    assert tuple(int(p) for p in match.group(1).split(".")) >= (3, 7, 2)


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell 7 not installed")
def test_every_exchange_call_sets_error_action():
    # The Exchange cmdlets are functions in a generated module and don't see the script's
    # $ErrorActionPreference when it runs as .\new-worker-app.ps1 from an open window: without
    # -ErrorAction, their errors print and the script reports success anyway.
    command = f"""
        $ast = [System.Management.Automation.Language.Parser]::ParseFile('{SCRIPT}', [ref]$null, [ref]$null)
        $start = $ast.Find({{ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and
            $n.GetCommandName() -eq 'Connect-ExchangeOnline' }}, $true).Extent.StartOffset
        $ast.FindAll({{ param($n) $n -is [System.Management.Automation.Language.CommandAst] }}, $true) |
            Where-Object {{ $_.Extent.StartOffset -ge $start }} |
            ForEach-Object {{
                $params = @($_.CommandElements | Where-Object {{ $_ -is [System.Management.Automation.Language.CommandParameterAst] }} |
                    ForEach-Object ParameterName)
                "$($_.GetCommandName()) $($params -contains 'ErrorAction')"
            }}
    """
    result = run_pwsh(command)
    assert result.returncode == 0, result.stdout + result.stderr
    exchange_calls = {}
    for line in result.stdout.splitlines():
        name, has_error_action = line.rsplit(" ", 1)
        if name in POWERSHELL_BUILTINS or name == "Disconnect-ExchangeOnline":  # in finally: must not mask the error
            continue
        exchange_calls[name] = exchange_calls.get(name, True) and has_error_action == "True"
    assert "New-ManagementRoleAssignment" in exchange_calls
    assert [name for name, ok in exchange_calls.items() if not ok] == []


POWERSHELL_BUILTINS = {
    "Done", "Step", "Select-Object", "Where-Object", "ForEach-Object", "Format-Table", "Out-String", "Out-Null",
}


def script_function(name: str) -> str:
    """PowerShell that defines the script's function `name`, taken from the script's own AST."""
    return f"""
        $ast = [System.Management.Automation.Language.Parser]::ParseFile('{SCRIPT}', [ref]$null, [ref]$null)
        $fn = $ast.Find({{ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $n.Name -eq '{name}' }}, $true)
        . ([scriptblock]::Create($fn.Extent.Text))
    """


STUBS = """
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'
    function Done { param($Text) "done: $Text" | Out-Host }
    function Invoke-Graph { param($Method, $Path, $Body) "$Method $Path $($Body | ConvertTo-Json -Compress -Depth 5)" | Out-Host }
"""


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell 7 not installed")
def test_client_secrets_and_other_certificates_are_removed():
    # An app first made by hand (issue #13's original steps: "new client secret") keeps no secret.
    command = STUBS + script_function("Set-OnlyCredential") + """
        $app = @{ id = 'obj'; appId = 'app'
            keyCredentials = @(@{ displayName = 'CN=RestoreProof Worker (lab) ABC123' }, @{ displayName = 'portal upload' })
            passwordCredentials = @(@{ keyId = 'k1'; displayName = 'first secret' }, @{ keyId = 'k2'; displayName = 'second' }) }
        Set-OnlyCredential -App $app -KeyCredential @{ key = 'KEY' } -Thumbprint 'ABC123'
    """
    result = run_pwsh(command)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'PATCH applications/obj {"keyCredentials":[{"key":"KEY"}]}' in result.stdout
    assert "replaces 2 certificate(s)" in result.stdout
    assert 'POST applications/obj/removePassword {"keyId":"k1"}' in result.stdout
    assert 'POST applications/obj/removePassword {"keyId":"k2"}' in result.stdout


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell 7 not installed")
def test_an_app_with_only_its_certificate_is_left_alone():
    command = STUBS + script_function("Set-OnlyCredential") + """
        $app = @{ id = 'obj'; appId = 'app'; keyCredentials = @(@{ displayName = 'CN=x ABC123' }); passwordCredentials = @() }
        Set-OnlyCredential -App $app -KeyCredential @{ key = 'KEY' } -Thumbprint 'ABC123'
        $app = @{ id = 'obj'; appId = 'app'; keyCredentials = @(@{ displayName = 'CN=x ABC123' }); passwordCredentials = $null }
        Set-OnlyCredential -App $app -KeyCredential @{ key = 'KEY' } -Thumbprint 'ABC123'
    """
    result = run_pwsh(command)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PATCH" not in result.stdout and "POST" not in result.stdout
    assert result.stdout.count("certificate already uploaded") == 2


RETRY = STUBS + script_function("Get-GraphStatus") + script_function("Invoke-WithRetry") + """
    function Start-Sleep { param($Seconds) }
    $script:attempts = 0
    function Fail([string]$Message, $Status) {
        $exception = [Exception]::new($Message)
        if ($null -ne $Status) {
            $exception | Add-Member -NotePropertyName Response -NotePropertyValue ([pscustomobject]@{ StatusCode = $Status })
        }
        throw [System.Management.Automation.ErrorRecord]::new($exception, 'x', 'NotSpecified', $null)
    }
"""


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell 7 not installed")
@pytest.mark.parametrize(
    ("failure", "attempts"),
    [
        ("Fail 'Response status code does not indicate success: NotFound (Not Found).'", 6),
        ("Fail 'Response status code does not indicate success: BadRequest (Bad Request).'", 6),
        ("Fail 'x' 404", 6),
        ("Fail 'Response status code does not indicate success: Forbidden (Forbidden).'", 1),
        ("Fail 'Authorization_RequestDenied' 403", 1),
        ("Fail 'server busy' 503", 1),
        ("Fail 'connection reset'", 1),
    ],
)
def test_only_replication_lag_is_retried(failure, attempts):
    command = RETRY + f"""
        try {{ Invoke-WithRetry -What 'consent' -Action {{ $script:attempts++; {failure} }}; 'no error' }}
        catch {{ "attempts: $script:attempts" }}
    """
    result = run_pwsh(command)
    assert result.returncode == 0, result.stdout + result.stderr
    assert f"attempts: {attempts}" in result.stdout


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell 7 not installed")
def test_a_consent_already_in_place_counts_as_granted():
    # An earlier POST got through but its answer was lost; the retry then gets 400 "already exists".
    command = RETRY + f"""
        $ast = [System.Management.Automation.Language.Parser]::ParseFile('{SCRIPT}', [ref]$null, [ref]$null)
        $loop = $ast.Find({{ param($n) $n -is [System.Management.Automation.Language.ForEachStatementAst] -and
            $n.Variable.VariablePath.UserPath -eq 'name' -and $n.Body.Extent.Text -like '*appRoleAssignments*' }}, $true)
        function Invoke-Graph {{ param($Method, $Path, $Body)
            Fail 'Permission being assigned already exists on the object' 400 }}
        $GraphRoles = @('Sites.Selected'); $assigned = @(); $spId = 'sp'
        $graphSp = @{{ id = 'graph' }}; $roleIds = @{{ 'Sites.Selected' = 'r1' }}
        . ([scriptblock]::Create($loop.Extent.Text))
    """
    result = run_pwsh(command)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "done: Sites.Selected granted" in result.stdout
    assert "not ready yet" not in result.stdout


def credential_type() -> str:
    match = re.search(r'Add-Type -TypeDefinition @"\n(.*?)\n"@', script_text(), re.DOTALL)
    assert match
    return match.group(1)


@pytest.mark.skipif(sys.platform != "win32" or shutil.which("pwsh") is None, reason="Credential Manager, Windows only")
def test_credential_manager_reader_null_only_for_a_missing_credential_and_empty_for_an_empty_one():
    target = f"RestoreProof Lab - test {uuid.uuid4()}"
    source = credential_type().replace("'", "''")
    command = f"""
        $ErrorActionPreference = 'Stop'
        Add-Type -TypeDefinition '{source}'
        Add-Type -TypeDefinition 'public static class RpTestCredDelete {{
            [System.Runtime.InteropServices.DllImport("advapi32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
            static extern bool CredDeleteW(string t, int type, int f);
            public static void Delete(string t) {{ CredDeleteW(t, 1, 0); }} }}'
        if ($null -ne [RpWorkerCredential]::Read('{target}')) {{ throw 'missing credential not null' }}
        [RpWorkerCredential]::Write('{target}', 'u', '')
        try {{ $read = [RpWorkerCredential]::Read('{target}'); "empty: [$read] null: $($null -eq $read)" }}
        finally {{ [RpTestCredDelete]::Delete('{target}') }}
    """
    result = run_pwsh(command)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "empty: [] null: False" in result.stdout


def test_credential_manager_reader_throws_on_any_other_error():
    # ERROR_NO_SUCH_LOGON_SESSION and the like must not read as "no password": the script would
    # then say to delete the PFX, the only copy of the key.
    source = credential_type()
    assert "if (error == 1168) return null;" in source
    assert "throw new System.ComponentModel.Win32Exception(error);" in source

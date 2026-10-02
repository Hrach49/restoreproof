"""lab/entra/new-worker-app.ps1 (L1.5): its constants agree with seeder/tenant.py and the checker,
it parses, and the PFX password only ever reaches the calls that need it. And
lab/entra/check-worker-grants.ps1 (W3.4, build notes point 13): it only reads, and its rules find a
Worker app grant at a canary and a missing one on a restore target."""

import json
import re
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

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
        ("RestoreTargetListId", tenant.RESTORE_TARGET_LIST_ID),
        ("RestoreTargetName", worker_app.TARGET_FOLDER_NAME),
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
    # The script grants on RestoreTarget only; the canary library and folder must not appear
    # (check-worker-grants.ps1 names them, and only reads).
    text = script_text()
    assert tenant.ONEDRIVE_FOLDER_ID not in text
    assert tenant.SHAREPOINT_DRIVE_ID not in text
    assert tenant.SHAREPOINT_LIST_ID not in text


def code_text() -> str:
    """The script without its comment-based help and comment lines."""
    text = re.sub(r"<#.*?#>", "", script_text(), flags=re.DOTALL)
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


# Every Invoke-Graph call that sends roles: its method, its path and the body up to its end.
_GRANT_CALL = re.compile(r'Invoke-Graph (POST|PATCH) "([^"]*permissions[^"]*)" @\{(.*?)\}\s*\|', re.DOTALL)


def grant_calls() -> list[tuple[str, str, str]]:
    calls = []
    for method, path, body in _GRANT_CALL.findall(code_text()):
        roles = re.search(r"roles\s*=\s*@\(([^)]*)\)", body)
        assert roles, (method, path)
        calls.append((method, path, roles.group(1).strip()))
    return calls


def test_the_only_write_grants_are_the_restore_target_list_and_folder():
    # W3.4 (docs/decisions.md 2026-10-02, point 1): the site keeps read; write goes on the
    # RestoreTarget list and alice's RestoreTarget folder only, and nothing is owner or fullcontrol.
    calls = grant_calls()
    assert {roles for _, _, roles in calls} == {"'read'", "'write'"}, calls
    writes = {(method, path.split("/permissions")[0]) for method, path, roles in calls if roles == "'write'"}
    assert writes == {("POST", "$list"), ("PATCH", "$list"), ("POST", "$folder"), ("PATCH", "$folder")}
    reads = {path.split("/permissions")[0] for _, path, roles in calls if roles == "'read'"}
    assert reads == {"sites/$SiteId"}
    roles_anywhere = re.findall(r"roles\s*=\s*@\(([^)]*)\)", code_text())
    assert len(roles_anywhere) == len(calls)  # no roles sent any other way
    code = code_text()
    assert re.search(r'^\s*\$list = "sites/\$SiteId/lists/\$RestoreTargetListId"$', code, re.MULTILINE)
    assert re.search(r'^\s*\$folder = "drives/\$OneDriveDriveId/items/\$OneDriveTargetFolderId"$', code, re.MULTILINE)
    assert len(re.findall(r"^\s*\$(list|folder) = ", code, re.MULTILINE)) == 2  # never re-pointed


def test_the_only_mail_role_is_application_mail_readwrite():
    assert constant("MailRoleName") == "Application Mail.ReadWrite"
    assert constant("MailAssignmentName") == "RestoreProof Worker - Application Mail.ReadWrite - restoretest"
    assert constant("MailScopeName") == "RestoreProof Worker - restoretest mailbox"  # the existing scope
    assert set(re.findall(r"Application Mail\.\w+", code_text())) == {"Application Mail.ReadWrite"}
    # The old "Application Mail.Read" assignment goes through the extra-assignment loop.
    assert "Remove-ManagementRoleAssignment -Identity $extra.Identity" in code_text()


def test_the_list_grant_uses_only_the_restore_target_list_id():
    lists = re.findall(r"lists/([^\"?/]+)", code_text())
    assert lists and set(lists) <= {"$RestoreTargetListId", "${RestoreTargetListId}"}, lists
    assert tenant.RESTORE_TARGET_LIST_ID != tenant.SHAREPOINT_LIST_ID


def test_each_write_grant_sits_behind_its_name_check():
    # Within its step, the name check runs before the step's first permission write.
    checked = set()
    for step in re.split(r"^\s*Step ", code_text(), flags=re.MULTILINE):
        if "@('write')" not in step:
            continue
        first_write = min(step.index(m) for m in ('Invoke-Graph POST "$', 'Invoke-Graph PATCH "$') if m in step)
        for check, variable in (("Assert-RestoreTargetList", "$list"), ("Assert-RestoreTargetFolder", "$folder")):
            if f'Invoke-Graph POST "{variable}/permissions"' in step:
                assert check in step[:first_write], check
                checked.add(check)
    assert checked == {"Assert-RestoreTargetList", "Assert-RestoreTargetFolder"}


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


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell 7 not installed")
def test_no_comment_text_runs_as_a_command():
    # A comment once split before "\new-worker-app.ps1", leaving "ew-worker-app.ps1 from an open
    # window, ..." as a command line: the script stopped there, between Graph and Exchange.
    command = f"""
        $ast = [System.Management.Automation.Language.Parser]::ParseFile('{SCRIPT}', [ref]$null, [ref]$null)
        $ast.FindAll({{ param($n) $n -is [System.Management.Automation.Language.CommandAst] }}, $true) |
            ForEach-Object {{ $_.GetCommandName() }} | Where-Object {{ $_ -match '\\.ps1$|[\\\\/]' }}
    """
    result = run_pwsh(command)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.split() == []


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


def name_check(function: str, reply: str) -> subprocess.CompletedProcess:
    """Runs the script's name check `function` with Invoke-Graph answering `reply` (a hashtable,
    as Invoke-MgGraphRequest -OutputType HashTable gives) and the script's own constants."""
    constants = "\n".join(
        f"${name} = '{constant(name)}'"
        for name in ("SiteId", "OneDriveDriveId", "OneDriveTargetFolderId", "RestoreTargetListId", "RestoreTargetName")
    )
    command = f"""
        Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'
        function Done {{ param($Text) "done: $Text" | Out-Host }}
        function Invoke-Graph {{ param($Method, $Path, $Body) "request: $Method $Path" | Out-Host; {reply} }}
        {constants}
        {script_function(function)}
        try {{ {function}; 'checked' }} catch {{ "refused: $_" }}
    """
    return run_pwsh(command)


_SITE_URL = "https://restoreprooflab.sharepoint.com/sites/RestoreTest"


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell 7 not installed")
@pytest.mark.parametrize(
    ("reply", "refused"),
    [
        # failure paths first: the canary library, a renamed list, the address of another list
        (f"@{{ id = 'x'; displayName = 'RestoreTest'; webUrl = '{_SITE_URL}/RestoreTest' }}", True),
        (f"@{{ id = 'x'; displayName = 'RestoreTarget'; webUrl = '{_SITE_URL}/RestoreTest' }}", True),
        (f"@{{ id = 'x'; displayName = 'RestoreTest'; webUrl = '{_SITE_URL}/RestoreTarget' }}", True),
        (f"@{{ id = 'x'; displayName = 'restoretarget'; webUrl = '{_SITE_URL}/RestoreTarget' }}", True),
        (f"@{{ id = 'x'; displayName = 'RestoreTarget'; webUrl = '{_SITE_URL}/Lists/RestoreTarget2' }}", True),
        ("@{ id = 'x'; displayName = 'RestoreTarget' }", True),
        ("@{ id = 'x' }", True),
        (f"@{{ id = 'x'; displayName = 'RestoreTarget'; webUrl = '{_SITE_URL}/RestoreTarget' }}", False),
        (f"@{{ id = 'x'; displayName = 'RestoreTarget'; webUrl = '{_SITE_URL}/restoretarget/' }}", False),
    ],
)
def test_the_list_name_check(reply, refused):
    result = name_check("Assert-RestoreTargetList", reply)
    assert result.returncode == 0, result.stdout + result.stderr
    request = f"request: GET sites/{tenant.SHAREPOINT_SITE_ID}/lists/{tenant.RESTORE_TARGET_LIST_ID}?$select=id,displayName,webUrl"
    assert request in result.stdout
    if refused:
        assert "refused: The list $RestoreTargetListId names" in result.stdout
        assert "no write grant was made" in result.stdout
        assert "checked" not in result.stdout.splitlines()
    else:
        assert result.stdout.splitlines()[-1] == "checked"


def _folder(name: str, *, folder: bool = True, drive: str | None = tenant.ONEDRIVE_DRIVE_ID, path: str = "/drive/root:") -> str:
    parts = [f"name = '{name}'"]
    if folder:
        parts.append("folder = @{ childCount = 0 }")
    if drive is not None:
        parts.append(f"parentReference = @{{ driveId = '{drive}'; path = '{path}' }}")
    return "@{ " + "; ".join(parts) + " }"


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell 7 not installed")
@pytest.mark.parametrize(
    ("reply", "refused"),
    [
        # failure paths first: the canary folder, a nested RestoreTarget, another drive, a file
        (_folder("RestoreTest"), True),
        (_folder("RestoreTarget", path="/drive/root:/RestoreTest"), True),
        (_folder("RestoreTarget", drive="b!other"), True),
        (_folder("RestoreTarget", folder=False), True),
        (_folder("restoretarget"), True),
        (_folder("RestoreTarget", drive=None), True),
        (_folder("RestoreTarget"), False),
        (_folder("RestoreTarget", path=f"/drives/{tenant.ONEDRIVE_DRIVE_ID}/root:"), False),
    ],
)
def test_the_folder_name_check(reply, refused):
    result = name_check("Assert-RestoreTargetFolder", reply)
    assert result.returncode == 0, result.stdout + result.stderr
    request = (
        f"request: GET drives/{tenant.ONEDRIVE_DRIVE_ID}/items/{tenant.ONEDRIVE_TARGET_FOLDER_ID}"
        "?$select=id,name,folder,parentReference"
    )
    assert request in result.stdout
    if refused:
        assert "refused: The item $OneDriveTargetFolderId names" in result.stdout
        assert "no write grant was made" in result.stdout
    else:
        assert result.stdout.splitlines()[-1] == "checked"


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


# ---- check-worker-grants.ps1 (W3.4, build notes point 13): the read-only grant check ------------

GRANTS = LAB_DIR / "entra" / "check-worker-grants.ps1"
APP = tenant.WORKER_CLIENT_ID
OTHER_APP = "99999999-8888-7777-6666-555555555555"
GRAPH = "https://graph.microsoft.com/v1.0/"
needs_pwsh = pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell 7 not installed")


def grants_text() -> str:
    return GRANTS.read_text(encoding="utf-8")


def grants_code() -> str:
    """check-worker-grants.ps1 without its comment-based help and comment lines."""
    text = re.sub(r"<#.*?#>", "", grants_text(), flags=re.DOTALL)
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def grants_constant(name: str) -> str:
    match = re.search(rf"^\${name}\s*=\s*'([^']*)'", grants_text(), re.MULTILINE)
    assert match, f"${name} = '...' not found in {GRANTS.name}"
    return match.group(1)


@pytest.mark.parametrize(
    "name, value",
    [
        ("TenantId", tenant.TENANT_ID),
        ("AdminUpn", tenant.ADMIN_UPN),
        ("WorkerAppId", tenant.WORKER_CLIENT_ID),
        ("SiteId", tenant.SHAREPOINT_SITE_ID),
        ("CanaryListId", tenant.SHAREPOINT_LIST_ID),
        ("CanaryLibraryDriveId", tenant.SHAREPOINT_DRIVE_ID),
        ("OneDriveDriveId", tenant.ONEDRIVE_DRIVE_ID),
        ("CanaryFolderId", tenant.ONEDRIVE_FOLDER_ID),
        ("OneDriveTargetFolderId", tenant.ONEDRIVE_TARGET_FOLDER_ID),
        ("RestoreTargetListId", tenant.RESTORE_TARGET_LIST_ID),
        ("OneDriveHost", tenant.ONEDRIVE_HOST),
        ("AliceSitePath", tenant.ALICE_ONEDRIVE_SITE_PATH),
    ],
)
def test_grant_check_constants_match_tenant_py_and_the_setup_script(name, value):
    assert grants_constant(name) == value
    if re.search(rf"^\${name}\s*=", script_text(), re.MULTILINE):
        assert constant(name) == value  # the two scripts' copies agree


def test_grant_check_matches_the_app_by_id_never_by_name():
    code = grants_code()
    assert "$_.Id -eq $AppId" in code and "$_.Id -ne $AppId" in code
    assert "RestoreProof Worker'" not in code and '"RestoreProof Worker"' not in code
    assert not re.search(r"\.Name\s+-c?(eq|ne|like|match)", code)


def test_grant_check_only_reads():
    code = grants_code()
    # No write verb anywhere in the code, and no Microsoft Graph cmdlet that changes anything.
    assert not re.search(r"\b(POST|PATCH|PUT|DELETE)\b", code), "a write verb in check-worker-grants.ps1"
    assert not re.search(r"\b(New|Set|Update|Remove|Grant|Revoke|Invoke)-Mg(?!GraphRequest\b)\w*", code)
    # The one scope that can read grants, and nothing else.
    scopes = re.findall(r"Connect-MgGraph\b[^\n]*-Scopes\s+([^\n]*)", code)
    assert scopes == ["'Sites.FullControl.All'"], scopes
    assert "Disconnect-MgGraph" in code


@needs_pwsh
def test_grant_check_every_graph_request_is_a_get():
    command = f"""
        $ast = [System.Management.Automation.Language.Parser]::ParseFile('{GRANTS}', [ref]$null, [ref]$null)
        $ast.FindAll({{ param($n) $n -is [System.Management.Automation.Language.CommandAst] }}, $true) |
            Where-Object {{ $_.GetCommandName() -like 'Invoke-*' }} |
            ForEach-Object {{ "$($_.GetCommandName()) | $($_.Extent.Text)" }}
    """
    result = run_pwsh(command)
    assert result.returncode == 0, result.stdout + result.stderr
    calls = [line.split(" | ", 1) for line in result.stdout.splitlines() if line.strip()]
    names = {name for name, _ in calls}
    assert names == {"Invoke-MgGraphRequest", "Invoke-GraphGet", "Invoke-GrantCheck"}, names
    graph = [text for name, text in calls if name == "Invoke-MgGraphRequest"]
    assert graph == ["Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType HashTable"]


@needs_pwsh
def test_grant_check_parses():
    command = (
        "$e = $null; $null = [System.Management.Automation.Language.Parser]::ParseFile("
        f"'{GRANTS}', [ref]$null, [ref]$e); $e | ForEach-Object {{ $_.ToString() }}; exit $e.Count"
    )
    result = run_pwsh(command)
    assert result.returncode == 0, result.stdout + result.stderr


def test_the_setup_script_runs_the_grant_check_after_the_grants_and_stops_on_a_problem():
    code = code_text()
    call = "& (Join-Path $PSScriptRoot 'check-worker-grants.ps1') -UseCurrentSession -AppId $appId"
    assert code.count(call) == 1
    at = code.index(call)
    last_grant = code.rindex('Invoke-Graph PATCH "$folder/permissions/')
    disconnect = code.index("finally {\n    Disconnect-MgGraph")
    assert last_grant < at < disconnect, "the check runs after the grants, in the Graph session"
    after = code[at : at + 400]
    assert "if ($LASTEXITCODE -ne 0) {" in after and "throw" in after
    assert at < code.index("Connect-ExchangeOnline")


def grants_function(*names: str) -> str:
    """PowerShell that defines check-worker-grants.ps1's functions `names` and its constants."""
    constants = "\n".join(
        f"${name} = '{grants_constant(name)}'"
        for name in (
            "SiteId", "CanaryListId", "CanaryLibraryDriveId", "OneDriveDriveId", "CanaryFolderId",
            "OneDriveTargetFolderId", "RestoreTargetListId", "WorkerAppId", "OneDriveHost", "AliceSitePath",
            "CanaryLibraryFolderPath", "GuidPattern",
        )
    )
    finds = "\n".join(
        f"""$fn = $ast.Find({{ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $n.Name -eq '{name}' }}, $true); . ([scriptblock]::Create($fn.Extent.Text))"""
        for name in names
    )
    return f"""
        Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'
        {constants}
        $GraphBase = '{GRAPH}'; $MinCanaryFiles = 20; $MaxPages = 100
        $ast = [System.Management.Automation.Language.Parser]::ParseFile('{GRANTS}', [ref]$null, [ref]$null)
        {finds}
    """


RULE_FUNCTIONS = ("Get-Field", "Get-GrantedApps", "Test-NamesApp", "Get-SharePointFormApps", "Get-RoleText", "Test-Inherited", "Test-PermissionRule")


def perm(roles=("read",), *, app=APP, facet="grantedToV2", inherited=False, name="RestoreProof Worker",
         user=False, as_object=False, site_user=False) -> str:
    """One permission as Invoke-MgGraphRequest -OutputType HashTable gives it (or as an object).
    site_user: the app as SharePoint can show an app principal, a siteUser with its claim login name
    and no application facet."""
    if user:
        identity = "@{ user = @{ displayName = 'Owner' } }"
    elif site_user:
        identity = (f"@{{ siteUser = @{{ id = '7'; displayName = ''; "
                    f"loginName = 'i:0i.t|ms.sp.ext|{app}@{tenant.TENANT_ID}' }} }}")
    else:
        identity = f"@{{ application = @{{ id = '{app}'; displayName = '{name}' }} }}"
    if facet in ("grantedToIdentitiesV2", "grantedToIdentities"):
        identity = f"@({identity})"
    parts = ["id = 'perm'"]
    if roles is not None:
        parts.append("roles = @(" + ", ".join(f"'{r}'" for r in roles) + ")")
    parts.append(f"{facet} = {identity}")
    if inherited:
        parts.append("inheritedFrom = @{ id = 'parent' }")
    body = "@{ " + "; ".join(parts) + " }"
    return f"[pscustomobject]{body}" if as_object else body


def rule_result(rule: str, permissions: list[str]) -> tuple[list[str], list[str], str]:
    command = grants_function(*RULE_FUNCTIONS) + f"""
        $r = Test-PermissionRule -Permissions @({", ".join(permissions)}) -AppId '{APP}' -Rule '{rule}'
        $r.Problems | ForEach-Object {{ "problem: $_" }}
        $r.Notes | ForEach-Object {{ "note: $_" }}
        "counts: $($r.Total) $($r.Worker) $($r.Others)"
    """
    result = run_pwsh(command)
    assert result.returncode == 0, result.stdout + result.stderr
    lines = result.stdout.splitlines()
    problems = [line for line in lines if line.startswith("problem: ")]
    notes = [line for line in lines if line.startswith("note: ")]
    return problems, notes, lines[-1]


GRANT_ROWS = [
    # failure rows first
    ("canary-list-worker-write", "inherited-read-only", [perm(("write",))], "a grant of its own here, roles 'write'"),
    ("canary-list-worker-inherited-write", "inherited-read-only", [perm(("write",), inherited=True)], "inherits roles 'write'"),
    ("canary-list-worker-own-read", "inherited-read-only", [perm(("read",))], "a grant of its own here, roles 'read'"),
    ("canary-file-own-read", "inherited-read-only", [perm(("read",), facet="grantedToIdentitiesV2")], "a grant of its own"),
    ("canary-file-inherited-roles-missing", "inherited-read-only", [perm(None, inherited=True)], "inherits roles ''"),
    ("alice-canary-folder-inherited-read", "none", [perm(("read",), inherited=True)], "an inherited grant here, roles 'read'"),
    ("alice-canary-folder-write", "none", [perm(("write",), facet="grantedTo")], "a grant here, roles 'write'"),
    ("alice-canary-folder-identities", "none", [perm(("read",), facet="grantedToIdentities")], "a grant here"),
    ("onedrive-root-any-entry", "none", [perm(("owner",))], "a grant here, roles 'owner'"),
    ("app-matched-by-id-with-empty-name", "none", [perm(("write",), name="")], "a grant here, roles 'write'"),
    ("app-id-in-upper-case", "none", [perm(("read",), app=APP.upper())], "a grant here"),
    ("app-as-an-object", "none", [perm(("read",), as_object=True)], "a grant here"),
    ("site-role-write", "site-read", [perm(("write",), facet="grantedToIdentitiesV2")], "roles 'write'; only 'read'"),
    ("site-roles-read-and-write", "site-read", [perm(("read", "write"))], "roles 'read,write'; only 'read'"),
    ("site-grant-missing", "site-read", [perm(("read",), app=OTHER_APP)], "has no grant here"),
    ("site-two-grants", "site-read", [perm(("read",)), perm(("read",), facet="grantedToIdentitiesV2")], "has 2 grants here"),
    ("target-write-missing", "target-write", [perm(("read",))], "roles 'read'; it needs exactly 'write'"),
    ("target-no-grant", "target-write", [perm(("owner",), user=True)], "no grant of its own here"),
    ("target-only-inherited-write", "target-write", [perm(("write",), inherited=True)], "no grant of its own here"),
    ("target-write-and-owner", "target-write", [perm(("owner", "write"))], "roles 'owner,write'"),
    ("target-two-grants", "target-write", [perm(("write",)), perm(("write",), facet="grantedTo")], "2 grants of its own"),
    # an app grant in a shape without the application facet is still the Worker app's (fail closed)
    ("canary-file-site-user-write", "inherited-read-only", [perm(("write",), site_user=True)], "a grant of its own here, roles 'write'"),
    ("alice-canary-folder-site-user", "none", [perm(("write",), site_user=True, inherited=True)], "an inherited grant here, roles 'write'"),
    ("alice-canary-folder-id-anywhere", "none",
     [f"@{{ id = 'x'; roles = @('write'); grantedToV2 = @{{ user = @{{ id = '{APP.upper()}' }} }} }}"], "a grant here, roles 'write'"),
    # passing rows
    ("site-one-read", "site-read", [perm(("read",)), perm(("write",), app=OTHER_APP, name="Other")], None),
    ("canary-list-inherited-read", "inherited-read-only", [perm(("read",), inherited=True), perm(("owner",), user=True)], None),
    ("canary-file-nothing", "inherited-read-only", [], None),
    ("alice-canary-folder-other-app", "none", [perm(("write",), app=OTHER_APP, name="Other")], None),
    ("alice-canary-folder-other-app-site-user", "none", [perm(("write",), app=OTHER_APP, site_user=True)], None),
    ("target-write", "target-write", [perm(("write",)), perm(("read",), inherited=True)], None),
    ("target-write-empty-name", "target-write", [perm(("write",), name="")], None),
]


@needs_pwsh
@pytest.mark.parametrize(("rule", "permissions", "problem"), [r[1:] for r in GRANT_ROWS], ids=[r[0] for r in GRANT_ROWS])
def test_the_grant_rules(rule, permissions, problem):
    problems, notes, counts = rule_result(rule, permissions)
    if problem is None:
        assert problems == []
    else:
        assert any(problem in p for p in problems), problems
    others = sum(OTHER_APP in p for p in permissions)
    worker = sum(APP.lower() in p.lower() for p in permissions)
    assert len(notes) == others  # another application's grant is a note, never a problem
    assert all(OTHER_APP in n and "another application's grant" in n for n in notes)
    assert counts == f"counts: {len(permissions)} {worker} {others}"


@needs_pwsh
def test_an_unknown_rule_is_refused():
    command = grants_function(*RULE_FUNCTIONS) + """
        try { Test-PermissionRule -Permissions @() -AppId 'x' -Rule 'write-anywhere'; 'accepted' } catch { "refused: $_" }
    """
    result = run_pwsh(command)
    assert "refused: unknown rule 'write-anywhere'" in result.stdout


# ---- the whole grant check, with Graph stubbed ------------------------------------------------------

MANIFEST = LAB_DIR / "seed-manifest.json"


def manifest_files() -> list[dict]:
    entries = json.loads(MANIFEST.read_text(encoding="utf-8"))["entries"]
    return [e for e in entries if e["kind"] in ("sharepoint_file", "onedrive_file")]


SITE_PERMS = f"sites/{tenant.SHAREPOINT_SITE_ID}/permissions"
CANARY_LIST = f"sites/{tenant.SHAREPOINT_SITE_ID}/lists/{tenant.SHAREPOINT_LIST_ID}/permissions"
TARGET_LIST = f"sites/{tenant.SHAREPOINT_SITE_ID}/lists/{tenant.RESTORE_TARGET_LIST_ID}/permissions"
ONEDRIVE_ROOT = f"drives/{tenant.ONEDRIVE_DRIVE_ID}/root/permissions"
CANARY_FOLDER = f"drives/{tenant.ONEDRIVE_DRIVE_ID}/items/{tenant.ONEDRIVE_FOLDER_ID}/permissions"
TARGET_FOLDER = f"drives/{tenant.ONEDRIVE_DRIVE_ID}/items/{tenant.ONEDRIVE_TARGET_FOLDER_ID}/permissions"
LIBRARY_ROOT = f"drives/{tenant.SHAREPOINT_DRIVE_ID}/root/permissions"
# alice's OneDrive site and its Documents list, resolved read-only before any permission is read
ALICE_SITE_ID = f"{tenant.ONEDRIVE_HOST},6d600fc0-65f8-4811-ad18-096ec5b7e834,98cfff1a-b404-4438-ae6e-6927a6ccc325"
ALICE_LIST_ID = "1a9f64df-d9fd-4302-af7a-457d2beff537"
ALICE_SITE_GET = f"sites/{tenant.ONEDRIVE_HOST}:{tenant.ALICE_ONEDRIVE_SITE_PATH}?$select=id"
ALICE_SITE_DRIVE = f"sites/{ALICE_SITE_ID}/drive?$select=id"
ALICE_LIST_GET = f"drives/{tenant.ONEDRIVE_DRIVE_ID}/list?$select=id"
ALICE_SITE_PERMS = f"sites/{ALICE_SITE_ID}/permissions"
ALICE_LIST_PERMS = f"sites/{ALICE_SITE_ID}/lists/{ALICE_LIST_ID}/permissions"
RESOLVE = [ALICE_SITE_GET, ALICE_SITE_DRIVE, ALICE_LIST_GET]


def file_perms(entry: dict) -> str:
    return f"drives/{entry['location']['drive_id']}/items/{entry['drive_item_id']}/permissions"


def page(*permissions: str, next_link: str | None = None) -> str:
    parts = ["value = @(" + ", ".join(permissions) + ")"]
    if next_link:
        parts.append(f"'@odata.nextLink' = '{next_link}'")
    return "@{ " + "; ".join(parts) + " }"


def good_replies() -> dict[str, str]:
    """The grants as they should be: the site's list without roles (each of the Worker app's grants
    is read by its ID), an inherited read on the canary list, the two write grants (the list's with
    an empty application name, as seen live), and another application's site grant."""
    worker_without_roles = (
        "@{ id = 'p1'; grantedToIdentitiesV2 = @(@{ application = @{ id = '"
        + APP
        + "'; displayName = 'RestoreProof Worker' } }) }"
    )
    return {
        ALICE_SITE_GET: f"@{{ id = '{ALICE_SITE_ID}' }}",
        ALICE_SITE_DRIVE: f"@{{ id = '{tenant.ONEDRIVE_DRIVE_ID}' }}",
        ALICE_LIST_GET: f"@{{ id = '{ALICE_LIST_ID}' }}",
        SITE_PERMS: page(worker_without_roles, perm(("read",), app=OTHER_APP, name="Other app")),
        f"{SITE_PERMS}/p1": perm(("read",), facet="grantedToIdentitiesV2"),
        CANARY_LIST: page(perm(("read",), inherited=True), perm(("owner",), user=True)),
        TARGET_LIST: page(perm(("write",), name="")),
        TARGET_FOLDER: page(perm(("write",))),
    }


def grant_check(*, replies=None, fail=None, manifest: Path | None = None,
                account: str = tenant.ADMIN_UPN) -> tuple[int, list[str], list[str]]:
    """Runs check-worker-grants.ps1 -UseCurrentSession with Get-MgContext and Invoke-MgGraphRequest
    stubbed: replies maps a path (relative to Graph v1.0) to its answer, any other path answers an
    empty list, and fail maps a path to the HTTP status it fails with (None: no answer).
    Returns (exit code, output lines, requests as 'METHOD URI')."""
    replies = good_replies() if replies is None else replies
    table = "\n".join(f"$Replies['{GRAPH}{path}'] = {reply}" for path, reply in replies.items())
    failures = "\n".join(
        f"$Failures['{GRAPH}{path}'] = {'$null' if status is None else status}" for path, status in (fail or {}).items()
    )
    command = f"""
        $ErrorActionPreference = 'Stop'
        $Replies = @{{}}; $Failures = @{{}}
        {table}
        {failures}
        function Get-MgContext {{ [pscustomobject]@{{ Account = '{account}' }} }}
        function Connect-MgGraph {{ 'request: CONNECT' | Out-Host }}
        function Invoke-MgGraphRequest {{
            param([string]$Method, [string]$Uri, [string]$OutputType)
            "request: $Method $Uri" | Out-Host
            if ($Failures.ContainsKey($Uri)) {{
                $exception = [Exception]::new('Response status code does not indicate success')
                if ($null -ne $Failures[$Uri]) {{
                    $exception | Add-Member -NotePropertyName Response -NotePropertyValue ([pscustomobject]@{{ StatusCode = $Failures[$Uri] }})
                }}
                throw [System.Management.Automation.ErrorRecord]::new($exception, 'x', 'NotSpecified', $null)
            }}
            if ($Replies.ContainsKey($Uri)) {{ return $Replies[$Uri] }}
            return @{{ value = @() }}
        }}
        & '{GRANTS}' -UseCurrentSession -ManifestPath '{manifest or MANIFEST}'
        exit $LASTEXITCODE
    """
    result = run_pwsh(command)
    lines = result.stdout.splitlines()
    requests = [line[len("request: "):] for line in lines if line.startswith("request: ")]
    output = [line for line in lines if not line.startswith("request: ")]
    return result.returncode, output, requests


def location_line(lines: list[str], label: str) -> str:
    found = [line for line in lines if line.startswith(label + " ")]
    assert len(found) == 1, (label, lines)
    return found[0]


@needs_pwsh
def test_a_worker_write_grant_on_the_canary_list_fails_the_check():
    code, lines, _ = grant_check(replies=good_replies() | {CANARY_LIST: page(perm(("write",), name=""))})
    assert code == 1
    line = location_line(lines, "canary library RestoreTest (list)")
    assert " PROBLEM " in line and "1 Worker app" in line
    assert lines[-1] == "canary grants: 1 problem(s)"


@needs_pwsh
def test_a_non_inherited_read_on_a_canary_file_fails_the_check():
    library_file = next(e for e in manifest_files() if e["kind"] == "sharepoint_file")
    code, lines, _ = grant_check(replies=good_replies() | {file_perms(library_file): page(perm(("read",)))})
    assert code == 1
    assert " PROBLEM " in location_line(lines, f"canary file {library_file['name']} (library)")
    assert lines[-1] == "canary grants: 1 problem(s)"


@needs_pwsh
def test_any_worker_entry_on_a_onedrive_canary_file_or_folder_fails_the_check():
    onedrive_file = next(e for e in manifest_files() if e["kind"] == "onedrive_file")
    replies = good_replies() | {
        file_perms(onedrive_file): page(perm(("read",), inherited=True)),
        CANARY_FOLDER: page(perm(("read",), inherited=True, name="")),
    }
    code, lines, _ = grant_check(replies=replies)
    assert code == 1
    assert " PROBLEM " in location_line(lines, f"canary file {onedrive_file['name']} (OneDrive)")
    assert " PROBLEM " in location_line(lines, "alice's RestoreTest canary folder")
    assert lines[-1] == "canary grants: 2 problem(s)"


@needs_pwsh
@pytest.mark.parametrize(
    ("site_reply", "problem"),
    [
        ({SITE_PERMS: page()}, "has no grant here"),
        ({f"{SITE_PERMS}/p1": perm(("write",), facet="grantedToIdentitiesV2")}, "roles 'write'"),
    ],
    ids=["site-grant-missing", "site-role-write-read-by-its-id"],
)
def test_the_site_grant_must_be_exactly_one_read(site_reply, problem):
    code, lines, _ = grant_check(replies=good_replies() | site_reply)
    assert code == 1
    assert " PROBLEM " in location_line(lines, "RestoreTest site")
    assert any(problem in line for line in lines), lines


@needs_pwsh
@pytest.mark.parametrize("where", [TARGET_LIST, TARGET_FOLDER], ids=["list", "folder"])
def test_a_missing_restore_target_write_grant_fails_the_check(where):
    code, lines, _ = grant_check(replies=good_replies() | {where: page(perm(("read",)))})
    assert code == 1
    label = "RestoreTarget list" if where == TARGET_LIST else "alice's RestoreTarget folder"
    assert " PROBLEM " in location_line(lines, label)
    assert lines[-1] == "canary grants: 1 problem(s)"


@needs_pwsh
@pytest.mark.parametrize("status", [403, 404, None])
def test_a_failed_get_is_a_problem_never_a_pass(status):
    code, lines, requests = grant_check(fail={CANARY_FOLDER: status})
    assert code == 1
    line = location_line(lines, "alice's RestoreTest canary folder")
    assert " PROBLEM " in line and "can't be read" in line
    assert (f"HTTP {status}" in line) if status else "HTTP" not in line
    assert lines[-1] == "canary grants: 1 problem(s)"
    assert len(requests) == 33  # every other location was still read


@needs_pwsh
def test_a_next_page_is_read_and_counts():
    second = f"{GRAPH}{CANARY_FOLDER}?$skiptoken=2"
    replies = good_replies() | {CANARY_FOLDER: page(perm(("owner",), user=True), next_link=second)}
    replies[f"{CANARY_FOLDER}?$skiptoken=2"] = page(perm(("write",), name=""))
    code, lines, requests = grant_check(replies=replies)
    assert code == 1
    assert f"GET {second}" in requests
    line = location_line(lines, "alice's RestoreTest canary folder")
    assert " PROBLEM " in line and "2 permission(s), 1 Worker app" in line


@needs_pwsh
def test_a_next_page_outside_graph_is_not_followed():
    replies = good_replies() | {CANARY_FOLDER: page(next_link="https://example.com/permissions?page=2")}
    code, lines, requests = grant_check(replies=replies)
    assert code == 1
    assert "outside Microsoft Graph" in location_line(lines, "alice's RestoreTest canary folder")
    assert not any("example.com" in r for r in requests)


@needs_pwsh
@pytest.mark.parametrize(
    "case",
    ["missing", "not json", "short", "wrong drive", "bad item id", "library file in a subfolder",
     "library file in another list", "onedrive file in another folder"],
)
def test_a_manifest_that_cant_be_used_stops_the_check_before_any_request(tmp_path, case):
    path = tmp_path / "seed-manifest.json"
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    files = [e for e in data["entries"] if e["kind"] != "mail"]
    if case == "not json":
        path.write_text("{ not json", encoding="utf-8")
    elif case != "missing":
        if case == "short":
            data["entries"].remove(files[-1])
        elif case == "wrong drive":
            files[0]["location"]["drive_id"] = tenant.RESTORE_TARGET_DRIVE_ID
        elif case == "bad item id":
            files[3]["drive_item_id"] = "../../sites"
        elif case == "library file in a subfolder":
            files[1]["location"]["folder_path"] = "/Sub"
        elif case == "library file in another list":
            files[2]["location"]["list_id"] = tenant.RESTORE_TARGET_LIST_ID
        elif case == "onedrive file in another folder":
            next(f for f in files if f["kind"] == "onedrive_file")["location"]["folder_id"] = tenant.ONEDRIVE_TARGET_FOLDER_ID
        path.write_text(json.dumps(data), encoding="utf-8")
    code, lines, requests = grant_check(manifest=path)
    assert code == 1
    assert requests == []
    assert " PROBLEM " in location_line(lines, "canary manifest")
    assert lines[-1] == "canary grants: 1 problem(s)"


@needs_pwsh
def test_the_grant_check_refuses_another_account_before_any_request():
    code, _, requests = grant_check(account=tenant.ALICE_UPN)
    assert code != 0
    assert requests == []


@needs_pwsh
def test_the_grants_as_set_up_pass():
    code, lines, requests = grant_check()
    assert code == 0, lines
    assert lines[0] == f"RestoreProof Worker grant check (W3.4): read-only, Worker app {APP}"
    assert lines[-1] == "canary grants: ok"
    files = manifest_files()
    assert len(files) == 20
    assert lines[1].startswith("scope: ") and "check-worker-app" in lines[1]
    labels = ["RestoreTest site", "canary library RestoreTest (list)", "canary library root folder",
              "alice's OneDrive site", "alice's OneDrive Documents list", "alice's OneDrive root",
              "alice's RestoreTest canary folder"]
    labels += [f"canary file {e['name']} ({'library' if e['kind'] == 'sharepoint_file' else 'OneDrive'})" for e in files]
    labels += ["RestoreTarget list", "alice's RestoreTarget folder"]
    for label in labels:
        assert " ok " in location_line(lines, label)
    assert "1 permission(s), 1 Worker app, 0 other app(s)" in location_line(lines, "RestoreTarget list")
    # The other application's site grant is a note; the Worker app's own name never matters.
    notes = [line for line in lines if line.strip().startswith("note: ")]
    assert notes == [f"    note: another application's grant: {OTHER_APP} 'Other app', roles 'read'"]
    # GETs only, all to Graph v1.0: one per location, and the site's grant read by its ID.
    expected = RESOLVE + [SITE_PERMS, f"{SITE_PERMS}/p1", CANARY_LIST, LIBRARY_ROOT, ALICE_SITE_PERMS,
                          ALICE_LIST_PERMS, ONEDRIVE_ROOT, CANARY_FOLDER]
    expected += [file_perms(e) for e in files] + [TARGET_LIST, TARGET_FOLDER]
    assert requests == [f"GET {GRAPH}{path}" for path in expected]


@needs_pwsh
@pytest.mark.parametrize(
    ("where", "label"),
    [(ALICE_SITE_PERMS, "alice's OneDrive site"), (ALICE_LIST_PERMS, "alice's OneDrive Documents list")],
    ids=["site", "list"],
)
def test_a_grant_on_alices_onedrive_site_or_list_fails_the_check(where, label):
    # A Sites.Selected or Lists.SelectedOperations.Selected grant there reaches her canary folder.
    code, lines, _ = grant_check(replies=good_replies() | {where: page(perm(("write",), name=""))})
    assert code == 1
    assert " PROBLEM " in location_line(lines, label)
    assert lines[-1] == "canary grants: 1 problem(s)"


@needs_pwsh
@pytest.mark.parametrize(
    "broken",
    [
        {ALICE_SITE_GET: "@{ id = 'restoreprooflab.sharepoint.com,x,y' }"},
        {ALICE_SITE_GET: "@{ }"},
        {ALICE_SITE_DRIVE: "@{ id = 'b!someoneelse' }"},
        {ALICE_LIST_GET: "@{ id = '../x' }"},
    ],
    ids=["site-on-another-host", "site-without-id", "site-drive-not-alices", "list-id-not-a-guid"],
)
def test_alices_site_and_list_that_cant_be_resolved_are_a_problem(broken):
    code, lines, requests = grant_check(replies=good_replies() | broken)
    assert code == 1
    line = location_line(lines, "alice's OneDrive site and list")
    assert " PROBLEM " in line and "can't be resolved" in line
    assert lines[-1] == "canary grants: 1 problem(s)"
    assert not any("/permissions" in r and ALICE_SITE_ID in r for r in requests)
    assert f"GET {GRAPH}{CANARY_FOLDER}" in requests  # every other location is still read


@needs_pwsh
def test_a_failed_get_resolving_alices_site_is_a_problem():
    code, lines, _ = grant_check(fail={ALICE_SITE_GET: 403})
    assert code == 1
    assert "HTTP 403" in location_line(lines, "alice's OneDrive site and list")
    assert lines[-1] == "canary grants: 1 problem(s)"


@needs_pwsh
def test_a_worker_grant_on_the_canary_library_root_folder_fails_the_check():
    code, lines, _ = grant_check(replies=good_replies() | {LIBRARY_ROOT: page(perm(("write",)))})
    assert code == 1
    assert " PROBLEM " in location_line(lines, "canary library root folder")
    assert lines[-1] == "canary grants: 1 problem(s)"


@needs_pwsh
@pytest.mark.parametrize(
    "reply", ["@{ id = 'x' }", "@{ value = 'write' }", "$null"], ids=["no-value", "value-not-a-list", "null"]
)
def test_a_reply_without_a_permission_list_is_a_problem_never_a_pass(reply):
    library_file = next(e for e in manifest_files() if e["kind"] == "sharepoint_file")
    code, lines, _ = grant_check(replies=good_replies() | {file_perms(library_file): reply})
    assert code == 1
    line = location_line(lines, f"canary file {library_file['name']} (library)")
    assert " PROBLEM " in line and "can't be read" in line
    assert lines[-1] == "canary grants: 1 problem(s)"


@needs_pwsh
def test_a_worker_grant_in_sharepoints_app_form_on_a_canary_file_fails_the_check():
    onedrive_file = next(e for e in manifest_files() if e["kind"] == "onedrive_file")
    replies = good_replies() | {file_perms(onedrive_file): page(perm(("write",), site_user=True))}
    code, lines, _ = grant_check(replies=replies)
    assert code == 1
    assert " PROBLEM " in location_line(lines, f"canary file {onedrive_file['name']} (OneDrive)")

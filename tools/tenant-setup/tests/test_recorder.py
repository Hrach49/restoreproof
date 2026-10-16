"""tests/record/Record-TenantAnswers.ps1 (W7.0, decision point 10): it only reads.

The recorder runs as the tenant's global admin against the live lab tenant, so its text is held:
it parses, every Graph request is a GET, and every other command it runs is a reader."""

import base64

import pytest

from pwsh import RECORDER, ps_string, run_json

# Commands the recorder may run besides PowerShell's own: sign-in, sign-out and readers.
ALLOWED = {
    "Connect-MgGraph", "Disconnect-MgGraph", "Invoke-MgGraphRequest",
    "Import-Module", "Connect-ExchangeOnline", "Disconnect-ExchangeOnline",
    "Get-Recipient", "Get-OrganizationConfig", "Get-ServicePrincipal", "Get-ManagementScope",
    "Get-ManagementRoleAssignment", "Test-ServicePrincipalAuthorization",
}
POWERSHELL = {
    "ConvertTo-Json", "ConvertFrom-Json", "ForEach-Object", "Where-Object", "Get-ChildItem", "Get-Date",
    "New-Item", "Out-Null", "Set-StrictMode", "Split-Path", "Test-Path", "Write-Host", "Join-Path",
}


@pytest.fixture(scope="module")
def ast() -> dict:
    return run_json(f"""
        $errors = $null
        $tree = [System.Management.Automation.Language.Parser]::ParseFile({ps_string(RECORDER)}, [ref]$null, [ref]$errors)
        $functions = @($tree.FindAll({{ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }}, $true) | ForEach-Object Name)
        $commands = @($tree.FindAll({{ param($n) $n -is [System.Management.Automation.Language.CommandAst] }}, $true))
        @{{
            errors = @($errors | ForEach-Object {{ "$_" }})
            functions = $functions
            names = @($commands | ForEach-Object {{ $_.GetCommandName() }} | Where-Object {{ $_ }} | Sort-Object -Unique)
            graph = @($commands | Where-Object {{ $_.GetCommandName() -eq 'Invoke-MgGraphRequest' }} | ForEach-Object {{ $_.Extent.Text }})
        }}
    """)


def test_the_recorder_parses(ast):
    assert ast["errors"] == []


def test_every_graph_request_is_a_get(ast):
    assert ast["graph"], "the recorder sends no Graph request"
    for call in ast["graph"]:
        assert "-Method GET " in call, call


def test_every_command_is_a_reader(ast):
    unknown = set(ast["names"]) - ALLOWED - POWERSHELL - set(ast["functions"])
    assert not unknown, f"commands the recorder must not run: {sorted(unknown)}"


def test_nothing_is_written_but_the_answers():
    text = RECORDER.read_text(encoding="utf-8")
    assert text.count("WriteAllText(") == 1
    assert "Start-Transcript" not in text
    for verb in ("New-Mailbox", "New-Management", "Set-Management", "Remove-", "Enable-OrganizationCustomization"):
        assert verb not in text, verb


def scrubbed(text: str, pairs: list[tuple[str, str]]) -> str:
    """The recorder's own Get-Scrubbed (taken from its text) over `text` with `pairs`."""
    return run_json(f"""
        $tree = [System.Management.Automation.Language.Parser]::ParseFile({ps_string(RECORDER)}, [ref]$null, [ref]$null)
        $tree.FindAll({{ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -like '*Scrub*' }}, $true) |
            ForEach-Object {{ . ([scriptblock]::Create($_.Extent.Text)) }}
        $script:Scrub = @()
        {"; ".join(f"$script:Scrub += , @({ps_string(a)}, {ps_string(b)})" for a, b in pairs)}
        Get-Scrubbed {ps_string(text)}
    """)


PAIRS = [("Jane.Doe@contoso.onmicrosoft.com", "admin@contoso.onmicrosoft.com"), ("Jane.Doe", "admin"), ("Jane", "Admin"), ("Doe", "Admin")]


def b64url(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode("utf-8")).decode("ascii").rstrip("=")


def test_the_admin_is_scrubbed_in_plain_text():
    assert scrubbed('{"email": "JANE.DOE@contoso.onmicrosoft.com", "displayName": "Jane Doe"}', PAIRS) == \
        '{"email": "admin@contoso.onmicrosoft.com", "displayName": "Admin Admin"}'


def test_the_admin_is_scrubbed_inside_a_base64url_id():
    """SharePoint's permission IDs are the claim login name in base64url without padding."""
    claim = "i:0#.f|membership|jane.doe@contoso.onmicrosoft.com"
    other = "i:0#.f|membership|alice@contoso.onmicrosoft.com"
    text = f'{{"id": "{b64url(claim)}", "shareId": "{b64url(claim)}", "other": "{b64url(other)}"}}'
    assert scrubbed(text, PAIRS) == \
        f'{{"id": "{b64url("i:0#.f|membership|admin@contoso.onmicrosoft.com")}", "shareId": "{b64url("i:0#.f|membership|admin@contoso.onmicrosoft.com")}", "other": "{b64url(other)}"}}'


def test_a_base64_id_without_the_admin_is_left_as_it_was():
    # A drive ID and a GUID-shaped ID decode to bytes that aren't text: never rewritten.
    text = '"b!wA9gbfhlEUitGAluxbfoNBr_z5gEtDhErm5pJ6bMwyXfZJ8a_dkCQ696RX0r7_U3" "01ZK75LGDGB6QOO3MGNFGYOY6C6VBDG5OH"'
    assert scrubbed(text, PAIRS) == text

"""The scripts' text (W7.0, decision point 10), as lab/tests/test_entra_script.py holds the lab's:
they parse, no comment runs, the only write roles asked for are the two behind their name checks,
the only mail role is Application Mail.ReadWrite, nothing writes a transcript, every Exchange call
sets -ErrorAction, and no permission the rule forbids is ever asked for."""

import re

import pytest

from pwsh import CERT_SCRIPT, MODULE, SCRIPT, ps_string, run_json

FILES = [SCRIPT, MODULE, CERT_SCRIPT]
EXCHANGE = {
    "Connect-ExchangeOnline", "Disconnect-ExchangeOnline", "Get-Recipient", "New-Mailbox", "Get-OrganizationConfig",
    "Enable-OrganizationCustomization", "Get-ServicePrincipal", "New-ServicePrincipal", "Remove-ServicePrincipal", "Get-ManagementScope",
    "New-ManagementScope", "Set-ManagementScope", "Get-ManagementRoleAssignment", "New-ManagementRoleAssignment",
    "Remove-ManagementRoleAssignment", "Test-ServicePrincipalAuthorization",
}


def text(path) -> str:
    return path.read_text(encoding="utf-8")


def code(path) -> str:
    """The text without comments (the help block and # lines), for what the code itself names."""
    body = re.sub(r"<#.*?#>", "", text(path), flags=re.DOTALL)
    return "\n".join(line.split(" # ")[0] for line in body.splitlines() if not line.lstrip().startswith("#"))


@pytest.fixture(scope="module")
def parsed():
    return run_json("\n".join(
        f"""
        $errors = $null
        $tree = [System.Management.Automation.Language.Parser]::ParseFile({ps_string(path)}, [ref]$null, [ref]$errors)
        $commands = @($tree.FindAll({{ param($n) $n -is [System.Management.Automation.Language.CommandAst] }}, $true))
        $comments = [System.Collections.Generic.List[string]]::new()
        $tokens = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile({ps_string(path)}, [ref]$tokens, [ref]$null)
        $out_{i} = @{{
            errors = @($errors | ForEach-Object {{ "$_" }})
            commands = @($commands | ForEach-Object {{ @{{ name = $_.GetCommandName(); text = $_.Extent.Text }} }})
        }}"""
        for i, path in enumerate(FILES)
    ) + "\n@(" + ", ".join(f"$out_{i}" for i in range(len(FILES))) + ")")


@pytest.mark.parametrize("index", range(len(FILES)), ids=[p.name for p in FILES])
def test_it_parses(parsed, index):
    assert parsed[index]["errors"] == []


def test_every_exchange_call_sets_error_action(parsed):
    calls = [c for c in parsed[0]["commands"] if c["name"] in EXCHANGE]
    assert calls
    for call in calls:
        if call["name"] in ("Disconnect-ExchangeOnline",):
            continue
        assert "-ErrorAction" in call["text"], call["text"]


def test_the_only_write_roles_are_the_list_and_the_folder_behind_their_checks():
    script = code(SCRIPT)
    writes = [m.start() for m in re.finditer(r"roles = @\('write'\)", script)]
    assert len(writes) == 4  # the list's POST and PATCH, the folder's POST and PATCH
    for at in writes:
        before = script[:at]
        last_list = before.rfind("Test-RestoreTargetList")
        last_folder = before.rfind("Test-RestoreTargetFolder")
        line = script[before.rfind("\n"):at]
        if "lists/$listId/permissions" in line:
            assert last_list > before.rfind("Invoke-Change"), line
        else:
            assert "items/$folderId/permissions" in line, line
            assert last_folder > before.rfind("Invoke-Change"), line
    assert re.findall(r"roles = @\('(\w+)'\)", script) == ["read", "read", "write", "write", "write", "write"]


def test_no_forbidden_permission_or_role_is_ever_asked_for():
    for path in (SCRIPT, MODULE):
        body = code(path)
        for never in ("Sites.ReadWrite.All", "Sites.Read.All", "Files.ReadWrite.All\"", "Mail.Read'", "Mail.Send",
                      "full_access_as_app", "'owner'", "'fullcontrol'", "passwordCredentials = ", "addPassword"):
            assert never not in body, (path.name, never)
    assert re.findall(r"MailRoleName = '([^']+)'", text(MODULE)) == ["Application Mail.ReadWrite"]
    assert re.findall(r"GraphRoles = @\(([^)]*)\)", text(MODULE))[0].count("'") == 6


def test_the_graph_session_scopes_are_the_documented_ones():
    match = re.search(r"\$GraphScopes = @\(([^)]*)\)", text(SCRIPT))
    assert set(re.findall(r"'([^']+)'", match.group(1))) == {
        "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All", "Sites.FullControl.All",
        "Files.ReadWrite.All", "User.Read.All", "Organization.Read.All"}


def test_no_transcript_and_no_secret_is_written_out():
    for path in FILES:
        body = code(path)
        assert "Start-Transcript" not in body
        assert "Export-PfxCertificate" not in body and "Cert:\\" not in body
    cert = code(CERT_SCRIPT)
    # The password and the PFX reach rpworker on stdin and nowhere else.
    uses = [line.strip() for line in cert.splitlines() if re.search(r"\$(password|pfxBase64)\b", line)]
    assert uses
    for line in uses:
        assert not re.search(r"Write-|Out-File|Set-Content|Add-Content|Tee-Object|throw |Say ", line), line
        if "& $Worker" in line:
            assert re.fullmatch(r"\$(password|pfxBase64) \| & \$Worker vault set graph_cert_(password|pfx_base64) @vaultArgs", line), line


def test_no_variable_is_followed_by_a_colon_in_a_string():
    # "$why: ..." reads as a drive-qualified variable; the script must write "${why}:".
    for path in FILES:
        for line in text(path).splitlines():
            for literal in re.findall(r'"[^"]*"', line):
                assert not re.search(r"\$(?!\{)(?!script:|global:|env:)\w+:(?!:)", literal), (path.name, line.strip())


@pytest.fixture(scope="module")
def exchange_import():
    return run_json(f"""
        $tree = [System.Management.Automation.Language.Parser]::ParseFile({ps_string(SCRIPT)}, [ref]$null, [ref]$null)
        $module = [System.Management.Automation.Language.Parser]::ParseFile({ps_string(MODULE)}, [ref]$null, [ref]$null)
        $assign = @($tree.FindAll({{ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and "$($n.Left)" -eq '$ExchangeCommands' }}, $true))
        $connect = @($tree.FindAll({{ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Connect-ExchangeOnline' }}, $true))
        @{{
            assignments = $assign.Count
            listed = @($assign | ForEach-Object {{ $_.Right.FindAll({{ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] }}, $true) }} | ForEach-Object Value)
            connect = @($connect | ForEach-Object {{ $_.Extent.Text }})
            called = @($tree.FindAll({{ param($n) $n -is [System.Management.Automation.Language.CommandAst] }}, $true) | ForEach-Object {{ $_.GetCommandName() }} | Where-Object {{ $_ }} | Sort-Object -Unique)
            functions = @(@($tree, $module) | ForEach-Object {{ $_.FindAll({{ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }}, $true) }} | ForEach-Object Name)
        }}
    """)


def test_exchange_online_imports_only_the_cmdlets_the_script_calls(exchange_import):
    """The module imports every cmdlet the admin may run, as functions that shadow the setup
    module's of the same name (Exchange's Get-MailboxPlan did, on the first live run): the script
    connects with -CommandName, the list exactly the Exchange cmdlets it calls."""
    assert exchange_import["assignments"] == 1
    assert exchange_import["connect"] == ["Connect-ExchangeOnline -UserPrincipalName $account -ShowBanner:$false -DisableWAM -CommandName $ExchangeCommands -ErrorAction Stop"]
    called = set(exchange_import["called"]) & EXCHANGE - {"Connect-ExchangeOnline", "Disconnect-ExchangeOnline"}
    assert sorted(exchange_import["listed"]) == sorted(called)


def test_no_function_of_the_setup_is_named_like_an_exchange_cmdlet_it_imports(exchange_import):
    assert not set(exchange_import["listed"]) & set(exchange_import["functions"])

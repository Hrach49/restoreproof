"""The installer's text (W7.1): what it must and must never do, held on the files themselves."""

import re

from pwsh import FAKE_MACHINE, MACHINE_MODULE, MODULE, SCRIPT, UNINSTALL_SCRIPT


def text(path) -> str:
    return path.read_text(encoding="utf-8")


def test_the_script_is_strict_needs_pwsh_74_and_supports_whatif():
    script = text(SCRIPT)
    assert "#Requires -Version 7.4" in script
    assert "Set-StrictMode -Version Latest" in script
    assert "$ErrorActionPreference = 'Stop'" in script
    assert "[CmdletBinding(SupportsShouldProcess)]" in script


def test_a_secret_goes_to_the_worker_on_stdin_and_never_as_an_argument():
    script = text(SCRIPT)
    assert "Invoke-Worker @('vault', 'set', $name) -Stdin $value" in script
    assert not re.search(r"'set',\s*\$name,\s*\$value", script)
    assert "-MaskInput" in script, "a secret is read without echo"
    # Nothing of a secret is written anywhere by the script itself.
    for word in ("vault.bin", "ConvertTo-SecureString", "Set-Content", "Out-File", "Start-Transcript"):
        assert word not in script, word


def test_the_script_never_undoes_a_step_and_names_the_uninstall_script():
    script = text(SCRIPT)
    assert "service uninstall" not in script.replace("rpworker service stop; rpworker service uninstall", "")
    # The one thing the installer removes: the previous version's files, on an upgrade (W7.4 point 3).
    assert script.count("Remove-Item") == 1 and "Remove-Item -LiteralPath $previous -Recurse -Force" in script
    assert "Uninstall-RestoreProofWorker.ps1 (W7.3)" in script


def test_the_uninstall_script_is_strict_asks_nothing_and_holds_no_secret():
    script = text(UNINSTALL_SCRIPT)
    assert "#Requires -Version 7.4" in script and "Set-StrictMode -Version Latest" in script
    assert "$ErrorActionPreference = 'Stop'" in script and "[CmdletBinding(SupportsShouldProcess)]" in script
    for word in ("Read-Host", "-Stdin", "vault set", "ConvertTo-SecureString", "Set-Content", "Out-File", "Start-Transcript", "Get-Acl", "Set-Acl", "icacls.exe"):
        assert word not in script, word
    assert "Set-Location $env:SystemRoot" in script, "never in the folder it removes"
    # Nothing is removed before the service is uninstalled: every removal comes after step 8.
    assert script.index("rpworker service uninstall") < script.index("Remove-FileOverwritten")
    assert script.index("rpworker service uninstall") < script.index("Remove-Item -LiteralPath $ProgramDir")
    assert "securely" not in script.lower()


def test_the_fake_machine_exports_what_the_real_one_does():
    pattern = re.compile(r"Export-ModuleMember -Function (.+)")
    real = sorted(name.strip() for name in pattern.search(text(MACHINE_MODULE)).group(1).split(","))
    fake = sorted(name.strip() for name in pattern.search(text(FAKE_MACHINE)).group(1).split(","))
    assert real == fake == ["Get-CertificateKeyFile", "Get-InstalledService", "Get-MachineFacts", "Get-PwshPath", "Get-RemoteCertificate",
                            "Get-RunRecord", "Get-UninstallEntry", "Get-WorkerVersion", "Remove-FileOverwritten", "Remove-UninstallEntry",
                            "Set-UninstallEntry", "Test-IsElevated", "Test-VeeamOnThisMachine"]


def test_the_rules_module_reads_nothing_of_the_machine():
    module = text(MODULE)
    for word in ("Get-CimInstance", "Get-Service", "Cert:\\", "icacls.exe", "Get-Acl", "Set-Acl", "Test-Path", "Get-ChildItem", "Invoke-", "Start-Process"):
        # The word as a call: not as part of a longer name (Get-ServiceSid, Get-AclDifference)
        # and not possessive in a comment (Get-Acl's).
        assert not re.search(r"(?<![-\w])" + re.escape(word) + r"(?![-\w'])", module), word


def test_the_acls_are_set_through_dotnet_by_sid_and_recorded_as_the_icacls_line():
    # icacls refuses a service SID the machine can't map yet (error 1332 before `service
    # install`), so the script never runs it: .NET with the module's objects, by SID. Never
    # Get-Acl and Set-Acl, which elevated writes the SACL back and drops its audit entries (the
    # W7.1 review's finding 3): FileSystemAclExtensions writes the sections changed alone.
    script = text(SCRIPT)
    assert "icacls.exe" not in script
    assert not re.search(r"(?<![-\w])(Get|Set)-Acl(?![-\w])", script)
    assert "[IO.FileSystemAclExtensions]::SetAccessControl" in script
    assert "Set-PathAcl $Path $updated" in script
    assert "Update-AclObject -Acl $acl -Wanted $Wanted -Difference $difference" in script
    assert "Set-PathAcl $keyFile (Add-FileReadRule -Acl (Get-PathAcl $keyFile) -Sid $ServiceSid)" in script
    assert "Get-IcaclsArguments -Path $Path -Wanted $Wanted -Difference $difference" in script, "the line it amounts to is the record"

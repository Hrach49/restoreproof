"""RestoreProofWorker.psm1's rules, row by row, refusals first (W7.1, docs/decisions.md
2026-10-16 points 3 and 5 to 9), each table evaluated in one pwsh."""

import json
import re
import subprocess

import pytest
from cryptography import x509

from fake_rpworker import VEEAM_LIST
from install_lab import self_signed
from pwsh import evaluate, ps_string, run_json, with_module

SID = "S-1-5-80-2410341749-1432216181-1010774729-1630443783-2912569396"  # sc showsid RestoreProof
ACL_SETUP = """
function New-Acl([bool]$Protected, [object[]]$Rules) {
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($Protected, $false)
    $acl.SetOwner([Security.Principal.SecurityIdentifier]'S-1-5-32-544')
    foreach ($r in $Rules) {
        $flags = if ($r.Count -gt 3 -and $r[3]) { $r[3] } else { 'ContainerInherit, ObjectInherit' }
        $type = if ($r.Count -gt 2 -and $r[2]) { $r[2] } else { 'Allow' }
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]$r[0], $r[1], $flags, 'None', $type))
    }
    $acl
}
$root = (Get-WantedAcls -ServiceSid 'S-1-5-80-1-2-3-4-5')['']
$state = (Get-WantedAcls -ServiceSid 'S-1-5-80-1-2-3-4-5')['state']
$full = @(@('S-1-5-18', 'FullControl'), @('S-1-5-32-544', 'FullControl'), @('S-1-5-80-1-2-3-4-5', 'ReadAndExecute, Synchronize'))
"""


def sc_showsid(name: str) -> str:
    out = subprocess.run(["sc.exe", "showsid", name], capture_output=True, text=True).stdout
    return re.search(r"SERVICE SID:\s*(S-1-5-80-[\d-]+)", out).group(1)


# --- the service account ---------------------------------------------------------------


def test_the_service_sid_is_what_sc_showsid_prints():
    names = ["RestoreProof", "rp-test-w71-no-such-service", "Veeam.Archiver.REST.Service", "restoreproof"]
    rows = evaluate([f"Get-ServiceSid -ServiceName {ps_string(n)}" for n in names])
    assert rows == [sc_showsid(n) for n in names]
    assert rows[0] == SID
    assert rows[0] == rows[3], "the name's case doesn't matter"


def test_a_service_name_that_is_no_name_is_refused():
    rows = evaluate(["Get-ServiceSid -ServiceName ''", "Get-ServiceSid -ServiceName 'a b'", "Get-ServiceSid -ServiceName ('x' * 300)"])
    assert all(isinstance(r, dict) and "throws" in r for r in rows)


# --- the ACLs (point 7) ----------------------------------------------------------------


def test_the_wanted_acls_are_the_entrys_table():
    wanted = run_json(with_module(
        "$w = Get-WantedAcls -ServiceSid 'S-1-5-80-1-2-3-4-5'\n"
        "[pscustomobject]@{ keys = @($w.Keys); root = $w['']; state = $w['state']; logs = $w['logs'] }"
    ))
    assert wanted["keys"] == ["", "state", "runs", "outbox", "sent", "failed", "logs"]
    assert wanted["root"]["Protected"] is True
    assert [(r["Sid"], r["Rights"]) for r in wanted["root"]["Rules"]] == [
        ("S-1-5-18", "FullControl"), ("S-1-5-32-544", "FullControl"), ("S-1-5-80-1-2-3-4-5", "ReadAndExecute")]
    assert wanted["state"]["Protected"] is False
    assert [(r["Sid"], r["Rights"]) for r in wanted["state"]["Rules"]] == [("S-1-5-80-1-2-3-4-5", "Modify")]
    assert wanted["logs"] == wanted["state"]


def test_also_full_control_adds_a_full_rule_on_the_root_alone():
    wanted = run_json(with_module(
        "$w = Get-WantedAcls -ServiceSid 'S-1-5-80-1-2-3-4-5' -AlsoFullControl 'S-1-5-21-1-2-3-1001'\n"
        "[pscustomobject]@{ root = @($w[''].Rules | ForEach-Object Sid); runs = @($w['runs'].Rules | ForEach-Object Sid) }"
    ))
    assert wanted["root"] == ["S-1-5-18", "S-1-5-32-544", "S-1-5-21-1-2-3-1001", "S-1-5-80-1-2-3-4-5"]
    assert wanted["runs"] == ["S-1-5-80-1-2-3-4-5"]


@pytest.mark.parametrize(
    "protected, rules, wanted, missing, extra, protection_wrong",
    [
        # the root as the installer leaves it
        (True, "$full", "$root", [], [], False),
        # the inherited ProgramData ACL: nothing explicit, inheritance on
        (False, "@()", "$root", ["S-1-5-18", "S-1-5-32-544", "S-1-5-80-1-2-3-4-5"], [], True),
        # one rule short
        (True, "$full[0..1]", "$root", ["S-1-5-80-1-2-3-4-5"], [], False),
        # the account with Modify where Read and execute is wanted: missing, not extra
        (True, "@($full[0], $full[1], @('S-1-5-80-1-2-3-4-5', 'Modify, Synchronize'))", "$root", ["S-1-5-80-1-2-3-4-5"], [], False),
        # the account's rule without (OI)(CI): missing
        (True, "@($full[0], $full[1], @('S-1-5-80-1-2-3-4-5', 'ReadAndExecute, Synchronize', 'Allow', 'None'))", "$root", ["S-1-5-80-1-2-3-4-5"], [], False),
        # Users (S-1-5-32-545) with an explicit rule on the protected root: extra
        (True, "$full + ,@('S-1-5-32-545', 'ReadAndExecute, Synchronize')", "$root", [], [["S-1-5-32-545", "Allow"]], False),
        # a Deny for the account: extra, whatever the folder
        (True, "$full + ,@('S-1-5-80-1-2-3-4-5', 'Write', 'Deny')", "$root", [], [["S-1-5-80-1-2-3-4-5", "Deny"]], False),
        (False, "@(@('S-1-5-80-1-2-3-4-5', 'Modify, Synchronize'), @('S-1-5-80-1-2-3-4-5', 'Write', 'Deny'))", "$state", [], [["S-1-5-80-1-2-3-4-5", "Deny"]], False),
        # a subfolder: the account's Modify there, Users' explicit rule left alone (not protected)
        (False, "@(@('S-1-5-80-1-2-3-4-5', 'Modify, Synchronize'), @('S-1-5-32-545', 'ReadAndExecute, Synchronize'))", "$state", [], [], False),
        # a subfolder made by hand: nothing explicit
        (False, "@()", "$state", ["S-1-5-80-1-2-3-4-5"], [], False),
        # a subfolder somebody protected
        (True, "@(,@('S-1-5-80-1-2-3-4-5', 'Modify, Synchronize'))", "$state", [], [], True),
    ],
)
def test_the_acl_difference(protected, rules, wanted, missing, extra, protection_wrong):
    ps_protected = "$true" if protected else "$false"
    result = run_json(with_module(
        ACL_SETUP + f"$acl = New-Acl {ps_protected} ({rules})\n"
        f"$d = Get-AclDifference -Acl $acl -Wanted {wanted}\n"
        "[pscustomobject]@{ missing = @($d.Missing | ForEach-Object Sid); extra = @($d.Extra | ForEach-Object { ,@($_.Sid, $_.Type) }); wrong = $d.ProtectionWrong; ok = $d.Ok }"
    ))
    assert result["missing"] == missing
    assert result["extra"] == extra
    assert result["wrong"] is protection_wrong
    assert result["ok"] is (not missing and not extra and not protection_wrong)


def test_the_icacls_lines_are_the_entrys():
    result = run_json(with_module(
        ACL_SETUP +
        "$fresh = Get-AclDifference -Acl (New-Acl $false @()) -Wanted $root\n"
        "$extras = Get-AclDifference -Acl (New-Acl $true ($full + ,@('S-1-5-32-545', 'ReadAndExecute, Synchronize') + ,@('S-1-5-80-1-2-3-4-5', 'Write', 'Deny'))) -Wanted $root\n"
        "$sub = Get-AclDifference -Acl (New-Acl $true @()) -Wanted $state\n"
        "$ok = Get-AclDifference -Acl (New-Acl $true $full) -Wanted $root\n"
        "[pscustomobject]@{\n"
        "  fresh = @(Get-IcaclsArguments -Path 'C:\\ProgramData\\RestoreProof' -Wanted $root -Difference $fresh)\n"
        "  extras = @(Get-IcaclsArguments -Path 'C:\\ProgramData\\RestoreProof' -Wanted $root -Difference $extras)\n"
        "  sub = @(Get-IcaclsArguments -Path 'C:\\ProgramData\\RestoreProof\\state' -Wanted $state -Difference $sub)\n"
        "  ok = @(Get-IcaclsArguments -Path 'C:\\ProgramData\\RestoreProof' -Wanted $root -Difference $ok)\n"
        "}"
    ))
    assert result["fresh"] == [
        "C:\\ProgramData\\RestoreProof", "/inheritance:r", "/grant:r",
        "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-80-1-2-3-4-5:(OI)(CI)RX", "/Q"]
    assert result["extras"] == [
        "C:\\ProgramData\\RestoreProof", "/remove:g", "*S-1-5-32-545", "/remove:d", "*S-1-5-80-1-2-3-4-5", "/Q"]
    assert result["sub"] == ["C:\\ProgramData\\RestoreProof\\state", "/inheritance:e", "/grant:r", "*S-1-5-80-1-2-3-4-5:(OI)(CI)M", "/Q"]
    assert result["ok"] == []


def test_update_acl_object_makes_the_difference_good_in_memory():
    # The inherited ProgramData DACL, Users' explicit rule and a Deny for the account: after
    # Update-AclObject the difference is Ok, and nothing but the wanted rules is left.
    result = run_json(with_module(
        ACL_SETUP +
        "$acl = New-Acl $false ($full[0..1] + ,@('S-1-5-32-545', 'ReadAndExecute, Synchronize') + ,@('S-1-5-80-1-2-3-4-5', 'Write', 'Deny') + ,@('S-1-5-80-1-2-3-4-5', 'Modify, Synchronize'))\n"
        "$before = Get-AclDifference -Acl $acl -Wanted $root\n"
        "$updated = Update-AclObject -Acl $acl -Wanted $root -Difference $before\n"
        "$after = Get-AclDifference -Acl $updated -Wanted $root\n"
        "$rules = @($updated.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]) | ForEach-Object { \"$($_.IdentityReference.Value) $($_.AccessControlType) $($_.FileSystemRights)\" } | Sort-Object)\n"
        "$sub = New-Acl $false @()\n"
        "$subAfter = Get-AclDifference -Acl (Update-AclObject -Acl $sub -Wanted $state -Difference (Get-AclDifference -Acl $sub -Wanted $state)) -Wanted $state\n"
        "$file = [Security.AccessControl.FileSecurity]::new()\n"
        "$file = Add-FileReadRule -Acl $file -Sid 'S-1-5-80-1-2-3-4-5'\n"
        "$fileRules = @($file.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]) | ForEach-Object { \"$($_.IdentityReference.Value) $($_.AccessControlType) $($_.FileSystemRights) $($_.InheritanceFlags)\" })\n"
        "[pscustomobject]@{ beforeOk = $before.Ok; afterOk = $after.Ok; protected = $updated.AreAccessRulesProtected; rules = $rules; subOk = $subAfter.Ok; fileRules = $fileRules }"
    ))
    assert result["beforeOk"] is False and result["afterOk"] is True and result["protected"] is True
    assert result["rules"] == sorted([
        "S-1-5-18 Allow FullControl", "S-1-5-32-544 Allow FullControl", "S-1-5-80-1-2-3-4-5 Allow ReadAndExecute, Synchronize"])
    assert result["subOk"] is True
    assert result["fileRules"] == ["S-1-5-80-1-2-3-4-5 Allow Read, Synchronize None"]


def test_the_service_folder_names():
    assert run_json(with_module("@(Get-ServiceFolderNames)")) == ["state", "runs", "outbox", "sent", "failed", "logs"]


# --- the config (point 3) ----------------------------------------------------------------


def test_the_config_document_holds_the_two_urls_and_the_pin_and_nothing_else():
    rows = evaluate([
        "(New-ConfigDocument -CloudUrl 'https://cloud.example.invalid' -VeeamUrl 'https://localhost:4443') | ConvertTo-Json -Compress",
        "(New-ConfigDocument -CloudUrl 'https://c' -VeeamUrl 'https://v' -VeeamCaFile 'C:\\p\\veeam-rest.pem' -VeeamCertSha256 ('ab' * 32)) | ConvertTo-Json -Compress",
        "(New-ConfigDocument -CloudUrl 'https://c' -VeeamUrl 'https://v' -CloudCaFile 'C:\\p\\cloud-ca.pem') | ConvertTo-Json -Compress",
    ])
    assert json.loads(rows[0]) == {"cloud_url": "https://cloud.example.invalid", "veeam_url": "https://localhost:4443"}
    assert list(json.loads(rows[0])) == ["cloud_url", "veeam_url"]
    assert json.loads(rows[1]) == {"cloud_url": "https://c", "veeam_url": "https://v", "veeam_ca_file": "C:\\p\\veeam-rest.pem", "veeam_cert_sha256": "AB" * 32}
    assert json.loads(rows[2]) == {"cloud_url": "https://c", "veeam_url": "https://v", "cloud_ca_file": "C:\\p\\cloud-ca.pem"}


@pytest.mark.parametrize(
    "arguments",
    [
        "-CloudUrl 'http://cloud' -VeeamUrl 'https://v'",
        "-CloudUrl 'https://cloud' -VeeamUrl 'veeam:4443'",
        "-CloudUrl 'https://cloud?x=1' -VeeamUrl 'https://v'",
        "-CloudUrl 'https://u:p@cloud' -VeeamUrl 'https://v'",
        "-CloudUrl 'https://cloud' -VeeamUrl 'https://v' -VeeamCertSha256 ('ab' * 32)",
        "-CloudUrl 'https://cloud' -VeeamUrl 'https://v' -VeeamCaFile 'x.pem'",
        "-CloudUrl 'https://cloud' -VeeamUrl 'https://v' -VeeamCaFile 'x.pem' -VeeamCertSha256 'not-hex'",
    ],
)
def test_a_config_document_that_breaks_the_workers_rules_is_refused(arguments):
    row = evaluate([f"New-ConfigDocument {arguments}"])[0]
    assert isinstance(row, dict) and "throws" in row


# --- the vault (point 9, step 5) ----------------------------------------------------------


@pytest.mark.parametrize(
    "held, ask, needs_key, needs_cert, registered",
    [
        ([], ["veeam_username", "veeam_password", "cloud_install_token"], True, True, False),
        (["veeam_username"], ["veeam_password", "cloud_install_token"], True, True, False),
        (["veeam_username", "veeam_password", "cloud_install_token"], [], True, True, False),
        (["veeam_username", "veeam_password", "cloud_api_token"], [], True, True, True),
        (["veeam_username", "veeam_password", "signing_key_base64", "graph_cert_pfx_base64", "graph_cert_password", "cloud_api_token"], [], False, False, True),
        # half a certificate is made again (over it: the script's -Replace)
        (["graph_cert_pfx_base64"], ["veeam_username", "veeam_password", "cloud_install_token"], True, True, False),
        (["graph_cert_password"], ["veeam_username", "veeam_password", "cloud_install_token"], True, True, False),
        # names in another case are not the names
        (["Veeam_Username", "VEEAM_PASSWORD"], ["veeam_username", "veeam_password", "cloud_install_token"], True, True, False),
    ],
)
def test_the_vault_plan(held, ask, needs_key, needs_cert, registered):
    held_ps = "@(" + ", ".join(ps_string(h) for h in held) + ")"
    plan = run_json(with_module(f"Get-VaultPlan -Held {held_ps}"))
    assert plan["Ask"] == ask
    assert plan["NeedsSigningKey"] is needs_key
    assert plan["NeedsCertificate"] is needs_cert
    assert plan["Registered"] is registered
    assert plan["HasInstallToken"] is ("cloud_install_token" in held)
    assert plan["CertificateHalf"] is (("graph_cert_pfx_base64" in held) != ("graph_cert_password" in held))


def test_replace_asks_the_veeam_account_and_password_again_and_nothing_else():
    held = "@('veeam_username', 'veeam_password', 'signing_key_base64', 'graph_cert_pfx_base64', 'graph_cert_password', 'cloud_api_token')"
    plan = run_json(with_module(f"Get-VaultPlan -Held {held} -Replace $true"))
    assert plan["Ask"] == ["veeam_username", "veeam_password"]
    assert plan["NeedsSigningKey"] is False and plan["NeedsCertificate"] is False and plan["Registered"] is True


# --- Veeam's certificate (point 5) --------------------------------------------------------


@pytest.mark.parametrize(
    "own, chains, names, verdict",
    [
        (True, False, False, "pin"),
        (True, True, True, "pin"),
        (False, True, True, "store"),
        (False, True, False, "confirm"),
        (False, False, True, "confirm"),
        (False, False, False, "confirm"),
    ],
)
def test_the_veeam_certificate_rule(own, chains, names, verdict):
    b = lambda v: "$true" if v else "$false"
    assert evaluate([f"Test-VeeamCertificate -InLocalStoreWithKey {b(own)} -ChainsToStore {b(chains)} -NamesHost {b(names)}"]) == [verdict]


def test_a_thumbprint_is_forty_hex_digits():
    rows = evaluate([
        "Test-Thumbprint 'AC3220B58A2B4C438DA13816C2DD1E25D1F783A7'", "Test-Thumbprint 'ac3220b58a2b4c438da13816c2dd1e25d1f783a7'",
        "Test-Thumbprint 'AC3220B58A2B4C438DA13816C2DD1E25D1F783A'", "Test-Thumbprint ''", "Test-Thumbprint 'AC32 20B5 8A2B 4C43 8DA1 3816 C2DD 1E25 D1F7 83A7'"])
    assert rows == [True, True, False, False, False]


def test_convertto_pem_writes_the_der_in_64_character_lines():
    der = self_signed("Veeam Software")
    pem = evaluate([f"ConvertTo-Pem -Der ([Convert]::FromBase64String({ps_string(__import__('base64').b64encode(der).decode())}))"])[0]
    assert pem.startswith("-----BEGIN CERTIFICATE-----\n") and pem.endswith("\n-----END CERTIFICATE-----\n")
    body = pem.splitlines()[1:-1]
    assert all(len(line) <= 64 for line in body) and all(len(line) == 64 for line in body[:-1])
    assert x509.load_pem_x509_certificate(pem.encode("ascii")).public_bytes(serialization_der()) == der


def serialization_der():
    from cryptography.hazmat.primitives import serialization

    return serialization.Encoding.DER


# --- the organisation certificates (point 6) -----------------------------------------------


def test_the_thumbprints_are_read_from_the_lab_table():
    rows = run_json(with_module(f",@(Read-OrganisationThumbprints -Text {ps_string(VEEAM_LIST)})"))
    assert rows == [{"Organisation": "RestoreProofLab.onmicrosoft.com", "Thumbprints": ["AC3220B58A2B4C438DA13816C2DD1E25D1F783A7"], "Problems": []}]


def test_two_organisations_two_certificates_and_none():
    table = (
        "  ORGANIZATION           APP CERTIFICATE                                                                    BACKUP TIME          EX  SP  OD  TM  LONG-TERM  RESTORE POINT ID\n"
        "* alpha.onmicrosoft.com  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB  (no restore points)\n"
        "  Evil Org               -                                                                                  (no restore points)\n"
        "  Zeta.onmicrosoft.com   not-a-thumbprint                                                                   2026-09-25T19:37:15.2145203Z  x   x   x   -   no         c2f0\n"
        "  Zeta.onmicrosoft.com   not-a-thumbprint                                                                   2026-09-25T19:24:31.0936821Z  x   x   x   -   no         c2f1\n"
        "\n"
        "3 organisation(s), 2 restore point(s); * = veeam_org_name\n"
    )
    rows = run_json(with_module(f",@(Read-OrganisationThumbprints -Text {ps_string(table)})"))
    assert rows == [
        {"Organisation": "alpha.onmicrosoft.com", "Thumbprints": ["A" * 40, "B" * 40], "Problems": []},
        {"Organisation": "Evil Org", "Thumbprints": [], "Problems": []},
        {"Organisation": "Zeta.onmicrosoft.com", "Thumbprints": [], "Problems": ["not a thumbprint: not-a-thumbprint"]},
    ]


def test_a_table_without_the_column_or_no_table_is_refused():
    old = "  ORGANIZATION                     BACKUP TIME                   EX  SP  OD  TM  LONG-TERM  RESTORE POINT ID\n  x  (no restore points)\n"
    rows = evaluate([f"Read-OrganisationThumbprints -Text {ps_string(old)}", "Read-OrganisationThumbprints -Text ''",
                     "Read-OrganisationThumbprints -Text 'no organisations in Veeam'"])
    assert all(isinstance(r, dict) and "older Worker" in r["throws"] for r in rows)


def test_the_key_file_candidates_are_the_two_folders_of_w412():
    rows = run_json(with_module("@(Get-KeyFileCandidates -UniqueName 'abc_def' -ProgramData 'C:\\PD')"))
    assert rows == ["C:\\PD\\Microsoft\\Crypto\\RSA\\MachineKeys\\abc_def", "C:\\PD\\Microsoft\\Crypto\\Keys\\abc_def"]
    bad = evaluate(["Get-KeyFileCandidates -UniqueName '..\\x'", "Get-KeyFileCandidates -UniqueName '..'", "Get-KeyFileCandidates -UniqueName 'a/b'"])
    assert all(isinstance(r, dict) and "throws" in r for r in bad)


# --- the checks (point 9, step 1) ------------------------------------------------------------


@pytest.mark.parametrize(
    "arguments, problems",
    [
        ("-PSVersion '7.4.0' -Elevated $true -Is64Bit $true -IsWindows $true", []),
        ("-PSVersion '7.5.2' -Elevated $true -Is64Bit $true -IsWindows $true", []),
        ("-PSVersion '7.3.9' -Elevated $true -Is64Bit $true -IsWindows $true", ["PowerShell 7.4"]),
        ("-PSVersion '5.1.19041' -Elevated $false -Is64Bit $true -IsWindows $true", ["PowerShell 7.4", "elevated"]),
        ("-PSVersion '7.4.0' -Elevated $true -Is64Bit $false -IsWindows $true", ["64-bit"]),
        ("-PSVersion '7.4.0' -Elevated $true -Is64Bit $true -IsWindows $false", ["Windows alone"]),
    ],
)
def test_the_prerequisites(arguments, problems):
    rows = run_json(with_module(f",@(Test-Prerequisites {arguments})"))
    assert len(rows) == len(problems)
    for row, word in zip(rows, problems):
        assert row.startswith("problem: ") and word in row


def test_the_installed_service_rule():
    exe = "C:\\Program Files\\RestoreProof\\rpworker.exe"
    rows = evaluate([
        f"Get-ServiceCommandLine -Exe {ps_string(exe)}",
        f"Test-InstalledService -Service $null -ExpectedCommandLine (Get-ServiceCommandLine -Exe {ps_string(exe)})",
        f"Test-InstalledService -Service ([pscustomobject]@{{ PathName = '\"{exe}\" service run' }}) -ExpectedCommandLine (Get-ServiceCommandLine -Exe {ps_string(exe)})",
        f"Test-InstalledService -Service ([pscustomobject]@{{ PathName = '\"C:\\restoreproof\\worker\\build\\dev\\rpworker.exe\" service run' }}) -ExpectedCommandLine (Get-ServiceCommandLine -Exe {ps_string(exe)})",
        f"Test-InstalledService -Service ([pscustomobject]@{{ PathName = '\"{exe}\" service run --config \"C:\\x.json\"' }}) -ExpectedCommandLine (Get-ServiceCommandLine -Exe {ps_string(exe)})",
    ])
    assert rows == [f'"{exe}" service run', "absent", "ok", "other", "other"]


def test_the_registration_line():
    rows = run_json(with_module(
        "@((Read-RegistrationLine -Text \"registered worker 65fd2c3e-9b1a-4e87-a0c3-1f2e3d4c5b6a key $('a' * 64)`n\"), "
        "(Read-RegistrationLine -Text 'started RestoreProof'), (Read-RegistrationLine -Text ''))"
    ))
    assert rows[0] == {"WorkerId": "65fd2c3e-9b1a-4e87-a0c3-1f2e3d4c5b6a", "KeyId": "a" * 64}
    assert rows[1] is None and rows[2] is None


# --- the owner (the W7.1 review's finding 2) ----------------------------------------------


@pytest.mark.parametrize(
    "owner, owner_wrong",
    [
        ("S-1-5-18", False),
        ("S-1-5-32-544", False),
        ("S-1-5-21-1-2-3-1001", False),  # the account running the installer, passed in
        ("S-1-5-32-545", True),  # Users
        ("S-1-5-21-1-2-3-1002", True),  # another local user
    ],
)
def test_an_owner_nobody_trusts_is_a_difference_and_is_given_to_administrators(owner, owner_wrong):
    result = run_json(with_module(
        ACL_SETUP +
        f"$acl = New-Acl $true $full; $acl.SetOwner([Security.Principal.SecurityIdentifier]'{owner}')\n"
        "$trusted = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-21-1-2-3-1001')\n"
        "$d = Get-AclDifference -Acl $acl -Wanted $root -TrustedOwners $trusted\n"
        "$updated = Update-AclObject -Acl $acl -Wanted $root -Difference $d\n"
        "$after = Get-AclDifference -Acl $updated -Wanted $root -TrustedOwners $trusted\n"
        "[pscustomobject]@{ wrong = $d.OwnerWrong; owner = $d.Owner; daclOk = $d.DaclOk; ok = $d.Ok;\n"
        "  icacls = @(Get-IcaclsArguments -Path 'C:\\x' -Wanted $root -Difference $d);\n"
        "  newOwner = $updated.GetOwner([Security.Principal.SecurityIdentifier]).Value; afterOk = $after.Ok }"
    ))
    assert result["wrong"] is owner_wrong and result["owner"] == owner
    assert result["daclOk"] is True and result["ok"] is (not owner_wrong)
    assert result["icacls"] == [], "the DACL line is empty: the owner is its own line"
    assert result["newOwner"] == ("S-1-5-32-544" if owner_wrong else owner)
    assert result["afterOk"] is True


def test_the_default_trusted_owners_are_system_and_administrators():
    result = run_json(with_module(
        ACL_SETUP + "$acl = New-Acl $true $full; $acl.SetOwner([Security.Principal.SecurityIdentifier]'S-1-5-21-1-2-3-1001')\n"
        "(Get-AclDifference -Acl $acl -Wanted $root).OwnerWrong"
    ))
    assert result is True


@pytest.mark.parametrize(
    "owner, explicit, reason",
    [
        ("S-1-5-32-544", [], None),
        ("S-1-5-21-1-2-3-1001", ["S-1-5-18"], None),
        ("S-1-5-32-545", [], "is owned by S-1-5-32-545, not by SYSTEM, Administrators or this account"),
        ("", [], "is owned by nobody, not by SYSTEM, Administrators or this account"),
        ("S-1-5-32-544", ["S-1-5-32-545", "S-1-5-11", "S-1-5-32-545"], "has rules of its own for S-1-5-11, S-1-5-32-545"),
    ],
)
def test_a_kept_file_is_trusted_by_its_owner_and_its_own_rules(owner, explicit, reason):
    sids = "@(" + ", ".join(ps_string(s) for s in explicit) + ")"
    result = run_json(with_module(
        f"$r = Test-TrustedFile -Owner {ps_string(owner)} -ExplicitSids {sids} -TrustedOwners @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-21-1-2-3-1001')\n"
        "[pscustomobject]@{ reason = $r }"
    ))
    assert result["reason"] == reason


# --- the config check and the config plan (the review's findings 1 and 7) ----------------


@pytest.mark.parametrize(
    "code, out, err, ok",
    [
        (0, "config file: C:\\x\\config.json\n", "", True),
        # every first install: the settings, then the vault that isn't there yet
        (1, "config file: C:\\x\\config.json\ncloud_url: https://c\n", "config error: C:\\ProgramData\\RestoreProof\\vault.bin: vault file not found\n", True),
        # the config itself refused: nothing printed
        (1, "", "config error: C:\\x\\config.json: cannot read config file\n", False),
        (1, "", "config error: C:\\ProgramData\\RestoreProof\\vault.bin: vault file not found\n", False),
        # a vault that is there and can't be read is no pass
        (1, "config file: C:\\x\\config.json\n", "config error: C:\\v.bin: the vault couldn't be decrypted\n", False),
        (1, "config file: C:\\x\\config.json\n", "config error: a: vault file not found\nconfig error: b\n", False),
        (64, "config file: x\n", "config error: v: vault file not found\n", False),
    ],
)
def test_the_config_check_passes_before_the_vault_is_made(code, out, err, ok):
    result = run_json(with_module(f"[pscustomobject]@{{ ok = Test-ConfigCheck -Code {code} -Out {ps_string(out)} -Err {ps_string(err)} }}"))
    assert result["ok"] is ok


@pytest.mark.parametrize(
    "arguments, action, why",
    [
        ("-Exists $false", "write", ""),
        ("-Exists $true -CheckOk $false -Replace $true -Untrusted 'is owned by S-1-5-32-545'", "write", ""),
        ("-Exists $true -CheckOk $true -Replace $true -KeptCloudUrl 'https://a' -CloudUrl 'https://b'", "write", ""),
        ("-Exists $true -CheckOk $true", "keep", ""),
        ("-Exists $true -CheckOk $true -KeptCloudUrl 'https://a' -CloudUrl 'https://a' -KeptVeeamUrl 'https://v' -VeeamUrl 'https://v'", "keep", ""),
        ("-Exists $true -CheckOk $true -Untrusted 'is owned by S-1-5-32-545, not by SYSTEM, Administrators or this account'", "stop",
         "is there and is owned by S-1-5-32-545, not by SYSTEM, Administrators or this account: someone else may have written it; read it, then give -Replace to write a new one."),
        ("-Exists $true -CheckOk $false -CheckLine 'config error: cloud_url: must be an https:// URL'", "stop",
         "is there and fails rpworker config check (config error: cloud_url: must be an https:// URL); fix it, or give -Replace to write a new one."),
        ("-Exists $true -CheckOk $true -KeptCloudUrl 'https://a' -CloudUrl 'https://b'", "stop", "has cloud_url https://a, not https://b: give -Replace to write the new one."),
        ("-Exists $true -CheckOk $true -KeptVeeamUrl 'https://v:4443' -VeeamUrl 'https://V:4443'", "stop", "has veeam_url https://v:4443, not https://V:4443: give -Replace to write the new one."),
    ],
)
def test_the_config_plan(arguments, action, why):
    result = run_json(with_module(f"Get-ConfigPlan {arguments}"))
    assert result == {"Action": action, "Why": why}


def test_the_key_already_registered_is_the_409s_line_alone():
    result = run_json(with_module(
        "[pscustomobject]@{\n"
        "  yes = Test-KeyAlreadyRegistered -Code 4 -Err \"cloud register: this Worker's key is already registered`n\"\n"
        "  code = Test-KeyAlreadyRegistered -Code 1 -Err \"cloud register: this Worker's key is already registered`n\"\n"
        "  other = Test-KeyAlreadyRegistered -Code 4 -Err \"cloud register: refused (http_403)`n\"\n"
        "}"
    ))
    assert result == {"yes": True, "code": False, "other": False}


def test_the_wanted_acls_are_the_shared_vector():
    """W7.2 point 1: rpworker doctor checks the same folders against the same rules; both are
    held to shared/testdata/worker-acls-v1.json, so a change on one side fails here first."""
    from pathlib import Path

    vector = json.loads((Path(__file__).resolve().parents[3] / "shared" / "testdata" / "worker-acls-v1.json").read_text(encoding="utf-8"))
    wanted = run_json(with_module(
        "$w = Get-WantedAcls -ServiceSid 'S-1-5-80-1-2-3-4-5'\n"
        "@($w.Keys | ForEach-Object { [pscustomobject]@{ path = $_; protected = $w[$_].Protected;"
        " rules = @($w[$_].Rules | ForEach-Object { [pscustomobject]@{ sid = $_.Sid; rights = $_.Rights } }) } })"
    ))
    service = "S-1-5-80-1-2-3-4-5"
    expected = [
        {"path": f["path"], "protected": f["protected"],
         "rules": [{"sid": service if r["sid"] == vector["service_sid"] else r["sid"], "rights": r["rights"]} for r in f["rules"]]}
        for f in vector["folders"]
    ]
    assert wanted == expected

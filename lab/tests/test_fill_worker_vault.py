"""lab/entra/fill-worker-vault.ps1 (W4.5): feeds the lab's five secrets to `rpworker vault set
<name>` on stdin, from Credential Manager and the PFX file, never printing or writing one."""

import base64
import datetime as dt
import os
import re
import shutil
import subprocess
import sys
import uuid

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from seeder import LAB_DIR, signing_key, worker_app

SCRIPT = LAB_DIR / "entra" / "fill-worker-vault.ps1"
PASSWORD_SENTINEL = "pfx-password-SENTINEL-DO-NOT-LEAK"
VEEAM_SENTINEL = "veeam-password-SENTINEL-DO-NOT-LEAK"
# RFC 8032 section 7.1, test 1: a published key, in the shape the vault's signing_key_base64 holds.
KEY_SENTINEL = "MC4CAQAwBQYDK2VwBCIEIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g"
NAMES = ("veeam_username", "veeam_password", "graph_cert_pfx_base64", "graph_cert_password", "signing_key_base64")
HAVE_PWSH = shutil.which("pwsh") is not None
WINDOWS_PWSH = sys.platform == "win32" and HAVE_PWSH

# A stand-in for rpworker: records each call's arguments and the one stdin line it got, as
# `rpworker vault set` would read it, and answers as rpworker does.
STUB = r"""
$lines = @($input)
$line = if ($lines.Count -gt 0) { $lines[0] } else { $null }
$words = $args -join ' '
if ($args[0] -eq 'vault' -and $args[1] -eq 'set') {
    if ($null -eq $line -or $line -eq '') { [Console]::Error.WriteLine('vault error: the value is empty'); exit 1 }
    if ($env:RP_STUB_FAIL -eq $args[2]) { [Console]::Error.WriteLine("vault error: STUB refused $($args[2])"); exit 1 }
    Add-Content -LiteralPath $env:RP_STUB_LOG -Value "$words|$line" -Encoding utf8
    "set $($args[2]) in <stub>"
    exit 0
}
if ($args[0] -eq 'vault' -and $args[1] -eq 'list') {
    Add-Content -LiteralPath $env:RP_STUB_LOG -Value "$words|" -Encoding utf8
    "<stub list>"
    exit 0
}
[Console]::Error.WriteLine("stub: unexpected $words"); exit 64
"""


def script_text() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def run_pwsh(command: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=180,
        env={**os.environ, **(env or {})},
    )


# ---- the script's text ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name, value",
    [
        ("CredTarget", worker_app.CREDENTIAL_TARGET),
        ("PfxName", worker_app.PFX_NAME),
        ("SigningKeyCredTarget", signing_key.CREDENTIAL_TARGET),
        ("VeeamCredTarget", "RestoreProof Lab - rp-veeam (local Veeam REST)"),
    ],
)
def test_constants_match_the_labs_entries(name, value):
    match = re.search(rf"^\s*\${name}\s*=\s*'([^']*)'", script_text(), re.MULTILINE)
    assert match, f"${name} = '...' not found"
    assert match.group(1) == value


def test_it_sets_exactly_the_five_names_the_worker_knows():
    names = re.findall(r"Set-VaultValue '([a-z0-9_]+)'", script_text())
    assert tuple(names) == NAMES
    assert signing_key.VAULT_NAME in names


def test_it_sets_no_environment_variable():
    assert not re.search(r"\$env:RP_\w+\s*=", script_text())
    assert "Remove-Item Env:" not in script_text()
    assert "[Environment]::SetEnvironmentVariable" not in script_text()


def test_the_header_names_the_vault_and_the_five_names():
    header = script_text().split("#>", 1)[0]
    assert "vault" in header
    for name in NAMES:
        assert name in header
    assert "new-signing-key" in header
    assert "RP_GRAPH_CERT_PFX_BASE64" not in header


def test_the_signing_key_only_reaches_its_shape_check_and_the_vault():
    allowed = (
        r"^\s*\$signingKey\s*=\s*\[RpVaultCredential\]::Read\(\$SigningKeyTarget\)$",
        r"^\s*if \(\$null -ne \$signingKey -and \$signingKey -cnotmatch \$SigningKeyShape\) \{$",
        r"^\s*if \(\$null -eq \$signingKey\) \{$",
        r"^\s*Set-VaultValue 'signing_key_base64' \$signingKey$",
        r"^\s*\$secret = \$null; \$veeamPassword = \$null; \$signingKey = \$null; \$bytes = \$null$",
    )
    used = 0
    for number, line in enumerate(script_text().splitlines(), 1):
        if re.search(r"\$signingKey\b", line) and not line.lstrip().startswith("#"):
            used += 1
            assert any(re.search(p, line) for p in allowed), f"line {number} uses $signingKey: {line.strip()}"
    assert used == len(allowed)


def test_the_scripts_key_shape_is_the_seeders():
    match = re.search(r"^\s*\$SigningKeyShape\s*=\s*'([^']*)'", script_text(), re.MULTILINE)
    assert match, "$SigningKeyShape = '...' not found"
    shape = re.compile(match.group(1).replace(r"\z", r"\Z"))
    assert shape.search(KEY_SENTINEL)
    assert signing_key.is_private_key_line(KEY_SENTINEL)
    for bad in (KEY_SENTINEL + "\n", KEY_SENTINEL[:-1], KEY_SENTINEL + "A", KEY_SENTINEL.replace("/", "_"), ""):
        assert not shape.search(bad), repr(bad)
        assert not signing_key.is_private_key_line(bad)
    for _ in range(20):
        assert shape.search(signing_key.new_key_pair().private_pkcs8_base64)


def test_nothing_is_written_to_disk_or_printed_by_the_script_itself():
    text = script_text()
    for banned in ("Set-Content", "Add-Content", "Out-File", "Export-", "Start-Transcript", "WriteAll", "setx"):
        assert banned not in text, banned
    assert not re.search(r"\s>{1,2}\s", text), "no redirection to a file"
    assert not re.search(r"(Write-\w+|Out-\w+)[^\n]*\$(secret|bytes|signingKey|veeamPassword|Value)\b", text, re.IGNORECASE)


def test_the_passwords_only_reach_their_checks_and_the_vault():
    allowed = {
        "secret": (
            r"^\s*\$secret\s*=\s*\[RpVaultCredential\]::Read\(\$CredentialTarget\)$",
            r"^\s*if \(-not \$secret\) \{$",
            r"^\s*\$bytes, \$secret, \[Security\.Cryptography\.X509Certificates\.X509KeyStorageFlags\]::EphemeralKeySet\)$",
            r"^\s*Set-VaultValue 'graph_cert_password' \$secret$",
            r"^\s*\$secret = \$null; \$veeamPassword = \$null; \$signingKey = \$null; \$bytes = \$null$",
        ),
        "veeamPassword": (
            r"^\s*\$veeamPassword\s*=\s*\[RpVaultCredential\]::Read\(\$VeeamCredentialTarget\)$",
            r"^\s*if \(-not \$veeamPassword\) \{$",
            r"^\s*Set-VaultValue 'veeam_password' \$veeamPassword$",
            r"^\s*\$secret = \$null; \$veeamPassword = \$null; \$signingKey = \$null; \$bytes = \$null$",
        ),
    }
    for variable, patterns in allowed.items():
        for number, line in enumerate(script_text().splitlines(), 1):
            if re.search(rf"\${variable}\b", line) and not line.lstrip().startswith("#"):
                assert any(re.search(p, line) for p in patterns), f"line {number} uses ${variable}: {line.strip()}"


def test_the_value_goes_to_rpworker_on_stdin_and_never_on_its_command_line():
    text = script_text()
    assert re.search(r"^\s*\$Value \| & \$Worker vault set \$Name @vaultArgs$", text, re.MULTILINE)
    assert not re.search(r"vault set \$Name[^\n]*\$Value", text)
    assert "$OutputEncoding = [Text.UTF8Encoding]::new($false)" in text


@pytest.mark.skipif(not HAVE_PWSH, reason="PowerShell 7 not installed")
def test_script_parses():
    command = (
        "$e = $null; $null = [System.Management.Automation.Language.Parser]::ParseFile("
        f"'{SCRIPT}', [ref]$null, [ref]$e); $e | ForEach-Object {{ $_.ToString() }}; exit $e.Count"
    )
    result = run_pwsh(command)
    assert result.returncode == 0, result.stdout + result.stderr


# ---- end to end on Windows, with a throwaway PFX, credentials and a stub Worker ---------------


@pytest.fixture
def lab_pfx(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "RestoreProof Worker (test)")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    data = pkcs12.serialize_key_and_certificates(
        b"rp-worker", key, cert, None, serialization.BestAvailableEncryption(PASSWORD_SENTINEL.encode())
    )
    path = tmp_path / "worker-graph.pfx"
    path.write_bytes(data)
    return path


@pytest.fixture
def stub(tmp_path):
    """The stub Worker and its log: {"worker": <path>, "log": <path>}."""
    worker = tmp_path / "rpworker-stub.ps1"
    worker.write_text(STUB, encoding="utf-8")
    log = tmp_path / "stub.log"
    return {"worker": worker, "log": log}


def stub_calls(stub) -> list[tuple[str, str]]:
    """Each call the stub got: (its arguments, the stdin line)."""
    if not stub["log"].exists():
        return []
    calls = []
    for line in stub["log"].read_text(encoding="utf-8-sig").splitlines():
        words, _, value = line.partition("|")
        calls.append((words, value))
    return calls


CRED_HELPER = """
Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices;
public static class RpTestCred {
  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  struct CREDENTIAL { public int Flags; public int Type; public string TargetName; public string Comment;
    public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten; public int CredentialBlobSize; public IntPtr CredentialBlob;
    public int Persist; public int AttributeCount; public IntPtr Attributes; public string TargetAlias; public string UserName; }
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool CredWriteW(ref CREDENTIAL c, int f);
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] static extern bool CredDeleteW(string t, int type, int f);
  public static void Write(string t, string secret) {
    var c = new CREDENTIAL(); c.Type = 1; c.TargetName = t; c.UserName = "u"; c.Persist = 1;
    c.CredentialBlobSize = secret.Length * 2; c.CredentialBlob = Marshal.StringToCoTaskMemUni(secret);
    try { if (!CredWriteW(ref c, 0)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()); }
    finally { Marshal.ZeroFreeCoTaskMemUnicode(c.CredentialBlob); } }
  public static void Delete(string t) { CredDeleteW(t, 1, 0); } }'
"""


def with_credentials(body: str, *, pfx_password: str | None = PASSWORD_SENTINEL,
                     veeam_password: str | None = VEEAM_SENTINEL, key: str | None = None) -> str:
    # Throwaway targets, with an entry only when a value is given: no test reads the lab's own.
    base = f"RestoreProof Lab - test {uuid.uuid4()}"
    writes = []
    if pfx_password is not None:
        writes.append(f"[RpTestCred]::Write($target, '{pfx_password}')")
    if veeam_password is not None:
        writes.append(f"[RpTestCred]::Write($veeamTarget, '{veeam_password}')")
    if key is not None:
        writes.append(f"[RpTestCred]::Write($keyTarget, '{key}')")
    return CRED_HELPER + f"""
        $target = '{base}'
        $veeamTarget = '{base} veeam'
        $keyTarget = '{base} key'
        {'; '.join(writes)}
        try {{ {body} }} finally {{ [RpTestCred]::Delete($target); [RpTestCred]::Delete($veeamTarget); [RpTestCred]::Delete($keyTarget) }}
    """


def invoke(lab_pfx, stub, *, extra: str = "", vault: str = "") -> str:
    vault_arg = f" -VaultPath '{vault}'" if vault else ""
    return (
        f". '{SCRIPT}' -Worker '{stub['worker']}' -PfxPath '{lab_pfx}' -CredentialTarget $target "
        f"-VeeamCredentialTarget $veeamTarget -SigningKeyTarget $keyTarget -VeeamUser 'LAB\\rp-veeam'{vault_arg}{extra}"
    )


@pytest.mark.skipif(not WINDOWS_PWSH, reason="Credential Manager, Windows only")
def test_it_feeds_the_five_values_to_vault_set_on_stdin_in_order(lab_pfx, stub):
    expected_b64 = base64.b64encode(lab_pfx.read_bytes()).decode("ascii")
    result = run_pwsh(with_credentials(invoke(lab_pfx, stub, vault=r"C:\x\v.bin"), key=KEY_SENTINEL),
                      env={"RP_STUB_LOG": str(stub["log"])})
    out = result.stdout
    assert result.returncode == 0, out + result.stderr
    assert stub_calls(stub) == [
        (r"vault set veeam_username --vault C:\x\v.bin", "LAB\\rp-veeam"),
        (r"vault set veeam_password --vault C:\x\v.bin", VEEAM_SENTINEL),
        (r"vault set graph_cert_pfx_base64 --vault C:\x\v.bin", expected_b64),
        (r"vault set graph_cert_password --vault C:\x\v.bin", PASSWORD_SENTINEL),
        (r"vault set signing_key_base64 --vault C:\x\v.bin", KEY_SENTINEL),
        (r"vault list --vault C:\x\v.bin", ""),
    ]
    # rpworker's own lines come through; no value does.
    assert "set veeam_username in <stub>" in out
    assert "<stub list>" in out
    for sentinel in (PASSWORD_SENTINEL, VEEAM_SENTINEL, KEY_SENTINEL, expected_b64):
        assert sentinel not in out + result.stderr


@pytest.mark.skipif(not WINDOWS_PWSH, reason="Credential Manager, Windows only")
def test_without_a_vault_path_rpworker_reads_its_default_vault(lab_pfx, stub):
    result = run_pwsh(with_credentials(invoke(lab_pfx, stub), key=KEY_SENTINEL), env={"RP_STUB_LOG": str(stub["log"])})
    assert result.returncode == 0, result.stdout + result.stderr
    assert [words for words, _ in stub_calls(stub)] == [
        "vault set veeam_username", "vault set veeam_password", "vault set graph_cert_pfx_base64",
        "vault set graph_cert_password", "vault set signing_key_base64", "vault list",
    ]


@pytest.mark.skipif(not WINDOWS_PWSH, reason="Credential Manager, Windows only")
def test_without_a_signing_key_it_sets_four_with_a_notice_and_does_not_fail(lab_pfx, stub):
    result = run_pwsh(with_credentials(invoke(lab_pfx, stub)), env={"RP_STUB_LOG": str(stub["log"])})
    out = result.stdout
    assert result.returncode == 0, out + result.stderr
    assert [words for words, _ in stub_calls(stub)] == [
        "vault set veeam_username", "vault set veeam_password", "vault set graph_cert_pfx_base64",
        "vault set graph_cert_password", "vault list",
    ]
    assert "skipped signing_key_base64: Credential Manager has no 'RestoreProof Lab - test " in out
    assert "new-signing-key" in out


@pytest.mark.skipif(not WINDOWS_PWSH, reason="Credential Manager, Windows only")
@pytest.mark.parametrize(
    "entry",
    ["not-a-key-SENTINEL", KEY_SENTINEL[:-1], KEY_SENTINEL + "A", "-----BEGIN PRIVATE KEY-----"],
)
def test_an_entry_that_is_not_a_signing_key_sets_nothing_and_is_not_shown(lab_pfx, stub, entry):
    body = f"""
        try {{ {invoke(lab_pfx, stub)}; 'no error' }}
        catch {{ "error: $($_.Exception.Message)" }}
    """
    result = run_pwsh(with_credentials(body, key=entry), env={"RP_STUB_LOG": str(stub["log"])})
    out = result.stdout
    assert "isn't an Ed25519 signing key" in out, out + result.stderr
    assert "new-signing-key --replace" in out
    assert "Nothing was set" in out
    assert stub_calls(stub) == []
    assert entry not in out.split("error:", 1)[1] + result.stderr


@pytest.mark.skipif(not WINDOWS_PWSH, reason="Credential Manager, Windows only")
@pytest.mark.parametrize(
    ("pfx_password", "veeam_password", "message"),
    [
        (None, VEEAM_SENTINEL, "has no generic credential"),
        ("wrong-password-SENTINEL", VEEAM_SENTINEL, "can't be opened with the password"),
        (PASSWORD_SENTINEL, None, "has no generic credential 'RestoreProof Lab - test"),
    ],
)
def test_a_missing_or_wrong_credential_sets_nothing(lab_pfx, stub, pfx_password, veeam_password, message):
    body = f"""
        try {{ {invoke(lab_pfx, stub)}; 'no error' }}
        catch {{ "error: $($_.Exception.Message)" }}
    """
    result = run_pwsh(with_credentials(body, pfx_password=pfx_password, veeam_password=veeam_password),
                      env={"RP_STUB_LOG": str(stub["log"])})
    assert message in result.stdout, result.stdout + result.stderr
    assert stub_calls(stub) == []
    assert "wrong-password-SENTINEL" not in result.stdout.split("error:", 1)[-1]


@pytest.mark.skipif(not WINDOWS_PWSH, reason="Credential Manager, Windows only")
def test_a_missing_pfx_or_worker_names_the_file(lab_pfx, stub, tmp_path):
    missing = tmp_path / "nope.pfx"
    body = f"""
        try {{ . '{SCRIPT}' -Worker '{stub["worker"]}' -PfxPath '{missing}' -CredentialTarget $target -VeeamCredentialTarget $veeamTarget -SigningKeyTarget $keyTarget; 'no error' }}
        catch {{ "error: $($_.Exception.Message)" }}
        try {{ . '{SCRIPT}' -Worker '{tmp_path / "no-rpworker.exe"}' -PfxPath '{lab_pfx}' -CredentialTarget $target -VeeamCredentialTarget $veeamTarget -SigningKeyTarget $keyTarget; 'no error' }}
        catch {{ "error: $($_.Exception.Message)" }}
    """
    result = run_pwsh(with_credentials(body), env={"RP_STUB_LOG": str(stub["log"])})
    assert f"No certificate file at {missing}" in result.stdout, result.stdout + result.stderr
    assert "new-worker-app.ps1" in result.stdout
    assert "No Worker at" in result.stdout
    assert stub_calls(stub) == []


@pytest.mark.skipif(not WINDOWS_PWSH, reason="Credential Manager, Windows only")
def test_a_set_that_fails_stops_the_script_with_its_exit_code(lab_pfx, stub):
    body = f"""
        try {{ {invoke(lab_pfx, stub)}; 'no error' }}
        catch {{ "error: $($_.Exception.Message)" }}
    """
    result = run_pwsh(with_credentials(body, key=KEY_SENTINEL),
                      env={"RP_STUB_LOG": str(stub["log"]), "RP_STUB_FAIL": "graph_cert_pfx_base64"})
    assert "rpworker vault set graph_cert_pfx_base64 failed (exit 1); nothing more was set" in result.stdout, result.stdout + result.stderr
    assert [words for words, _ in stub_calls(stub)] == ["vault set veeam_username", "vault set veeam_password"]


@pytest.mark.skipif(not WINDOWS_PWSH, reason="Credential Manager, Windows only")
def test_a_damaged_pfx_is_not_blamed_on_the_password(tmp_path, stub):
    damaged = tmp_path / "worker-graph.pfx"
    damaged.write_bytes(b"this is not a PFX file at all" * 10)
    body = f"""
        try {{ . '{SCRIPT}' -Worker '{stub["worker"]}' -PfxPath '{damaged}' -CredentialTarget $target -VeeamCredentialTarget $veeamTarget -SigningKeyTarget $keyTarget; 'no error' }}
        catch {{ "error: $($_.Exception.Message)" }}
    """
    result = run_pwsh(with_credentials(body), env={"RP_STUB_LOG": str(stub["log"])})
    out = result.stdout
    assert "can't be read as a PFX" in out, out + result.stderr
    assert "can't be opened with the password" not in out
    assert stub_calls(stub) == []
    assert PASSWORD_SENTINEL not in out + result.stderr

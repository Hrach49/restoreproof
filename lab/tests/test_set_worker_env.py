"""lab/entra/set-worker-env.ps1 (W2.1): fills RP_GRAPH_CERT_PFX_BASE64 and RP_GRAPH_CERT_PASSWORD
in the dot-sourcing session from the lab's PFX and Credential Manager, never prints or writes them."""

import base64
import datetime as dt
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

from seeder import LAB_DIR, worker_app

SCRIPT = LAB_DIR / "entra" / "set-worker-env.ps1"
PASSWORD_SENTINEL = "pfx-password-SENTINEL-DO-NOT-LEAK"
HAVE_PWSH = shutil.which("pwsh") is not None
WINDOWS_PWSH = sys.platform == "win32" and HAVE_PWSH


def script_text() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def run_pwsh(command: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", command], capture_output=True, text=True, timeout=120
    )


@pytest.mark.parametrize(
    "name, value",
    [("CredTarget", worker_app.CREDENTIAL_TARGET), ("PfxName", worker_app.PFX_NAME)],
)
def test_constants_match_the_checker(name, value):
    match = re.search(rf"^\s*\${name}\s*=\s*'([^']*)'", script_text(), re.MULTILINE)
    assert match, f"${name} = '...' not found"
    assert match.group(1) == value


def test_it_sets_exactly_the_two_worker_variables():
    assert set(re.findall(r"\$env:(RP_\w+)\s*=", script_text())) == {"RP_GRAPH_CERT_PFX_BASE64", "RP_GRAPH_CERT_PASSWORD"}


def test_nothing_is_written_to_disk_or_printed():
    text = script_text()
    for banned in ("Set-Content", "Add-Content", "Out-File", "Export-", "Start-Transcript", "WriteAll", "setx", "[Environment]::SetEnvironmentVariable"):
        assert banned not in text, banned
    assert not re.search(r"\s>{1,2}\s", text), "no redirection to a file"
    assert not re.search(r"(Write-\w+|Out-\w+)[^\n]*\$(secret|bytes|env:RP_)", text, re.IGNORECASE)


def test_the_password_only_reaches_the_pfx_check_and_the_variable():
    allowed = (
        r"^\s*\$secret\s*=\s*\[RpWorkerEnvCredential\]::Read\(\$CredentialTarget\)$",
        r"^\s*if \(-not \$secret\) \{$",
        r"^\s*\$bytes, \$secret, \[Security\.Cryptography\.X509Certificates\.X509KeyStorageFlags\]::EphemeralKeySet\)$",
        r"^\s*\$env:RP_GRAPH_CERT_PASSWORD = \$secret$",
    )
    for number, line in enumerate(script_text().splitlines(), 1):
        if re.search(r"\$secret\b", line) and not line.lstrip().startswith("#"):
            assert any(re.search(p, line) for p in allowed), f"line {number} uses $secret: {line.strip()}"


@pytest.mark.skipif(not HAVE_PWSH, reason="PowerShell 7 not installed")
def test_script_parses():
    command = (
        "$e = $null; $null = [System.Management.Automation.Language.Parser]::ParseFile("
        f"'{SCRIPT}', [ref]$null, [ref]$e); $e | ForEach-Object {{ $_.ToString() }}; exit $e.Count"
    )
    result = run_pwsh(command)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.skipif(not HAVE_PWSH, reason="PowerShell 7 not installed")
def test_run_without_dot_sourcing_it_refuses_and_sets_nothing():
    result = run_pwsh(f"& '{SCRIPT}'; \"exit=$LASTEXITCODE set=$(Test-Path env:RP_GRAPH_CERT_PASSWORD)\"")
    assert "exit=1 set=False" in result.stdout
    assert "Dot-source this script" in result.stderr


# ---- end to end on Windows, with a throwaway PFX and credential ----------------------------


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


def with_credential(secret: str | None, body: str) -> str:
    target = f"RestoreProof Lab - test {uuid.uuid4()}"
    write = f"[RpTestCred]::Write('{target}', '{secret}')" if secret is not None else ""
    return CRED_HELPER + f"""
        $target = '{target}'
        {write}
        try {{ {body} }} finally {{ [RpTestCred]::Delete($target) }}
    """


@pytest.mark.skipif(not WINDOWS_PWSH, reason="Credential Manager, Windows only")
def test_dot_sourced_it_sets_both_variables_then_clear_removes_them(lab_pfx):
    expected_b64 = base64.b64encode(lab_pfx.read_bytes()).decode("ascii")
    body = f"""
        . '{SCRIPT}' -PfxPath '{lab_pfx}' -CredentialTarget $target
        "pfx: $($env:RP_GRAPH_CERT_PFX_BASE64 -ceq '{expected_b64}')"
        "password: $($env:RP_GRAPH_CERT_PASSWORD -ceq '{PASSWORD_SENTINEL}')"
        "left behind: $(@(Get-Variable | Where-Object {{ $_.Value -is [string] -and $_.Value -ceq '{PASSWORD_SENTINEL}' }}).Count)"
        "script variables: [$(@('Clear', 'PfxPath', 'CredentialTarget', 'secret', 'bytes') | Where-Object {{ Test-Path "variable:$_" }})]"
        . '{SCRIPT}' -Clear
        "after clear: $(Test-Path env:RP_GRAPH_CERT_PASSWORD) $(Test-Path env:RP_GRAPH_CERT_PFX_BASE64)"
    """
    result = run_pwsh(with_credential(PASSWORD_SENTINEL, body))
    out = result.stdout
    assert result.returncode == 0, out + result.stderr
    assert "set RP_GRAPH_CERT_PFX_BASE64 and RP_GRAPH_CERT_PASSWORD for this session" in out
    assert "pfx: True" in out and "password: True" in out
    assert "left behind: 0" in out
    assert "script variables: []" in out
    assert "cleared RP_GRAPH_CERT_PFX_BASE64 and RP_GRAPH_CERT_PASSWORD" in out
    assert "after clear: False False" in out
    assert PASSWORD_SENTINEL not in out + result.stderr


@pytest.mark.skipif(not WINDOWS_PWSH, reason="Credential Manager, Windows only")
@pytest.mark.parametrize(
    ("secret", "message"),
    [
        (None, "has no generic credential"),
        ("wrong-password-SENTINEL", "can't be opened with the password"),
    ],
)
def test_a_missing_or_wrong_password_sets_nothing(lab_pfx, secret, message):
    body = f"""
        try {{ . '{SCRIPT}' -PfxPath '{lab_pfx}' -CredentialTarget $target; 'no error' }}
        catch {{ "error: $($_.Exception.Message)" }}
        "set: $(Test-Path env:RP_GRAPH_CERT_PASSWORD) $(Test-Path env:RP_GRAPH_CERT_PFX_BASE64)"
    """
    result = run_pwsh(with_credential(secret, body))
    assert message in result.stdout, result.stdout + result.stderr
    assert "set: False False" in result.stdout
    assert "wrong-password-SENTINEL" not in result.stdout.split("error:", 1)[1]


@pytest.mark.skipif(not WINDOWS_PWSH, reason="Credential Manager, Windows only")
def test_a_missing_pfx_names_the_file_and_the_setup_script(tmp_path):
    missing = tmp_path / "nope.pfx"
    body = f"""
        try {{ . '{SCRIPT}' -PfxPath '{missing}' -CredentialTarget $target; 'no error' }}
        catch {{ "error: $($_.Exception.Message)" }}
    """
    result = run_pwsh(with_credential(PASSWORD_SENTINEL, body))
    assert f"No certificate file at {missing}" in result.stdout, result.stdout + result.stderr
    assert "new-worker-app.ps1" in result.stdout


# ---- review of W2.1 --------------------------------------------------------------------------


@pytest.mark.skipif(not WINDOWS_PWSH, reason="Credential Manager, Windows only")
def test_a_relative_pfx_path_is_read_where_powershell_is(lab_pfx):
    # Test-Path resolves against PowerShell's location, [IO.File] against the process's
    # directory, which Set-Location doesn't move: both must read the same file.
    expected_b64 = base64.b64encode(lab_pfx.read_bytes()).decode("ascii")
    body = f"""
        Set-Location -LiteralPath '{lab_pfx.parent}'
        . '{SCRIPT}' -PfxPath '.\\{lab_pfx.name}' -CredentialTarget $target
        "pfx: $($env:RP_GRAPH_CERT_PFX_BASE64 -ceq '{expected_b64}')"
    """
    result = run_pwsh(with_credential(PASSWORD_SENTINEL, body))
    assert "pfx: True" in result.stdout, result.stdout + result.stderr


@pytest.mark.skipif(not WINDOWS_PWSH, reason="Credential Manager, Windows only")
def test_the_callers_own_variables_of_the_same_names_are_kept(lab_pfx):
    # Dot-sourced, the param block binds in the caller's scope: it must not take over (and
    # then remove) variables the caller already had.
    body = f"""
        $PfxPath = 'mine'; $CredentialTarget = 'theirs'; $Clear = 'kept'
        . '{SCRIPT}' -PfxPath '{lab_pfx}' -CredentialTarget $target
        "after: $PfxPath $CredentialTarget $Clear"
    """
    result = run_pwsh(with_credential(PASSWORD_SENTINEL, body))
    assert "after: mine theirs kept" in result.stdout, result.stdout + result.stderr


@pytest.mark.skipif(not WINDOWS_PWSH, reason="Credential Manager, Windows only")
def test_a_failure_leaves_no_script_variable_behind(tmp_path):
    body = f"""
        try {{ . '{SCRIPT}' -PfxPath '{tmp_path / "nope.pfx"}' -CredentialTarget $target }} catch {{ }}
        "left: [$(@(Get-Variable -Name 'RpWorkerEnv*', 'PfxPath', 'CredentialTarget', 'Clear' -ErrorAction SilentlyContinue).Name)]"
    """
    result = run_pwsh(with_credential(PASSWORD_SENTINEL, body))
    assert "left: []" in result.stdout, result.stdout + result.stderr


@pytest.mark.skipif(not WINDOWS_PWSH, reason="Credential Manager, Windows only")
def test_a_damaged_pfx_is_not_blamed_on_the_password(tmp_path):
    damaged = tmp_path / "worker-graph.pfx"
    damaged.write_bytes(b"this is not a PFX file at all" * 10)
    body = f"""
        try {{ . '{SCRIPT}' -PfxPath '{damaged}' -CredentialTarget $target; 'no error' }}
        catch {{ "error: $($_.Exception.Message)" }}
        "set: $(Test-Path env:RP_GRAPH_CERT_PASSWORD)"
    """
    result = run_pwsh(with_credential(PASSWORD_SENTINEL, body))
    out = result.stdout
    assert "can't be read as a PFX" in out, out + result.stderr
    assert "can't be opened with the password" not in out
    assert "set: False" in out
    assert PASSWORD_SENTINEL not in out + result.stderr

<#
.SYNOPSIS
    Sets the Worker's Graph certificate and signing key variables in this PowerShell session
    (W2.1, W4.3).

.DESCRIPTION
    Until the Worker's DPAPI vault lands (W4.5), rpworker reads the RestoreProof Worker app's
    certificate and its signing key from three environment variables:

      RP_GRAPH_CERT_PFX_BASE64  the PFX file, Base64
      RP_GRAPH_CERT_PASSWORD    its password
      RP_SIGNING_KEY_BASE64     the Ed25519 signing key: one line, Base64 of its PKCS#8 DER

    This script fills the first two from where lab\entra\new-worker-app.ps1 keeps the certificate:
    the PFX file %LOCALAPPDATA%\RestoreProof\lab\worker-graph.pfx and the password in Windows
    Credential Manager (generic credential "RestoreProof Lab - Worker Graph app PFX"). It first
    checks that the password opens the PFX.

    The third comes from the generic credential "RestoreProof Lab - Worker signing key", which
    `python -m seeder new-signing-key` (in lab\) makes. Only `rpworker test --evidence` needs it,
    so when there is no such credential the script sets the other two, says that it skipped this
    one and does not fail. An entry that isn't a signing key stops it before anything is set, and
    takes an RP_SIGNING_KEY_BASE64 left from an earlier call out of the session.

    It never prints any of the values and never writes anything to disk: the variables live only
    in this PowerShell process and go away when it ends.

    Dot-source it, so the variables stay in your session; run any other way, it refuses.
    -Clear removes all three variables again.

.EXAMPLE
    . lab\entra\set-worker-env.ps1
    . lab\entra\set-worker-env.ps1 -Clear
#>
[CmdletBinding()]
param(
    # Dot-sourced, these bind in the caller's scope, so their variables have names no caller
    # uses: a caller's own $PfxPath or $Clear is neither taken over nor removed. The parameters
    # keep their short names through the aliases.
    [Alias('Clear')][switch]$RpWorkerEnvClear,
    [Alias('PfxPath')][string]$RpWorkerEnvPfxPath = '',
    [Alias('CredentialTarget')][string]$RpWorkerEnvCredentialTarget = '',
    [Alias('SigningKeyTarget')][string]$RpWorkerEnvSigningKeyTarget = ''
)

if ($MyInvocation.InvocationName -ne '.') {
    # `exit` ends only this script when it was started with & or by path, and pwsh -File with 1.
    Write-Error "Dot-source this script so the variables stay in your session: . $($MyInvocation.MyCommand.Path)" -ErrorAction Continue
    exit 1
}

# A child scope: none of the script's own variables (the password above all) are left behind in
# the dot-sourcing session. Only the three environment variables, which are process-wide, remain,
# and the parameters' variables go in `finally`, on a failure too.
try {
& {
    param([bool]$Clear, [string]$PfxPath, [string]$CredentialTarget, [string]$SigningKeyTarget)
    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest

    $CredTarget = 'RestoreProof Lab - Worker Graph app PFX'
    $PfxName = 'worker-graph.pfx'
    $SetupScript = 'lab\entra\new-worker-app.ps1'
    $SigningKeyCredTarget = 'RestoreProof Lab - Worker signing key'
    # What `python -m seeder new-signing-key` stores and the Worker takes: 64 characters of
    # standard Base64, the 48 bytes of an Ed25519 key's PKCS#8 DER (16 fixed bytes, then the key).
    $SigningKeyShape = '^MC4CAQAwBQYDK2VwBCIEI[A-P][A-Za-z0-9+/]{42}\z'

    if ($Clear) {
        Remove-Item Env:RP_GRAPH_CERT_PFX_BASE64, Env:RP_GRAPH_CERT_PASSWORD, Env:RP_SIGNING_KEY_BASE64 -ErrorAction SilentlyContinue
        Write-Host 'cleared RP_GRAPH_CERT_PFX_BASE64, RP_GRAPH_CERT_PASSWORD and RP_SIGNING_KEY_BASE64 for this session'
        return
    }

    if (-not $CredentialTarget) { $CredentialTarget = $CredTarget }
    if (-not $SigningKeyTarget) { $SigningKeyTarget = $SigningKeyCredTarget }
    if (-not $PfxPath) { $PfxPath = Join-Path $env:LOCALAPPDATA "RestoreProof\lab\$PfxName" }
    if (-not (Test-Path -LiteralPath $PfxPath -PathType Leaf)) {
        throw "No certificate file at $PfxPath. Create it with $SetupScript (lab/README.md)."
    }
    # A relative path, or ~, as PowerShell reads it: [IO.File] would resolve it against the
    # process's directory, which Set-Location doesn't move.
    $PfxPath = (Resolve-Path -LiteralPath $PfxPath).ProviderPath

    if (-not ('RpWorkerEnvCredential' -as [type])) {
        Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices;
public static class RpWorkerEnvCredential {
  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  struct CREDENTIAL { public int Flags; public int Type; public string TargetName; public string Comment;
    public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten; public int CredentialBlobSize; public IntPtr CredentialBlob;
    public int Persist; public int AttributeCount; public IntPtr Attributes; public string TargetAlias; public string UserName; }
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool CredReadW(string t, int type, int f, out IntPtr c);
  [DllImport("advapi32.dll")] static extern void CredFree(IntPtr p);
  // A generic credential's blob, as UTF-16LE (how CredWriteW and cmdkey store a password).
  // null only when there is no such credential (ERROR_NOT_FOUND); any other failure throws.
  public static string Read(string t) {
    IntPtr p;
    if (!CredReadW(t, 1, 0, out p)) {
      int error = Marshal.GetLastWin32Error();
      if (error == 1168) return null;
      throw new System.ComponentModel.Win32Exception(error);
    }
    try { var c = (CREDENTIAL)Marshal.PtrToStructure(p, typeof(CREDENTIAL));
          if (c.CredentialBlobSize == 0) return "";
          return Marshal.PtrToStringUni(c.CredentialBlob, c.CredentialBlobSize / 2); } finally { CredFree(p); } }
}
"@
    }

    $secret = [RpWorkerEnvCredential]::Read($CredentialTarget)
    if (-not $secret) {
        throw "Credential Manager has no generic credential '$CredentialTarget'. $SetupScript creates it together with the certificate."
    }
    $bytes = [IO.File]::ReadAllBytes($PfxPath)

    # The password must open the PFX, or the Worker would fail later with a less clear message.
    # EphemeralKeySet: the private key is never written to a key container on disk.
    try {
        $x509 = [Security.Cryptography.X509Certificates.X509Certificate2]::new(
            $bytes, $secret, [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
        $hasKey = $x509.HasPrivateKey
        $x509.Dispose()
    } catch [Security.Cryptography.CryptographicException] {
        # ERROR_INVALID_PASSWORD (0x80070056): a PFX, and the password doesn't open it. Anything
        # else is the file's fault, not the password's.
        if ($_.Exception.HResult -eq -2147024810) {
            throw "$PfxPath can't be opened with the password in Credential Manager ('$CredentialTarget'). The file and the password must come from the same $SetupScript run."
        }
        throw "$PfxPath can't be read as a PFX ($($_.Exception.Message.Trim())). Re-create it with $SetupScript."
    }
    if (-not $hasKey) { throw "$PfxPath holds no private key. Re-create it with $SetupScript." }

    # The signing key (W4.3). No entry is no error: only `rpworker test --evidence` signs. An
    # entry of another shape is one, before anything is set, and its value is never shown.
    $signingKey = [RpWorkerEnvCredential]::Read($SigningKeyTarget)
    if ($null -ne $signingKey -and $signingKey -cnotmatch $SigningKeyShape) {
        # A key left from an earlier call goes here too, or the next run would sign with it.
        Remove-Item Env:RP_SIGNING_KEY_BASE64 -ErrorAction SilentlyContinue
        throw "The Credential Manager entry '$SigningKeyTarget' isn't an Ed25519 signing key (one line, Base64 of its PKCS#8 DER). Nothing was set. Make a new key in lab\ with: uv run python -m seeder new-signing-key --replace (every signature made with the old key is then orphaned)."
    }

    $env:RP_GRAPH_CERT_PFX_BASE64 = [Convert]::ToBase64String($bytes)
    $env:RP_GRAPH_CERT_PASSWORD = $secret
    if ($null -eq $signingKey) {
        # A value left from an earlier call goes too: the session never holds a key that
        # Credential Manager doesn't.
        Remove-Item Env:RP_SIGNING_KEY_BASE64 -ErrorAction SilentlyContinue
        Write-Host 'set RP_GRAPH_CERT_PFX_BASE64 and RP_GRAPH_CERT_PASSWORD for this session'
        Write-Host "skipped RP_SIGNING_KEY_BASE64: Credential Manager has no '$SigningKeyTarget'. Only rpworker test --evidence needs it; make the key in lab\ with: uv run python -m seeder new-signing-key"
    } else {
        $env:RP_SIGNING_KEY_BASE64 = $signingKey
        Write-Host 'set RP_GRAPH_CERT_PFX_BASE64, RP_GRAPH_CERT_PASSWORD and RP_SIGNING_KEY_BASE64 for this session'
    }
} $RpWorkerEnvClear.IsPresent $RpWorkerEnvPfxPath $RpWorkerEnvCredentialTarget $RpWorkerEnvSigningKeyTarget
} finally {
    Remove-Variable RpWorkerEnvClear, RpWorkerEnvPfxPath, RpWorkerEnvCredentialTarget, RpWorkerEnvSigningKeyTarget -ErrorAction SilentlyContinue
}

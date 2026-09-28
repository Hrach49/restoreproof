<#
.SYNOPSIS
    Sets the Worker's Graph certificate variables in this PowerShell session (W2.1).

.DESCRIPTION
    Until the Worker's DPAPI vault lands (W4.5), rpworker reads the RestoreProof Worker app's
    certificate from two environment variables:

      RP_GRAPH_CERT_PFX_BASE64  the PFX file, Base64
      RP_GRAPH_CERT_PASSWORD    its password

    This script fills them from where lab\entra\new-worker-app.ps1 keeps the certificate: the PFX
    file %LOCALAPPDATA%\RestoreProof\lab\worker-graph.pfx and the password in Windows Credential
    Manager (generic credential "RestoreProof Lab - Worker Graph app PFX"). It first checks that
    the password opens the PFX. It never prints either value and never writes anything to disk:
    the variables live only in this PowerShell process and go away when it ends.

    Dot-source it, so the variables stay in your session; run any other way, it refuses.
    -Clear removes both variables again.

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
    [Alias('CredentialTarget')][string]$RpWorkerEnvCredentialTarget = ''
)

if ($MyInvocation.InvocationName -ne '.') {
    # `exit` ends only this script when it was started with & or by path, and pwsh -File with 1.
    Write-Error "Dot-source this script so the variables stay in your session: . $($MyInvocation.MyCommand.Path)" -ErrorAction Continue
    exit 1
}

# A child scope: none of the script's own variables (the password above all) are left behind in
# the dot-sourcing session. Only the two environment variables, which are process-wide, remain,
# and the parameters' variables go in `finally`, on a failure too.
try {
& {
    param([bool]$Clear, [string]$PfxPath, [string]$CredentialTarget)
    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest

    $CredTarget = 'RestoreProof Lab - Worker Graph app PFX'
    $PfxName = 'worker-graph.pfx'
    $SetupScript = 'lab\entra\new-worker-app.ps1'

    if ($Clear) {
        Remove-Item Env:RP_GRAPH_CERT_PFX_BASE64, Env:RP_GRAPH_CERT_PASSWORD -ErrorAction SilentlyContinue
        Write-Host 'cleared RP_GRAPH_CERT_PFX_BASE64 and RP_GRAPH_CERT_PASSWORD for this session'
        return
    }

    if (-not $CredentialTarget) { $CredentialTarget = $CredTarget }
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

    $env:RP_GRAPH_CERT_PFX_BASE64 = [Convert]::ToBase64String($bytes)
    $env:RP_GRAPH_CERT_PASSWORD = $secret
    Write-Host 'set RP_GRAPH_CERT_PFX_BASE64 and RP_GRAPH_CERT_PASSWORD for this session'
} $RpWorkerEnvClear.IsPresent $RpWorkerEnvPfxPath $RpWorkerEnvCredentialTarget
} finally {
    Remove-Variable RpWorkerEnvClear, RpWorkerEnvPfxPath, RpWorkerEnvCredentialTarget -ErrorAction SilentlyContinue
}

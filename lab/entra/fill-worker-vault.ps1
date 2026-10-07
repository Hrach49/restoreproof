<#
.SYNOPSIS
    Fills the Worker's DPAPI vault from the lab's Credential Manager entries and PFX file (W4.5).

.DESCRIPTION
    Since W4.5 rpworker reads its five secrets from the vault (%ProgramData%\RestoreProof\vault.bin;
    docs/worker-config.md, "Secrets"), never from environment variables. This script feeds each
    value to `rpworker vault set <name>` on stdin, one process per value, so no value is ever on
    a command line, in an environment variable or in a file:

      veeam_username          -VeeamUser, default <COMPUTERNAME>\rp-veeam
      veeam_password          Credential Manager, "RestoreProof Lab - rp-veeam (local Veeam REST)"
      graph_cert_pfx_base64   the PFX file %LOCALAPPDATA%\RestoreProof\lab\worker-graph.pfx
      graph_cert_password     Credential Manager, "RestoreProof Lab - Worker Graph app PFX"
      signing_key_base64      Credential Manager, "RestoreProof Lab - Worker signing key"

    The PFX and its password come from lab\entra\new-worker-app.ps1, which first checks that the
    password opens the PFX. The signing key comes from `python -m seeder new-signing-key` (in
    lab\); only `rpworker test --evidence` needs it, so when there is no such entry the script
    sets the other four, says that it skipped this one and does not fail. An entry that isn't a
    signing key stops it before anything is set.

    It never prints any of the values, never writes anything itself (rpworker writes the vault),
    and ends with `rpworker vault list`. The default vault is under %ProgramData%, so run it from
    an elevated shell (the vault file's ACL is SYSTEM, Administrators and its owner); with
    -VaultPath it fills another vault file (`--vault`), which needs no elevation. PowerShell 7
    only: it pipes the values as UTF-8.

.EXAMPLE
    .\lab\entra\fill-worker-vault.ps1
    .\lab\entra\fill-worker-vault.ps1 -VaultPath C:\restoreproof-runs\lab-vault.bin
#>
[CmdletBinding()]
param(
    # rpworker.exe; default: the dev build beside this repository.
    [string]$Worker = '',
    # Passed to rpworker as --vault <file>; default: the Worker's default vault.
    [string]$VaultPath = '',
    [string]$VeeamUser = '',
    [string]$VeeamCredentialTarget = '',
    [string]$PfxPath = '',
    [string]$CredentialTarget = '',
    [string]$SigningKeyTarget = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$CredTarget = 'RestoreProof Lab - Worker Graph app PFX'
$PfxName = 'worker-graph.pfx'
$SetupScript = 'lab\entra\new-worker-app.ps1'
$SigningKeyCredTarget = 'RestoreProof Lab - Worker signing key'
$VeeamCredTarget = 'RestoreProof Lab - rp-veeam (local Veeam REST)'
# What `python -m seeder new-signing-key` stores and the Worker takes: 64 characters of
# standard Base64, the 48 bytes of an Ed25519 key's PKCS#8 DER (16 fixed bytes, then the key).
$SigningKeyShape = '^MC4CAQAwBQYDK2VwBCIEI[A-P][A-Za-z0-9+/]{42}\z'

if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw 'Run this script with PowerShell 7 (pwsh): it pipes each value to rpworker as UTF-8.'
}
# What a native command reads from a pipe: UTF-8, no BOM, whatever the console's code page.
$OutputEncoding = [Text.UTF8Encoding]::new($false)

if (-not $CredentialTarget) { $CredentialTarget = $CredTarget }
if (-not $SigningKeyTarget) { $SigningKeyTarget = $SigningKeyCredTarget }
if (-not $VeeamCredentialTarget) { $VeeamCredentialTarget = $VeeamCredTarget }
if (-not $VeeamUser) { $VeeamUser = "$env:COMPUTERNAME\rp-veeam" }
if (-not $PfxPath) { $PfxPath = Join-Path $env:LOCALAPPDATA "RestoreProof\lab\$PfxName" }
if (-not $Worker) { $Worker = Join-Path $PSScriptRoot '..\..\worker\build\dev\rpworker.exe' }
if (-not (Test-Path -LiteralPath $Worker -PathType Leaf)) {
    throw "No Worker at $Worker. Build it (cmake --build --preset dev in worker\) or pass -Worker."
}
$Worker = (Resolve-Path -LiteralPath $Worker).ProviderPath
if (-not (Test-Path -LiteralPath $PfxPath -PathType Leaf)) {
    throw "No certificate file at $PfxPath. Create it with $SetupScript (lab/README.md)."
}
# A relative path, or ~, as PowerShell reads it: [IO.File] would resolve it against the
# process's directory, which Set-Location doesn't move.
$PfxPath = (Resolve-Path -LiteralPath $PfxPath).ProviderPath
$vaultArgs = @()
if ($VaultPath) { $vaultArgs = @('--vault', $VaultPath) }

if (-not ('RpVaultCredential' -as [type])) {
    Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices;
public static class RpVaultCredential {
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

# One value into the vault: `rpworker vault set <name>` reads it from stdin, prints
# `set <name> in <file>` and exits 0, or says why not on stderr and exits 1 or 64.
function Set-VaultValue([string]$Name, [string]$Value) {
    $Value | & $Worker vault set $Name @vaultArgs
    if ($LASTEXITCODE -ne 0) { throw "rpworker vault set $Name failed (exit $LASTEXITCODE); nothing more was set" }
}

$secret = [RpVaultCredential]::Read($CredentialTarget)
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

$veeamPassword = [RpVaultCredential]::Read($VeeamCredentialTarget)
if (-not $veeamPassword) {
    throw "Credential Manager has no generic credential '$VeeamCredentialTarget' (docs/api/veeam-m365/README.md says how it is made). Nothing was set."
}

# The signing key (W4.3). No entry is no error: only `rpworker test --evidence` signs. An
# entry of another shape is one, before anything is set, and its value is never shown.
$signingKey = [RpVaultCredential]::Read($SigningKeyTarget)
if ($null -ne $signingKey -and $signingKey -cnotmatch $SigningKeyShape) {
    throw "The Credential Manager entry '$SigningKeyTarget' isn't an Ed25519 signing key (one line, Base64 of its PKCS#8 DER). Nothing was set. Make a new key in lab\ with: uv run python -m seeder new-signing-key --replace (every signature made with the old key is then orphaned)."
}

Set-VaultValue 'veeam_username' $VeeamUser
Set-VaultValue 'veeam_password' $veeamPassword
Set-VaultValue 'graph_cert_pfx_base64' ([Convert]::ToBase64String($bytes))
Set-VaultValue 'graph_cert_password' $secret
if ($null -eq $signingKey) {
    Write-Host "skipped signing_key_base64: Credential Manager has no '$SigningKeyTarget'. Only rpworker test --evidence needs it; make the key in lab\ with: uv run python -m seeder new-signing-key"
} else {
    Set-VaultValue 'signing_key_base64' $signingKey
}
$secret = $null; $veeamPassword = $null; $signingKey = $null; $bytes = $null

& $Worker vault list @vaultArgs
if ($LASTEXITCODE -ne 0) { throw "rpworker vault list failed (exit $LASTEXITCODE)" }

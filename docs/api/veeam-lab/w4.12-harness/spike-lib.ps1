# W4.12 (#135) spike harness, dot-sourced by the elevated shell. Nothing here runs as the
# service account; it only makes the service, serves the secrets over a named pipe and
# collects the output. Secrets are read from Windows Credential Manager (the user's) and the
# Worker Graph PFX file, held in this process, and written to the pipe only.
Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'
$script:SpikeDir = 'C:\ProgramData\RestoreProof\spike-w4.12'
$script:OutDir = Join-Path $script:SpikeDir 'out'
$script:Service = 'RpSpikeProbe'
$script:Pipe = 'rp-spike-w412-secrets'

if (-not ('RpSpikeCred' -as [type])) {
    Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices;
public static class RpSpikeCred {
  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  struct CREDENTIAL { public int Flags; public int Type; public string TargetName; public string Comment;
    public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten; public int CredentialBlobSize; public IntPtr CredentialBlob;
    public int Persist; public int AttributeCount; public IntPtr Attributes; public string TargetAlias; public string UserName; }
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool CredReadW(string t, int type, int f, out IntPtr c);
  [DllImport("advapi32.dll")] static extern void CredFree(IntPtr p);
  public static string Read(string t) {
    IntPtr p;
    if (!CredReadW(t, 1, 0, out p)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "Credential Manager: " + t);
    try { var c = (CREDENTIAL)Marshal.PtrToStructure(p, typeof(CREDENTIAL));
          return Marshal.PtrToStringUni(c.CredentialBlob, c.CredentialBlobSize / 2); } finally { CredFree(p); } }
}
"@
}

# The Worker's secret variables, as rpworker reads them (worker/include/rp/secrets.hpp).
function Get-SpikeSecrets {
    $pfxPath = Join-Path $env:LOCALAPPDATA 'RestoreProof\lab\worker-graph.pfx'
    [ordered]@{
        RP_VEEAM_USERNAME        = 'DESKTOP-P55CDUM\rp-veeam'
        RP_VEEAM_PASSWORD        = [RpSpikeCred]::Read('RestoreProof Lab - rp-veeam (local Veeam REST)')
        RP_GRAPH_CERT_PFX_BASE64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($pfxPath))
        RP_GRAPH_CERT_PASSWORD   = [RpSpikeCred]::Read('RestoreProof Lab - Worker Graph app PFX')
    }
}

# Sets the current user's Worker variables in this process (for graph list etc.).
function Set-SpikeEnv {
    $s = Get-SpikeSecrets
    foreach ($k in $s.Keys) { Set-Item "Env:$k" $s[$k] }
}

# The account's name for an ACL: sc.exe says LocalSystem, the SID's name is NT AUTHORITY\SYSTEM.
function Get-AclAccount([string]$Account) { if ($Account -eq 'LocalSystem') { 'NT AUTHORITY\SYSTEM' } else { $Account } }

# (Re)creates the service under $Account. $Account: 'LocalSystem' or 'NT SERVICE\RpSpikeProbe'.
function New-SpikeService([string]$Account) {
    Remove-SpikeService
    $bin = "`"$script:SpikeDir\bin\RpSpikeHost.exe`" $script:OutDir $script:Pipe"
    $r = sc.exe create $script:Service binPath= $bin type= own start= demand obj= $Account DisplayName= "RestoreProof W4.12 spike probe (temporary)"
    if ($LASTEXITCODE -ne 0) { throw "sc create: $r" }
    "service $script:Service created as $Account"
    # The account must read and run the host and write the output.
    $acl = Get-AclAccount $Account
    icacls $script:SpikeDir /grant "${acl}:(OI)(CI)RX" /T /Q | Out-Null
    icacls $script:OutDir /grant "${acl}:(OI)(CI)M" /Q | Out-Null
}

function Remove-SpikeService {
    $svc = Get-Service $script:Service -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.Status -ne 'Stopped') { Stop-Service $script:Service -Force -ErrorAction SilentlyContinue }
        sc.exe delete $script:Service | Out-Null
        for ($i = 0; $i -lt 20 -and (Get-Service $script:Service -ErrorAction SilentlyContinue); $i++) { Start-Sleep -Milliseconds 500 }
        "service $script:Service deleted"
    }
}

# Runs one command line as the service's account: writes command.txt, serves the secrets on the
# pipe (only to $Account), starts the service, waits for exit.txt, returns stdout/stderr/exit.
function Invoke-AsSpikeService([string]$Account, [string[]]$Command, [hashtable]$ExtraEnv = @{}, [int]$TimeoutSeconds = 900) {
    foreach ($f in 'stdout.txt', 'stderr.txt', 'exit.txt', 'host.log') { Remove-Item (Join-Path $script:OutDir $f) -ErrorAction SilentlyContinue }
    [IO.File]::WriteAllLines((Join-Path $script:OutDir 'command.txt'), $Command, [Text.UTF8Encoding]::new($false))

    $sec = [System.IO.Pipes.PipeSecurity]::new()
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $sec.AddAccessRule([System.IO.Pipes.PipeAccessRule]::new($me, [System.IO.Pipes.PipeAccessRights]::FullControl, 'Allow'))
    $sec.AddAccessRule([System.IO.Pipes.PipeAccessRule]::new([Security.Principal.NTAccount]::new((Get-AclAccount $Account)), [System.IO.Pipes.PipeAccessRights]::ReadWrite, 'Allow'))
    $server = [System.IO.Pipes.NamedPipeServerStreamAcl]::Create($script:Pipe, [System.IO.Pipes.PipeDirection]::Out, 1,
        [System.IO.Pipes.PipeTransmissionMode]::Byte, [System.IO.Pipes.PipeOptions]::Asynchronous, 0, 0, $sec)
    try {
        $wait = $server.WaitForConnectionAsync()
        $started = [DateTime]::UtcNow
        Start-Service $script:Service
        if (-not $wait.Wait(120000)) { throw 'the service did not connect to the secrets pipe within 120 s' }
        $client = $server.GetImpersonationUserName()
        "pipe: connected by $client at $([DateTime]::UtcNow.ToString('HH:mm:ss'))Z"
        $secrets = Get-SpikeSecrets
        foreach ($k in $ExtraEnv.Keys) { $secrets[$k] = $ExtraEnv[$k] }
        $w = [IO.StreamWriter]::new($server, [Text.UTF8Encoding]::new($false))
        foreach ($k in $secrets.Keys) { $w.WriteLine("$k=$($secrets[$k])") }
        $w.Flush(); $server.WaitForPipeDrain(); $w.Dispose()
        $secrets = $null
    } finally { $server.Dispose() }

    $exitFile = Join-Path $script:OutDir 'exit.txt'
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while (-not (Test-Path $exitFile) -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Seconds 2 }
    if (-not (Test-Path $exitFile)) { throw "no exit.txt after $TimeoutSeconds s" }
    Start-Sleep -Seconds 1
    $svc = Get-Service $script:Service
    "service state after the run: $($svc.Status)  (took $([int]([DateTime]::UtcNow - $started).TotalSeconds) s)"
    [pscustomobject]@{
        Exit   = [int](Get-Content $exitFile -Raw).Trim()
        Stdout = Get-Content (Join-Path $script:OutDir 'stdout.txt') -Raw -ErrorAction SilentlyContinue
        Stderr = Get-Content (Join-Path $script:OutDir 'stderr.txt') -Raw -ErrorAction SilentlyContinue
        Host   = Get-Content (Join-Path $script:OutDir 'host.log') -Raw -ErrorAction SilentlyContinue
    }
}

# A text file of evidence under docs/api/veeam-lab/, LF, refused if a known secret survives.
function Save-SpikeEvidence([string]$Name, [string]$Text) {
    $s = Get-SpikeSecrets
    foreach ($k in 'RP_VEEAM_PASSWORD', 'RP_GRAPH_CERT_PFX_BASE64', 'RP_GRAPH_CERT_PASSWORD') {
        if ($Text.Contains($s[$k])) { throw "a secret ($k) survived in $Name; nothing written" }
    }
    if ($Text -match 'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.' -or $Text -match 'MII[A-Za-z0-9+/]{60,}') { throw "a token or PFX/PEM-shaped value in $Name; nothing written" }
    $path = "C:\restoreproof\docs\api\veeam-lab\$Name"
    [IO.File]::WriteAllText($path, $Text.Replace("`r`n", "`n").TrimEnd("`n") + "`n", [Text.UTF8Encoding]::new($false))
    "saved $path"
}

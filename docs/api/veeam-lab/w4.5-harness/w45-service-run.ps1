# W4.5 (#48): the W4.12 harness once more, the service account reading the vault. Dot-sources
# the W4.12 library (the temporary service RpSpikeProbe, its host RpSpikeHost.exe, the named
# pipe) but serves NOTHING over the pipe: since W4.5 rpworker reads its secrets from
# %ProgramData%\RestoreProof\vault.bin, so the service gets no variable at all. Run from an
# elevated shell. Everything it makes is taken away by Remove-W45Harness.
#
#   . docs\api\veeam-lab\w4.5-harness\w45-service-run.ps1
#   Initialize-W45Harness            # the spike folder, the host (compiled with csc), the service
#   Invoke-W45Restore -Grant         # vault grant + key-file ACE, then rpworker restore --mail 1
#   Invoke-W45Restore                # without the vault grant: the refusal
#   Remove-W45Harness                # service, ACEs, folder
Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot '..\w4.12-harness\spike-lib.ps1')

$script:W45Account = 'NT SERVICE\RpSpikeProbe'
$script:Vault = 'C:\ProgramData\RestoreProof\vault.bin'
$script:KeyFile = 'C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\76c3cba9ff326aabc15dd987a090ecaf_979c0e2f-70cd-4490-8214-782eeb81f138'
$script:Worker = 'C:\restoreproof\worker\build\dev\rpworker.exe'
$script:LabConfig = Join-Path $env:LOCALAPPDATA 'RestoreProof\lab\config.json'

# The W4.12 library's secrets, used here for scrubbing the evidence only. Nothing is served.
function Get-W45Secrets {
    $pfxPath = Join-Path $env:LOCALAPPDATA 'RestoreProof\lab\worker-graph.pfx'
    @(
        [RpSpikeCred]::Read('RestoreProof Lab - rp-veeam (local Veeam REST)'),
        [Convert]::ToBase64String([IO.File]::ReadAllBytes($pfxPath)),
        [RpSpikeCred]::Read('RestoreProof Lab - Worker Graph app PFX'),
        [RpSpikeCred]::Read('RestoreProof Lab - Worker signing key')
    )
}

function Initialize-W45Harness {
    New-Item -ItemType Directory -Force $script:SpikeDir, (Join-Path $script:SpikeDir 'bin'), $script:OutDir | Out-Null
    $csc = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    $src = Join-Path $PSScriptRoot '..\w4.12-harness\RpSpikeHost.cs'
    & $csc /nologo /target:exe /out:"$script:SpikeDir\bin\RpSpikeHost.exe" /r:System.ServiceProcess.dll $src
    if ($LASTEXITCODE -ne 0) { throw 'csc failed' }
    Copy-Item $script:LabConfig (Join-Path $script:SpikeDir 'config.json') -Force
    New-SpikeService $script:W45Account
    "harness ready: $script:SpikeDir, service $script:Service as $script:W45Account"
}

# Runs one command line as the service account with an EMPTY pipe (0 variables), returns the
# host's result. Copied from Invoke-AsSpikeService but for the pipe's content.
function Invoke-W45AsService([string[]]$Command, [int]$TimeoutSeconds = 900) {
    foreach ($f in 'stdout.txt', 'stderr.txt', 'exit.txt', 'host.log') { Remove-Item (Join-Path $script:OutDir $f) -ErrorAction SilentlyContinue }
    [IO.File]::WriteAllLines((Join-Path $script:OutDir 'command.txt'), $Command, [Text.UTF8Encoding]::new($false))
    $sec = [System.IO.Pipes.PipeSecurity]::new()
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $sec.AddAccessRule([System.IO.Pipes.PipeAccessRule]::new($me, [System.IO.Pipes.PipeAccessRights]::FullControl, 'Allow'))
    $sec.AddAccessRule([System.IO.Pipes.PipeAccessRule]::new([Security.Principal.NTAccount]::new($script:W45Account), [System.IO.Pipes.PipeAccessRights]::ReadWrite, 'Allow'))
    $server = [System.IO.Pipes.NamedPipeServerStreamAcl]::Create($script:Pipe, [System.IO.Pipes.PipeDirection]::Out, 1,
        [System.IO.Pipes.PipeTransmissionMode]::Byte, [System.IO.Pipes.PipeOptions]::Asynchronous, 0, 0, $sec)
    try {
        $wait = $server.WaitForConnectionAsync()
        $started = [DateTime]::UtcNow
        Start-Service $script:Service
        if (-not $wait.Wait(120000)) { throw 'the service did not connect to the pipe within 120 s' }
        "pipe: connected by $($server.GetImpersonationUserName()); nothing served (W4.5: the vault is the only source of secrets)"
        $server.WaitForPipeDrain()
    } finally { $server.Dispose() }
    $exitFile = Join-Path $script:OutDir 'exit.txt'
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while (-not (Test-Path $exitFile) -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Seconds 2 }
    if (-not (Test-Path $exitFile)) { throw "no exit.txt after $TimeoutSeconds s" }
    Start-Sleep -Seconds 1
    "service state after the run: $((Get-Service $script:Service).Status)  (took $([int]([DateTime]::UtcNow - $started).TotalSeconds) s)"
    [pscustomobject]@{
        Exit   = [int](Get-Content $exitFile -Raw).Trim()
        Stdout = Get-Content (Join-Path $script:OutDir 'stdout.txt') -Raw -ErrorAction SilentlyContinue
        Stderr = Get-Content (Join-Path $script:OutDir 'stderr.txt') -Raw -ErrorAction SilentlyContinue
        Host   = Get-Content (Join-Path $script:OutDir 'host.log') -Raw -ErrorAction SilentlyContinue
    }
}

# `rpworker restore --mail 1 --sp 0 --od 0` as the service account. -Grant: first the vault's
# Read entry (rpworker vault grant) and the key file's ACE (W4.12 point 2).
function Invoke-W45Restore([switch]$Grant, [string]$RunId = 'w45-service-1') {
    if ($Grant) {
        & $script:Worker vault grant $script:W45Account
        if ($LASTEXITCODE -ne 0) { throw "vault grant failed ($LASTEXITCODE)" }
        icacls $script:KeyFile /grant "${script:W45Account}:(R)" /Q | Out-Null
        "key file ACE granted"
    }
    "vault ACL: $((icacls $script:Vault | Select-Object -SkipLast 2) -join '; ')"
    Invoke-W45AsService @($script:Worker, 'restore', '--mail', '1', '--sp', '0', '--od', '0', '--run-id', $RunId,
        '--config', (Join-Path $script:SpikeDir 'config.json'), '--manifest', 'C:\restoreproof\lab\seed-manifest.json')
}

function Remove-W45Harness {
    Remove-SpikeService
    icacls $script:KeyFile /remove "$script:W45Account" /Q | Out-Null
    "key file ACE removed: $((icacls $script:KeyFile | Select-Object -SkipLast 2) -join '; ')"
    # The vault's Read entry for the account: taken away with icacls (no rpworker command removes one).
    icacls $script:Vault /remove "$script:W45Account" /Q | Out-Null
    "vault ACL: $((icacls $script:Vault | Select-Object -SkipLast 2) -join '; ')"
    Remove-Item -Recurse -Force $script:SpikeDir -ErrorAction SilentlyContinue
    "spike folder removed: $(-not (Test-Path $script:SpikeDir))"
}

# A text file of evidence under docs/api/veeam-lab/, LF, refused if a known secret survives.
function Save-W45Evidence([string]$Name, [string]$Text) {
    foreach ($s in Get-W45Secrets) { if ($s -and $Text.Contains($s)) { throw "a secret survived in $Name; nothing written" } }
    if ($Text -match 'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.' -or $Text -match 'MII[A-Za-z0-9+/]{60,}' -or $Text -match 'MC4CAQAwBQYDK2VwBCIEI[A-Za-z0-9+/]{43}') { throw "a token, PFX or key-shaped value in $Name; nothing written" }
    $path = "C:\restoreproof\docs\api\veeam-lab\$Name"
    [IO.File]::WriteAllText($path, $Text.Replace("`r`n", "`n").TrimEnd("`n") + "`n", [Text.UTF8Encoding]::new($false))
    "saved $path"
}

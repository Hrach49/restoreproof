# W4.6 (#49): the outbox's Done-when run in the lab. A stub Cloud (stub-cloud.py, beside this
# file) on https://localhost:8443 with a certificate made for the run, and a copy of the lab's
# config whose cloud_url and cloud_ca_file point at it. Everything it makes is under
# %TEMP%\rp-w46, outside the repository, and is taken away by Remove-W46Harness. Run from an
# elevated PowerShell 7 (the runs root and the outbox are under ProgramData).
#
#   . docs\api\veeam-lab\w4.6-harness\w46-run.ps1
#   Initialize-W46Harness            # the certificate (Git's openssl) and the config copy
#   Start-W46Stub [-Slow]            # the stub, its lines in %TEMP%\rp-w46\stub.log
#   Stop-W46Stub                     # killed, as a network that goes away
#   Invoke-W46 @('outbox','flush','--config',$W46Config)   # exit code, stdout, stderr
#   Get-W46Hashes <folder>           # name, size, SHA-256 of each file
#   Save-W46Evidence <name> <text>   # refused if a secret, a token or a key survives
#   Remove-W46Harness
Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot '..\w4.12-harness\spike-lib.ps1')

$script:W46Dir = Join-Path $env:TEMP 'rp-w46'
$script:Worker = 'C:\restoreproof\worker\build\dev\rpworker.exe'
$script:LabConfig = Join-Path $env:LOCALAPPDATA 'RestoreProof\lab\config.json'
$W46Config = Join-Path $script:W46Dir 'config.json'
$W46Port = 8443

# The lab's secrets, read for scrubbing the evidence only (the W4.5 harness's rule).
function Get-W46Secrets {
    $pfxPath = Join-Path $env:LOCALAPPDATA 'RestoreProof\lab\worker-graph.pfx'
    @(
        [RpSpikeCred]::Read('RestoreProof Lab - rp-veeam (local Veeam REST)'),
        [Convert]::ToBase64String([IO.File]::ReadAllBytes($pfxPath)),
        [RpSpikeCred]::Read('RestoreProof Lab - Worker Graph app PFX'),
        [RpSpikeCred]::Read('RestoreProof Lab - Worker signing key')
    )
}

function Initialize-W46Harness {
    New-Item -ItemType Directory -Force $script:W46Dir | Out-Null
    $openssl = 'C:\Program Files\Git\usr\bin\openssl.exe'
    & $openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj '/CN=localhost' `
        -addext 'subjectAltName=DNS:localhost' `
        -keyout (Join-Path $script:W46Dir 'stub-key.pem') -out (Join-Path $script:W46Dir 'stub-cert.pem') 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'openssl failed' }
    $config = Get-Content $script:LabConfig -Raw | ConvertFrom-Json -AsHashtable
    $config['cloud_url'] = "https://localhost:$W46Port"
    $config['cloud_ca_file'] = (Join-Path $script:W46Dir 'stub-cert.pem')
    [IO.File]::WriteAllText($W46Config, ($config | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
    "config copy: cloud_url $($config['cloud_url']), cloud_ca_file <the stub's certificate>"
}

function Start-W46Stub([switch]$Slow) {
    $log = Join-Path $script:W46Dir 'stub.log'
    $arguments = @((Join-Path $PSScriptRoot 'stub-cloud.py'), '--cert', (Join-Path $script:W46Dir 'stub-cert.pem'),
        '--key', (Join-Path $script:W46Dir 'stub-key.pem'), '--port', "$W46Port")
    if ($Slow) { $arguments += '--slow' }
    $script:W46Stub = Start-Process python -ArgumentList $arguments -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $log -RedirectStandardError (Join-Path $script:W46Dir 'stub.err')
    Set-Content (Join-Path $script:W46Dir 'stub.pid') $script:W46Stub.Id
    foreach ($try in 1..50) {
        if ((Test-Path $log) -and (Get-Content $log -Raw)) { break }
        Start-Sleep -Milliseconds 100
    }
    "stub started (pid $($script:W46Stub.Id))$(if ($Slow) { ', slow' })"
}

# The stub's lines so far.
function Get-W46StubLog { Get-Content (Join-Path $script:W46Dir 'stub.log') -ErrorAction SilentlyContinue }

function Stop-W46Stub {
    $pidFile = Join-Path $script:W46Dir 'stub.pid'
    if (Test-Path $pidFile) {
        Stop-Process -Id ([int](Get-Content $pidFile)) -Force -ErrorAction SilentlyContinue
        Remove-Item $pidFile
    }
    'stub killed'
}

# Runs rpworker with `Arguments`; its exit code, stdout and stderr as one text.
function Invoke-W46([string[]]$Arguments) {
    $out = Join-Path $script:W46Dir 'out.txt'; $err = Join-Path $script:W46Dir 'err.txt'
    $started = [DateTime]::UtcNow
    $process = Start-Process $script:Worker -ArgumentList $Arguments -PassThru -Wait -NoNewWindow `
        -RedirectStandardOutput $out -RedirectStandardError $err
    $shown = ($Arguments -join ' ').Replace($W46Config, '<the config copy>')
    "command: rpworker $shown`n$($started.ToString('s'))Z to $([DateTime]::UtcNow.ToString('s'))Z`nexit code: $($process.ExitCode)`n--- stdout`n$((Get-Content $out -Raw))--- stderr`n$((Get-Content $err -Raw))"
}

function Get-W46Hashes([string]$Folder) {
    Get-ChildItem $Folder -File | Sort-Object Name | ForEach-Object {
        '{0,-20} {1,8} {2}' -f $_.Name, $_.Length, (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower()
    }
}

# A text file of evidence under docs/api/veeam-lab/, LF, refused if a known secret survives.
function Save-W46Evidence([string]$Name, [string]$Text) {
    foreach ($s in Get-W46Secrets) { if ($s -and $Text.Contains($s)) { throw "a secret survived in $Name; nothing written" } }
    if ($Text -match 'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.' -or $Text -match 'MII[A-Za-z0-9+/]{60,}' -or $Text -match 'MC4CAQAwBQYDK2VwBCIEI[A-Za-z0-9+/]{43}' -or $Text -match 'PRIVATE KEY') { throw "a token, PFX or key-shaped value in $Name; nothing written" }
    $path = "C:\restoreproof\docs\api\veeam-lab\$Name"
    [IO.File]::WriteAllText($path, $Text.Replace("`r`n", "`n").TrimEnd("`n") + "`n", [Text.UTF8Encoding]::new($false))
    "saved $path"
}

function Remove-W46Harness {
    Stop-W46Stub | Out-Null
    Remove-Item -Recurse -Force $script:W46Dir -ErrorAction SilentlyContinue
    "harness folder removed: $(-not (Test-Path $script:W46Dir))"
}

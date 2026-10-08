# W4.7 (#50): the Windows service's Done-when run in the lab. The service is installed with a
# copy of the lab's config under %ProgramData%\RestoreProof\w47 (the service's account can't
# read the developer's profile), started, killed, restarted with the machine, stopped, its log
# rotated and searched, and uninstalled. Run from an elevated PowerShell 7. What it makes: the
# config copy, and through `rpworker service install` the service and
# %ProgramData%\RestoreProof\logs; Remove-W47Harness takes the copy and the logs away, and
# refuses while the service is still installed.
#
#   . docs\api\veeam-lab\w4.7-harness\w47-run.ps1
#   Initialize-W47Harness            # the config copy
#   Invoke-W47 @('service','install','--config',$W47Config)   # exit code, stdout, stderr
#   Get-W47Setup                     # sc qc, qfailure, qdescription, the registry's FailureActions
#   Get-W47Process                   # state, PID, account, start time, the machine's boot time
#   Stop-W47Process                  # the service's process killed, as a crash
#   Get-W47Events <since>            # the Service Control Manager's events about the service
#   Get-W47Log [-Tail <n>]           # the log files and worker.log's last lines
#   Add-W47Filler                    # the stopped service's worker.log filled to just under 10 MiB
#   Test-W47LogSecrets               # counts only
#   Save-W47Evidence <name> <text>   # refused if a secret, a token or a key survives
#   Remove-W47Harness
Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot '..\w4.12-harness\spike-lib.ps1')

$script:W47Service = 'RestoreProof'
$script:W47Dir = Join-Path $env:ProgramData 'RestoreProof\w47'
$script:W47Logs = Join-Path $env:ProgramData 'RestoreProof\logs'
$script:W47Temp = Join-Path $env:TEMP 'rp-w47'
$script:Worker = 'C:\restoreproof\worker\build\dev\rpworker.exe'
$script:LabConfig = Join-Path $env:LOCALAPPDATA 'RestoreProof\lab\config.json'
$W47Config = Join-Path $script:W47Dir 'config.json'

# The values the lab's vault was filled from, read for the log's search and for scrubbing the
# evidence only; never printed.
function Get-W47Secrets {
    $pfxPath = Join-Path $env:LOCALAPPDATA 'RestoreProof\lab\worker-graph.pfx'
    @(
        'DESKTOP-P55CDUM\rp-veeam',
        [RpSpikeCred]::Read('RestoreProof Lab - rp-veeam (local Veeam REST)'),
        [Convert]::ToBase64String([IO.File]::ReadAllBytes($pfxPath)),
        [RpSpikeCred]::Read('RestoreProof Lab - Worker Graph app PFX'),
        [RpSpikeCred]::Read('RestoreProof Lab - Worker signing key')
    )
}

function Initialize-W47Harness {
    New-Item -ItemType Directory -Force $script:W47Dir, $script:W47Temp | Out-Null
    Copy-Item $script:LabConfig $W47Config -Force
    "config copy: $W47Config"
}

# Runs rpworker with `Arguments`; its exit code, stdout and stderr as one text.
function Invoke-W47([string[]]$Arguments) {
    New-Item -ItemType Directory -Force $script:W47Temp | Out-Null
    $out = Join-Path $script:W47Temp 'out.txt'; $err = Join-Path $script:W47Temp 'err.txt'
    $started = [DateTime]::UtcNow
    $process = Start-Process $script:Worker -ArgumentList $Arguments -PassThru -Wait -NoNewWindow `
        -RedirectStandardOutput $out -RedirectStandardError $err
    "command: rpworker $($Arguments -join ' ')`n$($started.ToString('s'))Z to $([DateTime]::UtcNow.ToString('s'))Z`nexit code: $($process.ExitCode)`n--- stdout`n$((Get-Content $out -Raw))--- stderr`n$((Get-Content $err -Raw))"
}

# What Windows holds for the service: sc's three queries (read-only) and the registry's
# FailureActions decoded.
function Get-W47Setup {
    $lines = @()
    foreach ($query in 'qc', 'qfailure', 'qdescription') {
        $lines += "> sc $query $script:W47Service"
        $lines += (sc.exe $query $script:W47Service | Where-Object { $_.Trim() })
        $lines += ''
    }
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$script:W47Service"
    $lines += "> registry FailureActions"
    $bytes = (Get-ItemProperty $key -Name FailureActions -ErrorAction SilentlyContinue)?.FailureActions
    if (-not $bytes) { $lines += '(none)'; return ($lines -join "`n") }
    $lines += "reset period $([BitConverter]::ToUInt32($bytes, 0)) s, actions $([BitConverter]::ToUInt32($bytes, 12))"
    $kinds = @{ 0 = 'none'; 1 = 'restart'; 2 = 'reboot'; 3 = 'run command' }
    for ($at = 20; $at + 8 -le $bytes.Length; $at += 8) {
        $lines += "  $($kinds[[int][BitConverter]::ToUInt32($bytes, $at)]) after $([BitConverter]::ToUInt32($bytes, $at + 4)) ms"
    }
    $lines -join "`n"
}

# The service's state, its process and whose it is, beside the machine's boot time.
function Get-W47Process {
    $service = Get-CimInstance Win32_Service -Filter "Name='$script:W47Service'"
    if (-not $service) { return "service $script:W47Service: not installed" }
    $lines = @("service $($service.Name): state $($service.State), start mode $($service.StartMode), account $($service.StartName), pid $($service.ProcessId)")
    if ($service.ProcessId) {
        $process = Get-CimInstance Win32_Process -Filter "ProcessId=$($service.ProcessId)"
        $owner = Invoke-CimMethod -InputObject $process -MethodName GetOwner
        $lines += "process $($process.ProcessId): owner $($owner.Domain)\$($owner.User), started $($process.CreationDate.ToUniversalTime().ToString('s'))Z"
        $lines += "command line: $($process.CommandLine)"
    }
    $lines += "machine booted $((Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('s'))Z, now $([DateTime]::UtcNow.ToString('s'))Z"
    $lines -join "`n"
}

# The service's process ended from outside, as a crash would end it.
function Stop-W47Process {
    $service = Get-CimInstance Win32_Service -Filter "Name='$script:W47Service'"
    if (-not $service -or -not $service.ProcessId) { return 'no process to kill' }
    Stop-Process -Id $service.ProcessId -Force
    "killed pid $($service.ProcessId) at $([DateTime]::UtcNow.ToString('s'))Z"
}

# The Service Control Manager's events that name the service, oldest first.
function Get-W47Events([DateTime]$Since) {
    $events = Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; StartTime = $Since } -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match 'RestoreProof' } | Sort-Object TimeCreated
    if (-not $events) { return '(no events)' }
    ($events | ForEach-Object { "$($_.TimeCreated.ToUniversalTime().ToString('s'))Z $($_.Id) $($_.LevelDisplayName): $(($_.Message -replace '\s+', ' ').Trim())" }) -join "`n"
}

# The log files, and worker.log's last lines.
function Get-W47Log([int]$Tail = 20) {
    $lines = @(Get-ChildItem $script:W47Logs -File -ErrorAction SilentlyContinue | Sort-Object Name | ForEach-Object {
            '{0,-14} {1,10} bytes  owner {2}' -f $_.Name, $_.Length, (Get-Acl $_.FullName).Owner })
    $live = Join-Path $script:W47Logs 'worker.log'
    if (Test-Path $live) {
        $lines += "--- worker.log, last $Tail line(s)"
        $lines += (Get-Content $live -Tail $Tail)
    }
    $lines -join "`n"
}

# Appends filler lines to the service's own worker.log (so its owner and ACL stay) until it is
# 100 bytes under spdlog's 10 MiB limit: the next line the service writes rotates it.
function Add-W47Filler {
    $live = Join-Path $script:W47Logs 'worker.log'
    if (-not (Test-Path $live)) { throw 'no worker.log yet: start and stop the service once' }
    $limit = 10 * 1024 * 1024 - 100
    $line = [Text.Encoding]::ASCII.GetBytes("2026-10-08T00:00:00.000Z info w47 filler " + ('x' * 157) + "`r`n")   # 200 bytes
    $stream = [IO.File]::Open($live, 'Append', 'Write', 'Read')
    try {
        $count = 0
        while ($stream.Length + $line.Length -le $limit) { $stream.Write($line, 0, $line.Length); $count++ }
        $size = $stream.Length
    } finally { $stream.Dispose() }
    "appended $count filler line(s) of $($line.Length) bytes; worker.log is $size bytes, $(10 * 1024 * 1024 - $size) under the limit"
}

# Every worker*.log searched for the five values, a JWT shape, a PEM block and an MII run.
# Counts only.
function Test-W47LogSecrets {
    $names = 'veeam_username', 'veeam_password', 'graph_cert_pfx_base64', 'graph_cert_password', 'signing_key_base64'
    $secrets = Get-W47Secrets
    $lines = @()
    foreach ($file in Get-ChildItem $script:W47Logs -File -Filter 'worker*.log' | Sort-Object Name) {
        $text = [IO.File]::ReadAllText($file.FullName)
        $counts = for ($i = 0; $i -lt $names.Count; $i++) {
            "$($names[$i]) $(([regex]::Matches($text, [regex]::Escape($secrets[$i]))).Count)"
        }
        $counts += "jwt $(([regex]::Matches($text, 'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.')).Count)"
        $counts += "pem $(([regex]::Matches($text, '-----BEGIN')).Count)"
        $counts += "mii $(([regex]::Matches($text, 'MII[A-Za-z0-9+/]{60,}')).Count)"
        $lines += "$($file.Name) ($($file.Length) bytes): $($counts -join ', ')"
    }
    $lines -join "`n"
}

# A text file of evidence under docs/api/veeam-lab/, LF, refused if a known secret survives.
# The account name is no secret by itself and stays readable.
function Save-W47Evidence([string]$Name, [string]$Text) {
    foreach ($s in (Get-W47Secrets | Select-Object -Skip 1)) { if ($s -and $Text.Contains($s)) { throw "a secret survived in $Name; nothing written" } }
    if ($Text -match 'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.' -or $Text -match 'MII[A-Za-z0-9+/]{60,}' -or $Text -match 'MC4CAQAwBQYDK2VwBCIEI[A-Za-z0-9+/]{43}' -or $Text -match 'PRIVATE KEY') { throw "a token, PFX or key-shaped value in $Name; nothing written" }
    $path = "C:\restoreproof\docs\api\veeam-lab\$Name"
    [IO.File]::WriteAllText($path, $Text.Replace("`r`n", "`n").TrimEnd("`n") + "`n", [Text.UTF8Encoding]::new($false))
    "saved $path"
}

# The config copy and the logs taken away. Only once the service is gone: its log is its own.
function Remove-W47Harness {
    if (Get-CimInstance Win32_Service -Filter "Name='$script:W47Service'") { throw "the service $script:W47Service is still installed: rpworker service stop, then uninstall" }
    Remove-Item -Recurse -Force $script:W47Dir, $script:W47Logs, $script:W47Temp -ErrorAction SilentlyContinue
    "config copy removed: $(-not (Test-Path $script:W47Dir)); logs removed: $(-not (Test-Path $script:W47Logs))"
}

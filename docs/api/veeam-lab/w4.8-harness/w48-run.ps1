# W4.8 (#51): the scheduler loop's Done-when run in the lab. The service is installed with a copy
# of the lab's config under %ProgramData%\RestoreProof\w48 that names a stub jobs file and the
# stub Cloud (stub-cloud.py, beside this file); jobs are dropped into the file, the process is
# killed and stopped during runs, and everything is taken away again. Run from an elevated
# PowerShell 7 on the lab machine.
#
# W7.1 (the installer) isn't built, so Grant-W48Account makes by hand what the service's account
# needs, after `service install` (the account exists only then), and Revoke-W48Account takes it
# away again BEFORE `service uninstall` (the name resolves only while the service is installed).
#
#   . docs\api\veeam-lab\w4.8-harness\w48-run.ps1
#   Initialize-W48Harness            # the folder, the certificate, the config and manifest copies
#   Start-W48Stub / Stop-W48Stub     # the stub Cloud, its lines in <w48>\stub.log
#   Invoke-W48 @('service','install','--config',$W48Config)   # exit code, stdout, stderr
#   Grant-W48Account / Revoke-W48Account
#   Set-W48Jobs @(New-W48Job 'w48-job-1' 5 5 5), ...          # the stub jobs file, replaced whole
#   Wait-W48Log '<regex>' -Seconds 600                        # the first worker.log line that matches
#   Get-W48Record                    # state\running.json as it is, or '(no running.json)'
#   Stop-W48Process                  # the service's process killed, as a crash
#   Get-W48Log -Since <utc> [-Match <regex>]
#   Get-W48Folders                   # what is under runs\, outbox\, sent\
#   Test-W48Folder <folder>          # both verifiers' lines for a run folder
#   Get-W48Targets                   # rpworker graph list: the three restore targets
#   Get-W48Sessions                  # Veeam's restore sessions of the account still Working
#   Save-W48Evidence <name> <text>   # refused if a secret, a token or a key survives
#   Remove-W48Harness
Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot '..\w4.12-harness\spike-lib.ps1')

$script:W48Service = 'RestoreProof'
$script:W48Account = 'NT SERVICE\RestoreProof'
$script:W48Root = Join-Path $env:ProgramData 'RestoreProof'
$script:W48Dir = Join-Path $script:W48Root 'w48'
$script:W48Logs = Join-Path $script:W48Root 'logs'
$script:W48State = Join-Path $script:W48Root 'state'
$script:W48Temp = Join-Path $env:TEMP 'rp-w48'
$script:Repo = 'C:\restoreproof'
$script:Worker = Join-Path $script:Repo 'worker\build\dev\rpworker.exe'
$script:LabConfig = Join-Path $env:LOCALAPPDATA 'RestoreProof\lab\config.json'
$script:W48Vault = Join-Path $script:W48Root 'vault.bin'
$W48Config = Join-Path $script:W48Dir 'config.json'
$W48Jobs = Join-Path $script:W48Dir 'jobs.json'
$W48PublicKey = Join-Path $script:W48Dir 'worker-signing.pub.pem'
$W48Port = 8443

# The values the lab's vault was filled from, read for scrubbing the evidence only; never printed.
function Get-W48Secrets {
    $pfxPath = Join-Path $env:LOCALAPPDATA 'RestoreProof\lab\worker-graph.pfx'
    @(
        [RpSpikeCred]::Read('RestoreProof Lab - rp-veeam (local Veeam REST)'),
        [Convert]::ToBase64String([IO.File]::ReadAllBytes($pfxPath)),
        [RpSpikeCred]::Read('RestoreProof Lab - Worker Graph app PFX'),
        [RpSpikeCred]::Read('RestoreProof Lab - Worker signing key')
    )
}

# The private key file of Veeam's organisation app certificate (W4.12: the one ACE the account needs).
function Get-W48KeyFile {
    # The thumbprint Veeam reports for the lab organisation's app (w4.12-1-probe evidence).
    $candidates = @(Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.HasPrivateKey -and $_.Thumbprint -eq 'AC3220B58A2B4C438DA13816C2DD1E25D1F783A7' })
    if ($candidates.Count -ne 1) { throw "the organisation app's certificate isn't in LocalMachine\My exactly once" }
    foreach ($cert in $candidates) {
        $key = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
        $name = if ($key -is [Security.Cryptography.RSACng]) { $key.Key.UniqueName } else { $key.CspKeyContainerInfo.UniqueKeyContainerName }
        foreach ($folder in 'Microsoft\Crypto\RSA\MachineKeys', 'Microsoft\Crypto\Keys') {
            $file = Join-Path $env:ProgramData "$folder\$name"
            if (Test-Path $file) { [pscustomobject]@{ Thumbprint = $cert.Thumbprint; File = $file } }
        }
    }
}

function Initialize-W48Harness {
    New-Item -ItemType Directory -Force $script:W48Dir, $script:W48Temp | Out-Null
    $openssl = 'C:\Program Files\Git\usr\bin\openssl.exe'
    & $openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj '/CN=localhost' `
        -addext 'subjectAltName=DNS:localhost' `
        -keyout (Join-Path $script:W48Temp 'stub-key.pem') -out (Join-Path $script:W48Dir 'stub-cert.pem') 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'openssl failed' }
    $config = Get-Content $script:LabConfig -Raw | ConvertFrom-Json -AsHashtable
    Copy-Item $config['veeam_ca_file'] (Join-Path $script:W48Dir 'veeam-ca.pem') -Force
    $config['veeam_ca_file'] = (Join-Path $script:W48Dir 'veeam-ca.pem')
    $config['cloud_url'] = "https://localhost:$W48Port"
    $config['cloud_ca_file'] = (Join-Path $script:W48Dir 'stub-cert.pem')
    $config['jobs_file'] = $W48Jobs
    $config['poll_interval_s'] = 30
    $config['heartbeat_interval_s'] = 60
    [IO.File]::WriteAllText($W48Config, ($config | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
    Copy-Item (Join-Path $script:Repo 'lab\seed-manifest.json') (Join-Path $script:W48Dir 'seed-manifest.json') -Force
    # The jobs file is believed only when SYSTEM, Administrators or the service's account owns it.
    icacls $script:W48Dir /setowner 'BUILTIN\Administrators' /T /Q | Out-Null
    "config copy: $W48Config (cloud_url https://localhost:$W48Port, cloud_ca_file and veeam_ca_file copies beside it, jobs_file $W48Jobs, poll_interval_s 30, heartbeat_interval_s 60); seed-manifest.json copied beside it"
}

function Start-W48Stub {
    $log = Join-Path $script:W48Temp 'stub.log'
    $arguments = @((Join-Path $PSScriptRoot 'stub-cloud.py'), '--cert', (Join-Path $script:W48Dir 'stub-cert.pem'),
        '--key', (Join-Path $script:W48Temp 'stub-key.pem'), '--port', "$W48Port")
    $stub = Start-Process python -ArgumentList $arguments -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $log -RedirectStandardError (Join-Path $script:W48Temp 'stub.err')
    Set-Content (Join-Path $script:W48Temp 'stub.pid') $stub.Id
    foreach ($try in 1..50) {
        if ((Test-Path $log) -and (Get-Content $log -Raw)) { break }
        Start-Sleep -Milliseconds 100
    }
    "stub started (pid $($stub.Id))"
}

function Get-W48StubLog([string]$Match = '.') {
    Get-Content (Join-Path $script:W48Temp 'stub.log') -ErrorAction SilentlyContinue | Where-Object { $_ -match $Match }
}

function Stop-W48Stub {
    $pidFile = Join-Path $script:W48Temp 'stub.pid'
    if (Test-Path $pidFile) {
        Stop-Process -Id ([int](Get-Content $pidFile)) -Force -ErrorAction SilentlyContinue
        Remove-Item $pidFile
    }
    'stub killed'
}

# Runs rpworker with `Arguments`; its exit code, stdout and stderr as one text.
function Invoke-W48([string[]]$Arguments) {
    New-Item -ItemType Directory -Force $script:W48Temp | Out-Null
    $out = Join-Path $script:W48Temp 'out.txt'; $err = Join-Path $script:W48Temp 'err.txt'
    $started = [DateTime]::UtcNow
    $quoted = $Arguments | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }
    $process = Start-Process $script:Worker -ArgumentList $quoted -PassThru -Wait -NoNewWindow `
        -RedirectStandardOutput $out -RedirectStandardError $err
    "command: rpworker $($Arguments -join ' ')`n$($started.ToString('s'))Z to $([DateTime]::UtcNow.ToString('s'))Z`nexit code: $($process.ExitCode)`n--- stdout`n$((Get-Content $out -Raw))--- stderr`n$((Get-Content $err -Raw))"
}

# What W7.1 will do: the vault's Read entry, the Read ACE on Veeam's key file, and Modify on the
# four folders the loop writes in (made here by the administrator, so they are Administrators').
function Grant-W48Account {
    $lines = @()
    $lines += (Invoke-W48 @('vault', 'grant', $script:W48Account))
    foreach ($key in @(Get-W48KeyFile)) {
        icacls $key.File /grant "$($script:W48Account):(R)" /Q | Out-Null
        $lines += "key file of certificate $($key.Thumbprint): Read granted to $script:W48Account"
    }
    foreach ($name in 'state', 'runs', 'outbox', 'sent') {
        $folder = Join-Path $script:W48Root $name
        New-Item -ItemType Directory -Force $folder | Out-Null
        icacls $folder /grant "$($script:W48Account):(OI)(CI)M" /Q | Out-Null
        $lines += "${folder}: Modify granted to $script:W48Account"
    }
    icacls $script:W48State /setowner 'BUILTIN\Administrators' /Q | Out-Null
    $lines += Get-W48Acls
    $lines -join "`n"
}

# The ACLs the grants touch, the account's entries only (and the owner).
function Get-W48Acls {
    $paths = @($script:W48Vault) + @(Get-W48KeyFile | ForEach-Object File) +
        @('state', 'runs', 'outbox', 'sent' | ForEach-Object { Join-Path $script:W48Root $_ })
    $lines = foreach ($path in $paths) {
        if (-not (Test-Path $path)) { "${path}: not there"; continue }
        $acl = Get-Acl $path
        $shown = $path -replace '[0-9a-f]{32}_[0-9a-f-]{36}', '<Veeam key file>'
        $entries = @($acl.Access | Where-Object { "$($_.IdentityReference)" -match 'RestoreProof|S-1-5-80-' } |
            ForEach-Object { "$($_.IdentityReference) $($_.FileSystemRights)" })
        "${shown}: owner $($acl.Owner); the account's entries: $(if ($entries) { $entries -join '; ' } else { 'none' })"
    }
    $lines -join "`n"
}

function Revoke-W48Account {
    if (-not (Get-CimInstance Win32_Service -Filter "Name='$script:W48Service'")) { throw 'the service is not installed: the account no longer resolves; remove its entries by SID' }
    $paths = @($script:W48Vault) + @(Get-W48KeyFile | ForEach-Object File) +
        @('state', 'runs', 'outbox', 'sent' | ForEach-Object { Join-Path $script:W48Root $_ })
    foreach ($path in $paths) { if (Test-Path $path) { icacls $path /remove:g $script:W48Account /Q | Out-Null } }
    "entries of $script:W48Account removed`n$(Get-W48Acls)"
}

function New-W48Job([string]$RunId, [int]$Mail, [int]$Sp, [int]$Od) {
    [ordered]@{ run_id = $RunId; client_id = 'lab-client'; sample_mail = $Mail; sample_sp = $Sp; sample_od = $Od
        restore_point = 'latest'; screenshots_enabled = $false }
}

# The stub jobs file, replaced whole (written beside it and renamed, so the loop never reads half).
function Set-W48Jobs([object[]]$Jobs = @(), [string]$Raw = '') {
    $text = if ($Raw) { $Raw } else { ([ordered]@{ format = 'restoreproof.jobs.v1'; jobs = @($Jobs) } | ConvertTo-Json -Depth 5) }
    $next = "$W48Jobs.next"
    [IO.File]::WriteAllText($next, $text, [Text.UTF8Encoding]::new($false))
    icacls $next /setowner 'BUILTIN\Administrators' /Q | Out-Null
    Move-Item $next $W48Jobs -Force
    "jobs file written at $([DateTime]::UtcNow.ToString('s'))Z:`n$text"
}

function Get-W48LogLines([DateTime]$Since = [DateTime]::MinValue) {
    $files = @(Get-ChildItem $script:W48Logs -File -Filter 'worker*.log' -ErrorAction SilentlyContinue | Sort-Object LastWriteTimeUtc)
    foreach ($file in $files) {
        $stream = [IO.File]::Open($file.FullName, 'Open', 'Read', 'ReadWrite, Delete')
        try { $text = [IO.StreamReader]::new($stream).ReadToEnd() } finally { $stream.Dispose() }
        foreach ($line in $text -split "`r?`n") {
            if ($line.Length -ge 24 -and $line.Substring(0, 24) -ge $Since.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')) { $line }
        }
    }
}

function Get-W48Log([DateTime]$Since = [DateTime]::MinValue, [string]$Match = '.') {
    (Get-W48LogLines $Since | Where-Object { $_ -match $Match }) -join "`n"
}

# Waits for the first log line at or after `Since` that matches; that line, or a throw at the time limit.
function Wait-W48Log([string]$Pattern, [DateTime]$Since = [DateTime]::MinValue, [int]$Seconds = 300) {
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $hit = Get-W48LogLines $Since | Where-Object { $_ -match $Pattern } | Select-Object -First 1
        if ($hit) { return $hit }
        Start-Sleep -Seconds 2
    }
    throw "no log line matching '$Pattern' within $Seconds s"
}

function Get-W48Record {
    $file = Join-Path $script:W48State 'running.json'
    if (-not (Test-Path $file)) { return "(no running.json) at $([DateTime]::UtcNow.ToString('s'))Z" }
    "running.json at $([DateTime]::UtcNow.ToString('s'))Z:`n$([IO.File]::ReadAllText($file))"
}

# Waits until running.json holds `Pattern` (e.g. '"restore_requested":true'); its text.
function Wait-W48Record([string]$Pattern, [int]$Seconds = 300) {
    $file = Join-Path $script:W48State 'running.json'
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        if (Test-Path $file) {
            try { $text = [IO.File]::ReadAllText($file) } catch { $text = '' }
            if ($text -match $Pattern) { return "running.json at $([DateTime]::UtcNow.ToString('s'))Z:`n$text" }
        }
        Start-Sleep -Milliseconds 200
    }
    throw "running.json didn't match '$Pattern' within $Seconds s"
}

function Get-W48Process {
    $service = Get-CimInstance Win32_Service -Filter "Name='$script:W48Service'"
    if (-not $service) { return "service ${script:W48Service}: not installed" }
    $lines = @("service $($service.Name): state $($service.State), account $($service.StartName), pid $($service.ProcessId), now $([DateTime]::UtcNow.ToString('s'))Z")
    if ($service.ProcessId) {
        $process = Get-CimInstance Win32_Process -Filter "ProcessId=$($service.ProcessId)"
        $lines += "process $($process.ProcessId) started $($process.CreationDate.ToUniversalTime().ToString('s'))Z"
    }
    $lines -join "`n"
}

function Stop-W48Process {
    $service = Get-CimInstance Win32_Service -Filter "Name='$script:W48Service'"
    if (-not $service -or -not $service.ProcessId) { return 'no process to kill' }
    Stop-Process -Id $service.ProcessId -Force
    "killed pid $($service.ProcessId) at $([DateTime]::UtcNow.ToString('s'))Z"
}

function Get-W48Events([DateTime]$Since) {
    $events = Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; StartTime = $Since.ToLocalTime() } -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match 'RestoreProof Worker' } | Sort-Object TimeCreated
    if (-not $events) { return '(no events)' }
    ($events | ForEach-Object { "$($_.TimeCreated.ToUniversalTime().ToString('s'))Z $($_.Id) $($_.LevelDisplayName): $(($_.Message -replace '\s+', ' ').Trim())" }) -join "`n"
}

# What is under the three roots: each folder's files with their sizes.
function Get-W48Folders {
    $lines = foreach ($root in 'runs', 'outbox', 'sent') {
        $path = Join-Path $script:W48Root $root
        "$root\:"
        foreach ($folder in @(Get-ChildItem $path -Directory -ErrorAction SilentlyContinue | Sort-Object Name)) {
            $files = @(Get-ChildItem $folder.FullName -File | Sort-Object Name | ForEach-Object { "$($_.Name) $($_.Length)" })
            "  $($folder.Name): $(if ($files) { $files -join ', ' } else { '(empty)' })"
        }
    }
    $lines -join "`n"
}

# Both verifiers over one run folder, and the result's status object.
function Test-W48Folder([string]$Folder) {
    if (-not (Test-Path $W48PublicKey)) {
        $pem = & $script:Worker signer public-key 2>$null
        [IO.File]::WriteAllText($W48PublicKey, (($pem -join "`n") + "`n"), [Text.UTF8Encoding]::new($false))
    }
    $ca = Join-Path $script:Repo 'shared\tsa\tsa-ca.pem'
    $lines = @("folder: $Folder")
    $lines += (Invoke-W48 @('signer', 'verify', $Folder, '--public-key', $W48PublicKey, '--tsa-ca', $ca))
    $script = Join-Path $script:Repo 'shared\tools\verify_bundle.py'
    $python = & uv run $script $Folder --public-key $W48PublicKey --tsa-ca $ca --schemas (Join-Path $script:Repo 'shared\schemas') 2>&1
    $lines += "verify_bundle.py (exit code $LASTEXITCODE): $($python -join ' | ')"
    $result = Get-Content (Join-Path $Folder 'result.json') -Raw | ConvertFrom-Json
    $lines += "result.json: run_id $($result.run_id), status $($result.status.status)$(if ($result.status.PSObject.Properties['error_code']) { ' ' + $result.status.error_code }), restore_sent $($result.status.restore_sent), message: $($result.status.message)"
    $lines += "result.json sha256 $((Get-FileHash (Join-Path $Folder 'result.json') -Algorithm SHA256).Hash.ToLower())"
    $lines -join "`n"
}

# The three restore targets as rpworker graph list shows them (the developer's own config and the vault).
function Get-W48Targets {
    Invoke-W48 @('graph', 'list', '--config', $script:LabConfig)
}

# Veeam's restore sessions that still read Working, whoever started them (read-only; one sign-in
# as rp-veeam through the collection's VeeamLab.ps1, logged out again).
function Get-W48Sessions {
    . (Join-Path $script:Repo 'docs\api\veeam-m365\VeeamLab.ps1')
    Connect-VeeamAdmin | Out-Null
    try {
        $list = Get-Body (Invoke-Veeam -Path '/v8/RestoreSessions?limit=200&orderBy=CreationTime&orderAsc=false')
        $working = @($list.results | Where-Object state -eq 'Working')
        if (-not $working) { return "no session Working at $([DateTime]::UtcNow.ToString('s'))Z" }
        "Working at $([DateTime]::UtcNow.ToString('s'))Z:`n" + (($working | ForEach-Object { "  $($_.id) type $($_.type) created $($_.creationTime) by $($_.initiatedBy)" }) -join "`n")
    } finally { Disconnect-VeeamAdmin | Out-Null }
}

# A text file of evidence under docs/api/veeam-lab/, LF, refused if a known secret survives.
function Save-W48Evidence([string]$Name, [string]$Text) {
    foreach ($s in Get-W48Secrets) { if ($s -and $Text.Contains($s)) { throw "a secret survived in $Name; nothing written" } }
    if ($Text -match 'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.' -or $Text -match 'MII[A-Za-z0-9+/]{60,}' -or $Text -match 'MC4CAQAwBQYDK2VwBCIEI[A-Za-z0-9+/]{43}' -or $Text -match 'PRIVATE KEY') { throw "a token, PFX or key-shaped value in $Name; nothing written" }
    $path = Join-Path $script:Repo "docs\api\veeam-lab\$Name"
    [IO.File]::WriteAllText($path, $Text.Replace("`r`n", "`n").TrimEnd("`n") + "`n", [Text.UTF8Encoding]::new($false))
    "saved $path"
}

# The config copy, the state folder and the logs taken away. Only once the service is gone.
# runs\, outbox\ and sent\ stay: they hold the runs made by hand before, and this run's sent
# folders are moved out by the caller first.
function Remove-W48Harness {
    if (Get-CimInstance Win32_Service -Filter "Name='$script:W48Service'") { throw "the service $script:W48Service is still installed: revoke, stop, then uninstall" }
    Stop-W48Stub | Out-Null
    Remove-Item -Recurse -Force $script:W48Dir, $script:W48Logs, $script:W48State, $script:W48Temp -ErrorAction SilentlyContinue
    "config copy removed: $(-not (Test-Path $script:W48Dir)); state removed: $(-not (Test-Path $script:W48State)); logs removed: $(-not (Test-Path $script:W48Logs))"
}

# W7.1 (#80): the live Done-when on this laptop, the Veeam server (docs/decisions.md 2026-10-16,
# "W7.1 (#80)", point 11 (b)): the release package installed by Install-RestoreProofWorker.ps1
# around the W5.1 harness's stack and plan: the installer registers the Worker, a plan's run goes
# queued -> dispatched -> pass under the installer's ACLs, a second run of the installer changes
# nothing. Run from an ELEVATED PowerShell 7, Docker Desktop running, no RestoreProof service
# installed, the vault holding the five secrets and no Cloud token, no config.json under
# %ProgramData%\RestoreProof (the installer writes it), the restore targets empty:
#
#   pwsh -File docs\api\veeam-lab\w7.1-harness\w71-live.ps1 [-Package <folder of the unpacked zip>] [-NoCopy]
#
# Without -Package the package is built by worker\tools\package.ps1 -NoBuild from build\ci (build
# the ci preset first: cmake --preset ci; cmake --build --preset ci --target rpworker, from a VS
# Developer PowerShell) and unpacked into the run folder. In order:
#   1. rpworker graph list: the three restore targets empty (else stop); icacls of the root, the
#      vault and Veeam's key file before
#   2. the stack up with --build, re-migrated; Caddy's root copied into the run folder
#   3. manage.py: an MSP, the lab tenant's client, an install token (into the installer's -Answers,
#      an in-memory hashtable: never a file, a command line or a log)
#   4. the installer: -CloudUrl https://localhost:8443 -CloudCaFile <Caddy's root> -WorkerName
#      w71-live; the vault's five names are there, so it asks nothing, pins Veeam's own REST
#      certificate, grants the account by SID, makes nothing it finds, installs, registers, starts;
#      its lines and its "installed in <s> s" are the evidence; icacls after
#   5. the connector on the lab profile and a plan with a 5-minute cron
#   6. the database read every 10 s until a run of the plan is pass (or fail/error, or 30 minutes)
#   7. the service stopped; its log; both verifiers on the sent folder; the run's row
#   8. the installer again: "changes: 0"
#   9. in the finally: the service uninstalled, both Cloud tokens removed from the vault, the
#      account's Read entry taken off Veeam's key file, the installer's config.json and the two PEM
#      files moved into the run folder, %ProgramFiles%\RestoreProof removed, state\'s files and the
#      kept jobs removed, the sent folder kept under %ProgramData%\RestoreProof\w71; the data
#      folder's new ACL stays (it is what W7.1 wants there); graph list after
# Only when every step held and no secret, token or key survives in the text is it copied to
# docs\api\veeam-lab\w7.1-done-when.txt, the copy last. Before the commit, also run
# `python tools/fixture_secret_scan.py` from worker\ and `audit-evidence.ps1`.
#Requires -Version 7.4
param([string]$Package = '', [switch]$NoCopy)
. (Join-Path $PSScriptRoot '..\w4.8-harness\w48-run.ps1')

$RunDir = Join-Path $env:LOCALAPPDATA ("RestoreProof\lab\w7.1-" + (Get-Date -Format 'yyyyMMddTHHmmss'))
$CloudDir = Join-Path $script:Repo 'cloud'
$LabProfile = Join-Path $env:LOCALAPPDATA 'RestoreProof\lab\lab-profile.json'
$Installer = Join-Path $script:Repo 'tools\worker-install\Install-RestoreProofWorker.ps1'
$Packager = Join-Path $script:Repo 'worker\tools\package.ps1'
$ProgramDir = Join-Path $env:ProgramFiles 'RestoreProof'
$Root = $script:W48Root
$ConfigPath = Join-Path $Root 'config.json'
$Kept = Join-Path $Root 'w71'
$Evidence = Join-Path $script:Repo 'docs\api\veeam-lab\w7.1-done-when.txt'
$CloudCa = Join-Path $RunDir 'cloud-ca.pem'
$commit = git -C $script:Repo rev-parse --short HEAD
function Get-Utc { [DateTime]::UtcNow.ToString('s') + 'Z' }

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'run from an elevated shell'; exit 64
}
docker info *> $null
if ($LASTEXITCODE -ne 0) { Write-Error 'Docker Desktop is not running'; exit 64 }
if (Get-CimInstance Win32_Service -Filter "Name='$script:W48Service'") { Write-Error 'a RestoreProof service is installed: uninstall it first'; exit 64 }
if (Test-Path -LiteralPath $ConfigPath) { Write-Error "$ConfigPath is there: the installer writes it; move it away first"; exit 64 }
if (Test-Path -LiteralPath $ProgramDir) { Write-Error "$ProgramDir is there: remove it first"; exit 64 }
New-Item -ItemType Directory -Force $RunDir | Out-Null

function Invoke-Compose([string[]]$Arguments, [string]$Stdin = $null) {
    Push-Location $CloudDir
    try {
        if ($null -ne $Stdin) { $out = $Stdin | & docker compose @Arguments 2>&1 } else { $out = & docker compose @Arguments 2>&1 }
        [pscustomobject]@{ Code = $LASTEXITCODE; Text = (($out | ForEach-Object { "$_" }) -join "`n") }
    } finally { Pop-Location }
}
function Invoke-Manage([string[]]$Arguments) { Invoke-Compose (@('exec', '-T', 'api', 'python', 'manage.py') + $Arguments) }
function Get-Value([string]$Text, [string]$Name) { ($Text -split "`n" | Where-Object { $_ -like "$Name *" } | Select-Object -First 1) -replace "^$Name ", '' }
function Invoke-Sql([string]$Statement) {
    (Invoke-Compose @('exec', '-T', 'postgres', 'psql', '-U', 'restoreproof', '-d', 'restoreproof', '-tAc', $Statement)).Text.Trim()
}
# icacls of the paths the installer sets, the key file's name shortened.
function Get-Acls([string[]]$Paths) {
    $lines = foreach ($path in $Paths) {
        if (-not (Test-Path -LiteralPath $path)) { "${path}: not there"; continue }
        $shown = $path -replace '[0-9a-f]{32}_[0-9a-f-]{36}', '<Veeam key file>'
        (& icacls.exe $path 2>&1 | Where-Object { $_ -and $_ -notmatch 'Successfully processed' }) -replace [regex]::Escape($path), $shown
    }
    $lines -join "`n"
}
function Get-AclPaths {
    @($Root, (Join-Path $Root 'vault.bin')) + @('state', 'runs', 'outbox', 'sent', 'failed', 'logs' | ForEach-Object { Join-Path $Root $_ }) + @(Get-W48KeyFile | ForEach-Object File)
}

$t = @("W7.1 (#80) Done-when, live, on this laptop (the Veeam server): the release package installed by Install-RestoreProofWorker.ps1; the installer registers the Worker with the Compose stack over https://localhost:8443 (Caddy, its own CA); a plan's run goes queued -> dispatched -> pass under the installer's ACLs; a second run of the installer changes nothing. $(Get-Utc), commit $commit, branch $(git -C $script:Repo branch --show-current)")
$t += "Windows, PowerShell $($PSVersionTable.PSVersion), Docker Desktop, the Compose stack on 127.0.0.1"
$ok = $false
$installed = $false
$installToken = $null
$vaultOurs = $false
$keyFileGranted = $false
$since = [DateTime]::UtcNow
$after = ''
$serviceSid = ''
try {
    # 1
    $t += "`n== 1. the restore targets and the ACLs before =="
    $before = Get-W48Targets
    $t += $before
    if ($before -notmatch '(?m)^0 item\(s\) in the three restore targets') { throw 'the restore targets are not empty (or graph list failed); nothing is cleaned' }
    $vaultList = Invoke-W48 @('vault', 'list')
    foreach ($name in 'cloud_api_token', 'cloud_install_token') {
        if ($vaultList -match "(?m)^$name\r?$") { throw "the vault already holds ${name}: remove it first" }
    }
    $vaultOurs = $true
    $t += "rpworker vault list: $(((($vaultList -split "`n") | Where-Object { $_ -match '^[a-z_]+\r?$' } | ForEach-Object { $_.Trim() }) -join ', ')) (names only)"
    $t += "-- icacls before`n$(Get-Acls (Get-AclPaths))"

    # the package
    $t += "`n== the package =="
    if (-not $Package) {
        $packaged = & pwsh -NoProfile -File $Packager -Out $RunDir -NoBuild 2>&1 | ForEach-Object { "$_" }
        if ($LASTEXITCODE -ne 0) { throw "package.ps1 failed: $($packaged -join ' ')" }
        $t += $packaged
        $zip = ($packaged | Where-Object { $_ -like 'package: *' }) -replace '^package: ', ''
        $Package = Join-Path $RunDir 'package'
        Expand-Archive -LiteralPath $zip -DestinationPath $Package
        $t += "unpacked to $Package"
    } else {
        $t += "package given: $Package"
    }
    $t += "files: $((Get-ChildItem -LiteralPath $Package -File | Sort-Object Name | ForEach-Object Name) -join ', ')"

    # 2
    $t += "`n== 2. the stack, re-migrated; Caddy's root =="
    $t += (Invoke-Compose @('up', '-d', '--wait', '--build')).Text -split "`n" | Where-Object { $_ -match 'Healthy|Exited|Running|Started' }
    $t += "alembic downgrade base: exit $((Invoke-Compose @('exec', '-T', 'api', 'alembic', 'downgrade', 'base')).Code)"
    $t += "alembic upgrade head: exit $((Invoke-Compose @('exec', '-T', 'api', 'alembic', 'upgrade', 'head')).Code)"
    $copied = Invoke-Compose @('cp', 'proxy:/data/caddy/pki/authorities/local/root.crt', $CloudCa)
    if ($copied.Code -ne 0) { throw "Caddy's root couldn't be copied: $($copied.Text)" }
    $root = [Security.Cryptography.X509Certificates.X509Certificate2]::new($CloudCa)
    $t += "Caddy's root: $($root.Subject), until $($root.NotAfter.ToUniversalTime().ToString('s'))Z, SHA-256 $((Get-FileHash $CloudCa -Algorithm SHA256).Hash.ToLower()), copied to $CloudCa"

    # 3
    $t += "`n== 3. manage.py: the MSP, the client, the install token =="
    $tenant = (Get-Content $LabProfile -Raw | ConvertFrom-Json).graph_tenant_id
    $msp = Invoke-Manage @('create-msp', '--name', 'w71-live')
    $mspId = Get-Value $msp.Text 'msp_id'
    $client = Invoke-Manage @('create-client', '--msp-id', $mspId, '--name', 'lab-tenant', '--tenant-id', $tenant)
    $clientId = Get-Value $client.Text 'client_id'
    if (-not $mspId -or -not $clientId) { throw "the MSP or the client wasn't made: $($msp.Text) $($client.Text)" }
    $t += "create-msp: msp_id $mspId; create-client --tenant-id ${tenant}: client_id $clientId"
    $made = Invoke-Manage @('create-worker-token', '--msp-id', $mspId, '--label', 'w7.1 live')
    $installToken = Get-Value $made.Text 'install_token'
    $t += "create-worker-token --label 'w7.1 live': exit $($made.Code), $((($made.Text -split "`n") | Where-Object { $_ -notlike 'install_token *' }) -join '; '); install_token (not shown; handed to the installer in memory)"
    if (-not $installToken) { throw 'no install token' }

    # 4
    $t += "`n== 4. the installer =="
    $since = [DateTime]::UtcNow
    $installStarted = [DateTime]::UtcNow
    $answers = @{ cloud_install_token = $installToken }
    $installLines = @(& $Installer -Package $Package -CloudUrl 'https://localhost:8443' -CloudCaFile $CloudCa -WorkerName 'w71-live' -Answers $answers 2>&1 | ForEach-Object { "$_" })
    $installEnded = [DateTime]::UtcNow
    $answers = $null
    $installToken = $null
    $installed = $true
    $keyFileGranted = $true
    $t += "pwsh Install-RestoreProofWorker.ps1 -Package <the unpacked package> -CloudUrl https://localhost:8443 -CloudCaFile <Caddy's root> -WorkerName w71-live -Answers <the install token, in memory>"
    $t += "$($installStarted.ToString('s'))Z to $($installEnded.ToString('s'))Z ($([int]($installEnded - $installStarted).TotalSeconds) s wall clock, nothing typed)"
    $t += $installLines
    $workerLine = $installLines | Where-Object { $_ -match '^worker ([0-9a-f-]{36}) key ([0-9a-f]{64})$' } | Select-Object -First 1
    if (-not $workerLine) { throw 'the installer printed no worker line' }
    $workerId = [regex]::Match($workerLine, '^worker ([0-9a-f-]{36})').Groups[1].Value
    if (-not ($installLines | Where-Object { $_ -match '^change: rpworker cloud register' })) { throw 'the installer did not register' }
    if (-not ($installLines | Where-Object { $_ -match '^change: rpworker service start \(started' })) { throw 'the installer did not start the service' }
    $serviceSid = (& sc.exe showsid $script:W48Service | Where-Object { $_ -match 'SERVICE SID' }) -replace '.*: ', ''
    $t += "sc showsid ${script:W48Service}: $serviceSid"
    $t += "rpworker vault list after: $(((((Invoke-W48 @('vault', 'list')) -split "`n") | Where-Object { $_ -match '^[a-z_]+\r?$' } | ForEach-Object { $_.Trim() }) -join ', ')) (names only)"
    $t += "config.json: $([IO.File]::ReadAllText($ConfigPath))"
    $t += "state\worker.json: $([IO.File]::ReadAllText((Join-Path $script:W48State 'worker.json')))"
    $t += "-- icacls after`n$(Get-Acls (Get-AclPaths))"

    # 5
    $t += "`n== 5. the connector and the plan =="
    Push-Location $CloudDir
    try { docker compose cp $LabProfile api:/tmp/w71-profile.json 2>&1 | Out-Null } finally { Pop-Location }
    $connector = Invoke-Manage @('create-connector', '--msp-id', $mspId, '--client-id', $clientId, '--worker-id', $workerId, '--profile-file', '/tmp/w71-profile.json')
    $connectorId = Get-Value $connector.Text 'connector_id'
    $plan = Invoke-Manage @('create-plan', '--msp-id', $mspId, '--client-id', $clientId, '--connector-id', $connectorId, '--mail', '10', '--sp', '10', '--od', '10', '--cron', '*/5 * * * *')
    $planId = Get-Value $plan.Text 'plan_id'
    if (-not $connectorId -or -not $planId) { throw "the connector or the plan wasn't made: $($connector.Text) $($plan.Text)" }
    $t += "create-connector --profile-file <the lab profile>: connector_id $connectorId"
    $t += "create-plan --mail 10 --sp 10 --od 10 --cron '*/5 * * * *' (no --canaries): plan_id $planId, at $(Get-Utc)"

    # 6
    $t += "`n== 6. the plan's runs in the database, every 10 s =="
    $deadline = [DateTime]::UtcNow.AddMinutes(30)
    $seen = @{}
    $runId = $null
    while ([DateTime]::UtcNow -lt $deadline -and -not $runId) {
        $rows = Invoke-Sql "SELECT id, state, coalesce(to_char(dispatched_at, 'YYYY-MM-DD""T""HH24:MI:SS""Z""'), '-'), coalesce(to_char(received_at, 'YYYY-MM-DD""T""HH24:MI:SS""Z""'), '-') FROM test_run WHERE plan_id = '$planId' ORDER BY created_at"
        foreach ($row in @($rows -split "`n" | Where-Object { $_ })) {
            $id, $state, $dispatched, $received = $row -split '\|'
            if ($seen[$id] -ne $state) {
                $t += "$(Get-Utc) run $id $(if ($seen[$id]) { "$($seen[$id]) -> " })$state (dispatched_at $dispatched, received_at $received)"
                $seen[$id] = $state
            }
            if ($state -eq 'pass') { $runId = $id }
            if ($state -in 'fail', 'error', 'expired') { throw "run $id is $state" }
        }
        if (-not $runId) { Start-Sleep -Seconds 10 }
    }
    if (-not $runId) { throw 'no run of the plan was pass within 30 minutes' }

    # 7
    $t += "`n== 7. the service stopped; its log; both verifiers; the row =="
    Start-Sleep -Seconds 5
    $t += Invoke-W48 @('service', 'stop')
    $t += "-- worker.log from the installer's start on`n$(Get-W48Log -Since $since)"
    $t += "-- outbox list`n$(Invoke-W48 @('outbox', 'list'))"
    $sent = Join-Path $Root "sent\$runId"
    $verified = Test-W48Folder $sent
    $t += "-- the sent folder`n$verified"
    if ($verified -notmatch '(?m)^verified ' -or $verified -notmatch 'verify_bundle.py \(exit code 0\)') { throw 'the sent folder did not verify' }
    $row = Invoke-Sql "SELECT state, bundle_sha256, worker_id, signature_ok, tsa_ok, attempt FROM test_run WHERE id = '$runId'"
    $state, $bundle, $rowWorker, $signatureOk, $tsaOk, $attempt = $row -split '\|'
    $t += "test_run ${runId}: state $state, bundle_sha256 $bundle, worker_id $rowWorker, signature_ok $signatureOk, tsa_ok $tsaOk, attempt $attempt"
    $fileHash = (Get-FileHash (Join-Path $sent 'result.json') -Algorithm SHA256).Hash.ToLower()
    if ($state -ne 'pass' -or $bundle -ne $fileHash -or $rowWorker -ne $workerId) { throw 'the row is not the sent bundle''s pass' }
    $t += "test_item: $(Invoke-Sql "SELECT count(*) || ' item(s), ' || count(*) FILTER (WHERE match) || ' matched; ' || string_agg(DISTINCT expected_kind, ', ') FROM test_item WHERE run_id = '$runId'")"
    $t += "worker ${workerId}: $(Invoke-Sql "SELECT 'name ' || name || ', version ' || coalesce(version, '-') || ', last_seen_at ' || coalesce(to_char(last_seen_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'), '-') || ' UTC' FROM worker WHERE id = '$workerId'")"

    # 8
    $t += "`n== 8. the installer again =="
    $t += Invoke-W48 @('service', 'start')
    $againLines = @(& $Installer -Package $Package 2>&1 | ForEach-Object { "$_" })
    $t += $againLines
    if (-not ($againLines | Where-Object { $_ -eq 'changes: 0' })) { throw 'the second run made a change' }
    $t += Invoke-W48 @('service', 'stop')
    $ok = $true
} catch {
    $t += "`n!! FAILED: $($_.Exception.Message)"
} finally {
    $installToken = $null
    $t += "`n== 9. taken away =="
    if ($installed) {
        $t += "-- the service`n$(Remove-W48Service)"
        if ($keyFileGranted -and $serviceSid) {
            foreach ($key in @(Get-W48KeyFile)) { icacls $key.File /remove:g "*$serviceSid" /Q | Out-Null; $t += "key file of certificate $($key.Thumbprint): the account's entry removed" }
        }
        foreach ($name in 'config.json', 'veeam-rest.pem', 'cloud-ca.pem') {
            $file = Join-Path $Root $name
            if (Test-Path -LiteralPath $file) { Move-Item -LiteralPath $file (Join-Path $RunDir "installed-$name") -Force; $t += "$file moved to the run folder" }
        }
        if (Test-Path -LiteralPath $ProgramDir) { Remove-Item -LiteralPath $ProgramDir -Recurse -Force; $t += "$ProgramDir removed" }
        foreach ($name in 'worker.json', 'jobs.json', 'running.json') {
            $file = Join-Path $script:W48State $name
            if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file -Force; $t += "$file removed" }
        }
    }
    if ($vaultOurs) {
        foreach ($name in 'cloud_api_token', 'cloud_install_token') { $t += (Invoke-W48 @('vault', 'remove', $name)) -split "`n" | Where-Object { $_ -match '^(command|exit code|removed|vault)' } }
    } else {
        $t += 'the vault left as it was: this run put no token there'
    }
    New-Item -ItemType Directory -Force $Kept | Out-Null
    foreach ($folder in @(Get-ChildItem (Join-Path $Root 'sent') -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^[0-9a-f-]{36}$' -and $_.LastWriteTimeUtc -ge $since.AddMinutes(-1) })) {
        Move-Item $folder.FullName (Join-Path $Kept $folder.Name) -Force
        $t += "sent folder kept: $(Join-Path $Kept $folder.Name)"
    }
    $t += "-- icacls at the end (the data folder's ACL stays)`n$(Get-Acls (Get-AclPaths))"
    $after = Get-W48Targets
    $t += "-- the restore targets after`n$after"
    $text = ($t -join "`n")
    $runFile = Join-Path $RunDir 'w7.1-done-when.txt'
    [IO.File]::WriteAllText($runFile, $text.Replace("`r`n", "`n") + "`n", [Text.UTF8Encoding]::new($false))
    "run text: $runFile"
}
if (-not $ok) { Write-Error 'the Done-when did not hold; nothing copied into the repository'; exit 1 }
if ($after -notmatch '(?m)^0 item\(s\) in the three restore targets') { Write-Warning 'the targets after: see the text' }
if (-not $NoCopy) {
    $saved = Save-W48Evidence 'w7.1-done-when.txt' ($t -join "`n")
    $saved
}

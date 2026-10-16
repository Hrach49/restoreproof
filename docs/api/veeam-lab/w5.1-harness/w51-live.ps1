# W5.1 (#66): the live Done-when, "the DB shows a pass run whose bundle was produced by the service
# on the Veeam VM" (docs/decisions.md 2026-10-15, "W5.1 (#66)", point 13). Everything on this
# laptop: the Compose stack (with Caddy's HTTPS front at https://localhost:8443) and the Veeam VM
# that it is. Run from an ELEVATED PowerShell 7, Docker Desktop running, no RestoreProof service
# installed, no session of rp-veeam Working, the vault without cloud_api_token:
#
#   pwsh -File docs\api\veeam-lab\w5.1-harness\w51-live.ps1
#   pwsh -File docs\api\veeam-lab\w5.1-harness\w51-live.ps1 -NoCopy   # leave the evidence in the run folder
#
# In order:
#   1. rpworker graph list: the three restore targets empty (else stop; nothing is cleaned)
#   2. the stack up with --build, re-migrated (downgrade base, upgrade head), Caddy's root copied
#      beside the service's config copy
#   3. manage.py: an MSP, the lab tenant's client, an install token, which goes straight into
#      `rpworker vault set cloud_install_token` on stdin (never a file, a command line or a log)
#   4. the config copy (W4.8's): cloud_url https://localhost:8443, cloud_ca_file Caddy's root, no
#      jobs_file (the Cloud is the job source), no client keys, poll and heartbeat every 60 s
#   5. service install, the grants (W4.8's, and failed\), service start: the first start
#      registers (`registered worker ...`), then the connector on the lab profile and the plan
#      with a 5-minute cron
#   6. the database read every 10 s until a run of the plan is pass (or fail/error, or 30 minutes):
#      queued by the scheduler, dispatched by the poll, pass by the upload, each change with its time
#   7. the service stopped; its log, the outbox, both verifiers on the sent folder
#   8. the run's row (state, bundle_sha256, worker_id, tsa_ok), the Worker's last_seen_at, the
#      objects under msp/<msp_id>/runs/<run_id>/
#   9. in the finally: the grants taken away, the service uninstalled, both Cloud tokens removed
#      from the vault, the config copy and the state folder taken away (the sent folder is kept
#      outside the repository under %ProgramData%\RestoreProof\w51), graph list
# Only when every step held and no secret, token or key survives in the text is it copied to
# docs\api\veeam-lab\w5.1-done-when.txt, the copy last. Before the commit, also run
# `python tools/fixture_secret_scan.py` from worker\ and `audit-evidence.ps1`.
param([switch]$NoCopy)
. (Join-Path $PSScriptRoot '..\w4.8-harness\w48-run.ps1')

$RunDir = Join-Path $env:LOCALAPPDATA ("RestoreProof\lab\w5.1-" + (Get-Date -Format 'yyyyMMddTHHmmss'))
$CloudDir = Join-Path $script:Repo 'cloud'
$LabProfile = Join-Path $env:LOCALAPPDATA 'RestoreProof\lab\lab-profile.json'
$CloudCa = Join-Path $script:W48Dir 'cloud-ca.pem'
$Kept = Join-Path $script:W48Root 'w51'
$Failed = Join-Path $script:W48Root 'failed'
$Evidence = Join-Path $script:Repo 'docs\api\veeam-lab\w5.1-done-when.txt'
$commit = git -C $script:Repo rev-parse --short HEAD
function Get-Utc { [DateTime]::UtcNow.ToString('s') + 'Z' }

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'run from an elevated shell'; exit 64
}
docker info *> $null
if ($LASTEXITCODE -ne 0) { Write-Error 'Docker Desktop is not running'; exit 64 }
if (Get-CimInstance Win32_Service -Filter "Name='$script:W48Service'") { Write-Error 'a RestoreProof service is installed: uninstall it first'; exit 64 }
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

$t = @("W5.1 (#66) Done-when, live: a plan made with manage.py create-plan (5-minute cron); the service on this laptop (the Veeam VM) registers on its first start, polls GET /v1/jobs over https://localhost:8443 (Caddy, its own CA), runs the job and uploads it; the run goes queued -> dispatched -> pass in the stack's database. $(Get-Utc), commit $commit, branch $(git -C $script:Repo branch --show-current)")
$t += "Windows, PowerShell $($PSVersionTable.PSVersion), Docker Desktop, the Compose stack on 127.0.0.1; $((& $script:Worker --version) -join ' ')"
$ok = $false
$installed = $false
$installToken = $null
# The vault's two Cloud tokens are this run's to remove only once the run has
# seen that neither was there before it (the W5.1 code review's finding 5: a
# registered Worker's token, shown once by the Cloud, was removed by a run
# that refused to start).
$vaultOurs = $false
$since = [DateTime]::UtcNow
$after = ''
try {
    # 1
    $t += "`n== 1. the restore targets before =="
    $before = Get-W48Targets
    $t += $before
    if ($before -notmatch '(?m)^0 item\(s\) in the three restore targets') { throw 'the restore targets are not empty (or graph list failed); nothing is cleaned' }
    $vaultList = Invoke-W48 @('vault', 'list')
    if ($vaultList -match '(?m)^cloud_api_token\r?$') { throw 'the vault already holds cloud_api_token: remove it first (rpworker vault remove cloud_api_token)' }
    if ($vaultList -match '(?m)^cloud_install_token\r?$') { throw 'the vault already holds cloud_install_token: remove it first (rpworker vault remove cloud_install_token)' }
    $vaultOurs = $true

    # 2
    $t += "`n== 2. the stack, re-migrated; Caddy's root =="
    $t += (Invoke-Compose @('up', '-d', '--wait', '--build')).Text -split "`n" | Where-Object { $_ -match 'Healthy|Exited|Running|Started' }
    $t += "alembic downgrade base: exit $((Invoke-Compose @('exec', '-T', 'api', 'alembic', 'downgrade', 'base')).Code)"
    $t += "alembic upgrade head: exit $((Invoke-Compose @('exec', '-T', 'api', 'alembic', 'upgrade', 'head')).Code)"
    $t += "-- the config copy`n$(Initialize-W48Harness)"
    $copied = Invoke-Compose @('cp', 'proxy:/data/caddy/pki/authorities/local/root.crt', $CloudCa)
    if ($copied.Code -ne 0) { throw "Caddy's root couldn't be copied: $($copied.Text)" }
    $root = [Security.Cryptography.X509Certificates.X509Certificate2]::new($CloudCa)
    $t += "Caddy's root: $($root.Subject), until $($root.NotAfter.ToUniversalTime().ToString('s'))Z, SHA-256 $((Get-FileHash $CloudCa -Algorithm SHA256).Hash.ToLower()), copied to $CloudCa"
    $version = & curl.exe -s -i --ssl-revoke-best-effort --cacert $CloudCa https://localhost:8443/v1/version
    $t += "GET https://localhost:8443/v1/version (curl, the root as its CA):`n$(($version | Where-Object { $_ -match '^HTTP/|^X-Restoreproof-Api|^Via|^\{' }) -join "`n")"

    # 3
    $t += "`n== 3. manage.py: the MSP, the client, the install token =="
    $tenant = (Get-Content $LabProfile -Raw | ConvertFrom-Json).graph_tenant_id
    $msp = Invoke-Manage @('create-msp', '--name', 'w51-live')
    $mspId = Get-Value $msp.Text 'msp_id'
    $client = Invoke-Manage @('create-client', '--msp-id', $mspId, '--name', 'lab-tenant', '--tenant-id', $tenant)
    $clientId = Get-Value $client.Text 'client_id'
    if (-not $mspId -or -not $clientId) { throw "the MSP or the client wasn't made: $($msp.Text) $($client.Text)" }
    $t += "create-msp: msp_id $mspId; create-client --tenant-id ${tenant}: client_id $clientId"
    $made = Invoke-Manage @('create-worker-token', '--msp-id', $mspId, '--label', 'w5.1 live')
    $installToken = Get-Value $made.Text 'install_token'
    $t += "create-worker-token --label 'w5.1 live': exit $($made.Code), $((($made.Text -split "`n") | Where-Object { $_ -notlike 'install_token *' }) -join '; '); install_token (not shown)"
    if (-not $installToken) { throw 'no install token' }
    $set = $installToken | & $script:Worker vault set cloud_install_token 2>&1
    $t += "rpworker vault set cloud_install_token (the token on stdin): exit $LASTEXITCODE $(($set | ForEach-Object { "$_" }) -join ' ')"
    $t += "rpworker vault list, its cloud_ names: $(((Invoke-W48 @('vault', 'list')) -split "`n" | Where-Object { $_ -match '^cloud_' } | ForEach-Object { $_.Trim() }) -join ', ') (names only)"

    # 4
    $t += "`n== 4. the service's config copy =="
    $config = Get-Content $W48Config -Raw | ConvertFrom-Json -AsHashtable
    foreach ($key in 'veeam_org_name', 'graph_tenant_id', 'graph_client_id', 'test_mailbox', 'test_site_id', 'test_library_id', 'test_onedrive_drive_id', 'test_onedrive_folder_id', 'jobs_file') { $config.Remove($key) }
    $config['cloud_url'] = 'https://localhost:8443'
    $config['cloud_ca_file'] = $CloudCa
    $config['poll_interval_s'] = 60
    $config['heartbeat_interval_s'] = 60
    [IO.File]::WriteAllText($W48Config, ($config | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
    $t += "cloud_url https://localhost:8443, cloud_ca_file $CloudCa, no jobs_file, the eight client keys taken out, poll_interval_s 60, heartbeat_interval_s 60"
    $t += (Invoke-W48 @('config', 'check', '--config', $W48Config)) -split "`n" | Where-Object { $_ -match '^(cloud_|jobs|poll|heartbeat|exit code)' }

    # 5
    $t += "`n== 5. install, grants, the first start; the connector and the plan =="
    $t += Invoke-W48 @('service', 'install', '--config', $W48Config)
    $installed = $true
    New-Item -ItemType Directory -Force $Failed | Out-Null
    $t += "-- the grants`n$(Grant-W48Account)"
    icacls $Failed /grant "$($script:W48Account):(OI)(CI)M" /Q | Out-Null
    $t += "${Failed}: Modify granted to $script:W48Account"
    $since = [DateTime]::UtcNow
    $start = Invoke-W48 @('service', 'start')
    $t += "-- the first start`n$start"
    $workerId = [regex]::Match($start, 'registered worker ([0-9a-f-]{36}) key ([0-9a-f]{64})').Groups[1].Value
    if (-not $workerId) { throw 'service start did not register' }
    $installToken = $null
    $t += "rpworker vault list after the first start, its cloud_ names: $(((Invoke-W48 @('vault', 'list')) -split "`n" | Where-Object { $_ -match '^cloud_' } | ForEach-Object { $_.Trim() }) -join ', ') (names only)"
    $t += "state\worker.json: $([IO.File]::ReadAllText((Join-Path $script:W48State 'worker.json')))"
    Push-Location $CloudDir
    try { docker compose cp $LabProfile api:/tmp/w51-profile.json 2>&1 | Out-Null } finally { Pop-Location }
    $connector = Invoke-Manage @('create-connector', '--msp-id', $mspId, '--client-id', $clientId, '--worker-id', $workerId, '--profile-file', '/tmp/w51-profile.json')
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
    $t += "`n== 7. the service stopped; its log; the outbox; both verifiers =="
    Start-Sleep -Seconds 5
    $t += Invoke-W48 @('service', 'stop')
    $t += "-- worker.log from the first start on`n$(Get-W48Log -Since $since)"
    $t += "-- outbox list`n$(Invoke-W48 @('outbox', 'list'))"
    $sent = Join-Path $script:W48Root "sent\$runId"
    $verified = Test-W48Folder $sent
    $t += "-- the sent folder`n$verified"
    if ($verified -notmatch '(?m)^verified ' -or $verified -notmatch 'verify_bundle.py \(exit code 0\)') { throw 'the sent folder did not verify' }

    # 8
    $t += "`n== 8. the run's row, the Worker's row, the objects =="
    $row = Invoke-Sql "SELECT state, bundle_sha256, worker_id, signature_ok, tsa_ok, to_char(tsa_time, 'YYYY-MM-DD""T""HH24:MI:SS""Z""'), attempt FROM test_run WHERE id = '$runId'"
    $state, $bundle, $rowWorker, $signatureOk, $tsaOk, $tsaTime, $attempt = $row -split '\|'
    $t += "test_run ${runId}: state $state, bundle_sha256 $bundle, worker_id $rowWorker, signature_ok $signatureOk, tsa_ok $tsaOk, tsa_time $tsaTime, attempt $attempt"
    $fileHash = (Get-FileHash (Join-Path $sent 'result.json') -Algorithm SHA256).Hash.ToLower()
    $t += "the sent result.json's SHA-256: $fileHash"
    if ($state -ne 'pass' -or $bundle -ne $fileHash -or $rowWorker -ne $workerId) { throw 'the row is not the sent bundle''s pass' }
    $t += "test_item: $(Invoke-Sql "SELECT count(*) || ' item(s), ' || count(*) FILTER (WHERE match) || ' matched; ' || string_agg(DISTINCT expected_kind, ', ') FROM test_item WHERE run_id = '$runId'")"
    $t += "worker ${workerId}: $(Invoke-Sql "SELECT 'name ' || name || ', version ' || coalesce(version, '-') || ', last_seen_at ' || coalesce(to_char(last_seen_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'), '-') || ' UTC, last_error ' || coalesce(last_error, '-') || ', outbox_depth ' || coalesce(outbox_depth::text, '-') FROM worker WHERE id = '$workerId'")"
    $t += "audit_log: $(Invoke-Sql "SELECT string_agg(action || ' ' || target, '; ' ORDER BY at) FROM audit_log WHERE msp_id = '$mspId'")"
    $listing = Invoke-Compose @('exec', '-T', 'api', 'python', '-c', "import os, boto3; c = boto3.client('s3', endpoint_url=os.environ['S3_ENDPOINT'], aws_access_key_id=os.environ['S3_ACCESS_KEY'], aws_secret_access_key=os.environ['S3_SECRET_KEY']); [print(o['Key'], o['Size']) for o in c.list_objects_v2(Bucket=os.environ['S3_BUCKET'], Prefix='msp/$mspId/runs/$runId/').get('Contents', [])]")
    $t += "the objects under msp/$mspId/runs/${runId}/:`n$($listing.Text)"
    $ok = $true
} catch {
    $t += "`n!! FAILED: $($_.Exception.Message)"
} finally {
    $installToken = $null
    $t += "`n== 9. taken away =="
    if ($installed) {
        try { $t += "-- the grants`n$(Revoke-W48Account)" } catch { $t += "-- the grants couldn't be taken away: $($_.Exception.Message)" }
        try { icacls $Failed /remove:g $script:W48Account /Q | Out-Null } catch { }
        $t += "-- the service`n$(Remove-W48Service)"
    }
    if ($vaultOurs) {
        foreach ($name in 'cloud_api_token', 'cloud_install_token') { $t += (Invoke-W48 @('vault', 'remove', $name)) -split "`n" | Where-Object { $_ -match '^(command|exit code|removed|vault)' } }
    } else {
        $t += 'the vault left as it was: this run put no token there'
    }
    New-Item -ItemType Directory -Force $Kept | Out-Null
    foreach ($folder in @(Get-ChildItem (Join-Path $script:W48Root 'sent') -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^[0-9a-f-]{36}$' -and $_.LastWriteTimeUtc -ge $since.AddMinutes(-1) })) {
        Move-Item $folder.FullName (Join-Path $Kept $folder.Name) -Force
        $t += "sent folder kept: $(Join-Path $Kept $folder.Name)"
    }
    $t += Remove-W48Harness
    $after = Get-W48Targets
    $t += "-- the restore targets after`n$after"
    $text = ($t -join "`n")
    $runFile = Join-Path $RunDir 'w5.1-done-when.txt'
    [IO.File]::WriteAllText($runFile, $text.Replace("`r`n", "`n") + "`n", [Text.UTF8Encoding]::new($false))
    "run text: $runFile"
}
if (-not $ok) { Write-Error 'the Done-when did not hold; nothing copied into the repository'; exit 1 }
if ($after -notmatch '(?m)^0 item\(s\) in the three restore targets') { Write-Warning 'the targets after: see the text' }
if (-not $NoCopy) {
    $saved = Save-W48Evidence 'w5.1-done-when.txt' ($t -join "`n")
    $saved
}

# C5.7 (#60): the live Done-when, "a real Worker bundle lands as pass in the DB", from the
# Veeam VM to the Compose stack, in one go, over the W4.8 harness (docs/decisions.md
# 2026-10-10, C5.7, point 17; docs/testing.md "The upload"). The Worker sends no Authorization
# header until W5.1, so its own flush goes to the W4.6 stub Cloud (202) as in W4.8 to W4.11; the
# real Worker bundle it made is then posted by hand with the API token, exactly as the Worker
# will post it, to the stack on 127.0.0.1:8000.
#
#   (1) the stack up and its database re-migrated once (the edit of 0001), alembic check clean;
#   (2) the rows: one MSP, one client of the lab tenant, one install token (c57-rows.py init);
#   (3) the Worker's key from the vault (rpworker signer public-key) registered through
#       POST /v1/workers/register with that token: 201, the API token kept for the session;
#   (4) the connector on the lab's profile, a plan and one queued run (c57-rows.py run), then
#       GET /v1/jobs with the API token: the restoreproof.jobs.v1 document with the run's uuid,
#       which becomes the service's jobs file;
#   (5) the service on the config copy (W4.8's harness, the eight client keys taken out): the
#       run lands under outbox\<uuid>\ and goes to sent\ by the stub's 202;
#   (6) curl.exe posts that folder's files to POST /v1/results with the token: 202
#       {"run_id","state":"pass"}; the same again: 202 with no change;
#   (7) the row, the items and the audit rows (c57-rows.py show); the objects listed through
#       boto3 and downloaded, verify_bundle.py on them under the Worker's key and the pinned root;
#   (8) a tampered copy (one byte of items.csv): 400 attachment_hash, one audit row, no object;
#   (9) the teardown: the service gone, the folder kept outside the repo, the token file removed,
#       the stack's rows left (docker compose down -v drops them).
# Each step's text goes into docs/api/cloud-lab/c5.7-done-when.txt, refused if a secret or a
# token survives in it. Run from an elevated PowerShell 7 on the lab machine with Docker Desktop
# and the stack up, nothing installed and no session of rp-veeam Working:
#
#   pwsh -File docs\api\cloud-lab\c5.7-harness\c57-live.ps1 [-Prefix c57]
#
# W6.3 (docs/decisions.md 2026-10-14, W6.3 and W6.2, point 15) runs it as its upload step with
# its own -Title, -EvidenceDir and -Evidence, so the C5.7 file is never replaced by that run.
param(
    [string]$Prefix = 'c57',
    [string]$Title = 'C5.7 (#60) Done-when, the live upload: a real Worker bundle from the Veeam VM lands as pass in the stack''s DB.',
    [string]$EvidenceDir = '',
    [string]$Evidence = 'c5.7-done-when.txt'
)
. (Join-Path $PSScriptRoot '..\..\veeam-lab\w4.8-harness\w48-run.ps1')

$Cloud = 'http://127.0.0.1:8000'
$CloudDir = Join-Path $script:Repo 'cloud'
$Rows = Join-Path $PSScriptRoot 'c57-rows.py'
$Lab = Join-Path $env:LOCALAPPDATA 'RestoreProof\lab'
$LabProfile = Join-Path $Lab 'lab-profile.json'
$C57Temp = Join-Path $env:TEMP 'rp-c57'
$C57Kept = Join-Path $script:W48Root 'c57'
$TsaCa = Join-Path $script:Repo 'shared\tsa\tsa-ca.pem'
$commit = git -C $script:Repo rev-parse --short HEAD
function Get-Utc { [DateTime]::UtcNow.ToString('s') + 'Z' }
function Invoke-Rows([string[]]$Arguments) {
    Push-Location $CloudDir
    try { (& uv run python $Rows @Arguments 2>&1) -join "`n" } finally { Pop-Location }
}
function Get-Value([string]$Text, [string]$Name) { ($Text -split "`n" | Where-Object { $_ -like "$Name *" } | Select-Object -First 1) -replace "^$Name ", '' }
# curl, with the token read from the file and never put into the evidence.
function Invoke-Curl([string[]]$Arguments) {
    $token = Get-Content (Join-Path $C57Temp 'api-token.txt') -Raw
    $out = & curl.exe -s -S --max-time 300 -H "Authorization: Bearer $($token.Trim())" @Arguments 2>&1
    ($out -join "`n")
}
# The two tokens' values, read while their files are still there (the C5.7 review's finding 11:
# the guard used to look for files the teardown had just removed).
function Get-C57Tokens {
    foreach ($file in 'install-token.txt', 'api-token.txt') {
        $path = Join-Path $C57Temp $file
        if (Test-Path $path) { $value = (Get-Content $path -Raw).Trim(); if ($value) { $value } }
    }
}
# The text of a run, the evidence or a failed run's, refused if a secret, a token or a key survives.
function Save-C57Evidence([string]$Name, [string]$Text, [string[]]$Tokens) {
    foreach ($s in Get-W48Secrets) { if ($s -and $Text.Contains($s)) { throw "a secret survived in $Name; nothing written" } }
    foreach ($value in $Tokens) { if ($value -and $Text.Contains($value)) { throw "a token's value survived in $Name; nothing written" } }
    if ($Text -match 'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.' -or $Text -match 'MII[A-Za-z0-9+/]{60,}' -or $Text -match 'MC4CAQAwBQYDK2VwBCIEI[A-Za-z0-9+/]{43}' -or $Text -match 'PRIVATE KEY') { throw "a token or key-shaped value in $Name; nothing written" }
    $dir = $EvidenceDir ? $EvidenceDir : (Join-Path $script:Repo 'docs\api\cloud-lab')
    $path = Join-Path $dir $Name
    [IO.File]::WriteAllText($path, $Text.Replace("`r`n", "`n").TrimEnd("`n") + "`n", [Text.UTF8Encoding]::new($false))
    "saved $path"
}
# The status of a `curl -i` answer: its last status line's (a `100 Continue` may come first).
# Never a search of the whole text: every answer's Date header holds "202" until 2030.
function Get-C57Status([string]$Response) {
    $lines = @($Response -split "`r?`n" | Where-Object { $_ -match '^HTTP/\S+ \d{3}( |$)' })
    if ($lines.Count -eq 0) { return 0 }
    [int](($lines[-1] -split ' ')[1])
}

New-Item -ItemType Directory -Force $C57Temp, $C57Kept | Out-Null
$t = @("$Title $(Get-Utc), commit $commit, branch $(git -C $script:Repo branch --show-current)")
$t += "Windows, Python 3.12, Docker Desktop, the Compose stack (postgres:16, MinIO, api) on 127.0.0.1; rpworker $((& $script:Worker --version) -join ' ')"
$done = $false
try {
    # (1)
    $t += "`n== (1) the stack =="
    Push-Location $CloudDir
    try {
        $t += (docker compose up -d --wait --build 2>&1 | Where-Object { $_ -match 'Healthy|Exited|Started|Created' }) -join "`n"
        $t += "GET /healthz: $(& curl.exe -s -i $Cloud/healthz | Select-Object -First 1) $(& curl.exe -s $Cloud/healthz)"
        $t += "alembic (downgrade -1, upgrade head, check):"
        $t += (docker compose exec -T api alembic downgrade -1 2>&1 | Where-Object { $_ -match 'Running' }) -join "`n"
        $t += (docker compose exec -T api alembic upgrade head 2>&1 | Where-Object { $_ -match 'Running' }) -join "`n"
        $t += (docker compose exec -T api alembic check 2>&1 | Select-Object -Last 1)
        $t += "the image: $((docker compose exec -T api ls /srv/shared/tools /srv/shared/tsa 2>&1) -join ' ')"
    } finally { Pop-Location }

    # (2)
    $t += "`n== (2) the rows: one MSP, one client of the lab tenant, one install token =="
    $tenant = (Get-Content $LabProfile -Raw | ConvertFrom-Json).graph_tenant_id
    $init = Invoke-Rows @('init', $tenant)
    $mspId = Get-Value $init 'msp_id'; $clientId = Get-Value $init 'client_id'
    if (-not $mspId -or -not $clientId) { throw "c57-rows.py init failed: $init" }
    Set-Content (Join-Path $C57Temp 'install-token.txt') (Get-Value $init 'install_token')
    $t += "c57-rows.py init ${tenant}:`n$(($init -split "`n" | Where-Object { $_ -notlike 'install_token *' }) -join "`n")`ninstall_token: (kept in $C57Temp, not shown)"

    # (3)
    $t += "`n== (3) the Worker registers with its vault key =="
    $pemPath = Join-Path $C57Temp 'worker.pub.pem'
    $pem = & $script:Worker signer public-key 2>$null
    [IO.File]::WriteAllText($pemPath, (($pem -join "`n") + "`n"), [Text.UTF8Encoding]::new($false))
    $version = ((& $script:Worker --version) -join ' ') -replace '^rpworker\s+', ''
    $body = [ordered]@{ install_token = (Get-Content (Join-Path $C57Temp 'install-token.txt') -Raw).Trim(); public_key_pem = [IO.File]::ReadAllText($pemPath); worker_name = 'veeam-vm'; version = $version } | ConvertTo-Json
    $registerFile = Join-Path $C57Temp 'register.json'
    [IO.File]::WriteAllText($registerFile, $body, [Text.UTF8Encoding]::new($false))
    $registered = & curl.exe -s -S -X POST "$Cloud/v1/workers/register" -H 'Content-Type: application/json' -d "@$registerFile" 2>&1 | ConvertFrom-Json
    Set-Content (Join-Path $C57Temp 'api-token.txt') $registered.api_token
    $workerId = $registered.worker_id
    $t += "rpworker signer public-key: the PEM written to $pemPath, key $((& $script:Worker signer public-key 2>&1 | Where-Object { $_ -like 'key *' }) -join '')"
    $t += "POST /v1/workers/register (install_token, public_key_pem, worker_name veeam-vm, version $version): 201 worker_id $workerId, key_id $($registered.key_id), api_token (43 characters: $($registered.api_token.Length), kept in $C57Temp, not shown)"
    $t += "the same install token again: $(& curl.exe -s -X POST "$Cloud/v1/workers/register" -H 'Content-Type: application/json' -d "@$registerFile")"

    # (4)
    $t += "`n== (4) the connector, the plan, one run; the poll =="
    $run = Invoke-Rows @('run', $mspId, $clientId, $workerId, $LabProfile)
    $runId = Get-Value $run 'run_id'
    if (-not $runId) { throw "c57-rows.py run failed: $run" }
    $t += "c57-rows.py run (the lab's profile, a plan 10/10/10):`n$run"
    $jobs = Invoke-Curl @("$Cloud/v1/jobs")
    $jobsPath = Join-Path $Lab 'jobs.json'
    [IO.File]::WriteAllText($jobsPath, $jobs, [Text.UTF8Encoding]::new($false))
    $document = $jobs | ConvertFrom-Json
    $t += "GET /v1/jobs: format $($document.format), $($document.jobs.Count) job(s): run_id $($document.jobs[0].run_id), client_id $($document.jobs[0].client_id), connector $($document.jobs[0].connector.type), sizes $($document.jobs[0].sample_mail)/$($document.jobs[0].sample_sp)/$($document.jobs[0].sample_od), restore_point $($document.jobs[0].restore_point), screenshots_enabled $($document.jobs[0].screenshots_enabled); client.graph_tenant_id $($document.jobs[0].client.graph_tenant_id); saved as $jobsPath"
    $t += "GET /v1/jobs again: $(Invoke-Curl @("$Cloud/v1/jobs"))"
    if ($document.jobs[0].run_id -ne $runId) { throw "the poll answered $($document.jobs[0].run_id), not $runId" }

    # (5)
    $t += "`n== (5) the service runs the job =="
    $t += "-- the config copy`n$(Initialize-W48Harness)"
    $config = Get-Content $W48Config -Raw | ConvertFrom-Json -AsHashtable
    foreach ($key in 'veeam_org_name', 'graph_tenant_id', 'graph_client_id', 'test_mailbox', 'test_site_id', 'test_library_id', 'test_onedrive_drive_id', 'test_onedrive_folder_id') { $config.Remove($key) }
    [IO.File]::WriteAllText($W48Config, ($config | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
    $t += "-- the eight client keys taken out of the config copy; the stub Cloud answers the service's own flush (no token until W5.1)`n$(Start-W48Stub)"
    $t += "`n$(Invoke-W48 @('service', 'install', '--config', $W48Config))"
    try {
        $t += "-- the grants`n$(Grant-W48Account)"
        $since = [DateTime]::UtcNow
        $t += "`n$(Invoke-W48 @('service', 'start'))"
        $t += "`n$(Set-W48Jobs -Raw $jobs)"
        $t += "-- taken: $(Wait-W48Log "run ${runId}: starting" $since 300)"
        $t += "-- ended: $(Wait-W48Log "run ${runId}: ended" $since 1200)"
        $t += "-- sent to the stub: $(Wait-W48Log "sent $runId" $since 180)"
        Start-Sleep 5
        $t += "`n$(Invoke-W48 @('service', 'stop'))"
        $t += "-- worker.log from the start on`n$(Get-W48Log -Since $since)"
        $t += "`n-- afterwards`n$(Get-W48Record)`n$(Get-W48Folders)"
        $t += "-- the stub's lines`n$((Get-W48StubLog) -join "`n")"
    } finally {
        try { $t += "`n-- the grants taken away`n$(Revoke-W48Account)" } catch { $t += "`n-- the grants couldn't be taken away: $($_.Exception.Message)" }
        finally { $t += "`n-- the service uninstalled`n$(Remove-W48Service)" }
    }
    $sent = Join-Path $script:W48Root "sent\$runId"
    $t += "`n-- the sent folder, both verifiers`n$(Test-W48Folder $sent)"
    $result = Get-Content (Join-Path $sent 'result.json') -Raw | ConvertFrom-Json
    $t += "result.json client: client_id $($result.client.client_id), tenant_id $($result.client.tenant_id), scope $($result.client.scope), resolved.organization.tenant_id $($result.client.resolved.organization.tenant_id)"

    # (6)
    $t += "`n== (6) the folder posted by hand to POST /v1/results, as the Worker will post it =="
    $parts = @('-F', "result=@result.json;type=application/json", '-F', "signature=@signature.json;type=application/json")
    if (Test-Path (Join-Path $sent 'timestamp.tst')) { $parts += @('-F', "timestamp=@timestamp.tst;type=application/octet-stream") }
    foreach ($attachment in $result.attachments) { $parts += @('-F', "$($attachment.name)=@$($attachment.name);type=application/octet-stream") }
    Push-Location $sent
    try {
        $t += "curl.exe -s -i -X POST $Cloud/v1/results -H 'Authorization: Bearer <token>' $($parts -join ' ')"
        $first = Invoke-Curl (@('-i', '-X', 'POST', "$Cloud/v1/results") + $parts)
        $t += "-- the first upload:`n$first"
        $second = Invoke-Curl (@('-i', '-X', 'POST', "$Cloud/v1/results") + $parts)
        $t += "-- the same again:`n$second"
    } finally { Pop-Location }
    if ((Get-C57Status $first) -ne 202 -or (Get-C57Status $second) -ne 202) { throw "the upload was not accepted twice: $(Get-C57Status $first), $(Get-C57Status $second)" }

    # (7)
    $t += "`n== (7) the row, the items, the audit rows, the objects =="
    $t += (Invoke-Rows @('show', $mspId, $runId))
    $downloaded = Join-Path $C57Temp 'downloaded'
    New-Item -ItemType Directory -Force $downloaded | Out-Null
    $listScript = @"
import boto3, sys
from pathlib import Path
s3 = boto3.client('s3', endpoint_url='http://127.0.0.1:9000', region_name='us-east-1', aws_access_key_id='local-only-minio', aws_secret_access_key='local-only-minio-secret')
prefix = 'msp/$mspId/runs/$runId/'
for obj in s3.list_objects_v2(Bucket='restoreproof', Prefix=prefix)['Contents']:
    name = obj['Key'][len(prefix):]
    body = s3.get_object(Bucket='restoreproof', Key=obj['Key'])
    Path(r'$downloaded', name).write_bytes(body['Body'].read())
    print(f"{obj['Key']} {obj['Size']} {body['ContentType']}")
"@
    $listFile = Join-Path $C57Temp 'list.py'
    [IO.File]::WriteAllText($listFile, $listScript, [Text.UTF8Encoding]::new($false))
    Push-Location $CloudDir
    try { $t += "the bucket under msp/$mspId/runs/$runId/ (boto3, the stack's local-only MinIO), each downloaded:`n$((& uv run python $listFile 2>&1) -join "`n")" } finally { Pop-Location }
    $t += "-- verify_bundle.py on the downloaded objects:`n$((& uv run (Join-Path $script:Repo 'shared\tools\verify_bundle.py') $downloaded --public-key $pemPath --tsa-ca $TsaCa --schemas (Join-Path $script:Repo 'shared\schemas') 2>&1) -join ' | ') (exit code $LASTEXITCODE)"
    $t += "-- the same folder, rpworker signer verify:`n$(Invoke-W48 @('signer', 'verify', $downloaded, '--public-key', $pemPath, '--tsa-ca', $TsaCa))"
    $t += "result.json sha256 as stored: $((Get-FileHash (Join-Path $downloaded 'result.json') -Algorithm SHA256).Hash.ToLower())"

    # (8)
    $t += "`n== (8) a tampered copy: one byte of items.csv =="
    $tampered = Join-Path $C57Temp 'tampered'
    Copy-Item $sent $tampered -Recurse -Force
    $bytes = [IO.File]::ReadAllBytes((Join-Path $tampered 'items.csv')); $bytes[-1] = $bytes[-1] -bxor 1; [IO.File]::WriteAllBytes((Join-Path $tampered 'items.csv'), $bytes)
    Push-Location $tampered
    try { $tamperedAnswer = Invoke-Curl (@('-i', '-X', 'POST', "$Cloud/v1/results") + $parts) } finally { Pop-Location }
    $t += "-- POST /v1/results with items.csv changed:`n$tamperedAnswer"
    if ((Get-C57Status $tamperedAnswer) -ne 400) { throw "the tampered copy was answered $(Get-C57Status $tamperedAnswer), not 400" }
    $t += (Invoke-Rows @('show', $mspId, $runId) | Select-String -Pattern 'state:|bundle_sha256|audit_log|result\.' | ForEach-Object Line) -join "`n"
    Push-Location $CloudDir
    try { $t += "the bucket afterwards: $((& uv run python -c "import boto3; s3 = boto3.client('s3', endpoint_url='http://127.0.0.1:9000', region_name='us-east-1', aws_access_key_id='local-only-minio', aws_secret_access_key='local-only-minio-secret'); print(len(s3.list_objects_v2(Bucket='restoreproof', Prefix='msp/$mspId/runs/$runId/')['Contents']), 'object(s)')" 2>&1) -join ' ')" } finally { Pop-Location }

    # (9)
    $t += "`n== (9) the teardown =="
    $t += "-- the three restore targets after`n$(Get-W48Targets)"
    $t += "-- Veeam: $(Get-W48Sessions)"
    Move-Item $sent (Join-Path $C57Kept $runId) -Force
    $t += "sent\$runId moved to $C57Kept (outside the repo); the stack's rows left; $jobsPath left"
    $t += (Remove-W48Harness)
    $t += "sc query: $((sc.exe query $script:W48Service 2>&1) -join ' ')"
    $done = $true
} finally {
    $tokens = @(Get-C57Tokens)
    Remove-Item -Recurse -Force $C57Temp -ErrorAction SilentlyContinue
    $t += "`n$C57Temp removed (the tokens, the PEM, the downloaded and tampered copies)"
    # A run that failed never replaces the committed evidence, and its text passes the same screen.
    $failedName = [IO.Path]::GetFileNameWithoutExtension($Evidence) + '.failed.txt'
    Save-C57Evidence ($done ? $Evidence : $failedName) ($t -join "`n") $tokens
    if (-not $done) { "a step failed; the text is in $failedName (not the evidence file)"; exit 1 }
}

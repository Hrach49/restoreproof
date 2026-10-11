# C5.8 (#61): the by-hand Done-when against the Compose stack (docs/decisions.md 2026-10-11,
# C5.8, point 11; docs/testing.md "The heartbeat"): the stack rebuilt and its schema checked, one
# MSP and one install token through the repos, a Worker registered with a key made for the run, the
# Worker's own recorded heartbeat bodies posted with curl fifteen minutes apart, the worker row
# read as C6.2's /workers page will read it after each, the issue's four-key body 422, no token
# 401, the api's request lines, the audit rows. The real service can't make this run until W5.1
# sends the Authorization header; the bodies are the service's own bytes
# (docs/api/veeam-lab/w4.11-3-service-run.txt lines 313 and 294).
#
#   pwsh -File docs\api\cloud-lab\c5.8-harness\c58-live.ps1 -Out docs\api\cloud-lab\c5.8-done-when.txt [-SleepSeconds 900]
#
# Nothing of the two tokens is written (the C5.8 review's finding 5): the install token goes to
# curl in the registration body on its standard input, the API token in a curl config on its
# standard input, so neither is in a file or on a command line; the evidence text is screened
# for both and for every token-shaped value before it is saved; a screen that fires leaves no file.
#
# The stack's rows are left alone (finding 6): the harness never downgrades. It adds one MSP, one
# install token, one Worker and their audit rows, reads only those, and stops when alembic check
# says the database isn't the models' (docs/testing.md "Cloud" has the two commands for that).
param([string]$Out, [int]$SleepSeconds = 900)
$ErrorActionPreference = 'Stop'
$Repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..\..')).Path
$CloudDir = Join-Path $Repo 'cloud'
$Rows = Join-Path $PSScriptRoot 'c58-rows.py'
$Cloud = 'http://127.0.0.1:8000'
$Temp = Join-Path $env:TEMP 'rp-c58'
New-Item -ItemType Directory -Force $Temp | Out-Null
function Now { [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ') }
function Invoke-Compose([string[]]$Arguments) { Push-Location $CloudDir; try { (& docker compose @Arguments 2>&1) -join "`n" } finally { Pop-Location } }
function Invoke-Rows([string[]]$Arguments) { Push-Location $CloudDir; try { (& uv run python $Rows @Arguments 2>&1) -join "`n" } finally { Pop-Location } }
function Invoke-Sql([string]$Sql) { Invoke-Compose @('exec', '-T', 'postgres', 'psql', '-U', 'restoreproof', '-d', 'restoreproof', '-c', $Sql) }
function Invoke-Curl([string[]]$Arguments) { (& curl.exe -s -S --max-time 60 @Arguments 2>&1) -join "`n" }
# The same with a text on curl's standard input: a body (--data-binary @-) or a config (-K -).
function Invoke-CurlWith([string]$Stdin, [string[]]$Arguments) { ($Stdin | & curl.exe -s -S --max-time 60 @Arguments 2>&1) -join "`n" }
# The API token as a curl config line, for standard input alone.
function Bearer([string]$Token) { "header = `"Authorization: Bearer $Token`"" }
function Status-Of([string]$Answer) { (($Answer -split "`n") | Where-Object { $_ -match '^HTTP/' } | Select-Object -Last 1).Trim() }

# The service's heartbeat after a job_invalid run (121 bytes) and its first heartbeat (88 bytes).
$Beat1 = '{"last_error":"job_invalid","last_error_at":"2026-10-09T20:27:38.206Z","outbox_depth":0,"uptime_s":152,"version":"0.0.0"}'
$Beat2 = '{"last_error":null,"last_error_at":null,"outbox_depth":0,"uptime_s":0,"version":"0.0.0"}'
# The issue's four-key body, which the Worker never sends.
$FourKeys = '{"last_error":null,"outbox_depth":0,"uptime_s":5,"version":"0.0.0"}'
$Columns = 'SELECT name, version, last_seen_at, last_error, last_error_at, outbox_depth, uptime_s, revoked_at FROM worker'
$started = Now
$utf8 = [Text.UTF8Encoding]::new($false)
foreach ($pair in @(@('beat-1.json', $Beat1), @('beat-2.json', $Beat2), @('four-keys.json', $FourKeys))) {
    [IO.File]::WriteAllText((Join-Path $Temp $pair[0]), $pair[1], $utf8)
}

$installToken = $null; $apiToken = $null
$t = @()
$t += "C5.8 (#61) Done-when, by hand against the Compose stack: the worker row's last_seen_at moves with each heartbeat, fifteen minutes apart. $(Now), commit $((git -C $Repo rev-parse --short HEAD 2>&1) -join ''), branch $((git -C $Repo rev-parse --abbrev-ref HEAD 2>&1) -join '')"
$t += "Windows, Python 3.12, Docker Desktop, the Compose stack (postgres:16, MinIO, api) on 127.0.0.1; the bodies are the Worker's own recorded bytes"
try {
    $t += "`n== (1) the stack =="
    # Compose's own status lines; BuildKit's progress (every layer, cached or not) is left out.
    $t += (((Invoke-Compose @('up', '-d', '--wait', '--build')) -split "`n") | Where-Object { $_ -match '^ (Container|Image|Network|Volume) ' }) -join "`n"
    $t += "GET /healthz: $((Invoke-Curl @('-i', "$Cloud/healthz")) -replace "`n", ' ' -replace '\s+', ' ')"
    $check = Invoke-Compose @('exec', '-T', 'api', 'alembic', 'check')
    $t += "alembic check (the stack's rows are left as they are; nothing is downgraded):`n$check"
    if ($LASTEXITCODE -ne 0) { throw 'alembic check: the database is not the models; re-migrate it by hand (docs/testing.md "Cloud") and run again' }
    $t += "the worker table's heartbeat columns: $((Invoke-Sql "SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'worker' AND column_name IN ('last_seen_at', 'last_error', 'last_error_at', 'outbox_depth', 'uptime_s', 'version') ORDER BY column_name") -replace "`n", ' | ')"
    $t += "its two CHECKs: $((Invoke-Sql "SELECT conname FROM pg_constraint WHERE conrelid = 'worker'::regclass AND contype = 'c' ORDER BY conname") -replace "`n", ' | ')"

    $t += "`n== (2) the rows: one MSP, one install token =="
    $init = Invoke-Rows @('init')
    $mspId = (($init -split "`n") | Where-Object { $_ -like 'msp_id *' }).Split(' ')[1]
    $installToken = (($init -split "`n") | Where-Object { $_ -like 'install_token *' }).Split(' ')[1]
    $keyLine = (($init -split "`n") | Where-Object { $_ -like 'public_key *' }).Split(' ')[1]
    $Pem = "-----BEGIN PUBLIC KEY-----`n$keyLine`n-----END PUBLIC KEY-----`n"
    $t += "c58-rows.py init: msp_id $mspId; install_token (kept in memory for the session, not shown); an Ed25519 public key made for this run, its private half never kept (uq_worker_key_id takes one key once across the Cloud, so a fixed test key would register once per database)"

    $t += "`n== (3) the Worker registers with the run's key =="
    $register = @{ install_token = $installToken; public_key_pem = $Pem; worker_name = 'c5.8 done-when'; version = '0.0.0-registered' } | ConvertTo-Json -Compress
    $answer = Invoke-CurlWith $register @('-X', 'POST', "$Cloud/v1/workers/register", '-H', 'Content-Type: application/json', '--data-binary', '@-')
    $registered = $null
    try { $registered = $answer | ConvertFrom-Json } catch { }
    $apiToken = if ($registered) { $registered.api_token } else { $null }
    if (-not $apiToken) { throw 'registration failed' }
    $workerId = [guid]::Parse($registered.worker_id).ToString()
    $Select = "$Columns WHERE id = '$workerId'"
    $t += "POST /v1/workers/register (install_token, public_key_pem, worker_name 'c5.8 done-when', version 0.0.0-registered; the body on curl's standard input): 201 worker_id $workerId, key_id $($registered.key_id); the API token kept in memory"
    $t += "the row before any heartbeat:`n$(Invoke-Sql $Select)"

    $t += "`n== (4) the first heartbeat: the service's recorded body after a job_invalid run (121 bytes) =="
    $t += "curl.exe -s -i -K - -X POST $Cloud/v1/heartbeat -H 'Content-Type: application/json' --data-binary @beat-1.json   (the config on standard input: header = `"Authorization: Bearer <token>`")"
    $t += "body: $Beat1"
    $sentAt1 = Now
    $answer = Invoke-CurlWith (Bearer $apiToken) @('-i', '-K', '-', '-X', 'POST', "$Cloud/v1/heartbeat", '-H', 'Content-Type: application/json', '--data-binary', "@$(Join-Path $Temp 'beat-1.json')")
    $t += "-- sent $sentAt1, answered:`n$answer"
    if ((Status-Of $answer) -notmatch ' 204 ') { throw "the first heartbeat was not 204: $(Status-Of $answer)" }
    $t += "the row (SELECT ... FROM worker WHERE id = the Worker's):`n$(Invoke-Sql $Select)"

    $t += "`n== (5) fifteen minutes later ($SleepSeconds s, heartbeat_interval_s's default): the service's first heartbeat (88 bytes), a restart's clean slate =="
    Start-Sleep -Seconds $SleepSeconds
    $t += "body: $Beat2"
    $sentAt2 = Now
    $answer = Invoke-CurlWith (Bearer $apiToken) @('-i', '-K', '-', '-X', 'POST', "$Cloud/v1/heartbeat", '-H', 'Content-Type: application/json', '--data-binary', "@$(Join-Path $Temp 'beat-2.json')")
    $t += "-- sent $sentAt2, answered:`n$answer"
    if ((Status-Of $answer) -notmatch ' 204 ') { throw "the second heartbeat was not 204: $(Status-Of $answer)" }
    $t += "the row:`n$(Invoke-Sql $Select)"
    $t += "as C6.2's /workers page will read it (WorkerRepo.list):`n$(Invoke-Rows @('show', $mspId))"

    $t += "`n== (6) the issue's four-key body, and no token =="
    $t += "body: $FourKeys"
    $answer = Invoke-CurlWith (Bearer $apiToken) @('-i', '-K', '-', '-X', 'POST', "$Cloud/v1/heartbeat", '-H', 'Content-Type: application/json', '--data-binary', "@$(Join-Path $Temp 'four-keys.json')")
    $t += "-- with the token:`n$answer"
    if ((Status-Of $answer) -notmatch ' 422 ') { throw "the four-key body was not 422: $(Status-Of $answer)" }
    $answer = Invoke-Curl @('-i', '-X', 'POST', "$Cloud/v1/heartbeat", '-H', 'Content-Type: application/json', '--data-binary', "@$(Join-Path $Temp 'beat-1.json')")
    $t += "-- the 121-byte body without a token:`n$answer"
    if ((Status-Of $answer) -notmatch ' 401 ') { throw "no token was not 401: $(Status-Of $answer)" }
    $t += "the row, unchanged by either:`n$(Invoke-Sql $Select)"

    $t += "`n== (7) the api's request lines (nothing of a body), the audit rows =="
    $lines = (Invoke-Compose @('logs', '--no-log-prefix', '--since', $started, 'api')) -split "`n" | Where-Object { $_ -match '/v1/heartbeat|/v1/workers/register' }
    $t += ($lines -join "`n")
    $t += "the audit rows: $((Invoke-Sql "SELECT action, target FROM audit_log WHERE msp_id = '$([guid]::Parse($mspId))' ORDER BY at") -replace "`n", ' | ')"
} finally {
    $t += "`n== (8) the teardown =="
    Remove-Item -Recurse -Force $Temp -ErrorAction SilentlyContinue
    $t += "$Temp removed (the three bodies, no token in them); the install token went to curl in the body on its standard input and the API token in a curl config on its standard input: neither was written to a file or put on a command line; this run's MSP, install token, Worker and audit rows are left in the stack's database and no other row was touched"
}
$text = ($t -join "`n").Replace("`r`n", "`n")
foreach ($s in @($installToken, $apiToken)) { if ($s -and $text.Contains($s)) { throw 'a token survived; nothing written' } }
if ($text -match '(?<![A-Za-z0-9_\-])[A-Za-z0-9_\-]{43}(?![A-Za-z0-9_\-=])' -or $text -match 'eyJ[A-Za-z0-9_\-]{10,}\.' -or $text -match 'PRIVATE KEY') { throw 'a token-shaped value; nothing written' }
[IO.File]::WriteAllText($Out, $text + "`n", $utf8)
"saved $Out"

# C6.6 (#72), with C6.7 (#73) and C6.5 (#71): the Done-when by hand against the Compose stack
# (docs/decisions.md 2026-10-13, "C6.6, C6.5 and C6.7", point 6; docs/testing.md "The report"):
# the stack rebuilt and its database re-migrated; by CLI an MSP with an admin and a member, a client
# of the lab tenant whose id becomes the kept C5.7 bundle's, the lab Worker's own key registered with
# curl, the connector on the lab profile, a plan with one run whose id becomes the bundle's; the poll;
# the real Worker bundle posted as the Worker posts it: 202 pass (a run of this month); then by SQL
# the rows of the previous month (a pass, a fail with two unmatched items, an error, a later pass, an
# expired run; the month computed from the clock); the scheduler restarted so its report job's start
# run makes that month's final report in the real process (no clock is moved); the row and the object
# held to each other; the two pages as the member; the Done-when, timed: "Generate now" clicked, the
# interim report listed and downloaded, its bytes' SHA-256 equal to file_sha256, under a minute; the
# cap's 429; another MSP's report 404; a cross-site click 403; /audit with the rows; the previous
# month's PDF (the new template: the four controls' sentences) kept beside the evidence when its text
# names no person and no tenant identifier; the teardown.
#
#   pwsh -File docs\api\cloud-lab\c6.5-c6.7-harness\c65-c67-live.ps1 -Out docs\api\cloud-lab\c6.5-c6.7-done-when.txt
#
# Nothing secret is written or put on a command line: the install token from the CLI's stdout into a
# variable and to curl in the registration body on its standard input; the API token in a curl config
# on its standard input; the passwords to the CLI and to curl on their standard input; the session
# cookie in curl's jar under %TEMP%, removed at the end. The evidence text is screened for all of them
# and for every token-, cookie- and signature-shaped value before it is saved; a screen that fires
# leaves no file. The stack's database is re-migrated once (the rows it held are dropped: nothing is
# deployed), and the harness reads only the rows it made. The harness never replaces committed
# evidence with a failed run's: the PDF is kept only once every step before it has passed.
param(
    [string]$Out,
    [string]$Bundle = 'C:\ProgramData\RestoreProof\c57\06aa7c8f-3611-4f00-92c8-797428f58f1a',
    [string]$Rpworker = '',
    [string]$KeepPdf = ''
)
$ErrorActionPreference = 'Stop'
$Repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..\..')).Path
$CloudDir = Join-Path $Repo 'cloud'
if (-not $Rpworker) { $Rpworker = Join-Path $Repo 'worker\build\dev\rpworker.exe' }
if (-not $KeepPdf) { $KeepPdf = Join-Path $Repo 'docs\api\cloud-lab\c6.4-sample-report.pdf' }
$PdfText = Join-Path $Repo 'docs\api\cloud-lab\c6.4-harness\c64-pdf-text.py'
$Cloud = 'http://127.0.0.1:8000'
$Temp = Join-Path $env:TEMP 'rp-c65'
$Jar = Join-Path $Temp 'jar.txt'
New-Item -ItemType Directory -Force $Temp | Out-Null
$utf8 = [Text.UTF8Encoding]::new($false)
function Now { [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ') }
function Invoke-Compose([string[]]$Arguments) { Push-Location $CloudDir; try { (& docker compose @Arguments 2>&1) -join "`n" } finally { Pop-Location } }
function Invoke-Manage([string[]]$Arguments, [string]$Stdin = $null) {
    Push-Location $CloudDir
    try {
        if ($null -ne $Stdin) { $text = ($Stdin | & docker compose exec -T api python manage.py @Arguments 2>&1) -join "`n" }
        else { $text = (& docker compose exec -T api python manage.py @Arguments 2>&1) -join "`n" }
        return [pscustomobject]@{ Text = $text; Exit = $LASTEXITCODE }
    } finally { Pop-Location }
}
# -q: no command tag after a RETURNING id, so the id is the whole answer.
function Invoke-Psql([string]$Sql) { Push-Location $CloudDir; try { ($Sql | & docker compose exec -T postgres psql -U restoreproof -d restoreproof -Atq 2>&1) -join "`n" } finally { Pop-Location } }
function Line-Of([string]$Text, [string]$Key) { (($Text -split "`n") | Where-Object { $_ -like "$Key *" } | Select-Object -First 1).Split(' ')[1] }
function Invoke-Curl([string[]]$Arguments) { (& curl.exe -s -S --max-time 120 @Arguments 2>&1) -join "`n" }
function Invoke-CurlWith([string]$Stdin, [string[]]$Arguments) { ($Stdin | & curl.exe -s -S --max-time 120 @Arguments 2>&1) -join "`n" }
function Bearer([string]$Token) { "header = `"Authorization: Bearer $Token`"" }
function Status-Of([string]$Answer) { (($Answer -split "`n") | Where-Object { $_ -match '^HTTP/' } | Select-Object -Last 1).Trim() }
function Header-Of([string]$Answer, [string]$Name) {
    $line = ($Answer -split "`n") | Where-Object { $_ -match "^${Name}:" } | Select-Object -First 1
    if (-not $line) { return '' }
    return ([string]$line -replace "^${Name}:\s*", '').Trim()
}
function Body-Of([string]$Answer) { ($Answer -split "`r?`n`r?`n", 2)[1] }
function Random-Password { [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(18)) }
function Login-Config([string]$Email, [string]$Password) { "url = `"$Cloud/login`"`ndata-urlencode = `"email=$Email`"`ndata-urlencode = `"password=$($Password)`"" }
# A page as text: the <main> part, tags gone, a table row per line with its cells apart.
function Page-Text([string]$Html) {
    $main = if ($Html -match '(?s)<main>(.*?)</main>') { $Matches[1] } else { $Html }
    $main = $main -replace '(?s)<script.*?</script>', '' -replace '\s+', ' ' -replace '</tr>', "`n" -replace '</t[dh]>', ' | ' -replace '</p>', "`n" -replace '</h[12]>', "`n" -replace '<dt>', "`n" -replace '</dt>', ': ' -replace '<[^>]+>', ''
    $main = [System.Net.WebUtility]::HtmlDecode($main)
    (($main -split "`n") | ForEach-Object { ($_ -replace '\s+', ' ').Trim() } | Where-Object { $_ -ne '' -and $_ -ne '|' }) -join "`n"
}
function Get-Page([string]$Path) { $a = Invoke-Curl @('-i', '-b', $Jar, "$Cloud$Path"); [pscustomobject]@{ Status = (Status-Of $a); Text = (Page-Text (Body-Of $a)); Raw = $a } }
function Nav-Of([string]$Html) { if ($Html -match '(?s)<nav>(.*?)</nav>') { (($Matches[1] -replace '<[^>]+>', ' ') -replace '\s+', ' ').Trim() } else { '' } }
function Login([string]$Email, [string]$Password) {
    $a = Invoke-CurlWith (Login-Config $Email $Password) @('-i', '-c', $Jar, '-K', '-')
    if ($a -match 'rp_session=([^;]+)') { $script:secrets += $Matches[1] }
    return (Status-Of $a)
}
# The object through the api's own client (the stack's MinIO is reached by the container's name).
function Fetch-Object([string]$Key, [string]$To) {
    $code = "import sys; from app.settings import storage_settings_from_environment; from app.storage import Storage; s = Storage.for_writing(storage_settings_from_environment()); open('/tmp/report.pdf', 'wb').write(s.get(sys.argv[1]))"
    Invoke-Compose @('exec', '-T', 'api', 'python', '-c', $code, $Key) | Out-Null
    Invoke-Compose @('cp', 'api:/tmp/report.pdf', $To) | Out-Null
}
function Pdf-Text([string]$Path) { Push-Location $CloudDir; try { (& uv run --no-sync python $PdfText $Path 2>&1) -join "`n" } finally { Pop-Location } }
function Sha256([string]$Path) { (Get-FileHash -Algorithm SHA256 $Path).Hash.ToLower() }
function Run-Sql([string]$State, [string]$CreatedAt, [string]$FinishedAt, [string]$RestorePoint, [string]$Recovery, [string]$Hash, [string]$TsaTime, [string]$ErrorCode, [string]$ErrorMessage) {
    $finishedSql = if ($FinishedAt) { "'$FinishedAt'" } else { 'NULL' }
    $pointSql = if ($RestorePoint) { "'$RestorePoint'" } else { 'NULL' }
    $recoverySql = if ($Recovery) { $Recovery } else { 'NULL' }
    $totalSql = if ($Recovery) { [int]$Recovery * 2 } else { 'NULL' }
    $hashSql = if ($Hash) { "'$Hash'" } else { 'NULL' }
    $keySql = if ($Hash) { "'msp/$script:msp/runs/none/'" } else { 'NULL' }
    $okSql = if ($Hash) { 'true' } else { 'NULL' }
    $tsaSql = if ($TsaTime) { "true, '$TsaTime'" } else { 'NULL, NULL' }
    $codeSql = if ($ErrorCode) { "'$ErrorCode', '$ErrorMessage'" } else { 'NULL, NULL' }
    $dispatchedSql = if ($State -eq 'expired') { "'$CreatedAt', 3" } else { "'$CreatedAt', 1" }
    $sql = "INSERT INTO test_run (msp_id, client_id, worker_id, plan_id, connector_id, state, dispatched_at, attempt, restore_point_at, started_at, finished_at, total_ms, recovery_ms, bundle_key, bundle_sha256, signature_ok, tsa_ok, tsa_time, cleanup_ok, error_code, error_message, created_at) " +
        "VALUES ('$script:msp', '$script:client', '$script:worker', '$script:plan', '$script:connector', '$State', $dispatchedSql, $pointSql, $finishedSql, $finishedSql, $totalSql, $recoverySql, $keySql, $hashSql, $okSql, $tsaSql, $okSql, $codeSql, '$CreatedAt') RETURNING id"
    return (Invoke-Psql $sql).Trim()
}
function Item-Sql([string]$RunId, [int]$Position, [string]$Type, [string]$Name, [string]$Found, [string]$Match, [string]$Reason) {
    $reasonSql = if ($Reason) { "'$Reason'" } else { 'NULL' }
    Invoke-Psql "INSERT INTO test_item (msp_id, run_id, position, type, name, expected_kind, found, match, reason, ms) VALUES ('$script:msp', '$RunId', $Position, '$Type', '$Name', 'manifest', $Found, $Match, $reasonSql, 900)" | Out-Null
}

$started = Now
$secrets = @()
$t = @()
$nowUtc = [DateTime]::UtcNow
$thisMonth = $nowUtc.ToString('yyyy-MM')
$prev = [DateTime]::new($nowUtc.Year, $nowUtc.Month, 1).AddMonths(-1)
$period = $prev.ToString('yyyy-MM')
function Day([int]$Day, [string]$Time) { "$period-$($Day.ToString('00'))T$Time" }
$t += "C6.6 (#72) Done-when, with C6.7 (#73) and C6.5 (#71), by hand against the Compose stack. $(Now), commit $((git -C $Repo rev-parse --short HEAD 2>&1) -join ''), branch $((git -C $Repo rev-parse --abbrev-ref HEAD 2>&1) -join '')"
$t += "Windows, Python 3.12, Docker Desktop, the Compose stack (postgres:16, MinIO, api, scheduler) on 127.0.0.1; the CLI runs in the api container; curl.exe 8.x with a cookie jar under %TEMP%; the PDF is read on the host with pypdf. This month is $thisMonth, the previous month (the job's) $period"
$passed = $false
try {
    $t += "`n== (1) the stack rebuilt, the database re-migrated once, the scheduler's environment =="
    $t += (((Invoke-Compose @('up', '-d', '--wait', '--build')) -split "`n") | Where-Object { $_ -match '^ (Container|Image) ' }) -join "`n"
    foreach ($step in @(@('downgrade', '-1'), @('upgrade', 'head'), @('check'))) {
        $r = Invoke-Compose (@('exec', '-T', 'api', 'alembic') + $step)
        $t += "alembic $($step -join ' '): $((($r -split "`n") | Select-Object -Last 1).Trim())"
    }
    $t += "GET /healthz: $((Invoke-Curl @('-i', "$Cloud/healthz")) -replace "`n", ' ' -replace '\s+', ' ')"
    $envNames = ((Invoke-Compose @('exec', '-T', 'scheduler', 'printenv')) -split "`n" | ForEach-Object { ($_ -split '=', 2)[0] } | Where-Object { $_ -match '^(DATABASE_URL|S3_|LOG_LEVEL|SECRET_KEY)' } | Sort-Object) -join ', '
    $t += "the scheduler's environment (names alone): $envNames"
    $t += "the scheduler's lines since the start (its start run of the report job, which met the database as it was being re-migrated above, or no MSP): $((((Invoke-Compose @('logs', '--no-log-prefix', '--since', $started, 'scheduler')) -split "`n" | Where-Object { $_ -match '"job": "reports".*"event": "tick"' } | Select-Object -First 1) -replace '"stack": \[[^\]]*\], ', '').Trim())"

    $t += "`n== (2) by CLI: the MSP, an admin and a member, the lab client (its id the kept bundle's), the lab Worker's key, the connector, a plan with one run (its id the bundle's); the poll; the real Worker bundle posted: 202 pass =="
    $bundleResult = Get-Content (Join-Path $Bundle 'result.json') -Raw | ConvertFrom-Json
    $bundleSignature = Get-Content (Join-Path $Bundle 'signature.json') -Raw | ConvertFrom-Json
    $bundleRun = $bundleResult.run_id; $bundleClient = $bundleResult.client.client_id; $labTenant = $bundleResult.client.tenant_id
    $t += "the kept C5.7 bundle: run $bundleRun, client $bundleClient, $($bundleResult.status.counts.items) items, status $($bundleResult.status.status), ended $($bundleResult.ended_at), bundle_sha256 $($bundleSignature.bundle_sha256)"
    $r = Invoke-Manage @('create-msp', '--name', 'C6.6 done-when MSP'); if ($r.Exit -ne 0) { throw "create-msp: $($r.Text)" }
    $script:msp = Line-Of $r.Text 'msp_id'
    $t += "create-msp --name 'C6.6 done-when MSP': exit $($r.Exit)`n$($r.Text)"
    $adminPassword = Random-Password; $memberPassword = Random-Password; $secrets += $adminPassword, $memberPassword
    $r = Invoke-Manage @('create-user', '--msp-id', $script:msp, '--email', 'admin@c66.example.test', '--role', 'admin') $adminPassword; if ($r.Exit -ne 0) { throw "create-user: $($r.Text)" }
    $t += "create-user --msp-id <msp_id> --email admin@c66.example.test --role admin (the password on standard input, 24 characters made for the run): exit $($r.Exit)`n$($r.Text)"
    $r = Invoke-Manage @('create-user', '--msp-id', $script:msp, '--email', 'member@c66.example.test', '--role', 'member') $memberPassword; if ($r.Exit -ne 0) { throw "create-user: $($r.Text)" }
    $t += "create-user --msp-id <msp_id> --email member@c66.example.test --role member: exit $($r.Exit)`n$($r.Text)"
    $r = Invoke-Manage @('create-client', '--msp-id', $script:msp, '--name', 'Lab tenant', '--tenant-id', $labTenant); if ($r.Exit -ne 0) { throw "create-client: $($r.Text)" }
    $madeClient = Line-Of $r.Text 'client_id'
    $t += "create-client --msp-id <msp_id> --name 'Lab tenant' --tenant-id <the lab tenant>: exit $($r.Exit)`n$($r.Text)"
    $t += "the client's id set to the bundle's by SQL (as tests/test_contract.py gives a test's rows the vector's ids): $(Invoke-Psql "UPDATE client SET id = '$bundleClient' WHERE id = '$madeClient' AND msp_id = '$script:msp'")"
    $script:client = $bundleClient
    $r = Invoke-Manage @('create-worker-token', '--msp-id', $script:msp, '--label', 'veeam-vm'); if ($r.Exit -ne 0) { throw "create-worker-token: $($r.Text)" }
    $installToken = Line-Of $r.Text 'install_token'; $secrets += $installToken
    $t += "create-worker-token --msp-id <msp_id> --label veeam-vm: exit $($r.Exit)`n$($r.Text.Replace($installToken, '<token>'))"
    $pem = (((& $Rpworker signer public-key 2>$null) -split "`r?`n") | Where-Object { $_ -match 'PUBLIC KEY-----$|^[A-Za-z0-9+/=]{20,}$' }) -join "`n"
    $pem += "`n"
    if ($pem -notmatch 'BEGIN PUBLIC KEY') { throw 'rpworker signer public-key gave no key' }
    $register = @{ install_token = $installToken; public_key_pem = $pem; worker_name = 'veeam-vm'; version = '0.0.0' } | ConvertTo-Json -Compress
    $registered = (Invoke-CurlWith $register @('-X', 'POST', "$Cloud/v1/workers/register", '-H', 'Content-Type: application/json', '--data-binary', '@-')) | ConvertFrom-Json
    $apiToken = $registered.api_token; if (-not $apiToken) { throw 'registration failed' }; $secrets += $apiToken
    $script:worker = [guid]::Parse($registered.worker_id).ToString()
    $t += "POST /v1/workers/register with curl (the lab Worker's own key from rpworker signer public-key; the token in the body on standard input): 201 worker_id $script:worker, key_id $($registered.key_id); the API token kept in memory"
    Invoke-Compose @('cp', (Join-Path $env:LOCALAPPDATA 'RestoreProof\lab\lab-profile.json'), 'api:/tmp/profile.json') | Out-Null
    $r = Invoke-Manage @('create-connector', '--msp-id', $script:msp, '--client-id', $script:client, '--worker-id', $script:worker, '--profile-file', '/tmp/profile.json'); if ($r.Exit -ne 0) { throw "create-connector: $($r.Text)" }
    $script:connector = Line-Of $r.Text 'connector_id'
    $t += "create-connector --msp-id <msp_id> --client-id <client_id> --worker-id <worker_id> --profile-file /tmp/profile.json (the lab profile, outside the repository): exit $($r.Exit)`n$($r.Text)"
    $r = Invoke-Manage @('create-plan', '--msp-id', $script:msp, '--client-id', $script:client, '--connector-id', $script:connector, '--mail', '10', '--sp', '10', '--od', '10', '--run-now'); if ($r.Exit -ne 0) { throw "create-plan: $($r.Text)" }
    $script:plan = Line-Of $r.Text 'plan_id'; $madeRun = Line-Of $r.Text 'run_id'
    $t += "create-plan --msp-id <msp_id> --client-id <client_id> --connector-id <connector_id> --mail 10 --sp 10 --od 10 --run-now: exit $($r.Exit)`n$($r.Text)"
    $t += "the run's id set to the bundle's by SQL: $(Invoke-Psql "UPDATE test_run SET id = '$bundleRun' WHERE id = '$madeRun' AND msp_id = '$script:msp'")"
    $jobs = (Invoke-CurlWith (Bearer $apiToken) @('-K', '-', "$Cloud/v1/jobs")) | ConvertFrom-Json
    $t += "GET /v1/jobs (the API token in a curl config on standard input): $($jobs.format), $(@($jobs.jobs).Count) job, run_id $($jobs.jobs[0].run_id)"
    $form = @('-F', "result=@$(Join-Path $Bundle 'result.json');type=application/json", '-F', "signature=@$(Join-Path $Bundle 'signature.json');type=application/json", '-F', "timestamp=@$(Join-Path $Bundle 'timestamp.tst');type=application/octet-stream", '-F', "items.csv=@$(Join-Path $Bundle 'items.csv');type=application/octet-stream", '-F', "veeam-session.log=@$(Join-Path $Bundle 'veeam-session.log');type=application/octet-stream")
    $answer = Invoke-CurlWith (Bearer $apiToken) (@('-i', '-K', '-', '-X', 'POST', "$Cloud/v1/results") + $form)
    $t += "POST /v1/results with the kept bundle's five files: $(Status-Of $answer) $((($answer -split "`n") | Select-Object -Last 1).Trim())"
    if ((Status-Of $answer) -notmatch ' 202 ') { throw 'the bundle did not land' }
    # The bundle's run is a test of this month, so the interim report below has a real run in it.
    $t += "the bundle's run moved into this month by SQL (its ended time is the bundle's own; the pages and the report date it by that): $(Invoke-Psql "UPDATE test_run SET finished_at = '$thisMonth-02T01:00:00Z', started_at = '$thisMonth-02T00:55:00Z', created_at = '$thisMonth-02T00:50:00Z', tsa_time = '$thisMonth-02T01:00:05Z' WHERE id = '$bundleRun'")"
    $t += "the run's row: $(Invoke-Psql "SELECT state, finished_at, recovery_ms, tsa_ok, bundle_sha256, (SELECT count(*) FROM test_item WHERE run_id = test_run.id) AS items FROM test_run WHERE id = '$bundleRun'")"

    $t += "`n== (3) the previous month, $period, by SQL: a pass, a fail with two unmatched items, an error, a later pass, an expired run (the bundle columns synthetic, no object behind them) =="
    $passed1 = Run-Sql 'pass' (Day 5 '01:59:00Z') (Day 5 '02:03:20Z') (Day 4 '23:00:00Z') '40000' ('11' * 32) (Day 5 '02:03:24Z') '' ''
    Item-Sql $passed1 0 'mail' 'RP-CANARY-0001' 'true' 'true' ''
    Item-Sql $passed1 1 'sharepoint' 'rp-canary-02.docx' 'true' 'true' ''
    $failed = Run-Sql 'fail' (Day 10 '01:59:00Z') (Day 10 '02:30:00Z') (Day 9 '23:00:00Z') '65000' ('22' * 32) (Day 10 '02:30:05Z') '' ''
    Item-Sql $failed 0 'mail' 'RP-CANARY-0003' 'false' 'false' 'no restored copy found'
    Item-Sql $failed 1 'sharepoint' 'rp-canary-04.docx' 'true' 'false' 'fields did not match: sha256'
    Item-Sql $failed 2 'onedrive' 'rp-canary-12.pdf' 'true' 'true' ''
    $errored = Run-Sql 'error' (Day 20 '01:59:00Z') (Day 20 '02:05:00Z') '' '' ('33' * 32) '' 'veeam_unreachable' 'the backup product did not answer'
    $later = Run-Sql 'pass' (Day 25 '01:59:00Z') (Day 25 '02:20:00Z') (Day 24 '23:00:00Z') '40000' ('44' * 32) (Day 25 '02:20:04Z') '' ''
    Item-Sql $later 0 'mail' 'RP-CANARY-0005' 'true' 'true' ''
    $expired = Run-Sql 'expired' (Day 15 '02:00:00Z') '' '' '' '' '' '' ''
    foreach ($id in @($passed1, $failed, $errored, $later, $expired)) { if ($id -notmatch '^[0-9a-f-]{36}$') { throw "a run's id was not read: $id" } }
    $t += "runs: pass $passed1, fail $failed, error $errored, pass $later, expired $expired"

    $t += "`n== (4) the job in the real process: the scheduler restarted, its start run makes the client's final report of $period; the row and the object =="
    $restartedAt = Now
    Invoke-Compose @('restart', 'scheduler') | Out-Null
    $deadline = (Get-Date).AddSeconds(120)
    $lines = @()
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 3
        $lines = (Invoke-Compose @('logs', '--no-log-prefix', '--since', $restartedAt, 'scheduler')) -split "`n" | Where-Object { $_ -match '"event": "(report created|report failed|tick|scheduler started)"' -and ($_ -match 'report ' -or $_ -match '"job": "reports"' -or $_ -match 'scheduler started') }
        if ($lines | Where-Object { $_ -match '"job": "reports".*"event": "tick"' }) { break }
    }
    $t += "the scheduler's lines (ids and counts alone):`n$(($lines | ForEach-Object { $_.Trim() }) -join "`n")"
    $row = Invoke-Psql "SELECT id, period_start, period_end, interim, generated_at, storage_key, content_sha256, file_sha256 FROM report WHERE msp_id = '$script:msp' AND client_id = '$script:client' AND period_start = '$period-01'"
    if (-not $row) { throw 'the job made no report' }
    $parts = $row.Split('|')
    $reportId = $parts[0]; $key = $parts[5]; $contentHash = $parts[6]; $fileHash = $parts[7]
    $t += "the row: id $reportId, period $($parts[1]) to $($parts[2]), interim $($parts[3]), generated $($parts[4]), key $key, content_sha256 $contentHash, file_sha256 $fileHash"
    $pdf = Join-Path $Temp "report-$period.pdf"
    Fetch-Object $key $pdf
    $got = Sha256 $pdf
    $t += "the object fetched through the api's own client: $((Get-Item $pdf).Length) bytes, sha256 $got; file_sha256 $fileHash; $(if ($got -eq $fileHash) { 'the same' } else { 'DIFFERENT' })"
    if ($got -ne $fileHash) { throw 'the object and the row disagree' }
    $text = Pdf-Text $pdf
    $t += "the PDF read with pypdf:`n$text"
    $words = (($text -split "`n") | Select-Object -Skip 2) -join ' '
    $t += "the content hash printed: $(if ($words.Contains($contentHash)) { 'yes' } else { 'NO' }); the file hash not printed: $(if ($words.Contains($fileHash)) { 'IT IS' } else { 'right' }); the four banned phrases: $(if ($words -match '(?i)fully recoverable|guarantee|certified|accepted by insurers') { 'FOUND' } else { 'none' }); the four controls' sentences (C6.7): $(if ($words.Contains('On the dates listed, a sample of items was restored from the backup copy') -and $words.Contains('not an assessment of the control')) { 'rendered' } else { 'MISSING' })"
    $t += "the audit row of the job's report: $(Invoke-Psql "SELECT action, user_id IS NOT NULL AS has_user, ip FROM audit_log WHERE msp_id = '$script:msp' AND target = 'report:$reportId'")"
    Invoke-Compose @('restart', 'scheduler') | Out-Null
    Start-Sleep -Seconds 8
    $again = (Invoke-Compose @('logs', '--no-log-prefix', '--since', (Now), 'scheduler'))
    $deadline = (Get-Date).AddSeconds(60); $existing = ''
    while ((Get-Date) -lt $deadline -and -not $existing) {
        Start-Sleep -Seconds 3
        $existing = [string]((Invoke-Compose @('logs', '--no-log-prefix', '--since', $restartedAt, 'scheduler')) -split "`n" | Where-Object { $_ -match '"job": "reports".*"event": "tick"' } | Select-Object -Last 1)
        if ($existing -notmatch '"existing": 1') { $existing = '' }
    }
    $t += "the scheduler restarted once more, its start run: $($existing.Trim())"
    $t += "report rows of the month after it: $(Invoke-Psql "SELECT count(*) FROM report WHERE msp_id = '$script:msp' AND period_start = '$period-01'")"

    $t += "`n== (5) the pages as the member: /reports (the nav entry) and /clients/{id}/reports =="
    $t += "POST /login as the member (the form in a curl config on standard input, the cookie into the jar): $(Login 'member@c66.example.test' $memberPassword)"
    $p = Get-Page '/reports'
    $t += "GET /reports: $($p.Status); the nav: $(Nav-Of $p.Raw)`n$($p.Text)"
    $p = Get-Page "/clients/$script:client/reports"
    $t += "GET /clients/<client_id>/reports: $($p.Status)`n$($p.Text)"
    $clientPage = Get-Page "/clients/$script:client"
    $reportsLink = 'href="/clients/' + $script:client + '/reports"'
    $t += "GET /clients/<client_id>: the Reports link: $(if ($clientPage.Raw.Contains($reportsLink)) { 'yes' } else { 'NO' })"

    $t += "`n== (6) the Done-when: 'Generate now' clicked as the member; the interim report listed and downloaded within a minute; the bytes' SHA-256 equal to file_sha256 =="
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $click = Invoke-Curl @('-i', '-b', $Jar, '-X', 'POST', '-H', 'Sec-Fetch-Site: same-origin', "$Cloud/clients/$script:client/reports/generate")
    $clickMs = $watch.ElapsedMilliseconds
    $t += "POST /clients/<client_id>/reports/generate: $(Status-Of $click) location $(Header-Of $click 'location') after $clickMs ms"
    if ((Status-Of $click) -notmatch ' 303 ') { throw "the click did not make a report: $(Body-Of $click)" }
    $p = Get-Page "/clients/$script:client/reports"
    $t += "GET /clients/<client_id>/reports after the click: $($p.Status)`n$($p.Text)"
    $interim = Invoke-Psql "SELECT id, storage_key, file_sha256, content_sha256, generated_at FROM report WHERE msp_id = '$script:msp' AND client_id = '$script:client' AND interim ORDER BY generated_at DESC LIMIT 1"
    $iparts = $interim.Split('|'); $interimId = $iparts[0]; $interimKey = $iparts[1]; $interimHash = $iparts[2]
    $t += "the interim row: id $interimId, key $interimKey, file_sha256 $interimHash, content_sha256 $($iparts[3]), generated $($iparts[4]); listed first on the page: $(if ($p.Text.IndexOf($interimHash) -lt $p.Text.IndexOf($fileHash)) { 'yes' } else { 'NO' })"
    $d = Invoke-Curl @('-i', '-b', $Jar, '-H', 'Sec-Fetch-Site: same-origin', "$Cloud/reports/$interimId/file")
    $location = Header-Of $d 'location'
    $locationShown = if ($location -match '^(https?://[^/]+/[^?]+)\?') { $Matches[1] + '?<the signed query, X-Amz-Expires=600>' } else { $location }
    $t += "GET /reports/<report_id>/file as the member: $(Status-Of $d) cache-control $(Header-Of $d 'cache-control'); location $locationShown"
    $interimPdf = Join-Path $Temp 'report-interim.pdf'
    Invoke-Curl @('-o', $interimPdf, $location) | Out-Null
    $watch.Stop()
    $interimGot = Sha256 $interimPdf
    $t += "the link followed: $((Get-Item $interimPdf).Length) bytes, sha256 $interimGot; file_sha256 $interimHash; $(if ($interimGot -eq $interimHash) { 'the same bytes' } else { 'DIFFERENT' })"
    $t += "from the click to the downloaded bytes: $([int]$watch.Elapsed.TotalSeconds) s ($($watch.ElapsedMilliseconds) ms): $(if ($watch.Elapsed.TotalSeconds -lt 60) { 'within a minute' } else { 'OVER A MINUTE' })"
    if ($interimGot -ne $interimHash) { throw 'the downloaded bytes and the row disagree' }
    $interimText = ((Pdf-Text $interimPdf) -split "`n" | Select-Object -Skip 2) -join ' '
    $t += "its text says 'Interim report': $(if ($interimText.Contains('Interim report')) { 'yes' } else { 'NO' }); the kept bundle's bundle_sha256 in its Integrity section: $(if ($interimText.Contains($bundleSignature.bundle_sha256)) { 'yes' } else { 'NO' }); its first 300 characters: $($interimText.Substring(0, [Math]::Min(300, $interimText.Length)))"

    $t += "`n== (7) the cap, another site, another MSP =="
    $again = Invoke-Curl @('-i', '-b', $Jar, '-X', 'POST', "$Cloud/clients/$script:client/reports/generate")
    $t += "POST /clients/<client_id>/reports/generate again at once: $(Status-Of $again) retry-after $(Header-Of $again 'retry-after'); the line: $((((Page-Text (Body-Of $again)) -split "`n") | Where-Object { $_ -match 'interim report of this month' } | Select-Object -First 1))"
    $cross = Invoke-Curl @('-i', '-b', $Jar, '-X', 'POST', '-H', 'Sec-Fetch-Site: cross-site', "$Cloud/clients/$script:client/reports/generate")
    $t += "POST ... with Sec-Fetch-Site: cross-site: $(Status-Of $cross) $((($cross -split "`n") | Select-Object -Last 1).Trim())"
    $r = Invoke-Manage @('create-msp', '--name', 'C6.6 done-when MSP B'); if ($r.Exit -ne 0) { throw "create-msp B: $($r.Text)" }
    $mspB = Line-Of $r.Text 'msp_id'
    $r = Invoke-Manage @('create-client', '--msp-id', $mspB, '--name', 'B client', '--tenant-id', ([guid]::NewGuid().ToString())); if ($r.Exit -ne 0) { throw "create-client B: $($r.Text)" }
    $clientB = Line-Of $r.Text 'client_id'
    $t += "MSP B by CLI: msp_id $mspB, client_id $clientB; its reports page and its button as MSP A's member: $(Status-Of (Invoke-Curl @('-i', '-b', $Jar, "$Cloud/clients/$clientB/reports"))), $(Status-Of (Invoke-Curl @('-i', '-b', $Jar, '-X', 'POST', "$Cloud/clients/$clientB/reports/generate")))"
    $rowB = Invoke-Psql "INSERT INTO report (msp_id, client_id, period_start, period_end, storage_key, content_sha256, file_sha256, interim, generated_at) VALUES ('$mspB', '$clientB', '$period-01', '$($prev.AddMonths(1).AddDays(-1).ToString('yyyy-MM-dd'))', 'msp/$mspB/reports/$clientB/$period.pdf', '$('55' * 32)', '$('66' * 32)', false, now()) RETURNING id"
    $t += "a report row of MSP B by SQL (no object behind it): $rowB; GET /reports/<that id>/file as MSP A's member: $(Status-Of (Invoke-Curl @('-i', '-b', $Jar, "$Cloud/reports/$($rowB.Trim())/file")))"
    $t += "GET /reports as the member: MSP B's row listed: $(if ((Get-Page '/reports').Text.Contains('B client')) { 'YES' } else { 'no' })"

    $t += "`n== (8) /audit as the admin: the download's row with user, time and IP; the two report.create rows =="
    $t += "POST /login as the admin: $(Login 'admin@c66.example.test' $adminPassword)"
    $p = Get-Page '/audit'
    $t += "GET /audit as the admin: $($p.Status)`n$((($p.Text -split "`n") | Where-Object { $_ -match 'report\.' }) -join "`n")"
    $t += "the audit rows (action, has_user, ip): $(Invoke-Psql "SELECT action, user_id IS NOT NULL, ip FROM audit_log WHERE msp_id = '$script:msp' AND action LIKE 'report.%' ORDER BY at" -replace "`n", ' ; ')"
    $passed = $true

    $t += "`n== (9) the $period PDF (the job's, the new template) kept beside the evidence when its text names no person and no tenant identifier =="
    $clean = -not ($words -match '@' -or $words.Contains($labTenant) -or $words -match '(?i)alice|bob|hrach|harutyunyan')
    if ($clean) { Copy-Item $pdf $KeepPdf -Force; $t += "kept as $KeepPdf (sha256 $got): the client's name, the MSP's name, canary subjects and file names, run ids, the Worker's id and fingerprint, the four controls' sentences, no address, no tenant id" }
    else { $t += "NOT kept: the text names a person or the tenant" }
    $apiLines = (Invoke-Compose @('logs', '--no-log-prefix', '--since', $started, 'api', 'scheduler')) -split "`n" | Where-Object { $_ -match 'X-Amz|restoreproof/|rp_session|password' }
    $t += "the api's and the scheduler's lines since the start naming a signed query, a bucket path, a cookie value or a password value, counted: $(@($apiLines).Count)"
} finally {
    $t += "`n== (10) the teardown =="
    Remove-Item -Recurse -Force $Temp -ErrorAction SilentlyContinue
    Invoke-Compose @('exec', '-T', 'api', 'rm', '-f', '/tmp/profile.json', '/tmp/report.pdf') | Out-Null
    $t += "$Temp (the cookie jar, the two fetched PDFs) and the container's profile copy and fetched object removed; the install token went to curl on its standard input, the API token into memory and to curl on its standard input, the passwords to the CLI and to curl on their standard input, the cookie into the jar: nothing was written to a file but the jar, which is gone, and nothing was put on a command line; the two MSPs and their rows, and the objects, are left in the stack"
}
$text = ($t -join "`n").Replace("`r`n", "`n")
foreach ($s in $secrets) { if ($s -and $text.Contains($s)) { throw 'a secret survived; nothing written' } }
if ($text -match '(?<![A-Za-z0-9_\-])[A-Za-z0-9_\-]{43}(?![A-Za-z0-9_\-=])' -or $text -match 'eyJ[A-Za-z0-9_\-]{10,}\.' -or $text -match 'PRIVATE KEY' -or $text -match 'X-Amz-Signature=[0-9a-f]' -or $text -match 'rp_session=[A-Za-z0-9]') { throw 'a secret-shaped value; nothing written' }
if (-not $passed) { throw 'a step failed; nothing written' }
[IO.File]::WriteAllText($Out, $text + "`n", $utf8)
"saved $Out"

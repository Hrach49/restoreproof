# C6.4 (#70): the Done-when by hand against the Compose stack (docs/decisions.md 2026-10-12,
# "C6.4", "Done-when, as it will be run"; docs/testing.md "The report"): the stack rebuilt with
# the four packages WeasyPrint renders with and its database re-migrated (the edit of 0001); by
# CLI an MSP, a client of the lab tenant whose id becomes the kept C5.7 bundle's, the lab Worker's
# own key registered with curl, the connector on the lab profile, a plan with one run whose id
# becomes the bundle's; the Worker's poll; the real Worker bundle posted as the Worker posts it:
# 202 pass (a run of October 2026); then by SQL the rows of a September 2026 with a pass, a fail
# with two unmatched items, an error, a later pass and an expired run (no bundle object behind
# them: the Done-when's shape); `manage.py generate-report --period 2026-09` in the api container:
# the six lines, the row, the object fetched from MinIO through the api's own client and held to
# `file_sha256`, its text through pypdf with the six headings in order; the same again refused
# `period: already reported` with no second object; the current month an interim report under a
# key with its time, "Interim report" in its text and the real bundle's hash in its Integrity
# section. The September PDF is kept beside the evidence when its text names no person and no
# tenant identifier.
#
#   pwsh -File docs\api\cloud-lab\c6.4-harness\c64-live.ps1 -Out docs\api\cloud-lab\c6.4-done-when.txt
#
# Nothing secret is written or put on a command line: the install token from the CLI's stdout into
# a variable and to curl in the registration body on its standard input; the API token in a curl
# config on its standard input. The evidence text is screened for both and for every token-shaped
# value before it is saved; a screen that fires leaves no file. The stack's database is re-migrated
# once (the rows it held are dropped: nothing is deployed), and the harness reads only the rows it
# made.
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
$Cloud = 'http://127.0.0.1:8000'
$Temp = Join-Path $env:TEMP 'rp-c64'
New-Item -ItemType Directory -Force $Temp | Out-Null
$utf8 = [Text.UTF8Encoding]::new($false)
function Now { [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ') }
function Invoke-Compose([string[]]$Arguments) { Push-Location $CloudDir; try { (& docker compose @Arguments 2>&1) -join "`n" } finally { Pop-Location } }
function Invoke-Manage([string[]]$Arguments) {
    Push-Location $CloudDir
    try {
        $text = (& docker compose exec -T api python manage.py @Arguments 2>&1) -join "`n"
        return [pscustomobject]@{ Text = $text; Exit = $LASTEXITCODE }
    } finally { Pop-Location }
}
# -q: no command tag after a RETURNING id, so the id is the whole answer.
function Invoke-Psql([string]$Sql) { Push-Location $CloudDir; try { ($Sql | & docker compose exec -T postgres psql -U restoreproof -d restoreproof -Atq 2>&1) -join "`n" } finally { Pop-Location } }
function Line-Of([string]$Text, [string]$Key) { (($Text -split "`n") | Where-Object { $_ -like "$Key *" } | Select-Object -First 1).Split(' ')[1] }
function Invoke-Curl([string[]]$Arguments) { (& curl.exe -s -S --max-time 60 @Arguments 2>&1) -join "`n" }
function Invoke-CurlWith([string]$Stdin, [string[]]$Arguments) { ($Stdin | & curl.exe -s -S --max-time 60 @Arguments 2>&1) -join "`n" }
function Bearer([string]$Token) { "header = `"Authorization: Bearer $Token`"" }
function Status-Of([string]$Answer) { (($Answer -split "`n") | Where-Object { $_ -match '^HTTP/' } | Select-Object -Last 1).Trim() }
# The object through the api's own client (the stack's MinIO is reached by the container's name):
# fetched to the container's /tmp, then copied out; and the keys under the client's prefix.
function Fetch-Object([string]$Key, [string]$Prefix, [string]$To) {
    $code = "import sys; from app.settings import storage_settings_from_environment; from app.storage import Storage; s = Storage.for_writing(storage_settings_from_environment()); open('/tmp/report.pdf', 'wb').write(s.get(sys.argv[1])); print(' '.join(sorted(s.list(sys.argv[2]))))"
    $listed = Invoke-Compose @('exec', '-T', 'api', 'python', '-c', $code, $Key, $Prefix)
    Invoke-Compose @('cp', 'api:/tmp/report.pdf', $To) | Out-Null
    return $listed.Trim()
}
function Pdf-Text([string]$Path) { Push-Location $CloudDir; try { (& uv run --no-sync python (Join-Path $PSScriptRoot 'c64-pdf-text.py') $Path 2>&1) -join "`n" } finally { Pop-Location } }
function Sha256([string]$Path) { (Get-FileHash -Algorithm SHA256 $Path).Hash.ToLower() }
function Run-Sql([string]$State, [string]$CreatedAt, [string]$FinishedAt, [string]$RestorePoint, [string]$Recovery, [string]$Hash, [string]$TsaTime, [string]$ErrorCode, [string]$ErrorMessage) {
    # One run of the September rows: every time given, the bundle's columns synthetic (no object behind them).
    # PowerShell's names are case-insensitive: the SQL fragments are named apart from the parameters.
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
$t += "C6.4 (#70) Done-when, by hand against the Compose stack. $(Now), commit $((git -C $Repo rev-parse --short HEAD 2>&1) -join ''), branch $((git -C $Repo rev-parse --abbrev-ref HEAD 2>&1) -join '')"
$t += "Windows, Python 3.12, Docker Desktop, the Compose stack (postgres:16, MinIO, api, scheduler) on 127.0.0.1; the CLI runs in the api container; the PDF is read on the host with pypdf"
try {
    $t += "`n== (1) the stack rebuilt with the four packages WeasyPrint renders with, the database re-migrated once (the edit of 0001), the report's new columns =="
    $t += (((Invoke-Compose @('up', '-d', '--wait', '--build')) -split "`n") | Where-Object { $_ -match '^ (Container|Image) ' }) -join "`n"
    $t += "the image's packages: $((Invoke-Compose @('exec', '-T', 'api', 'dpkg-query', '-W', '-f', '${Package} ${Version}\n', 'libpango-1.0-0', 'libpangoft2-1.0-0', 'libharfbuzz-subset0', 'fonts-dejavu-core')) -replace "`n", '; ')"
    $t += "weasyprint in the image: $((Invoke-Compose @('exec', '-T', 'api', 'python', '-c', 'import importlib.metadata as m; print(m.version("weasyprint"))')).Trim())"
    foreach ($step in @(@('downgrade', '-1'), @('upgrade', 'head'), @('check'))) {
        $r = Invoke-Compose (@('exec', '-T', 'api', 'alembic') + $step)
        $t += "alembic $($step -join ' '): $((($r -split "`n") | Select-Object -Last 1).Trim())"
    }
    $t += "GET /healthz: $((Invoke-Curl @('-i', "$Cloud/healthz")) -replace "`n", ' ' -replace '\s+', ' ')"
    $t += "report's columns: $(Invoke-Psql "SELECT string_agg(column_name || ' ' || data_type || CASE WHEN is_nullable = 'NO' THEN ' not null' ELSE '' END, ', ' ORDER BY ordinal_position) FROM information_schema.columns WHERE table_name = 'report'")"
    $t += "report's indexes and constraints: $(Invoke-Psql "SELECT string_agg(indexdef, ' ; ') FROM pg_indexes WHERE tablename = 'report' AND indexname LIKE 'uq_%'")"

    $t += "`n== (2) by CLI: the MSP, the lab client (its id the kept bundle's), the lab Worker's key, the connector, a plan with one run (its id the bundle's); the poll; the real Worker bundle posted: 202 pass =="
    $bundleResult = Get-Content (Join-Path $Bundle 'result.json') -Raw | ConvertFrom-Json
    $bundleSignature = Get-Content (Join-Path $Bundle 'signature.json') -Raw | ConvertFrom-Json
    $bundleRun = $bundleResult.run_id; $bundleClient = $bundleResult.client.client_id; $labTenant = $bundleResult.client.tenant_id
    $t += "the kept C5.7 bundle: run $bundleRun, client $bundleClient, $($bundleResult.status.counts.items) items, status $($bundleResult.status.status), ended $($bundleResult.ended_at), recovery $($bundleResult.timings.spans.recovery.ms) ms, bundle_sha256 $($bundleSignature.bundle_sha256)"
    $r = Invoke-Manage @('create-msp', '--name', 'C6.4 done-when MSP'); if ($r.Exit -ne 0) { throw "create-msp: $($r.Text)" }
    $script:msp = Line-Of $r.Text 'msp_id'
    $t += "create-msp --name 'C6.4 done-when MSP': exit $($r.Exit)`n$($r.Text)"
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
    $t += "the run's row: $(Invoke-Psql "SELECT state, finished_at, recovery_ms, tsa_ok, tsa_time, bundle_sha256, (SELECT count(*) FROM test_item WHERE run_id = test_run.id) AS items FROM test_run WHERE id = '$bundleRun'")"

    $t += "`n== (3) September 2026 by SQL: a pass, a fail with two unmatched items, an error, a later pass, an expired run (the Done-when's shape; the bundle columns synthetic, no object behind them) =="
    $passed = Run-Sql 'pass' '2026-09-05T01:59:00Z' '2026-09-05T02:03:20Z' '2026-09-04T23:00:00Z' '40000' ('11' * 32) '2026-09-05T02:03:24Z' '' ''
    Item-Sql $passed 0 'mail' 'RP-CANARY-0001' 'true' 'true' ''
    Item-Sql $passed 1 'sharepoint' 'rp-canary-02.docx' 'true' 'true' ''
    $failed = Run-Sql 'fail' '2026-09-10T01:59:00Z' '2026-09-10T02:30:00Z' '2026-09-09T23:00:00Z' '65000' ('22' * 32) '2026-09-10T02:30:05Z' '' ''
    Item-Sql $failed 0 'mail' 'RP-CANARY-0003' 'false' 'false' 'no restored copy found'
    Item-Sql $failed 1 'sharepoint' 'rp-canary-04.docx' 'true' 'false' 'fields did not match: sha256'
    Item-Sql $failed 2 'onedrive' 'rp-canary-12.pdf' 'true' 'true' ''
    $errored = Run-Sql 'error' '2026-09-20T01:59:00Z' '2026-09-20T02:05:00Z' '' '' ('33' * 32) '' 'veeam_unreachable' 'the backup product did not answer'
    $later = Run-Sql 'pass' '2026-09-25T01:59:00Z' '2026-09-25T02:20:00Z' '2026-09-24T23:00:00Z' '40000' ('44' * 32) '2026-09-25T02:20:04Z' '' ''
    Item-Sql $later 0 'mail' 'RP-CANARY-0005' 'true' 'true' ''
    $expired = Run-Sql 'expired' '2026-09-15T02:00:00Z' '' '' '' '' '' '' ''
    foreach ($id in @($passed, $failed, $errored, $later, $expired)) { if ($id -notmatch '^[0-9a-f-]{36}$') { throw "a run's id was not read: $id" } }
    $t += "runs: pass $passed, fail $failed, error $errored, pass $later, expired $expired"
    $t += "the month's rows: $(Invoke-Psql "SELECT state, finished_at, recovery_ms, error_code, (SELECT count(*) FROM test_item WHERE run_id = test_run.id) FROM test_run WHERE msp_id = '$script:msp' AND client_id = '$script:client' AND created_at >= '2026-09-01' AND created_at < '2026-10-01' ORDER BY created_at" -replace "`n", ' ; ')"

    $t += "`n== (4) the Done-when: manage.py generate-report --period 2026-09 in the api container; the row; the object fetched and held to file_sha256; the six sections in the PDF's text =="
    $r = Invoke-Manage @('generate-report', '--msp-id', $script:msp, '--client-id', $script:client, '--period', '2026-09'); if ($r.Exit -ne 0) { throw "generate-report: $($r.Text)" }
    $t += "generate-report --msp-id <msp_id> --client-id <client_id> --period 2026-09: exit $($r.Exit)`n$($r.Text)"
    $reportId = Line-Of $r.Text 'report_id'; $key = Line-Of $r.Text 'storage_key'; $fileHash = Line-Of $r.Text 'file_sha256'; $contentHash = Line-Of $r.Text 'content_sha256'
    $t += "the row: $(Invoke-Psql "SELECT period_start, period_end, interim, generated_at, storage_key, content_sha256 = '$contentHash' AS content_hash_printed, file_sha256 = '$fileHash' AS file_hash_printed FROM report WHERE id = '$reportId'")"
    $prefix = "msp/$script:msp/reports/$script:client/"
    $pdf = Join-Path $Temp 'report-2026-09.pdf'
    $listed = Fetch-Object $key $prefix $pdf
    $got = Sha256 $pdf
    $t += "the objects under $prefix (through the api's own client): $listed"
    $t += "the object fetched: $((Get-Item $pdf).Length) bytes, sha256 $got; file_sha256 $fileHash; $(if ($got -eq $fileHash) { 'the same' } else { 'DIFFERENT' })"
    $text = Pdf-Text $pdf
    $t += "the PDF read with pypdf:`n$text"
    $words = (($text -split "`n") | Select-Object -Skip 2) -join ' '
    $t += "the content hash printed in the Integrity section: $(if ($words.Contains($contentHash)) { 'yes' } else { 'NO' }); the file hash not printed: $(if ($words.Contains($fileHash)) { 'IT IS' } else { 'right' }); the four banned phrases: $(if ($words -match '(?i)fully recoverable|guarantee|certified|accepted by insurers') { 'FOUND' } else { 'none' })"

    $t += "`n== (5) the same month again: refused before rendering, no second object =="
    $r = Invoke-Manage @('generate-report', '--msp-id', $script:msp, '--client-id', $script:client, '--period', '2026-09')
    $t += "generate-report --period 2026-09 again: exit $($r.Exit): $($r.Text)"
    $t += "the rows of the month: $(Invoke-Psql "SELECT count(*) FROM report WHERE msp_id = '$script:msp' AND client_id = '$script:client' AND period_start = '2026-09-01'")"

    $t += "`n== (6) the current month: an interim report under a key with its time, the real bundle's run in it =="
    $month = [DateTime]::UtcNow.ToString('yyyy-MM')
    $r = Invoke-Manage @('generate-report', '--msp-id', $script:msp, '--client-id', $script:client, '--period', $month); if ($r.Exit -ne 0) { throw "generate-report interim: $($r.Text)" }
    $t += "generate-report --period ${month}: exit $($r.Exit)`n$($r.Text)"
    $interimKey = Line-Of $r.Text 'storage_key'; $interimHash = Line-Of $r.Text 'file_sha256'
    $interimPdf = Join-Path $Temp 'report-interim.pdf'
    $listed = Fetch-Object $interimKey $prefix $interimPdf
    $t += "the objects under the prefix now: $listed"
    $t += "the interim object fetched: sha256 $(Sha256 $interimPdf); file_sha256 $interimHash; $(if ((Sha256 $interimPdf) -eq $interimHash) { 'the same' } else { 'DIFFERENT' })"
    $interimText = ((Pdf-Text $interimPdf) -split "`n" | Select-Object -Skip 2) -join ' '
    $t += "its text says 'Interim report': $(if ($interimText.Contains('Interim report')) { 'yes' } else { 'NO' }); the kept bundle's bundle_sha256 in its Integrity section: $(if ($interimText.Contains($bundleSignature.bundle_sha256)) { 'yes' } else { 'NO' }); its first 400 characters: $($interimText.Substring(0, [Math]::Min(400, $interimText.Length)))"
    $t += "the report rows at the end (period_start, interim, storage_key): $(Invoke-Psql "SELECT period_start, interim, storage_key FROM report WHERE msp_id = '$script:msp' ORDER BY generated_at" -replace "`n", ' ; ')"
    $t += "the audit rows (action, has_user, ip): $(Invoke-Psql "SELECT action, user_id IS NOT NULL, ip FROM audit_log WHERE msp_id = '$script:msp' AND action LIKE 'report.%' ORDER BY at" -replace "`n", ' ; ')"

    $t += "`n== (7) the September PDF kept beside the evidence when its text names no person and no tenant identifier =="
    $clean = -not ($words -match '@' -or $words.Contains($labTenant) -or $words -match '(?i)alice|bob|hrach|harutyunyan')
    if ($clean) { Copy-Item $pdf $KeepPdf -Force; $t += "kept as $KeepPdf (sha256 $got): the client's name, the MSP's name, canary subjects and file names, run ids, the Worker's id and fingerprint, no address, no tenant id" }
    else { $t += "NOT kept: the text names a person or the tenant" }
    $apiLines = (Invoke-Compose @('logs', '--no-log-prefix', '--since', $started, 'api')) -split "`n" | Where-Object { $_ -match 'report|X-Amz|restoreproof/' }
    $t += "the api's log lines since the start naming a report, a signed query or a bucket path: $(@($apiLines).Count)"
} finally {
    $t += "`n== (8) the teardown =="
    Remove-Item -Recurse -Force $Temp -ErrorAction SilentlyContinue
    Invoke-Compose @('exec', '-T', 'api', 'rm', '-f', '/tmp/profile.json', '/tmp/report.pdf') | Out-Null
    $t += "$Temp (the two fetched PDFs) and the container's profile copy and fetched object removed; the install token went to curl on its standard input, the API token into memory and to curl on its standard input: nothing was written to a file and nothing was put on a command line; the MSP and its rows, and the two objects, are left in the stack"
}
$text = ($t -join "`n").Replace("`r`n", "`n")
foreach ($s in $secrets) { if ($s -and $text.Contains($s)) { throw 'a secret survived; nothing written' } }
if ($text -match '(?<![A-Za-z0-9_\-])[A-Za-z0-9_\-]{43}(?![A-Za-z0-9_\-=])' -or $text -match 'eyJ[A-Za-z0-9_\-]{10,}\.' -or $text -match 'PRIVATE KEY' -or $text -match 'X-Amz-Signature=[0-9a-f]') { throw 'a secret-shaped value; nothing written' }
[IO.File]::WriteAllText($Out, $text + "`n", $utf8)
"saved $Out"

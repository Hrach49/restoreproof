# C5.10 (#63) and C5.9 (#62): both by-hand Done-whens in one run against the Compose stack
# (docs/decisions.md 2026-10-11, "C5.10 and C5.9", point 12; docs/testing.md "The onboarding CLI
# and the scheduler"): the stack rebuilt with the scheduler service running the dispatcher and its
# schema checked; then, timed, the CLI in the api container makes an MSP, a client, an install
# token (shown once), a Worker registered with curl under a key made for the run, a connector from
# a profile file and a plan with a 5-minute cron; the CLI's refusals; then the scheduler's runs read
# as they appear, two periods apart; the Worker's poll takes them; revoke-worker; the poll 401; the
# audit rows.
#
#   pwsh -File docs\api\cloud-lab\c5.9-c5.10-harness\c59-c510-live.ps1 -Out docs\api\cloud-lab\c5.9-c5.10-done-when.txt [-WaitSeconds 720]
#
# Nothing of the two tokens is written (the C5.8 review's finding 5): the install token goes from
# the CLI's stdout into a variable and to curl in the registration body on its standard input, the
# API token in a curl config on its standard input, so neither is in a file or on a command line;
# the evidence text is screened for both and for every token-shaped value before it is saved; a
# screen that fires leaves no file.
#
# The stack's rows are left alone (finding 6): the harness never downgrades. It adds one MSP and
# its rows, reads only those (by the ids the CLI printed; the logs since the run's start filtered to
# them), and stops when alembic check says the database isn't the models' (docs/testing.md "Cloud"
# has the two commands for that).
param([string]$Out, [int]$WaitSeconds = 720)
$ErrorActionPreference = 'Stop'
$Repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..\..')).Path
$CloudDir = Join-Path $Repo 'cloud'
$Rows = Join-Path $PSScriptRoot 'c59-c510-rows.py'
$Cloud = 'http://127.0.0.1:8000'
$Temp = Join-Path $env:TEMP 'rp-c59'
New-Item -ItemType Directory -Force $Temp | Out-Null
function Now { [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ') }
function Invoke-Compose([string[]]$Arguments) { Push-Location $CloudDir; try { (& docker compose @Arguments 2>&1) -join "`n" } finally { Pop-Location } }
function Invoke-Rows([string[]]$Arguments) { Push-Location $CloudDir; try { (& uv run python $Rows @Arguments 2>&1) -join "`n" } finally { Pop-Location } }
# The CLI in the api container (the image's own copy of manage.py, the container's own DATABASE_URL);
# stdout and stderr together, the exit code kept.
function Invoke-Manage([string[]]$Arguments) {
    Push-Location $CloudDir
    try {
        $text = (& docker compose exec -T api python manage.py @Arguments 2>&1) -join "`n"
        return [pscustomobject]@{ Text = $text; Exit = $LASTEXITCODE }
    } finally { Pop-Location }
}
function Line-Of([string]$Text, [string]$Key) { (($Text -split "`n") | Where-Object { $_ -like "$Key *" } | Select-Object -First 1).Split(' ')[1] }
function Invoke-Curl([string[]]$Arguments) { (& curl.exe -s -S --max-time 60 @Arguments 2>&1) -join "`n" }
function Invoke-CurlWith([string]$Stdin, [string[]]$Arguments) { ($Stdin | & curl.exe -s -S --max-time 60 @Arguments 2>&1) -join "`n" }
function Bearer([string]$Token) { "header = `"Authorization: Bearer $Token`"" }
function Status-Of([string]$Answer) { (($Answer -split "`n") | Where-Object { $_ -match '^HTTP/' } | Select-Object -Last 1).Trim() }
function Hide([string]$Text, [string]$Secret) { if ($Secret) { $Text.Replace($Secret, '<token>') } else { $Text } }

$started = Now
$utf8 = [Text.UTF8Encoding]::new($false)
$installToken = $null; $apiToken = $null
$t = @()
$t += "C5.10 (#63) and C5.9 (#62) Done-whens, by hand against the Compose stack: an MSP with one client and plan by CLI, timed; the scheduler's queued runs on a 5-minute cron. $(Now), commit $((git -C $Repo rev-parse --short HEAD 2>&1) -join ''), branch $((git -C $Repo rev-parse --abbrev-ref HEAD 2>&1) -join '')"
$t += "Windows, Python 3.12, Docker Desktop, the Compose stack (postgres:16, MinIO, api, scheduler) on 127.0.0.1; the CLI runs in the api container"
try {
    $t += "`n== (1) the stack, the scheduler service running the dispatcher =="
    $t += (((Invoke-Compose @('up', '-d', '--wait', '--build')) -split "`n") | Where-Object { $_ -match '^ (Container|Image|Network|Volume) ' }) -join "`n"
    $t += "GET /healthz: $((Invoke-Curl @('-i', "$Cloud/healthz")) -replace "`n", ' ' -replace '\s+', ' ')"
    $check = Invoke-Compose @('exec', '-T', 'api', 'alembic', 'check')
    $t += "alembic check (the stack's rows are left as they are; nothing is downgraded):`n$check"
    if ($LASTEXITCODE -ne 0) { throw 'alembic check: the database is not the models; re-migrate it by hand (docs/testing.md "Cloud") and run again' }
    $t += "the period's unique and the plan's created_at: $((Invoke-Compose @('exec', '-T', 'postgres', 'psql', '-U', 'restoreproof', '-d', 'restoreproof', '-At', '-c', "SELECT conname FROM pg_constraint WHERE conname = 'uq_test_run_msp_id_plan_id_scheduled_for' UNION ALL SELECT column_name || ' ' || data_type FROM information_schema.columns WHERE table_name = 'test_plan' AND column_name = 'created_at'")) -replace "`n", ' | ')"
    $t += "manage.py in the image: $(Invoke-Compose @('exec', '-T', 'api', 'ls', '-l', '/srv/manage.py'))"
    Start-Sleep -Seconds 5
    $firstLines = ((Invoke-Compose @('logs', '--no-log-prefix', '--since', $started, 'scheduler')) -split "`n") | Where-Object { $_ -match 'scheduler started|event.: .tick' } | Select-Object -First 3
    $t += "the scheduler's first lines:`n$($firstLines -join "`n")"

    $t += "`n== (2) the C5.10 Done-when, timed: an MSP with one client and plan by CLI =="
    $tenant = [guid]::NewGuid().ToString()
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $r = Invoke-Manage @('create-msp', '--name', 'c5.9-c5.10 done-when'); if ($r.Exit -ne 0) { throw "create-msp: $($r.Text)" }
    $mspId = Line-Of $r.Text 'msp_id'
    $t += "create-msp --name 'c5.9-c5.10 done-when': exit $($r.Exit)`n$($r.Text)"
    $r = Invoke-Manage @('create-client', '--msp-id', $mspId, '--name', 'Fabrikam', '--tenant-id', $tenant); if ($r.Exit -ne 0) { throw "create-client: $($r.Text)" }
    $clientId = Line-Of $r.Text 'client_id'
    $t += "create-client --msp-id <msp_id> --name Fabrikam --tenant-id <a tenant made for the run>: exit $($r.Exit)`n$($r.Text)"
    $r = Invoke-Manage @('create-worker-token', '--msp-id', $mspId, '--label', 'veeam-vm'); if ($r.Exit -ne 0) { throw "create-worker-token: $($r.Text)" }
    $installToken = Line-Of $r.Text 'install_token'
    $t += "create-worker-token --msp-id <msp_id> --label veeam-vm: exit $($r.Exit)`n$(Hide $r.Text $installToken)"
    $keyLine = Line-Of (Invoke-Rows @('key')) 'public_key'
    $Pem = "-----BEGIN PUBLIC KEY-----`n$keyLine`n-----END PUBLIC KEY-----`n"
    $register = @{ install_token = $installToken; public_key_pem = $Pem; worker_name = 'veeam-vm'; version = '0.0.0' } | ConvertTo-Json -Compress
    $answer = Invoke-CurlWith $register @('-X', 'POST', "$Cloud/v1/workers/register", '-H', 'Content-Type: application/json', '--data-binary', '@-')
    $registered = $null
    try { $registered = $answer | ConvertFrom-Json } catch { }
    $apiToken = if ($registered) { $registered.api_token } else { $null }
    if (-not $apiToken) { throw 'registration failed' }
    $workerId = [guid]::Parse($registered.worker_id).ToString()
    $t += "POST /v1/workers/register with curl (the token in the body on standard input, a key made for this run): 201 worker_id $workerId, key_id $($registered.key_id); the API token kept in memory"
    $profile = Get-Content (Join-Path $Repo 'shared\testdata\client-profile-v1\valid.json') -Raw | ConvertFrom-Json
    $profile.graph_tenant_id = $tenant
    [IO.File]::WriteAllText((Join-Path $Temp 'profile.json'), ($profile | ConvertTo-Json -Compress), $utf8)
    Invoke-Compose @('cp', (Join-Path $Temp 'profile.json'), 'api:/tmp/profile.json') | Out-Null
    $r = Invoke-Manage @('create-connector', '--msp-id', $mspId, '--client-id', $clientId, '--worker-id', $workerId, '--profile-file', '/tmp/profile.json'); if ($r.Exit -ne 0) { throw "create-connector: $($r.Text)" }
    $connectorId = Line-Of $r.Text 'connector_id'
    $t += "create-connector --msp-id <msp_id> --client-id <client_id> --worker-id <worker_id> --profile-file /tmp/profile.json (the shared valid profile naming the run's tenant, copied into the container): exit $($r.Exit)`n$($r.Text)"
    $r = Invoke-Manage @('create-plan', '--msp-id', $mspId, '--client-id', $clientId, '--connector-id', $connectorId, '--mail', '5', '--sp', '3', '--od', '2', '--cron', '*/5 * * * *'); if ($r.Exit -ne 0) { throw "create-plan: $($r.Text)" }
    $planId = Line-Of $r.Text 'plan_id'
    $planMadeAt = Now
    $watch.Stop()
    $t += "create-plan --msp-id <msp_id> --client-id <client_id> --connector-id <connector_id> --mail 5 --sp 3 --od 2 --cron '*/5 * * * *': exit $($r.Exit)`n$($r.Text)"
    $t += "** the six steps took $([math]::Round($watch.Elapsed.TotalSeconds, 1)) s (the Done-when says under 300) **"
    $t += "the rows (c59-c510-rows.py show):`n$(Invoke-Rows @('show', $mspId))"

    $t += "`n== (3) the CLI's refusals, each exit 1 with one line and nothing written =="
    foreach ($case in @(
        @('the same tenant again', @('create-client', '--msp-id', $mspId, '--name', 'Again', '--tenant-id', $tenant.ToUpper())),
        @('a profile naming another tenant', @('create-connector', '--msp-id', $mspId, '--client-id', $clientId, '--worker-id', $workerId, '--profile-file', '/tmp/other-profile.json')),
        @('a yearly cron', @('create-plan', '--msp-id', $mspId, '--client-id', $clientId, '--connector-id', $connectorId, '--mail', '1', '--sp', '1', '--od', '1', '--cron', '0 2 1 1 *')),
        @('a cron that is not one', @('create-plan', '--msp-id', $mspId, '--client-id', $clientId, '--connector-id', $connectorId, '--mail', '1', '--sp', '1', '--od', '1', '--cron', 'nonsense')),
        @('sizes all 0', @('create-plan', '--msp-id', $mspId, '--client-id', $clientId, '--connector-id', $connectorId, '--mail', '0', '--sp', '0', '--od', '0'))
    )) {
        if ($case[0] -eq 'a profile naming another tenant') {
            $other = $profile.PSObject.Copy(); $other.graph_tenant_id = [guid]::NewGuid().ToString()
            [IO.File]::WriteAllText((Join-Path $Temp 'other-profile.json'), ($other | ConvertTo-Json -Compress), $utf8)
            Invoke-Compose @('cp', (Join-Path $Temp 'other-profile.json'), 'api:/tmp/other-profile.json') | Out-Null
        }
        $r = Invoke-Manage $case[1]
        $t += "$($case[0]): exit $($r.Exit): $($r.Text)"
        if ($r.Exit -ne 1) { throw "$($case[0]) was not exit 1" }
    }

    $t += "`n== (4) the C5.9 Done-when: the scheduler makes the plan's queued runs on its 5-minute cron (the plan made $planMadeAt; polled every 30 s, at most $WaitSeconds s) =="
    $deadline = (Get-Date).AddSeconds($WaitSeconds)
    $seen = @()
    while ((Get-Date) -lt $deadline) {
        $shown = Invoke-Rows @('show', $mspId)
        $runs = ($shown -split "`n") | Where-Object { $_ -match "^  run .* plan $planId state queued scheduled_for (\S+)" } | ForEach-Object { $Matches[1] }
        $new = $runs | Where-Object { $seen -notcontains $_ }
        foreach ($p in $new) { $t += "$(Now): a queued run for the period $p"; $seen += $p }
        if (@($seen).Count -ge 2) { break }
        Start-Sleep -Seconds 30
    }
    if (@($seen).Count -lt 2) { throw "the scheduler made $(@($seen).Count) run(s) in $WaitSeconds s" }
    $t += "the rows after two periods:`n$(Invoke-Rows @('show', $mspId))"
    $t += "the scheduler's lines for this MSP (docker compose logs --since the run's start, filtered to the MSP's id; the first two ticks too):"
    $lines = (Invoke-Compose @('logs', '--no-log-prefix', '--since', $started, 'scheduler')) -split "`n"
    $t += (($lines | Where-Object { $_ -match $mspId }) -join "`n")
    $t += (($lines | Where-Object { $_ -match 'event.: .tick' } | Select-Object -First 2) -join "`n")

    $t += "`n== (5) the Worker's poll takes the runs; revoke-worker; the poll is 401 =="
    $answer = Invoke-CurlWith (Bearer $apiToken) @('-s', '-K', '-', "$Cloud/v1/jobs")
    $jobs = $null
    try { $jobs = $answer | ConvertFrom-Json } catch { }
    if (-not $jobs) { throw "the poll failed: $answer" }
    $t += "GET /v1/jobs (the API token in a curl config on standard input): $($jobs.format), $(@($jobs.jobs).Count) jobs, run_ids $(($jobs.jobs | ForEach-Object { $_.run_id }) -join ', '); each job's client is the connector's profile (not shown)"
    $r = Invoke-Manage @('revoke-worker', '--msp-id', $mspId, '--worker-id', $workerId); if ($r.Exit -ne 0) { throw "revoke-worker: $($r.Text)" }
    $t += "revoke-worker --msp-id <msp_id> --worker-id <worker_id>: exit $($r.Exit)`n$($r.Text)"
    $answer = Invoke-CurlWith (Bearer $apiToken) @('-i', '-K', '-', "$Cloud/v1/jobs")
    $lastLine = (($answer -split "`n") | Select-Object -Last 1).Trim()
    $t += "GET /v1/jobs again: $(Status-Of $answer) $lastLine"
    if ((Status-Of $answer) -notmatch ' 401 ') { throw "the poll after the revoke was not 401" }
    $r = Invoke-Manage @('revoke-worker', '--msp-id', $mspId, '--worker-id', $workerId)
    $t += "revoke-worker again: exit $($r.Exit): $($r.Text)"

    $t += "`n== (6) the rows at the end, and the api's request lines =="
    $t += (Invoke-Rows @('show', $mspId))
    $apiLines = (Invoke-Compose @('logs', '--no-log-prefix', '--since', $started, 'api')) -split "`n" | Where-Object { $_ -match '/v1/jobs|/v1/workers/register' }
    $t += ($apiLines -join "`n")
} finally {
    $t += "`n== (7) the teardown =="
    Remove-Item -Recurse -Force $Temp -ErrorAction SilentlyContinue
    Invoke-Compose @('exec', '-T', 'api', 'rm', '-f', '/tmp/profile.json', '/tmp/other-profile.json') | Out-Null
    $t += "$Temp and the container's two profile copies removed (ids only, no token in them); the install token went from the CLI's stdout into memory and to curl in the body on its standard input, the API token in a curl config on its standard input: neither was written to a file or put on a command line; this run's MSP and its rows are left in the stack's database and no other row was touched; the scheduler keeps running"
}
$text = ($t -join "`n").Replace("`r`n", "`n")
foreach ($s in @($installToken, $apiToken)) { if ($s -and $text.Contains($s)) { throw 'a token survived; nothing written' } }
if ($text -match '(?<![A-Za-z0-9_\-])[A-Za-z0-9_\-]{43}(?![A-Za-z0-9_\-=])' -or $text -match 'eyJ[A-Za-z0-9_\-]{10,}\.' -or $text -match 'PRIVATE KEY') { throw 'a token-shaped value; nothing written' }
[IO.File]::WriteAllText($Out, $text + "`n", $utf8)
"saved $Out"

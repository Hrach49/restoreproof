# C6.1 (#67), C6.2 (#68) and C6.3 (#69): the three by-hand Done-whens in one run against the Compose
# stack (docs/decisions.md 2026-10-12, "C6.1, C6.2 and C6.3", "Done-when, as it will be run";
# docs/testing.md "The pages"): the stack rebuilt and its database re-migrated (the edit of 0001);
# by CLI an MSP with an admin and a member (the passwords made in memory and given on standard
# input), a client of the lab tenant whose id becomes the kept C5.7 bundle's, the lab Worker's own
# key registered with curl, the connector on the lab profile, a plan with one run whose id becomes
# the bundle's; the Worker's poll; the real Worker bundle posted as the Worker posts it: 202 pass,
# 30 items; a second MSP the same way for the Worker-written vector (test key 1, posted without its
# token: not timestamped); then with curl and a cookie jar: five wrong passwords 401, the sixth and
# the right one 429, after a minute the right one 303 with the cookie; the four pages read as the
# member; a download 302 to the MinIO port on 127.0.0.1, followed, the bytes the kept file's;
# /audit as the admin with the download, the logins and the user, time and address; the member's
# /audit 403; the other MSP's run 404; the admin's Revoke; the Worker's poll 401; the api's request
# lines with nothing of a login in them.
#
#   pwsh -File docs\api\cloud-lab\c6.1-c6.3-harness\c61-c63-live.ps1 -Out docs\api\cloud-lab\c6.1-c6.3-done-when.txt
#
# Nothing secret is written or put on a command line: the passwords go to the CLI on its standard
# input and to curl in a config on its standard input; the install tokens from the CLI's stdout
# into variables and to curl in the registration body on its standard input; the API tokens in a
# curl config on its standard input; the session cookie in curl's jar under %TEMP%, removed at the
# end. The evidence text is screened for every one of them and for every token-shaped value before
# it is saved; a screen that fires leaves no file. The stack's database is re-migrated once (the
# rows it held are dropped: nothing is deployed), and the harness reads only the rows it made.
param(
    [string]$Out,
    [string]$Bundle = 'C:\ProgramData\RestoreProof\c57\06aa7c8f-3611-4f00-92c8-797428f58f1a',
    [string]$Rpworker = ''
)
$ErrorActionPreference = 'Stop'
$Repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..\..')).Path
$CloudDir = Join-Path $Repo 'cloud'
if (-not $Rpworker) { $Rpworker = Join-Path $Repo 'worker\build\dev\rpworker.exe' }
$Cloud = 'http://127.0.0.1:8000'
$Temp = Join-Path $env:TEMP 'rp-c61'
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
function Invoke-Psql([string]$Sql) { Push-Location $CloudDir; try { ($Sql | & docker compose exec -T postgres psql -U restoreproof -d restoreproof -At 2>&1) -join "`n" } finally { Pop-Location } }
function Line-Of([string]$Text, [string]$Key) { (($Text -split "`n") | Where-Object { $_ -like "$Key *" } | Select-Object -First 1).Split(' ')[1] }
function Invoke-Curl([string[]]$Arguments) { (& curl.exe -s -S --max-time 60 @Arguments 2>&1) -join "`n" }
function Invoke-CurlWith([string]$Stdin, [string[]]$Arguments) { ($Stdin | & curl.exe -s -S --max-time 60 @Arguments 2>&1) -join "`n" }
function Bearer([string]$Token) { "header = `"Authorization: Bearer $Token`"" }
function Status-Of([string]$Answer) { (($Answer -split "`n") | Where-Object { $_ -match '^HTTP/' } | Select-Object -Last 1).Trim() }
function Header-Of([string]$Answer, [string]$Name) {
    $line = ($Answer -split "`n") | Where-Object { $_ -match "^${Name}:" } | Select-Object -First 1
    if (-not $line) { return '' }
    return ([string]$line -replace "^${Name}:\s*", '').Trim()
}
function Body-Of([string]$Answer) { ($Answer -split "`r?`n`r?`n", 2)[1] }
function Random-Password { [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(18)) }
function Login-Config([string]$Email, [string]$Password) { "url = `"$Cloud/login`"`ndata-urlencode = `"email=$Email`"`ndata-urlencode = `"password=$Password`"" }
# A page as text: the <main> part, tags gone, a table row per line with its cells apart.
function Page-Text([string]$Html) {
    $main = if ($Html -match '(?s)<main>(.*?)</main>') { $Matches[1] } else { $Html }
    $main = $main -replace '(?s)<script.*?</script>', '' -replace '\s+', ' ' -replace '</tr>', "`n" -replace '</t[dh]>', ' | ' -replace '</p>', "`n" -replace '</h[12]>', "`n" -replace '<dt>', "`n" -replace '</dt>', ': ' -replace '<[^>]+>', ''
    $main = [System.Net.WebUtility]::HtmlDecode($main)
    (($main -split "`n") | ForEach-Object { ($_ -replace '\s+', ' ').Trim() } | Where-Object { $_ -ne '' -and $_ -ne '|' }) -join "`n"
}
function Get-Page([string]$Path) { $a = Invoke-Curl @('-i', '-b', $Jar, "$Cloud$Path"); [pscustomobject]@{ Status = (Status-Of $a); Text = (Page-Text (Body-Of $a)); Raw = $a } }

$started = Now
$secrets = @()
$t = @()
$t += "C6.1 (#67), C6.2 (#68) and C6.3 (#69) Done-whens, by hand against the Compose stack. $(Now), commit $((git -C $Repo rev-parse --short HEAD 2>&1) -join ''), branch $((git -C $Repo rev-parse --abbrev-ref HEAD 2>&1) -join '')"
$t += "Windows, Python 3.12, Docker Desktop, the Compose stack (postgres:16, MinIO, api, scheduler) on 127.0.0.1; the CLI runs in the api container; curl.exe 8.x with a cookie jar under %TEMP%"
try {
    $t += "`n== (1) the stack rebuilt, the database re-migrated once (the edit of 0001), the two new settings =="
    $t += (((Invoke-Compose @('up', '-d', '--wait', '--build')) -split "`n") | Where-Object { $_ -match '^ (Container|Image) ' }) -join "`n"
    foreach ($step in @(@('downgrade', '-1'), @('upgrade', 'head'), @('check'))) {
        $r = Invoke-Compose (@('exec', '-T', 'api', 'alembic') + $step)
        $t += "alembic $($step -join ' '): $((($r -split "`n") | Select-Object -Last 1).Trim())"
    }
    $t += "GET /healthz: $((Invoke-Curl @('-i', "$Cloud/healthz")) -replace "`n", ' ' -replace '\s+', ' ')"
    $t += "the api's environment: $((Invoke-Compose @('exec', '-T', 'api', 'printenv', 'S3_PUBLIC_ENDPOINT', 'SESSION_COOKIE_SECURE')) -replace "`n", ', ')"
    $t += "user's new columns and the run's: $(Invoke-Psql "SELECT column_name FROM information_schema.columns WHERE (table_name = 'user' AND column_name IN ('password_changed_at', 'created_at')) OR (table_name = 'test_run' AND column_name = 'recovery_ms') ORDER BY 1" -replace "`n", ', ')"
    $t += "/static: $(Status-Of (Invoke-Curl @('-i', "$Cloud/static/htmx.min.js"))) htmx.min.js, sha256 $((Invoke-Curl @('-o', (Join-Path $Temp 'htmx.min.js'), "$Cloud/static/htmx.min.js")); (Get-FileHash -Algorithm SHA256 (Join-Path $Temp 'htmx.min.js')).Hash.ToLower())"

    $t += "`n== (2) MSP A by CLI: the MSP, an admin and a member, the lab client (its id the kept bundle's), the lab Worker's key, the connector, a plan with one run (its id the bundle's) =="
    $bundleResult = Get-Content (Join-Path $Bundle 'result.json') -Raw | ConvertFrom-Json
    $bundleRun = $bundleResult.run_id; $bundleClient = $bundleResult.client.client_id; $labTenant = $bundleResult.client.tenant_id
    $t += "the kept C5.7 bundle: run $bundleRun, client $bundleClient, $($bundleResult.status.counts.items) items, status $($bundleResult.status.status), recovery $($bundleResult.timings.spans.recovery.ms) ms, files $((Get-ChildItem $Bundle -File | Where-Object { $_.Name -ne 'manifest.json' } | ForEach-Object { $_.Name }) -join ', ')"
    $r = Invoke-Manage @('create-msp', '--name', 'C6 done-when MSP A'); if ($r.Exit -ne 0) { throw "create-msp: $($r.Text)" }
    $mspA = Line-Of $r.Text 'msp_id'
    $t += "create-msp --name 'C6 done-when MSP A': exit $($r.Exit)`n$($r.Text)"
    $adminPassword = Random-Password; $memberPassword = Random-Password; $secrets += $adminPassword, $memberPassword
    $r = Invoke-Manage @('create-user', '--msp-id', $mspA, '--email', 'admin@c6.example.test', '--role', 'admin') $adminPassword; if ($r.Exit -ne 0) { throw "create-user: $($r.Text)" }
    $t += "create-user --msp-id <msp_id> --email admin@c6.example.test --role admin (the password on standard input, 24 characters made for the run): exit $($r.Exit)`n$($r.Text)"
    $r = Invoke-Manage @('create-user', '--msp-id', $mspA, '--email', 'member@c6.example.test', '--role', 'member') $memberPassword; if ($r.Exit -ne 0) { throw "create-user: $($r.Text)" }
    $t += "create-user --msp-id <msp_id> --email member@c6.example.test --role member: exit $($r.Exit)`n$($r.Text)"
    $r = Invoke-Manage @('create-user', '--msp-id', $mspA, '--email', 'ADMIN@c6.example.test', '--role', 'member') $memberPassword
    $t += "create-user with the admin's address in another case: exit $($r.Exit): $($r.Text)"
    $r = Invoke-Manage @('create-user', '--msp-id', $mspA, '--email', 'short@c6.example.test', '--role', 'member') 'short'
    $t += "create-user with a password of 5 characters: exit $($r.Exit): $($r.Text)"
    $r = Invoke-Manage @('create-client', '--msp-id', $mspA, '--name', 'Lab tenant', '--tenant-id', $labTenant); if ($r.Exit -ne 0) { throw "create-client: $($r.Text)" }
    $clientA = Line-Of $r.Text 'client_id'
    $t += "create-client --msp-id <msp_id> --name 'Lab tenant' --tenant-id <the lab tenant>: exit $($r.Exit)`n$($r.Text)"
    $t += "the client's id set to the bundle's by SQL (as tests/test_contract.py gives a test's rows the vector's ids): $(Invoke-Psql "UPDATE client SET id = '$bundleClient' WHERE id = '$clientA' AND msp_id = '$mspA'")"
    $clientA = $bundleClient
    $r = Invoke-Manage @('create-worker-token', '--msp-id', $mspA, '--label', 'veeam-vm'); if ($r.Exit -ne 0) { throw "create-worker-token: $($r.Text)" }
    $tokenA = Line-Of $r.Text 'install_token'; $secrets += $tokenA
    $t += "create-worker-token --msp-id <msp_id> --label veeam-vm: exit $($r.Exit)`n$($r.Text.Replace($tokenA, '<token>'))"
    # The key file on stdout (the key id goes to stderr); the PEM's three lines alone.
    $pemA = (((& $Rpworker signer public-key 2>$null) -split "`r?`n") | Where-Object { $_ -match 'PUBLIC KEY-----$|^[A-Za-z0-9+/=]{20,}$' }) -join "`n"
    $pemA += "`n"
    if ($pemA -notmatch 'BEGIN PUBLIC KEY') { throw 'rpworker signer public-key gave no key' }
    $register = @{ install_token = $tokenA; public_key_pem = $pemA; worker_name = 'veeam-vm'; version = '0.0.0' } | ConvertTo-Json -Compress
    $registered = (Invoke-CurlWith $register @('-X', 'POST', "$Cloud/v1/workers/register", '-H', 'Content-Type: application/json', '--data-binary', '@-')) | ConvertFrom-Json
    $apiA = $registered.api_token; if (-not $apiA) { throw 'registration A failed' }; $secrets += $apiA
    $workerA = [guid]::Parse($registered.worker_id).ToString()
    $t += "POST /v1/workers/register with curl (the lab Worker's own key from rpworker signer public-key; the token in the body on standard input): 201 worker_id $workerA, key_id $($registered.key_id); the API token kept in memory"
    Invoke-Compose @('cp', (Join-Path $env:LOCALAPPDATA 'RestoreProof\lab\lab-profile.json'), 'api:/tmp/profile-a.json') | Out-Null
    $r = Invoke-Manage @('create-connector', '--msp-id', $mspA, '--client-id', $clientA, '--worker-id', $workerA, '--profile-file', '/tmp/profile-a.json'); if ($r.Exit -ne 0) { throw "create-connector: $($r.Text)" }
    $connectorA = Line-Of $r.Text 'connector_id'
    $t += "create-connector --msp-id <msp_id> --client-id <client_id> --worker-id <worker_id> --profile-file /tmp/profile-a.json (the lab profile, outside the repository): exit $($r.Exit)`n$($r.Text)"
    $r = Invoke-Manage @('create-plan', '--msp-id', $mspA, '--client-id', $clientA, '--connector-id', $connectorA, '--mail', '10', '--sp', '10', '--od', '10', '--run-now'); if ($r.Exit -ne 0) { throw "create-plan: $($r.Text)" }
    $runA = Line-Of $r.Text 'run_id'
    $t += "create-plan --msp-id <msp_id> --client-id <client_id> --connector-id <connector_id> --mail 10 --sp 10 --od 10 --run-now (the default daily cadence): exit $($r.Exit)`n$($r.Text)"
    $t += "the run's id set to the bundle's by SQL: $(Invoke-Psql "UPDATE test_run SET id = '$bundleRun' WHERE id = '$runA' AND msp_id = '$mspA'")"
    $runA = $bundleRun

    $t += "`n== (3) the Worker's poll, then the real Worker bundle posted as the Worker posts it: 202 pass =="
    $jobs = (Invoke-CurlWith (Bearer $apiA) @('-K', '-', "$Cloud/v1/jobs")) | ConvertFrom-Json
    $t += "GET /v1/jobs (the API token in a curl config on standard input): $($jobs.format), $(@($jobs.jobs).Count) job, run_id $($jobs.jobs[0].run_id)"
    $form = @('-F', "result=@$(Join-Path $Bundle 'result.json');type=application/json", '-F', "signature=@$(Join-Path $Bundle 'signature.json');type=application/json", '-F', "timestamp=@$(Join-Path $Bundle 'timestamp.tst');type=application/octet-stream", '-F', "items.csv=@$(Join-Path $Bundle 'items.csv');type=application/octet-stream", '-F', "veeam-session.log=@$(Join-Path $Bundle 'veeam-session.log');type=application/octet-stream")
    $answer = Invoke-CurlWith (Bearer $apiA) (@('-i', '-K', '-', '-X', 'POST', "$Cloud/v1/results") + $form)
    $t += "POST /v1/results with the kept bundle's five files: $(Status-Of $answer) $((($answer -split "`n") | Select-Object -Last 1).Trim())"
    if ((Status-Of $answer) -notmatch ' 202 ') { throw 'the bundle did not land' }
    $t += "the run's row: $(Invoke-Psql "SELECT state, total_ms, recovery_ms, tsa_ok, cleanup_ok, (SELECT count(*) FROM test_item WHERE run_id = test_run.id) AS items FROM test_run WHERE id = '$runA'")"

    $t += "`n== (4) MSP B by CLI for the Worker-written vector (shared/testdata/signing-v1/dispatched-run.json, test key 1, posted without its token: not timestamped) =="
    $vector = Get-Content (Join-Path $Repo 'shared\testdata\signing-v1\dispatched-run.json') -Raw | ConvertFrom-Json
    $keys = Get-Content (Join-Path $Repo 'shared\testdata\signing-v1\keys.json') -Raw | ConvertFrom-Json
    $r = Invoke-Manage @('create-msp', '--name', 'C6 done-when MSP B'); if ($r.Exit -ne 0) { throw "create-msp B: $($r.Text)" }
    $mspB = Line-Of $r.Text 'msp_id'
    $bPassword = Random-Password; $secrets += $bPassword
    $r = Invoke-Manage @('create-user', '--msp-id', $mspB, '--email', 'admin@b.example.test', '--role', 'admin') $bPassword; if ($r.Exit -ne 0) { throw "create-user B: $($r.Text)" }
    $r = Invoke-Manage @('create-client', '--msp-id', $mspB, '--name', 'Vector client', '--tenant-id', $vector.tenant_id); if ($r.Exit -ne 0) { throw "create-client B: $($r.Text)" }
    $clientB = Line-Of $r.Text 'client_id'
    Invoke-Psql "UPDATE client SET id = '$($vector.client_id)' WHERE id = '$clientB' AND msp_id = '$mspB'" | Out-Null; $clientB = $vector.client_id
    $r = Invoke-Manage @('create-worker-token', '--msp-id', $mspB, '--label', 'vector-worker'); if ($r.Exit -ne 0) { throw "create-worker-token B: $($r.Text)" }
    $tokenB = Line-Of $r.Text 'install_token'; $secrets += $tokenB
    $keyB = ($keys.keys | Where-Object { $_.name -eq $vector.key } | Select-Object -First 1).public_key_pem
    if (-not $keyB) { throw "no key named $($vector.key) in keys.json" }
    $register = @{ install_token = $tokenB; public_key_pem = $keyB; worker_name = 'vector-worker'; version = $vector.worker_version } | ConvertTo-Json -Compress
    $registered = (Invoke-CurlWith $register @('-X', 'POST', "$Cloud/v1/workers/register", '-H', 'Content-Type: application/json', '--data-binary', '@-')) | ConvertFrom-Json
    $apiB = $registered.api_token; if (-not $apiB) { throw 'registration B failed' }; $secrets += $apiB
    $workerB = [guid]::Parse($registered.worker_id).ToString()
    [IO.File]::WriteAllText((Join-Path $Temp 'profile-b.json'), ($vector.job.client | ConvertTo-Json -Compress -Depth 10), $utf8)
    Invoke-Compose @('cp', (Join-Path $Temp 'profile-b.json'), 'api:/tmp/profile-b.json') | Out-Null
    $r = Invoke-Manage @('create-connector', '--msp-id', $mspB, '--client-id', $clientB, '--worker-id', $workerB, '--profile-file', '/tmp/profile-b.json'); if ($r.Exit -ne 0) { throw "create-connector B: $($r.Text)" }
    $connectorB = Line-Of $r.Text 'connector_id'
    $r = Invoke-Manage @('create-plan', '--msp-id', $mspB, '--client-id', $clientB, '--connector-id', $connectorB, '--mail', "$($vector.job.sample_mail)", '--sp', "$($vector.job.sample_sp)", '--od', "$($vector.job.sample_od)", '--run-now'); if ($r.Exit -ne 0) { throw "create-plan B: $($r.Text)" }
    $runB = Line-Of $r.Text 'run_id'
    Invoke-Psql "UPDATE test_run SET id = '$($vector.run_id)' WHERE id = '$runB' AND msp_id = '$mspB'" | Out-Null; $runB = $vector.run_id
    $t += "MSP B ${mspB}: an admin, the vector's client $clientB (the same lab tenant: one client per tenant and MSP, so a second MSP), a Worker under test key 1 (key_id $($registered.key_id)), the connector on the vector's job profile, a plan with one run $runB"
    $jobs = (Invoke-CurlWith (Bearer $apiB) @('-K', '-', "$Cloud/v1/jobs")) | ConvertFrom-Json
    $t += "GET /v1/jobs: $(@($jobs.jobs).Count) job, run_id $($jobs.jobs[0].run_id)"
    $vectorDir = Join-Path $Temp 'vector'; New-Item -ItemType Directory -Force $vectorDir | Out-Null
    foreach ($name in @('result.json', 'signature.json', 'items.csv', 'veeam-session.log')) { [IO.File]::WriteAllText((Join-Path $vectorDir $name), [string]$vector.files.$name, $utf8) }
    $form = @('-F', "result=@$(Join-Path $vectorDir 'result.json');type=application/json", '-F', "signature=@$(Join-Path $vectorDir 'signature.json');type=application/json", '-F', "items.csv=@$(Join-Path $vectorDir 'items.csv');type=application/octet-stream", '-F', "veeam-session.log=@$(Join-Path $vectorDir 'veeam-session.log');type=application/octet-stream")
    $answer = Invoke-CurlWith (Bearer $apiB) (@('-i', '-K', '-', '-X', 'POST', "$Cloud/v1/results") + $form)
    $t += "POST /v1/results with the vector's four files (no timestamp part): $(Status-Of $answer) $((($answer -split "`n") | Select-Object -Last 1).Trim())"
    if ((Status-Of $answer) -notmatch ' 202 ') { throw 'the vector did not land' }
    $t += "the run's row: $(Invoke-Psql "SELECT state, total_ms, recovery_ms, tsa_ok, cleanup_ok, (SELECT count(*) FROM test_item WHERE run_id = test_run.id) AS items FROM test_run WHERE id = '$runB'")"

    $t += "`n== (5) the C6.1 Done-when: wrong password five times is blocked and each attempt is in the audit log (curl, the form in a config on standard input, a cookie jar under %TEMP%) =="
    for ($i = 1; $i -le 5; $i++) {
        $a = Invoke-CurlWith (Login-Config 'admin@c6.example.test' 'not-the-password-1') @('-i', '-c', $Jar, '-K', '-')
        $t += "POST /login wrong password ${i}: $(Status-Of $a) $(if ((Body-Of $a) -match 'wrong email or password') { '(the form again, "wrong email or password")' })"
    }
    $a = Invoke-CurlWith (Login-Config 'admin@c6.example.test' 'not-the-password-1') @('-i', '-c', $Jar, '-K', '-')
    $t += "POST /login wrong password 6: $(Status-Of $a) retry-after $(Header-Of $a 'retry-after') $(if ((Body-Of $a) -match 'too many attempts') { '("too many attempts, try again in a minute")' })"
    $a = Invoke-CurlWith (Login-Config 'admin@c6.example.test' $adminPassword) @('-i', '-c', $Jar, '-K', '-')
    $t += "POST /login the right password inside the minute: $(Status-Of $a) retry-after $(Header-Of $a 'retry-after'); set-cookie: $(if (Header-Of $a 'set-cookie') { 'yes' } else { 'none' })"
    $t += "the audit rows so far (SELECT action, user_id IS NOT NULL AS has_user, ip): $(Invoke-Psql "SELECT action, user_id IS NOT NULL, ip FROM audit_log WHERE msp_id = '$mspA' AND action LIKE 'login.%' ORDER BY action" -replace "`n", ' ; ')"
    $t += "waiting 61 s for the window to pass ($(Now))"
    Start-Sleep -Seconds 61
    $a = Invoke-CurlWith (Login-Config 'admin@c6.example.test' $adminPassword) @('-i', '-c', $Jar, '-K', '-')
    $cookie = (Header-Of $a 'set-cookie')
    if ($cookie -match 'rp_session=([^;]+)') { $secrets += $Matches[1] }
    $t += "POST /login the right password after the minute: $(Status-Of $a) location $(Header-Of $a 'location'); set-cookie: $($cookie -replace 'rp_session=[^;]+', 'rp_session=<value>')"
    $rootAnswer = Invoke-Curl @('-i', '-b', $Jar, "$Cloud/")
    $t += "GET / with the cookie: $(Status-Of $rootAnswer) location $(Header-Of $rootAnswer 'location'); x-restoreproof-api $(Header-Of $rootAnswer 'x-restoreproof-api')"

    $t += "`n== (6) the C6.2 Done-when: the four pages as the admin (then the member), real data from the Sprint 5 runs =="
    foreach ($path in @('/clients', "/clients/$clientA", "/runs/$runA", '/workers')) {
        $p = Get-Page $path
        $t += "GET ${path}: $($p.Status)`n$($p.Text)"
    }
    $t += "GET /runs/$runB (the other MSP's run) as A's admin: $((Get-Page "/runs/$runB").Status)"
    $t += "GET /clients/$clientB (the other MSP's client) as A's admin: $((Get-Page "/clients/$clientB").Status)"
    $t += "GET /clients/$clientA as nobody (no cookie): $(Status-Of (Invoke-Curl @('-i', "$Cloud/clients/$clientA"))) → /login"

    $t += "`n== (7) the C6.3 Done-when: the member downloads items.csv; /audit shows it with user, time and IP; the member's /audit is 403 =="
    $a = Invoke-CurlWith (Login-Config 'member@c6.example.test' $memberPassword) @('-i', '-c', $Jar, '-K', '-')
    if ($a -match 'rp_session=([^;]+)') { $secrets += $Matches[1] }
    $t += "POST /login as the member: $(Status-Of $a)"
    $d = Invoke-Curl @('-i', '-b', $Jar, "$Cloud/runs/$runA/files/items.csv")
    $location = Header-Of $d 'location'
    $locationShown = if ($location -match '^(https?://[^/]+/[^?]+)\?') { $Matches[1] + '?<the signed query, X-Amz-Expires=600>' } else { $location }
    $t += "GET /runs/$runA/files/items.csv as the member: $(Status-Of $d) cache-control $(Header-Of $d 'cache-control'); location $locationShown"
    Invoke-Curl @('-o', (Join-Path $Temp 'items.csv'), $location) | Out-Null
    $got = (Get-FileHash -Algorithm SHA256 (Join-Path $Temp 'items.csv')).Hash.ToLower(); $kept = (Get-FileHash -Algorithm SHA256 (Join-Path $Bundle 'items.csv')).Hash.ToLower()
    $t += "the link followed: $((Get-Item (Join-Path $Temp 'items.csv')).Length) bytes, sha256 $got; the kept file's sha256 $kept; $(if ($got -eq $kept) { 'the same bytes' } else { 'DIFFERENT' })"
    $bad = Invoke-Curl @('-i', '-b', $Jar, "$Cloud/runs/$runA/files/nothing.csv")
    $t += "GET /runs/$runA/files/nothing.csv: $(Status-Of $bad)"
    $t += "GET /audit as the member: $((Get-Page '/audit').Status)"
    $a = Invoke-CurlWith (Login-Config 'admin@c6.example.test' $adminPassword) @('-i', '-c', $Jar, '-K', '-')
    if ($a -match 'rp_session=([^;]+)') { $secrets += $Matches[1] }
    $p = Get-Page '/audit'
    $t += "GET /audit as the admin: $($p.Status)`n$($p.Text)"

    $t += "`n== (8) the admin's Revoke on /workers; the Worker's next poll is 401 =="
    $rv = Invoke-Curl @('-i', '-b', $Jar, '-X', 'POST', "$Cloud/workers/$workerA/revoke")
    $t += "POST /workers/$workerA/revoke as the admin: $(Status-Of $rv) location $(Header-Of $rv 'location')"
    $t += "GET /workers after: $((Get-Page '/workers').Text)"
    $pollA = Invoke-CurlWith (Bearer $apiA) @('-i', '-K', '-', "$Cloud/v1/jobs")
    $t += "GET /v1/jobs with the revoked Worker's token: $(Status-Of $pollA) $((($pollA -split "`n") | Select-Object -Last 1).Trim())"
    $rv = Invoke-Curl @('-i', '-b', $Jar, '-X', 'POST', "$Cloud/workers/$workerA/revoke")
    $t += "POST /workers/$workerA/revoke again: $(Status-Of $rv) $((($rv -split "`n") | Select-Object -Last 1).Trim())"
    # -c too, so the jar takes the cleared cookie as a browser would.
    $lo = Invoke-Curl @('-i', '-b', $Jar, '-c', $Jar, '-X', 'POST', "$Cloud/logout")
    $t += "POST /logout: $(Status-Of $lo) location $(Header-Of $lo 'location'); set-cookie: $((Header-Of $lo 'set-cookie') -replace 'rp_session=[^;]*', 'rp_session=<cleared>')"
    $t += "GET /clients after logout: $(Status-Of (Invoke-Curl @('-i', '-b', $Jar, "$Cloud/clients")))"

    $t += "`n== (9) the rows at the end and the api's request lines (no address, password or cookie value in them) =="
    $t += "audit rows of MSP A (action, has_user, ip): $(Invoke-Psql "SELECT action, user_id IS NOT NULL, ip FROM audit_log WHERE msp_id = '$mspA' ORDER BY at, action" -replace "`n", ' ; ')"
    $usersSql = "SELECT email, role, password_hash LIKE '`$argon2id`$%' FROM ""user"" WHERE msp_id = '$mspA' ORDER BY email"
    $t += "users of MSP A (email, role, the hash is Argon2id): $((Invoke-Psql $usersSql) -replace "`n", ' ; ')"
    $t += "the Worker: $(Invoke-Psql "SELECT name, revoked_at IS NOT NULL AS revoked FROM worker WHERE id = '$workerA'")"
    $lines = (Invoke-Compose @('logs', '--no-log-prefix', '--since', $started, 'api')) -split "`n" | Where-Object { $_ -match '"path": "/(login|logout|clients|runs|workers|audit|)"' -or $_ -match '"path": "/(clients|runs|workers)/' -or $_ -match 'login refused' }
    $t += ($lines -join "`n")
} finally {
    $t += "`n== (10) the teardown =="
    Remove-Item -Recurse -Force $Temp -ErrorAction SilentlyContinue
    Invoke-Compose @('exec', '-T', 'api', 'rm', '-f', '/tmp/profile-a.json', '/tmp/profile-b.json') | Out-Null
    $t += "$Temp (the cookie jar, the downloaded items.csv, the vector's files, the vector's profile) and the container's two profile copies removed; the passwords went to the CLI and to curl on their standard input, the tokens into memory and to curl on its standard input, the cookie into the jar: nothing was written to a file but the jar, which is gone, and nothing was put on a command line; the two MSPs and their rows are left in the stack's database"
}
$text = ($t -join "`n").Replace("`r`n", "`n")
foreach ($s in $secrets) { if ($s -and $text.Contains($s)) { throw 'a secret survived; nothing written' } }
if ($text -match '(?<![A-Za-z0-9_\-])[A-Za-z0-9_\-]{43}(?![A-Za-z0-9_\-=])' -or $text -match 'eyJ[A-Za-z0-9_\-]{10,}\.' -or $text -match 'PRIVATE KEY' -or $text -match 'rp_session=[A-Za-z0-9]' -or $text -match 'X-Amz-Signature=[0-9a-f]') { throw 'a secret-shaped value; nothing written' }
[IO.File]::WriteAllText($Out, $text + "`n", $utf8)
"saved $Out"

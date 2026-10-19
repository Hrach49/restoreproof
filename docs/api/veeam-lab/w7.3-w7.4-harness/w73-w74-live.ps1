# W7.3 (#82) and W7.4 (#83): the live Done-when on this laptop, the Veeam server
# (docs/decisions.md 2026-10-19, "W7.3 (#82) and W7.4 (#83)", point 10): the 0.1.0 package
# installed by W7.1's installer around the W7.1 harness's stack and plan, a run pass; the 0.1.1
# package's installer with -Upgrade (the wait for the run in progress seen once, previous\ kept,
# the vault and worker.json the same, the new version in the heartbeat and on /workers, a run
# pass on 0.1.1); the rollback from previous\ and the upgrade again; then
# Uninstall-RestoreProofWorker.ps1 without -Full: the flush, the revoke, the key file's entry
# gone, no service, no program folder, no Apps entry, logs\ and the lab's own folders left and
# named, the Cloud's row revoked, the targets empty. Run from an ELEVATED PowerShell 7, Docker
# Desktop running, the vault holding the lab's five secrets:
#
#   pwsh -File docs\api\veeam-lab\w7.3-w7.4-harness\w73-w74-live.ps1 [-OldPackage <0.1.0 zip>] [-NewPackage <0.1.1 zip>] [-NoCopy]
#
# Without -NewPackage the new package is built by worker\tools\package.ps1 -NoBuild from build\ci
# (build the ci preset on the branch first). The old package is the 0.1.0 zip built from main
# before the version bump (%LOCALAPPDATA%\RestoreProof\lab\packages\RestoreProof-Worker-0.1.0.zip).
#
# What this harness does to the lab's own state, and puts back: the lab's vault.bin is copied
# into the run folder before anything (the uninstall overwrites and deletes it) and copied back
# with its protected DACL after each uninstall, so the installer finds the five names and asks
# nothing and the lab keeps its secrets; the lab's run folders (runs\, outbox\, sent\, failed\,
# state\) are moved into the run folder's kept\ before and moved back at the end. A service W7.2
# left installed is taken away first with the new uninstall script (step 0), its lines in the
# evidence. -Full is never given here: the lab's folders live under the root.
# Only when every step held and no secret, token or key survives in the text is it copied to
# docs\api\veeam-lab\w7.3-w7.4-done-when.txt, the copy last.
#Requires -Version 7.4
param([string]$OldPackage = (Join-Path $env:LOCALAPPDATA 'RestoreProof\lab\packages\RestoreProof-Worker-0.1.0.zip'), [string]$NewPackage = '', [switch]$NoCopy)
. (Join-Path $PSScriptRoot '..\w4.8-harness\w48-run.ps1')

$RunDir = Join-Path $env:LOCALAPPDATA ("RestoreProof\lab\w7.3-w7.4-" + (Get-Date -Format 'yyyyMMddTHHmmss'))
$CloudDir = Join-Path $script:Repo 'cloud'
$LabProfile = Join-Path $env:LOCALAPPDATA 'RestoreProof\lab\lab-profile.json'
$Packager = Join-Path $script:Repo 'worker\tools\package.ps1'
$ProgramDir = Join-Path $env:ProgramFiles 'RestoreProof'
$Root = $script:W48Root
$ConfigPath = Join-Path $Root 'config.json'
$VaultPath = Join-Path $Root 'vault.bin'
$VaultCopy = Join-Path $RunDir 'vault.bin.copy'
$KeptFolders = Join-Path $RunDir 'kept'
$Kept = Join-Path $Root 'w73'
$Evidence = Join-Path $script:Repo 'docs\api\veeam-lab\w7.3-w7.4-done-when.txt'
$CloudCa = Join-Path $RunDir 'cloud-ca.pem'
$Pages = 'http://127.0.0.1:8000'
$Jar = Join-Path $RunDir 'cookies.txt'
$EntryKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\RestoreProofWorker'
$commit = git -C $script:Repo rev-parse --short HEAD
function Get-Utc { [DateTime]::UtcNow.ToString('s') + 'Z' }

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'run from an elevated shell'; exit 64
}
docker info *> $null
if ($LASTEXITCODE -ne 0) { Write-Error 'Docker Desktop is not running'; exit 64 }
if (-not (Test-Path -LiteralPath $OldPackage)) { Write-Error "no old package at $OldPackage"; exit 64 }
if (-not (Test-Path -LiteralPath $VaultPath)) { Write-Error "no vault at $VaultPath"; exit 64 }
New-Item -ItemType Directory -Force $RunDir | Out-Null

function Invoke-Compose([string[]]$Arguments, [string]$Stdin = $null) {
    Push-Location $CloudDir
    try {
        if ($null -ne $Stdin) { $out = $Stdin | & docker compose @Arguments 2>&1 } else { $out = & docker compose @Arguments 2>&1 }
        [pscustomobject]@{ Code = $LASTEXITCODE; Text = (($out | ForEach-Object { "$_" }) -join "`n") }
    } finally { Pop-Location }
}
function Invoke-Manage([string[]]$Arguments, [string]$Stdin = $null) { Invoke-Compose (@('exec', '-T', 'api', 'python', 'manage.py') + $Arguments) $Stdin }
function Get-Value([string]$Text, [string]$Name) { ($Text -split "`n" | Where-Object { $_ -like "$Name *" } | Select-Object -First 1) -replace "^$Name ", '' }
function Invoke-Sql([string]$Statement) {
    (Invoke-Compose @('exec', '-T', 'postgres', 'psql', '-U', 'restoreproof', '-d', 'restoreproof', '-tAc', $Statement)).Text.Trim()
}
function Invoke-Curl([string[]]$Arguments) { (& curl.exe -s -S --max-time 60 @Arguments 2>&1) -join "`n" }
function Status-Of([string]$Answer) { (($Answer -split "`n") | Where-Object { $_ -match '^HTTP/' } | Select-Object -Last 1).Trim() }
function Body-Of([string]$Answer) { ($Answer -split "`r?`n`r?`n", 2)[1] }
function Page-Text([string]$Html) {
    $main = if ($Html -match '(?s)<main>(.*?)</main>') { $Matches[1] } else { $Html }
    $main = $main -replace '(?s)<script.*?</script>', '' -replace '\s+', ' ' -replace '</tr>', "`n" -replace '</t[dh]>', ' | ' -replace '</p>', "`n" -replace '<[^>]+>', ''
    $main = [System.Net.WebUtility]::HtmlDecode($main)
    (($main -split "`n") | ForEach-Object { ($_ -replace '\s+', ' ').Trim() } | Where-Object { $_ -ne '' -and $_ -ne '|' }) -join "`n"
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
function Get-AclPaths { @($Root, $VaultPath) + @(Get-W48KeyFile | ForEach-Object File) }
function Get-VaultNames { ((((Invoke-W48 @('vault', 'list')) -split "`n") | Where-Object { $_ -match '^[a-z0-9_]+\r?$' } | ForEach-Object { $_.Trim() }) -join ', ') }
function Get-Entry {
    if (-not (Test-Path -LiteralPath $EntryKey)) { return 'no Apps & features entry' }
    $p = Get-ItemProperty -LiteralPath $EntryKey
    "Apps & features: $($p.DisplayName) $($p.DisplayVersion), $($p.InstallLocation), uninstall: $($p.UninstallString)"
}
function Get-ProgramFiles {
    if (-not (Test-Path -LiteralPath $ProgramDir)) { return "${ProgramDir}: not there" }
    $lines = foreach ($f in @(Get-ChildItem -LiteralPath $ProgramDir -File | Sort-Object Name)) { "  $($f.Name)  $($f.Length) bytes" }
    $previous = Join-Path $ProgramDir 'previous'
    if (Test-Path -LiteralPath $previous) { $lines += "  previous\: $((Get-ChildItem -LiteralPath $previous -File | Sort-Object Name | ForEach-Object Name) -join ', ')" }
    "${ProgramDir}:`n$($lines -join "`n")"
}
function Get-ServiceLine {
    $s = Get-CimInstance Win32_Service -Filter "Name='$script:W48Service'"
    if ($s) { "service $script:W48Service $($s.State), $($s.PathName)" } else { "service ${script:W48Service}: not installed (sc query 1060)" }
}
# The lab's vault, copied back whole with W4.5's protected DACL (SYSTEM, Administrators and the
# owner's rights, Full), so the installer's `vault grant` adds the service's Read entry as on a
# first install. The copy's owner is this account, which the owner rule allows.
function Restore-Vault {
    if (Test-Path -LiteralPath $VaultPath) { return 'vault.bin is there; the copy not used' }
    Copy-Item -LiteralPath $VaultCopy -Destination $VaultPath
    & icacls.exe $VaultPath /inheritance:r /grant '*S-1-5-18:F' '*S-1-5-32-544:F' '*S-1-3-4:F' /Q | Out-Null
    # The copy was taken before the uninstall's revoke: the tokens in it are nobody's now.
    foreach ($name in 'cloud_api_token', 'cloud_install_token') { & $script:Worker vault remove $name 2>&1 | Out-Null }
    "vault.bin put back from the run folder's copy, its DACL protected again (SYSTEM, Administrators, OWNER RIGHTS), both Cloud tokens removed from it"
}
function Move-LabFoldersOut {
    New-Item -ItemType Directory -Force $KeptFolders | Out-Null
    $lines = @()
    foreach ($name in 'runs', 'outbox', 'sent', 'failed', 'state') {
        $folder = Join-Path $Root $name
        if (-not (Test-Path -LiteralPath $folder)) { continue }
        $items = @(Get-ChildItem -LiteralPath $folder -Force)
        if ($items.Count -eq 0) { continue }
        $to = Join-Path $KeptFolders $name
        New-Item -ItemType Directory -Force $to | Out-Null
        foreach ($item in $items) { Move-Item -LiteralPath $item.FullName -Destination (Join-Path $to $item.Name) -Force }
        $lines += "$name\: $($items.Count) item(s) moved to $to"
    }
    if ($lines.Count -eq 0) { 'nothing of the lab under the five folders' } else { $lines -join "`n" }
}
function Move-LabFoldersBack {
    if (-not (Test-Path -LiteralPath $KeptFolders)) { return 'nothing kept' }
    $lines = @()
    foreach ($to in @(Get-ChildItem -LiteralPath $KeptFolders -Directory)) {
        $folder = Join-Path $Root $to.Name
        New-Item -ItemType Directory -Force $folder | Out-Null
        # The old service's own records don't come back (W7.1's harness removed them too): a
        # stale worker.json would name a Worker this machine no longer is.
        $items = @(Get-ChildItem -LiteralPath $to.FullName -Force | Where-Object { -not ($to.Name -eq 'state' -and $_.Name -in 'worker.json', 'jobs.json', 'running.json') })
        foreach ($item in $items) { Move-Item -LiteralPath $item.FullName -Destination (Join-Path $folder $item.Name) -Force }
        $lines += "$($to.Name)\: $($items.Count) item(s) put back (the folder made again with the root's inherited ACL; the next install sets the account's Modify)"
    }
    $lines -join "`n"
}
function Unpack([string]$Zip, [string]$Name) {
    $folder = Join-Path $RunDir $Name
    Expand-Archive -LiteralPath $Zip -DestinationPath $folder
    $folder
}
function Wait-Version([string]$WorkerId, [string]$Version, [int]$Seconds = 240) {
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $row = Invoke-Sql "SELECT coalesce(version, '-') || '|' || coalesce(to_char(last_seen_at AT TIME ZONE 'UTC', 'YYYY-MM-DD""T""HH24:MI:SS""Z""'), '-') FROM worker WHERE id = '$WorkerId'"
        $v, $seen = $row -split '\|'
        if ($v -eq $Version) { return "$(Get-Utc) worker.version $v, last_seen_at $seen (the heartbeat after the start)" }
        Start-Sleep -Seconds 5
    }
    throw "worker.version did not become $Version within $Seconds s (last: $row)"
}
# The first run of the plan that goes to pass and was dispatched at or after `After` (the
# upgrade's end, for a run on the new version: a run received before it is the old version's).
function Wait-Pass([string]$PlanId, [hashtable]$Seen, [int]$Minutes = 30, [DateTime]$After = [DateTime]::MinValue) {
    $deadline = [DateTime]::UtcNow.AddMinutes($Minutes)
    while ([DateTime]::UtcNow -lt $deadline) {
        $rows = Invoke-Sql "SELECT id, state, coalesce(to_char(dispatched_at, 'YYYY-MM-DD""T""HH24:MI:SS""Z""'), '-'), coalesce(to_char(received_at, 'YYYY-MM-DD""T""HH24:MI:SS""Z""'), '-') FROM test_run WHERE plan_id = '$PlanId' ORDER BY created_at"
        foreach ($row in @($rows -split "`n" | Where-Object { $_ })) {
            $id, $state, $dispatched, $received = $row -split '\|'
            if ($Seen[$id] -ne $state) {
                Add-Line ("$(Get-Utc) run $id $(if ($Seen[$id]) { "$($Seen[$id]) -> " })$state (dispatched_at $dispatched, received_at $received)")
                $wasFinal = $Seen[$id] -in 'pass', 'fail', 'error', 'expired'
                $Seen[$id] = $state
                $dispatchedAt = if ($dispatched -ne '-') { [DateTime]::Parse($dispatched, $null, [Globalization.DateTimeStyles]::AdjustToUniversal) } else { [DateTime]::MinValue }
                if ($state -eq 'pass' -and -not $wasFinal -and $dispatchedAt -ge $After) { return $id }
                if ($state -in 'fail', 'error', 'expired' -and $dispatchedAt -ge $After) { throw "run $id is $state" }
            }
        }
        Start-Sleep -Seconds 10
    }
    throw "no new run of the plan was pass within $Minutes minutes"
}
function Wait-RunRecord([int]$Seconds = 1500) {
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    $record = Join-Path $script:W48State 'running.json'
    while ([DateTime]::UtcNow -lt $deadline) {
        if (Test-Path -LiteralPath $record) { return "$(Get-Utc) state\running.json is there: a run is in progress" }
        Start-Sleep -Seconds 5
    }
    throw "no run record appeared within $Seconds s"
}

$t = [System.Collections.Generic.List[string]]::new()
$t.Add("W7.3 (#82) and W7.4 (#83) Done-when, live, on this laptop (the Veeam server): the 0.1.0 package installed, a run pass; -Upgrade to 0.1.1 keeps the vault and the registration and the service polls again, the heartbeat and /workers show 0.1.1, a run pass; the rollback from previous\ and the upgrade again; Uninstall-RestoreProofWorker.ps1 leaves no service, no program folder, no Apps entry, no key-file entry, the Worker revoked in the Cloud, logs\ and the lab's folders left and named, the targets empty. $(Get-Utc), commit $commit, branch $(git -C $script:Repo branch --show-current)")
function Add-Line { param([Parameter(ValueFromPipeline)]$Line) process { foreach ($l in @($Line)) { $script:t.Add("$l"); Write-Host "$l" } } }
Add-Line ("Windows, PowerShell $($PSVersionTable.PSVersion), Docker Desktop, the Compose stack on 127.0.0.1; $((& $script:Worker --version) -join ' ') is the dev build the lab library reads the targets with")
$ok = $false
$installed = $false
$installToken = $null
$password = $null
$since = [DateTime]::UtcNow
$serviceSid = (& sc.exe showsid $script:W48Service | Where-Object { $_ -match 'SERVICE SID' }) -replace '.*: ', ''
$newDir = ''
# Not $oldPackage/$newPackage for the folders: a variable's name ignores case, and those are the zips.
$Uninstaller = Join-Path $script:Repo 'tools\worker-install\Uninstall-RestoreProofWorker.ps1'
try {
    # the lab's state aside
    Add-Line ("`n== the lab's vault and folders aside ==")
    Copy-Item -LiteralPath $VaultPath -Destination $VaultCopy
    Add-Line ("vault.bin copied to the run folder ($((Get-Item $VaultPath).Length) bytes, names: $(Get-VaultNames))")
    Add-Line (Move-LabFoldersOut)
    Add-Line ("-- icacls before`n$(Get-Acls (Get-AclPaths))")
    Add-Line (Get-ServiceLine)
    Add-Line (Get-Entry)
    Add-Line (Get-ProgramFiles)

    # the packages
    Add-Line ("`n== the packages ==")
    $oldDir = Unpack $OldPackage 'package-0.1.0'
    Add-Line ("old: $OldPackage (sha256 $((Get-FileHash $OldPackage -Algorithm SHA256).Hash.ToLower())), unpacked to ${oldPackage}: $((Get-ChildItem -LiteralPath $oldDir -File | Sort-Object Name | ForEach-Object Name) -join ', ')")
    if (-not $NewPackage) {
        $packaged = & pwsh -NoProfile -File $Packager -Out $RunDir -NoBuild 2>&1 | ForEach-Object { "$_" }
        if ($LASTEXITCODE -ne 0) { throw "package.ps1 failed: $($packaged -join ' ')" }
        Add-Line ($packaged)
        $NewPackage = ($packaged | Where-Object { $_ -like 'package: *' }) -replace '^package: ', ''
    }
    $newDir = Unpack $NewPackage 'package-0.1.1'
    Add-Line ("new: $NewPackage (sha256 $((Get-FileHash $NewPackage -Algorithm SHA256).Hash.ToLower())), unpacked to ${newDir}: $((Get-ChildItem -LiteralPath $newDir -File | Sort-Object Name | ForEach-Object Name) -join ', ')")
    $oldVersion = (& (Join-Path $oldDir 'rpworker.exe') --version | Select-Object -First 1).Trim()
    $newVersion = (& (Join-Path $newDir 'rpworker.exe') --version | Select-Object -First 1).Trim()
    Add-Line ("rpworker --version: old $oldVersion, new $newVersion")
    if ($oldVersion -ne '0.1.0' -or $newVersion -ne '0.1.1') { throw "not 0.1.0 and 0.1.1" }
    $Uninstaller = Join-Path $newDir 'Uninstall-RestoreProofWorker.ps1'
    $NewInstaller = Join-Path $newDir 'Install-RestoreProofWorker.ps1'
    $OldInstaller = Join-Path $oldDir 'Install-RestoreProofWorker.ps1'

    # 0
    Add-Line ("`n== 0. the Worker W7.2 left, taken away with the new uninstall script ==")
    if (Get-CimInstance Win32_Service -Filter "Name='$script:W48Service'") {
        $lines0 = @(& $Uninstaller -WaitMinutes 10 2>&1 | ForEach-Object { "$_" })
        Add-Line ("pwsh $Uninstaller -WaitMinutes 10")
        Add-Line ($lines0)
        if (Get-CimInstance Win32_Service -Filter "Name='$script:W48Service'") { throw 'the service is still installed after step 0' }
        Add-Line (Get-ServiceLine)
        Add-Line (Restore-Vault)
    } else {
        Add-Line ('no service installed: nothing to take away')
        foreach ($file in $ConfigPath, (Join-Path $Root 'veeam-rest.pem'), (Join-Path $Root 'cloud-ca.pem')) { if (Test-Path -LiteralPath $file) { Move-Item -LiteralPath $file (Join-Path $RunDir ('before-' + (Split-Path -Leaf $file))) -Force; Add-Line ("$file moved to the run folder") } }
        if (Test-Path -LiteralPath $ProgramDir) { throw "$ProgramDir is there with no service: remove it first" }
    }
    Add-Line ("-- icacls after step 0`n$(Get-Acls (Get-AclPaths))")
    Add-Line ("vault.bin names: $(Get-VaultNames)")

    # 1
    Add-Line ("`n== 1. the stack, re-migrated; Caddy's root; the MSP, the client, the token ==")
    Add-Line ((Invoke-Compose @('up', '-d', '--wait', '--build')).Text -split "`n" | Where-Object { $_ -match 'Healthy|Exited|Running|Started' })
    Add-Line ("alembic downgrade base: exit $((Invoke-Compose @('exec', '-T', 'api', 'alembic', 'downgrade', 'base')).Code)")
    Add-Line ("alembic upgrade head: exit $((Invoke-Compose @('exec', '-T', 'api', 'alembic', 'upgrade', 'head')).Code)")
    $copied = Invoke-Compose @('cp', 'proxy:/data/caddy/pki/authorities/local/root.crt', $CloudCa)
    if ($copied.Code -ne 0) { throw "Caddy's root couldn't be copied: $($copied.Text)" }
    $tenant = (Get-Content $LabProfile -Raw | ConvertFrom-Json).graph_tenant_id
    $msp = Invoke-Manage @('create-msp', '--name', 'w73-live')
    $mspId = Get-Value $msp.Text 'msp_id'
    $client = Invoke-Manage @('create-client', '--msp-id', $mspId, '--name', 'lab-tenant', '--tenant-id', $tenant)
    $clientId = Get-Value $client.Text 'client_id'
    if (-not $mspId -or -not $clientId) { throw "the MSP or the client wasn't made: $($msp.Text) $($client.Text)" }
    Add-Line ("create-msp: msp_id $mspId; create-client --tenant-id ${tenant}: client_id $clientId")
    $made = Invoke-Manage @('create-worker-token', '--msp-id', $mspId, '--label', 'w7.3-w7.4 live')
    $installToken = Get-Value $made.Text 'install_token'
    if (-not $installToken) { throw 'no install token' }
    Add-Line ("create-worker-token: exit $($made.Code); install_token (not shown; handed to the installer in memory)")
    $password = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(18))
    $user = Invoke-Manage @('create-user', '--msp-id', $mspId, '--email', 'w73@example.invalid', '--role', 'admin') $password
    Add-Line ("create-user --email w73@example.invalid --role admin (the password on stdin, never shown): exit $($user.Code)")

    # 2
    Add-Line ("`n== 2. the 0.1.0 package installed by its own installer ==")
    $since = [DateTime]::UtcNow
    $answers = @{ cloud_install_token = $installToken }
    $installLines = @(& $OldInstaller -Package $oldDir -CloudUrl 'https://localhost:8443' -CloudCaFile $CloudCa -WorkerName 'w73-live' -Answers $answers 2>&1 | ForEach-Object { "$_" })
    $answers = $null
    $installToken = $null
    $installed = $true
    Add-Line ("pwsh <0.1.0>\Install-RestoreProofWorker.ps1 -Package <0.1.0> -CloudUrl https://localhost:8443 -CloudCaFile <Caddy's root> -WorkerName w73-live -Answers <the install token, in memory>")
    Add-Line ($installLines)
    $workerLine = $installLines | Where-Object { $_ -match '^worker ([0-9a-f-]{36}) key ([0-9a-f]{64})$' } | Select-Object -First 1
    if (-not $workerLine) { throw 'the installer printed no worker line' }
    $workerId = [regex]::Match($workerLine, '^worker ([0-9a-f-]{36})').Groups[1].Value
    if (-not ($installLines | Where-Object { $_ -match '^change: rpworker service start \(started' })) { throw 'the installer did not start the service' }
    $vaultNamesBefore = Get-VaultNames
    $workerJsonBefore = [IO.File]::ReadAllText((Join-Path $script:W48State 'worker.json'))
    $configBefore = [IO.File]::ReadAllText($ConfigPath)
    Add-Line ("vault.bin names: $vaultNamesBefore")
    Add-Line ("state\worker.json: $workerJsonBefore")
    Add-Line (Get-ProgramFiles)
    Add-Line (Get-Entry)
    Add-Line ("-- icacls after the install`n$(Get-Acls (Get-AclPaths))")

    # 3
    Add-Line ("`n== 3. the connector, the plan, a run on 0.1.0 ==")
    Push-Location $CloudDir
    try { docker compose cp $LabProfile api:/tmp/w73-profile.json 2>&1 | Out-Null } finally { Pop-Location }
    $connector = Invoke-Manage @('create-connector', '--msp-id', $mspId, '--client-id', $clientId, '--worker-id', $workerId, '--profile-file', '/tmp/w73-profile.json')
    $connectorId = Get-Value $connector.Text 'connector_id'
    $plan = Invoke-Manage @('create-plan', '--msp-id', $mspId, '--client-id', $clientId, '--connector-id', $connectorId, '--mail', '10', '--sp', '10', '--od', '10', '--cron', '*/15 * * * *')
    $planId = Get-Value $plan.Text 'plan_id'
    if (-not $connectorId -or -not $planId) { throw "the connector or the plan wasn't made: $($connector.Text) $($plan.Text)" }
    Add-Line ("create-connector: connector_id $connectorId; create-plan --mail 10 --sp 10 --od 10 --cron '*/15 * * * *' (a run takes about six minutes; every five, the record would never be gone for the upgrade's wait): plan_id $planId, at $(Get-Utc)")
    $seen = @{}
    $run1 = Wait-Pass $planId $seen
    Add-Line ("worker ${workerId}: $(Invoke-Sql "SELECT 'name ' || name || ', version ' || coalesce(version, '-') || ', last_seen_at ' || coalesce(to_char(last_seen_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'), '-') || ' UTC' FROM worker WHERE id = '$workerId'")")
    Add-Line ("test_item of ${run1}: $(Invoke-Sql "SELECT count(*) || ' item(s), ' || count(*) FILTER (WHERE match) || ' matched; ' || string_agg(DISTINCT expected_kind, ', ') FROM test_item WHERE run_id = '$run1'")")

    # 4
    Add-Line ("`n== 4. the upgrade to 0.1.1, started while the plan's next run is in progress ==")
    Add-Line (Wait-RunRecord)
    $upgradeStarted = [DateTime]::UtcNow
    $upgradeLines = @(& $NewInstaller -Upgrade -Package $newDir -WaitMinutes 20 2>&1 | ForEach-Object { "$_" })
    $upgradeEnded = [DateTime]::UtcNow
    Add-Line ("pwsh <0.1.1>\Install-RestoreProofWorker.ps1 -Upgrade -Package <0.1.1> -WaitMinutes 20")
    Add-Line ("$($upgradeStarted.ToString('s'))Z to $($upgradeEnded.ToString('s'))Z ($([int]($upgradeEnded - $upgradeStarted).TotalSeconds) s wall clock)")
    Add-Line ($upgradeLines)
    if (-not ($upgradeLines | Where-Object { $_ -eq 'upgrade: 0.1.0 -> 0.1.1' })) { throw 'no upgrade line' }
    if (-not ($upgradeLines | Where-Object { $_ -match '^waiting: run .* in progress for 0 min \(the upgrade' })) { throw 'the wait for the run in progress was not seen' }
    if (-not ($upgradeLines | Where-Object { $_ -match '^change: the previous files \(0\.1\.0\) kept as ' })) { throw 'previous\ was not kept' }
    if (-not ($upgradeLines | Where-Object { $_ -match '^change: rpworker service start \(started' })) { throw 'the upgrade did not start the service' }
    if (-not ($upgradeLines | Where-Object { $_ -match '^upgraded 0\.1\.0 -> 0\.1\.1; the previous version is in ' })) { throw 'no upgraded line' }
    $vaultNamesAfter = Get-VaultNames
    $workerJsonAfter = [IO.File]::ReadAllText((Join-Path $script:W48State 'worker.json'))
    Add-Line ("vault.bin names after: $vaultNamesAfter $(if ($vaultNamesAfter -eq $vaultNamesBefore) { '(the same)' } else { '(CHANGED)' })")
    Add-Line ("state\worker.json after: $(if ($workerJsonAfter -ceq $workerJsonBefore) { 'byte for byte the same' } else { 'CHANGED: ' + $workerJsonAfter })")
    Add-Line ("config.json after: $(if ([IO.File]::ReadAllText($ConfigPath) -ceq $configBefore) { 'byte for byte the same' } else { 'CHANGED' })")
    if ($vaultNamesAfter -ne $vaultNamesBefore -or $workerJsonAfter -cne $workerJsonBefore) { throw 'the vault or worker.json changed' }
    Add-Line (Get-ProgramFiles)
    Add-Line (Get-Entry)
    Add-Line ("rpworker --version at ${ProgramDir}: $((& (Join-Path $ProgramDir 'rpworker.exe') --version) -join ' ')")
    Add-Line (Wait-Version $workerId '0.1.1')
    $login = Invoke-Curl @('-i', '-c', $Jar, '--data-urlencode', 'email=w73@example.invalid', '--data-urlencode', "password=$password", "$Pages/login")
    Add-Line ("POST /login as w73@example.invalid: $(Status-Of $login)")
    $page = Invoke-Curl @('-i', '-b', $Jar, "$Pages/workers")
    $pageText = Page-Text (Body-Of $page)
    $workerRow = ($pageText -split "`n") | Where-Object { $_ -match 'w73-live' } | Select-Object -First 1
    Add-Line ("GET /workers: $(Status-Of $page); the row: $workerRow")
    if ($workerRow -notmatch '0\.1\.1') { throw '/workers does not show 0.1.1' }
    Add-Line ("-- worker.log since the upgrade`n$(Get-W48Log -Since $upgradeStarted -Match 'service running|scheduler started|interrupted run|cleanup|service stopped|stop requested|hold|closed')")
    $run2 = Wait-Pass $planId $seen -After $upgradeEnded
    Add-Line ("run $run2 pass on 0.1.1 (dispatched after the upgrade ended at $($upgradeEnded.ToString('s'))Z): $(Invoke-Sql "SELECT 'dispatched_at ' || to_char(dispatched_at AT TIME ZONE 'UTC', 'YYYY-MM-DD""T""HH24:MI:SS""Z""') || ', worker.version ' || coalesce((SELECT version FROM worker WHERE id = worker_id), '-') FROM test_run WHERE id = '$run2'")")

    # 5
    Add-Line ("`n== 5. the rollback from previous\, then the upgrade again ==")
    $rollbackLines = @(& $NewInstaller -Upgrade -Package (Join-Path $ProgramDir 'previous') -WaitMinutes 20 2>&1 | ForEach-Object { "$_" })
    Add-Line ("pwsh <ProgramDir>\Install-RestoreProofWorker.ps1 -Upgrade -Package <ProgramDir>\previous -WaitMinutes 20")
    Add-Line ($rollbackLines)
    if (-not ($rollbackLines | Where-Object { $_ -eq 'upgrade: 0.1.1 -> 0.1.0 (a downgrade: a rollback)' })) { throw 'no rollback line' }
    Add-Line ("rpworker --version at ${ProgramDir}: $((& (Join-Path $ProgramDir 'rpworker.exe') --version) -join ' ')")
    Add-Line (Get-ProgramFiles)
    Add-Line (Wait-Version $workerId '0.1.0')
    $againLines = @(& $NewInstaller -Upgrade -Package $newDir -WaitMinutes 20 2>&1 | ForEach-Object { "$_" })
    Add-Line ("pwsh <0.1.1>\Install-RestoreProofWorker.ps1 -Upgrade -Package <0.1.1> -WaitMinutes 20 (again)")
    Add-Line ($againLines)
    if (-not ($againLines | Where-Object { $_ -eq 'upgrade: 0.1.0 -> 0.1.1' })) { throw 'no second upgrade line' }
    Add-Line (Wait-Version $workerId '0.1.1')
    Add-Line ("vault.bin names: $(Get-VaultNames) $(if ((Get-VaultNames) -eq $vaultNamesBefore) { '(the same)' } else { '(CHANGED)' })")

    # 6
    Add-Line ("`n== 6. the uninstall (without -Full) ==")
    New-Item -ItemType Directory -Force $Kept | Out-Null
    foreach ($folder in @(Get-ChildItem -LiteralPath (Join-Path $Root 'sent') -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^[0-9a-f-]{36}$' })) {
        Move-Item $folder.FullName (Join-Path $Kept $folder.Name) -Force
        Add-Line ("sent folder kept first (the uninstall overwrites sent\): $(Join-Path $Kept $folder.Name)")
    }
    $uninstallStarted = [DateTime]::UtcNow
    $uninstallLines = @(& $Uninstaller -WaitMinutes 20 2>&1 | ForEach-Object { "$_" })
    $uninstallEnded = [DateTime]::UtcNow
    Add-Line ("pwsh <ProgramDir>\Uninstall-RestoreProofWorker.ps1 -WaitMinutes 20")
    Add-Line ("$($uninstallStarted.ToString('s'))Z to $($uninstallEnded.ToString('s'))Z ($([int]($uninstallEnded - $uninstallStarted).TotalSeconds) s wall clock)")
    Add-Line ($uninstallLines)
    $installed = $false
    if (-not ($uninstallLines | Where-Object { $_ -match '^change: rpworker cloud revoke \(revoked worker ' })) { throw 'the Worker was not revoked' }
    if (-not ($uninstallLines | Where-Object { $_ -match '^change: rpworker service uninstall \(uninstalled' })) { throw 'the service was not uninstalled' }
    if (-not ($uninstallLines | Where-Object { $_ -match "^note: .*left: not the installer's" })) { throw "nothing of the lab's was named as left" }
    Add-Line (Get-ServiceLine)
    if (Get-CimInstance Win32_Service -Filter "Name='$script:W48Service'") { throw 'the service is still installed' }
    Add-Line (Get-ProgramFiles)
    if (Test-Path -LiteralPath $ProgramDir) { throw "$ProgramDir is still there" }
    Add-Line (Get-Entry)
    if (Test-Path -LiteralPath $EntryKey) { throw 'the Apps entry is still there' }
    Add-Line ("under ${Root}: $((Get-ChildItem -LiteralPath $Root -Force | Sort-Object Name | ForEach-Object { $_.Name + $(if ($_.PSIsContainer) { '\' }) }) -join ', ')")
    foreach ($name in 'vault.bin', 'config.json', 'veeam-rest.pem', 'cloud-ca.pem', 'state', 'runs', 'outbox', 'sent', 'failed') { if (Test-Path -LiteralPath (Join-Path $Root $name)) { throw "$name is still under the root" } }
    if (-not (Test-Path -LiteralPath (Join-Path $Root 'logs\worker.log'))) { throw 'the log is gone' }
    Add-Line ("-- icacls after the uninstall (the root's ACL stays; the key file without the account's entry)`n$(Get-Acls (@($Root) + @(Get-W48KeyFile | ForEach-Object File)))")
    foreach ($key in @(Get-W48KeyFile)) { if ((& icacls.exe $key.File 2>&1) -match [regex]::Escape($serviceSid) -or (& icacls.exe $key.File 2>&1) -match 'NT SERVICE\\RestoreProof') { throw "the key file still holds the account's entry" } }
    Add-Line ("worker ${workerId}: $(Invoke-Sql "SELECT 'name ' || name || ', version ' || coalesce(version, '-') || ', revoked_at ' || coalesce(to_char(revoked_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'), 'NULL') || ' UTC' FROM worker WHERE id = '$workerId'")")
    if ((Invoke-Sql "SELECT revoked_at IS NOT NULL FROM worker WHERE id = '$workerId'") -ne 't') { throw 'the row is not revoked' }
    Add-Line ("audit_log: $(Invoke-Sql "SELECT string_agg(action || ' ' || target || ' user ' || coalesce(user_id::text, 'null') || ' ip ' || coalesce(ip::text, 'null'), '; ' ORDER BY at) FROM audit_log WHERE action = 'worker.revoke'")")
    Add-Line (Restore-Vault)
    $after = Get-W48Targets
    Add-Line ("-- the restore targets after`n$after")
    if ($after -notmatch '(?m)^0 item\(s\) in the three restore targets') { throw 'the restore targets are not empty' }
    # The library's cached public key file is an older lab key's: written again from the vault's.
    New-Item -ItemType Directory -Force $script:W48Dir | Out-Null
    Remove-Item -LiteralPath $W48PublicKey -Force -ErrorAction SilentlyContinue
    $verified = Test-W48Folder (Join-Path $Kept $run2)
    Add-Line ("-- both verifiers on the kept sent folder of $run2 (the public key from the vault's signing key)`n$verified")
    if ($verified -notmatch '(?m)^verified ' -or $verified -notmatch 'verify_bundle.py \(exit code 0\)') { throw 'the kept sent folder did not verify' }
    $ok = $true
} catch {
    Add-Line ("`n!! FAILED: $($_.Exception.Message)")
} finally {
    $installToken = $null
    $password = $null
    Add-Line ("`n== taken away, and the lab's state put back ==")
    try {
        if ($installed -or (Get-CimInstance Win32_Service -Filter "Name='$script:W48Service'")) {
            Add-Line ('a step failed with the Worker installed: the uninstall script, then the library''s removal of what it left')
            if (Test-Path -LiteralPath $Uninstaller) { Add-Line (@(& $Uninstaller -WaitMinutes 10 2>&1 | ForEach-Object { "$_" })) }
            if (Get-CimInstance Win32_Service -Filter "Name='$script:W48Service'") { Add-Line (Remove-W48Service) }
            foreach ($key in @(Get-W48KeyFile)) { icacls $key.File /remove:g "*$serviceSid" /Q | Out-Null }
            if (Test-Path -LiteralPath $ProgramDir) { Remove-Item -LiteralPath $ProgramDir -Recurse -Force; Add-Line ("$ProgramDir removed") }
            if (Test-Path -LiteralPath $EntryKey) { Remove-Item -LiteralPath $EntryKey -Recurse -Force; Add-Line ('the Apps entry removed') }
            foreach ($name in 'config.json', 'veeam-rest.pem', 'cloud-ca.pem') { $f = Join-Path $Root $name; if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force } }
            foreach ($name in 'state', 'runs', 'outbox', 'sent', 'failed') { $f = Join-Path $Root $name; if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Recurse -Force } }
        }
        Add-Line (Restore-Vault)
        if (Test-Path -LiteralPath $VaultPath) {
            foreach ($name in 'cloud_api_token', 'cloud_install_token') { $t.AddRange([string[]]@((Invoke-W48 @('vault', 'remove', $name)) -split "`n" | Where-Object { $_ -match '^(removed|' + $name + ')' })) }
        }
        Add-Line (Move-LabFoldersBack)
        Add-Line ("vault.bin names at the end: $(Get-VaultNames)")
        Add-Line ("-- icacls at the end`n$(Get-Acls (Get-AclPaths))")
        Add-Line (Get-ServiceLine)
    } catch { Add-Line ("!! the cleanup failed: $($_.Exception.Message) at $($_.ScriptStackTrace); put back by hand: the vault from $VaultCopy, the folders from $KeptFolders") }
    if (Test-Path -LiteralPath $Jar) { Remove-Item -LiteralPath $Jar -Force }
    $text = ($t -join "`n") -replace '[0-9a-f]{32}_[0-9a-f-]{36}', '<Veeam key file>'
    $runFile = Join-Path $RunDir 'w7.3-w7.4-done-when.txt'
    [IO.File]::WriteAllText($runFile, $text.Replace("`r`n", "`n") + "`n", [Text.UTF8Encoding]::new($false))
    "run text: $runFile"
}
if (-not $ok) { Write-Error 'the Done-when did not hold; nothing copied into the repository'; exit 1 }
if (-not $NoCopy) { Save-W48Evidence 'w7.3-w7.4-done-when.txt' $text }

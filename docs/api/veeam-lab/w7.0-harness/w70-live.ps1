# W7.0 (#189): the live Done-when (docs/decisions.md 2026-10-16, "W7.0 (#189)", point 11 (A)):
# "On a tenant that has never seen RestoreProof ..., the client's admin runs the script once; the
# grant check passes; the printed profile is accepted by manage.py create-connector; a Worker with
# that profile and certificate makes a pass run; and running the script a second time changes
# nothing." The lab tenant, after w70-teardown.ps1 and its recycle-bin step. Run from an ELEVATED
# PowerShell 7 (the vault and the W5.1 harness need it), Docker Desktop running, no RestoreProof
# service installed, the vault holding the Worker's Graph certificate and no Cloud token:
#
#   pwsh -File docs\api\veeam-lab\w7.0-harness\w70-live.ps1
#
# The setup script signs in twice per run (Graph, then Exchange Online): sign in as the lab's
# global admin each time. In order:
#   1. Initialize-RestoreProofTenant.ps1 on the lab tenant (-Worker: the vault's certificate):
#      "grants: ok", the profile written to the run folder
#   2. that profile becomes the lab's (%LOCALAPPDATA%\RestoreProof\lab\lab-profile.json), and the
#      lab config's client keys are set from it (the old files kept in the run folder)
#   2b. rpworker graph list every 5 minutes until it reads all three targets (Exchange applies the
#      mail role in 30 minutes to 2 hours), at most 2 hours
#   3. the W5.1 harness, -NoCopy: create-connector on that profile, the service's run, pass
#   4. Initialize-RestoreProofTenant.ps1 again: "changes: 0" and the same profile bytes
# Only when every step held, and no secret, token or key survives in the text, is it copied to
# docs\api\veeam-lab\w7.0-done-when.txt, the copy last. Then: the new IDs into lab/tenant.md,
# lab/seeder/tenant.py and the lab's Entra scripts, and `python -m seeder check-worker-app`.
#Requires -Version 7.4
param([string]$Worker = 'C:\restoreproof\worker\build\dev\rpworker.exe')
. (Join-Path $PSScriptRoot '..\w4.8-harness\w48-run.ps1')

$Setup = Join-Path $script:Repo 'tools\tenant-setup\Initialize-RestoreProofTenant.ps1'
$W51 = Join-Path $script:Repo 'docs\api\veeam-lab\w5.1-harness\w51-live.ps1'
$RunDir = Join-Path $env:LOCALAPPDATA ("RestoreProof\lab\w7.0-" + (Get-Date -Format 'yyyyMMddTHHmmss'))
$LabProfile = Join-Path $env:LOCALAPPDATA 'RestoreProof\lab\lab-profile.json'
$Lab = @{
    TenantId = 'bcd6bd1a-ea42-489d-aa28-2c19a44ad146'
    SiteUrl = 'https://restoreprooflab.sharepoint.com/sites/RestoreTest'
    OneDriveUser = 'alice@RestoreProofLab.onmicrosoft.com'
}
$ClientKeys = @('veeam_org_name', 'graph_tenant_id', 'graph_client_id', 'test_mailbox', 'test_site_id', 'test_library_id', 'test_onedrive_drive_id', 'test_onedrive_folder_id')
function Get-Utc { [DateTime]::UtcNow.ToString('s') + 'Z' }

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'run from an elevated shell'; exit 64
}
New-Item -ItemType Directory -Force $RunDir | Out-Null

function Invoke-Setup([string]$Name) {
    $profile = Join-Path $RunDir "$Name-profile.json"
    $out = & pwsh -NoProfile -File $Setup -TenantId $Lab.TenantId -SiteUrl $Lab.SiteUrl -OneDriveUser $Lab.OneDriveUser -Worker $Worker -ProfileFile $profile 2>&1
    [pscustomobject]@{ Code = $LASTEXITCODE; Text = (($out | ForEach-Object { "$_" }) -join "`n"); Profile = $profile }
}

$t = @("W7.0 (#189) Done-when, live: the client tenant setup script on the lab tenant after w70-teardown.ps1; its profile through create-connector and a service run; the script again. $(Get-Utc), commit $(git -C $script:Repo rev-parse --short HEAD), branch $(git -C $script:Repo branch --show-current)")
$t += "Windows, PowerShell $($PSVersionTable.PSVersion); $((& $Worker --version) -join ' ')"
$ok = $false
try {
    # 1
    $t += "`n== 1. the setup script, first run =="
    $first = Invoke-Setup 'first'
    $t += $first.Text
    if ($first.Code -ne 0 -or $first.Text -notmatch '(?m)^grants: ok$' -or -not (Test-Path $first.Profile)) { throw 'the first run did not end with grants: ok and a profile' }
    $t += "exit $($first.Code); changes: $([regex]::Match($first.Text, '(?m)^changes: (\d+)').Groups[1].Value)"

    # 2
    $t += "`n== 2. the profile becomes the lab's; the lab config's client keys set from it =="
    Copy-Item $LabProfile (Join-Path $RunDir 'lab-profile.before.json') -ErrorAction SilentlyContinue
    Copy-Item $script:LabConfig (Join-Path $RunDir 'config.before.json')
    Copy-Item $first.Profile $LabProfile -Force
    $profileValues = Get-Content $first.Profile -Raw | ConvertFrom-Json -AsHashtable
    $config = Get-Content $script:LabConfig -Raw | ConvertFrom-Json -AsHashtable
    foreach ($key in $ClientKeys) { $config[$key] = $profileValues[$key] }
    [IO.File]::WriteAllText($script:LabConfig, (ConvertTo-Json $config -Depth 10), [Text.UTF8Encoding]::new($false))
    & $Worker config check --config $script:LabConfig *> $null
    if ($LASTEXITCODE -ne 0) { throw 'the lab config with the new client keys does not pass rpworker config check' }
    $t += "lab-profile.json and the lab config's eight client keys now name: client $($profileValues.graph_client_id), library $($profileValues.test_library_id), folder $($profileValues.test_onedrive_folder_id)"

    # 2b. Exchange applies a new mail role in 30 minutes to 2 hours (the second live run's graph
    # list was refused the Inbox a minute after the script): the run starts once the Worker reads
    # all three targets, asked every 5 minutes for 2 hours.
    $t += "`n== 2b. waiting until the Worker reads the three targets (Exchange applies the mail role in 30 minutes to 2 hours) =="
    $readable = $false
    for ($attempt = 1; $attempt -le 24; $attempt++) {
        $listing = & $Worker graph list --config $script:LabConfig 2>&1 | ForEach-Object { "$_" }
        $code = $LASTEXITCODE
        $t += "$(Get-Utc) attempt ${attempt}: graph list exit $code"
        Write-Host "$(Get-Utc) attempt ${attempt}: graph list exit $code"
        if ($code -eq 0) { $readable = $true; $t += ($listing -join "`n"); break }
        if ($attempt -lt 24) { Start-Sleep -Seconds 300 }
    }
    if (-not $readable) { throw 'the Worker could not read the three targets within 2 hours' }

    # 3
    $t += "`n== 3. the W5.1 harness on that profile: create-connector, the service's run =="
    $w51 = & pwsh -NoProfile -File $W51 -NoCopy 2>&1 | ForEach-Object { "$_" }
    $w51Code = $LASTEXITCODE
    $runText = ($w51 | Where-Object { $_ -like 'run text: *' } | Select-Object -Last 1) -replace '^run text: ', ''
    if ($runText -and (Test-Path $runText)) { $t += (Get-Content $runText -Raw).TrimEnd("`n") }
    else { $t += ($w51 -join "`n") }
    if ($w51Code -ne 0) { throw "the W5.1 harness failed (exit $w51Code)" }

    # 4
    $t += "`n== 4. the setup script, second run =="
    $second = Invoke-Setup 'second'
    $t += $second.Text
    if ($second.Code -ne 0 -or $second.Text -notmatch '(?m)^changes: 0$' -or $second.Text -match '(?m)^change: ') { throw 'the second run changed something' }
    $same = (Get-FileHash $first.Profile).Hash -eq (Get-FileHash $second.Profile).Hash
    $t += "the second run's profile is the first's, byte for byte: $same"
    if (-not $same) { throw 'the second run printed another profile' }
    $ok = $true
}
catch {
    $t += "`nSTOPPED: $($_.Exception.Message)"
}
finally {
    $text = ($t -join "`n")
    [IO.File]::WriteAllText((Join-Path $RunDir 'w7.0-done-when.txt'), $text.Replace("`r`n", "`n") + "`n", [Text.UTF8Encoding]::new($false))
    "run text: $(Join-Path $RunDir 'w7.0-done-when.txt')"
}
if (-not $ok) { Write-Error 'the Done-when did not hold; nothing copied into the repository'; exit 1 }
Save-W48Evidence 'w7.0-done-when.txt' $text
'Next: the new IDs into lab/tenant.md, lab/seeder/tenant.py and lab/entra/*.ps1, then from lab\: uv run python -m seeder check-worker-app'

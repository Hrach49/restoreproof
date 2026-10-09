# W4.10 (#133): the live Done-when on the lab machine, in one go, over the W4.8 harness. With
# the real vault and a config copy without its eight client keys (config-no-client.json beside
# the lab config, outside the repo) and the lab's profile file (lab-profile.json, the eight
# keys as a restoreproof.client-profile.v1 object, written from the lab config):
#   (a) `config check` on the copy prints (not set) for the eight; `graph list` on the copy
#       exits 1 with the no-client-keys line; `client check --profile-file lab-profile.json`
#       prints the lab's three targets, exit 0, reading no config; a copy of the profile with
#       test_mailbox set to alice and one with graph_tenant_id in braces each exit 1 naming the
#       key;
#   (b) `rpworker test --evidence --outbox --profile-file lab-profile.json` on the copy
#       restores and verifies as before, the queued result's client the file's, client_id null;
#   (c) a short service run through the W4.8 harness, its config copy without the eight keys,
#       one job carrying the profile: to sent\, the result's client_id the job's, verified;
#   (d) the teardown: nothing installed, the folders kept outside the repo.
# Each step's text is saved as evidence (docs/api/veeam-lab/w4.10-<n>-*.txt) through
# Save-W48Evidence, which refuses a text holding a secret or a key shape.
# Run from an elevated PowerShell 7 on the lab machine, with nothing installed and no session of
# rp-veeam Working:
#
#   pwsh -File docs\api\veeam-lab\w4.10-harness\w410-live.ps1 [-Prefix w410] [-Steps a,b,c,d]
param([string]$Prefix = 'w410', [string[]]$Steps = @('a', 'b', 'c', 'd'))
. (Join-Path $PSScriptRoot '..\w4.8-harness\w48-run.ps1')

$script:W410Dir = Join-Path $script:W48Root 'w410'
$W410Runs = Join-Path $script:W410Dir 'runs'
$W410Box = Join-Path $script:W410Dir 'box'
$W410Kept = Join-Path $script:W410Dir 'sent-by-service'
$Lab = Join-Path $env:LOCALAPPDATA 'RestoreProof\lab'
$NoClientConfig = Join-Path $Lab 'config-no-client.json'
$LabProfile = Join-Path $Lab 'lab-profile.json'
$BadMailbox = Join-Path $Lab 'lab-profile-bad-mailbox.json'
$Braces = Join-Path $Lab 'lab-profile-braces.json'
$Manifest = Join-Path $script:Repo 'lab\seed-manifest.json'
$commit = git -C $script:Repo rev-parse --short HEAD
function Get-Utc { [DateTime]::UtcNow.ToString('s') + 'Z' }

# The result's client object of a run folder, as text.
function Get-W410Client([string]$Folder) {
    $result = Get-Content (Join-Path $Folder 'result.json') -Raw | ConvertFrom-Json
    "result.json client: " + ($result.client | ConvertTo-Json -Compress)
}

foreach ($file in @($NoClientConfig, $LabProfile, $BadMailbox, $Braces)) {
    if (-not (Test-Path $file)) { throw "$file is missing: write it as docs/testing.md says (Client check by hand)" }
}
$noClient = Get-Content $NoClientConfig -Raw | ConvertFrom-Json -AsHashtable
foreach ($key in 'veeam_org_name', 'graph_tenant_id', 'graph_client_id', 'test_mailbox', 'test_site_id', 'test_library_id', 'test_onedrive_drive_id', 'test_onedrive_folder_id') {
    if ($noClient.ContainsKey($key)) { throw "$NoClientConfig still holds $key" }
}

if ($Steps -contains 'a') {
    $t = @("W4.10 (#133) live Done-when, step (a): the commands at a prompt on a config without client keys, and client check on the lab's profile. $(Get-Utc), commit $commit")
    $t += "`n-- the config copy (no client keys; the two URLs and Veeam's certificate alone)`n$(Get-Content $NoClientConfig -Raw)"
    $t += "`n$(Invoke-W48 @('config', 'check', '--config', $NoClientConfig))"
    $t += "`n$(Invoke-W48 @('graph', 'list', '--config', $NoClientConfig))"
    $t += "`n-- the profile file: the eight keys of lab/tenant.md's restore targets and the Worker app, IDs only`n$(Get-Content $LabProfile -Raw)"
    $t += "`n$(Invoke-W48 @('client', 'check', '--profile-file', $LabProfile))"
    $t += "`n-- the same, through the lab config's own targets for comparison`n$(Get-W48Targets)"
    $t += "`n-- a profile that breaks the schema: test_mailbox another user`n$(Invoke-W48 @('client', 'check', '--profile-file', $BadMailbox))"
    $t += "`n-- a profile that breaks the schema: graph_tenant_id in braces`n$(Invoke-W48 @('client', 'check', '--profile-file', $Braces))"
    $t += "`n-- a profile file that isn't there`n$(Invoke-W48 @('client', 'check', '--profile-file', (Join-Path $Lab 'no-such-profile.json')))"
    $t += "`n-- veeam list on the copy: every organisation, none marked`n$(Invoke-W48 @('veeam', 'list', '--config', $NoClientConfig))"
    Save-W48Evidence 'w4.10-1-client-check.txt' ($t -join "`n")
}

if ($Steps -contains 'b') {
    # The W4.8 folder too: Test-W48Folder keeps the public key there.
    New-Item -ItemType Directory -Force $script:W410Dir, $script:W48Dir | Out-Null
    $t = @("W4.10 (#133) live Done-when, step (b): rpworker test --evidence --outbox --profile-file on the config copy without client keys. $(Get-Utc), commit $commit")
    $t += "`n-- Veeam before: $(Get-W48Sessions)"
    $t += "`n-- the three restore targets before`n$(Get-W48Targets)"
    $t += "`n$(Invoke-W48 @('test', '--mail', '2', '--sp', '1', '--od', '1', '--run-id', "$Prefix-1", '--config', $NoClientConfig, '--manifest', $Manifest, '--profile-file', $LabProfile, '--evidence', $W410Runs, '--outbox', $W410Box))"
    $queued = Join-Path $W410Box "outbox\$Prefix-1"
    $t += "`n-- the queued folder`n$(Test-W48Folder $queued)"
    $t += "`n-- $(Get-W410Client $queued)"
    $t += "`n-- the three restore targets after`n$(Get-W48Targets)"
    $t += "`n-- Veeam after: $(Get-W48Sessions)"
    Save-W48Evidence 'w4.10-2-test-profile-file.txt' ($t -join "`n")
}

if ($Steps -contains 'c') {
    $t = @("W4.10 (#133) live Done-when, step (c): a short service run through the W4.8 harness, the service's config without client keys, one job carrying the profile. $(Get-Utc), commit $commit")
    $t += "`n-- the config copy`n$(Initialize-W48Harness)"
    # The service's config holds no client key: each job carries its client.
    $config = Get-Content $W48Config -Raw | ConvertFrom-Json -AsHashtable
    foreach ($key in 'veeam_org_name', 'graph_tenant_id', 'graph_client_id', 'test_mailbox', 'test_site_id', 'test_library_id', 'test_onedrive_drive_id', 'test_onedrive_folder_id') { $config.Remove($key) }
    [IO.File]::WriteAllText($W48Config, ($config | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
    $t += "`n-- the eight client keys taken out of the service's config copy`n$(Invoke-W48 @('config', 'check', '--config', $W48Config))"
    $t += "`n-- the stub Cloud`n$(Start-W48Stub)"
    $t += "`n$(Invoke-W48 @('service', 'install', '--config', $W48Config))"
    try {
    $t += "`n-- the grants`n$(Grant-W48Account)"
    $since = [DateTime]::UtcNow
    $t += "`n$(Invoke-W48 @('service', 'start'))"
    $job = New-W48Job "$Prefix-2" 1 1 1
    $job['client'] = Get-Content $LabProfile -Raw | ConvertFrom-Json -AsHashtable
    $t += "`n$(Set-W48Jobs @($job))"
    $t += "`n-- taken: $(Wait-W48Log "run $Prefix-2: starting" $since 120)"
    $t += "`n-- the record while the run goes`n$(Get-W48Record)"
    $t += "`n-- ended: $(Wait-W48Log "run $Prefix-2: ended" $since 900)"
    $t += "`n-- sent: $(Wait-W48Log "sent $Prefix-2" $since 120)"
    Start-Sleep 5
    $t += "`n$(Invoke-W48 @('service', 'stop'))"
    $t += "`n-- worker.log from the start on`n$(Get-W48Log -Since $since)"
    $t += "`n`n-- afterwards`n$(Get-W48Record)`n$(Get-W48Folders)"
    $t += "`n-- the stub's lines`n$((Get-W48StubLog) -join "`n")"
    $sent = Join-Path $script:W48Root "sent\$Prefix-2"
    $t += "`n-- the sent folder`n$(Test-W48Folder $sent)"
    $t += "`n-- $(Get-W410Client $sent)"
    $t += "`n-- Veeam after: $(Get-W48Sessions)"
    } finally {
        # The W4.10 review's finding 15: the grants and the service go whatever happened above.
        $t += "`n-- the grants taken away, the service uninstalled`n$(Revoke-W48Account)`n$(Invoke-W48 @('service', 'uninstall'))"
        Save-W48Evidence 'w4.10-3-service-run.txt' ($t -join "`n")
    }
}

if ($Steps -contains 'd') {
    $t = @("W4.10 (#133) live Done-when, step (d): the teardown. $(Get-Utc), commit $commit")
    New-Item -ItemType Directory -Force $W410Kept | Out-Null
    $sent = Join-Path $script:W48Root "sent\$Prefix-2"
    if (Test-Path $sent) { Move-Item $sent (Join-Path $W410Kept "$Prefix-2") -Force; $t += "`n-- sent\$Prefix-2 moved to $W410Kept" }
    $t += "`n$(Remove-W48Harness)"
    $t += "`n-- sc query: $((sc.exe query $script:W48Service 2>&1) -join ' ')"
    $t += "`n-- $(Get-W48Folders)"
    $t += "`n-- Veeam: $(Get-W48Sessions)"
    $t += "`n-- the three restore targets after`n$(Get-W48Targets)"
    $t += "`n-- kept outside the repo: $script:W410Dir, $Lab (the profile files and the config copy)"
    Save-W48Evidence 'w4.10-4-teardown.txt' ($t -join "`n")
}

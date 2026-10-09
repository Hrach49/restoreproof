# W4.11 (#134): the live Done-when on the lab machine, in one go, over the W4.8 and W4.10
# harnesses. With the real vault, the config copy without its eight client keys
# (config-no-client.json beside the lab config, outside the repo, as W4.10 left it), the lab's
# profile file (lab-profile.json) and a copy of it with a made-up graph_tenant_id
# (lab-profile-other-tenant.json):
#   (a) `rpworker test --evidence --outbox --profile-file lab-profile-other-tenant.json`: the run
#       line, then `client error: client mismatch: ...`, `status error client_mismatch`, exit 4,
#       no `cleanup before` line, no session of rp-veeam opened, the folder signed, timestamped
#       and queued, both verifiers `verified`, the result's scope and resolved null;
#   (b) the same on lab-profile.json: `client ok: ...`, pass, the result's scope `same_tenant`
#       and resolved the lab's organisation and the three RestoreTargets' names and URLs;
#   (c) the service on the config copy with three jobs: one of connector type other_backup
#       (closed as error connector_unknown), one with the other-tenant profile (error
#       client_mismatch), one with the lab's (pass), all three to sent\ and verified;
#   (d) the teardown: nothing installed, the folders kept outside the repo.
# Each step's text is saved as evidence (docs/api/veeam-lab/w4.11-<n>-*.txt) through
# Save-W48Evidence, which refuses a text holding a secret or a key shape.
# Run from an elevated PowerShell 7 on the lab machine, with nothing installed and no session of
# rp-veeam Working:
#
#   pwsh -File docs\api\veeam-lab\w4.11-harness\w411-live.ps1 [-Prefix w411] [-Steps a,b,c,d]
param([string]$Prefix = 'w411', [string[]]$Steps = @('a', 'b', 'c', 'd'))
. (Join-Path $PSScriptRoot '..\w4.8-harness\w48-run.ps1')

$script:W411Dir = Join-Path $script:W48Root 'w411'
$W411Runs = Join-Path $script:W411Dir 'runs'
$W411Box = Join-Path $script:W411Dir 'box'
$W411Kept = Join-Path $script:W411Dir 'sent-by-service'
$Lab = Join-Path $env:LOCALAPPDATA 'RestoreProof\lab'
$NoClientConfig = Join-Path $Lab 'config-no-client.json'
$LabProfile = Join-Path $Lab 'lab-profile.json'
$OtherTenant = Join-Path $Lab 'lab-profile-other-tenant.json'
$Manifest = Join-Path $script:Repo 'lab\seed-manifest.json'
$commit = git -C $script:Repo rev-parse --short HEAD
function Get-Utc { [DateTime]::UtcNow.ToString('s') + 'Z' }

# The result's client object of a run folder, as text.
function Get-W411Client([string]$Folder) {
    $result = Get-Content (Join-Path $Folder 'result.json') -Raw | ConvertFrom-Json
    $status = $result.status.status
    if ($result.status.PSObject.Properties['error_code']) { $status += ' ' + $result.status.error_code }
    "result.json status: $status`nresult.json client: " + ($result.client | ConvertTo-Json -Compress -Depth 5) + "`nresult.json connector: " + ($result.connector | ConvertTo-Json -Compress)
}

foreach ($file in @($NoClientConfig, $LabProfile)) {
    if (-not (Test-Path $file)) { throw "$file is missing: write it as docs/testing.md says (Client check by hand)" }
}
if (-not (Test-Path $OtherTenant)) {
    # The lab's profile with a made-up tenant: everything else as it is.
    $other = Get-Content $LabProfile -Raw | ConvertFrom-Json -AsHashtable
    $other['graph_tenant_id'] = '11111111-2222-3333-4444-555555555555'
    [IO.File]::WriteAllText($OtherTenant, ($other | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
}

if ($Steps -contains 'a') {
    New-Item -ItemType Directory -Force $script:W411Dir, $script:W48Dir | Out-Null
    $t = @("W4.11 (#134) live Done-when, step (a): rpworker test --evidence --outbox --profile-file on a profile whose tenant isn't the organisation's msid. $(Get-Utc), commit $commit")
    $t += "`n-- the profile file: the lab's with a made-up graph_tenant_id`n$(Get-Content $OtherTenant -Raw)"
    $t += "`n-- Veeam before: $(Get-W48Sessions)"
    $t += "`n$(Invoke-W48 @('test', '--mail', '2', '--sp', '1', '--od', '1', '--run-id', "$Prefix-1", '--config', $NoClientConfig, '--manifest', $Manifest, '--profile-file', $OtherTenant, '--evidence', $W411Runs, '--outbox', $W411Box))"
    $queued = Join-Path $W411Box "outbox\$Prefix-1"
    $t += "`n-- the queued folder`n$(Test-W48Folder $queued)"
    $t += "`n-- $(Get-W411Client $queued)"
    $t += "`n-- Veeam after (no session opened by the run): $(Get-W48Sessions)"
    $t += "`n-- the three restore targets after`n$(Get-W48Targets)"
    Save-W48Evidence 'w4.11-1-client-mismatch.txt' ($t -join "`n")
}

if ($Steps -contains 'b') {
    New-Item -ItemType Directory -Force $script:W411Dir, $script:W48Dir | Out-Null
    $t = @("W4.11 (#134) live Done-when, step (b): the same on the lab's own profile: the client check passes, the result says scope same_tenant and what resolved. $(Get-Utc), commit $commit")
    $t += "`n-- Veeam before: $(Get-W48Sessions)"
    $t += "`n$(Invoke-W48 @('test', '--mail', '2', '--sp', '1', '--od', '1', '--run-id', "$Prefix-2", '--config', $NoClientConfig, '--manifest', $Manifest, '--profile-file', $LabProfile, '--evidence', $W411Runs, '--outbox', $W411Box))"
    $queued = Join-Path $W411Box "outbox\$Prefix-2"
    $t += "`n-- the queued folder`n$(Test-W48Folder $queued)"
    $t += "`n-- $(Get-W411Client $queued)"
    $t += "`n-- the three restore targets after`n$(Get-W48Targets)"
    $t += "`n-- Veeam after: $(Get-W48Sessions)"
    Save-W48Evidence 'w4.11-2-client-ok.txt' ($t -join "`n")
}

if ($Steps -contains 'c') {
    $t = @("W4.11 (#134) live Done-when, step (c): the service on the config copy without client keys, three jobs: a connector this Worker lacks, a profile of another tenant, the lab's profile. $(Get-Utc), commit $commit")
    $t += "`n-- the config copy`n$(Initialize-W48Harness)"
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
        $labJson = Get-Content $LabProfile -Raw | ConvertFrom-Json -AsHashtable
        $other = Get-Content $OtherTenant -Raw | ConvertFrom-Json -AsHashtable
        $done = $false
        $unknown = New-W48Job "$Prefix-3" 1 1 1
        $unknown['client'] = $labJson
        $unknown['connector'] = @{ type = 'other_backup' }
        $mismatch = New-W48Job "$Prefix-4" 1 1 1
        $mismatch['client'] = $other
        $good = New-W48Job "$Prefix-5" 1 1 1
        $good['client'] = $labJson
        $t += "`n$(Set-W48Jobs @($unknown, $mismatch, $good))"
        $t += "`n-- the unknown connector reported: $(Wait-W48Log "job $Prefix-3: connector type other_backup isn't one this Worker has" $since 120)"
        $t += "`n-- the mismatch ended: $(Wait-W48Log "run $Prefix-4: ended error client_mismatch" $since 300)"
        $t += "`n-- the good one taken: $(Wait-W48Log "run $Prefix-5: starting" $since 300)"
        $t += "`n-- the record while the run goes`n$(Get-W48Record)"
        $t += "`n-- ended: $(Wait-W48Log "run $Prefix-5: ended" $since 900)"
        $t += "`n-- sent: $(Wait-W48Log "sent $Prefix-5" $since 120)"
        Start-Sleep 5
        $t += "`n$(Invoke-W48 @('service', 'stop'))"
        $t += "`n-- worker.log from the start on`n$(Get-W48Log -Since $since)"
        $t += "`n`n-- afterwards`n$(Get-W48Record)`n$(Get-W48Folders)"
        $t += "`n-- the stub's lines`n$((Get-W48StubLog) -join "`n")"
        foreach ($n in 3, 4, 5) {
            $sent = Join-Path $script:W48Root "sent\$Prefix-$n"
            $t += "`n-- the sent folder $Prefix-$n`n$(Test-W48Folder $sent)"
            $t += "`n-- $(Get-W411Client $sent)"
        }
        $t += "`n-- Veeam after: $(Get-W48Sessions)"
        $done = $true
    } finally {
        # The service goes also when the grants can't be taken away (the W4.11 review's finding 7).
        try {
            $t += "`n-- the grants taken away`n$(Revoke-W48Account)"
        } catch {
            $t += "`n-- the grants couldn't be taken away: $($_.Exception.Message)"
        } finally {
            $t += "`n-- the service uninstalled`n$(Invoke-W48 @('service', 'uninstall'))"
            # A run that failed never replaces the committed evidence.
            Save-W48Evidence ($done ? 'w4.11-3-service-run.txt' : 'w4.11-3-service-run.failed.txt') ($t -join "`n")
        }
    }
}

if ($Steps -contains 'd') {
    $t = @("W4.11 (#134) live Done-when, step (d): the teardown. $(Get-Utc), commit $commit")
    New-Item -ItemType Directory -Force $W411Kept | Out-Null
    foreach ($n in 3, 4, 5) {
        $sent = Join-Path $script:W48Root "sent\$Prefix-$n"
        if (Test-Path $sent) { Move-Item $sent (Join-Path $W411Kept "$Prefix-$n") -Force; $t += "`n-- sent\$Prefix-$n moved to $W411Kept" }
    }
    $t += "`n$(Remove-W48Harness)"
    $t += "`n-- sc query: $((sc.exe query $script:W48Service 2>&1) -join ' ')"
    $t += "`n-- $(Get-W48Folders)"
    $t += "`n-- Veeam: $(Get-W48Sessions)"
    $t += "`n-- the three restore targets after`n$(Get-W48Targets)"
    $t += "`n-- kept outside the repo: $script:W411Dir, $Lab (the profile files and the config copy)"
    Save-W48Evidence 'w4.11-4-teardown.txt' ($t -join "`n")
}

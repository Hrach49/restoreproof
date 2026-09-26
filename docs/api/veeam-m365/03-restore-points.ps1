# Step 3: restore points, filters, paging, the ID format (docs/api/veeam-notes.md §3).
#   pwsh -File 03-restore-points.ps1 [-SaveEvidence]
# Read-only.
param([switch]$SaveEvidence)
. "$PSScriptRoot\VeeamLab.ps1"

function Show-Points($r) {
    $b = Get-Body $r
    if (-not $b -or -not $b.PSObject.Properties['results']) { return }
    "  limit=$($b.limit) offset=$($b.offset) setId=$(if ($b.PSObject.Properties['setId']) { $b.setId }) links=$(($b._links.PSObject.Properties.Name) -join ',')"
    @($b.results) | ForEach-Object { "  $($_.backupTime)  $($_.id)" }
}

Connect-VeeamAdmin | Out-Null
try {
    $r = Invoke-Veeam -Path '/v8/RestorePoints'
    Show-Call $r; Show-Points $r; Save-Evidence 'w1.4-rp-list' $r 'GET /v8/RestorePoints (no filter, default order and page)'

    $r = Invoke-Veeam -Path "/v8/RestorePoints?organizationId=$LabOrgId"
    Show-Call $r; Show-Points $r; Save-Evidence 'w1.4-rp-list-org' $r 'GET /v8/RestorePoints?organizationId={organizationId}'

    $r = Invoke-Veeam -Path "/v8/RestorePoints?organizationId=$LabOrgId&orderAsc=true"
    Show-Call $r; Show-Points $r; Save-Evidence 'w1.4-rp-list-asc' $r 'GET /v8/RestorePoints?organizationId=...&orderAsc=true'

    $r = Invoke-Veeam -Path "/v8/RestorePoints?organizationId=$LabOrgId&limit=1"
    Show-Call $r; Show-Points $r; Save-Evidence 'w1.4-rp-list-limit1' $r 'GET /v8/RestorePoints?organizationId=...&limit=1 (the newest? default order is descending)'
    $r = Invoke-Veeam -Path "/v8/RestorePoints?organizationId=$LabOrgId&limit=1&offset=1"
    Show-Call $r; Show-Points $r; Save-Evidence 'w1.4-rp-list-limit1-offset1' $r 'GET /v8/RestorePoints?organizationId=...&limit=1&offset=1'

    # from/to: between the two points, and a window that holds none.
    $r = Invoke-Veeam -Path "/v8/RestorePoints?organizationId=$LabOrgId&from=2026-09-25T19:30:00Z"
    Show-Call $r; Show-Points $r; Save-Evidence 'w1.4-rp-list-from' $r 'GET /v8/RestorePoints?organizationId=...&from=2026-09-25T19:30:00Z (between the two points)'
    $r = Invoke-Veeam -Path "/v8/RestorePoints?organizationId=$LabOrgId&to=2026-09-25T19:30:00Z"
    Show-Call $r; Show-Points $r; Save-Evidence 'w1.4-rp-list-to' $r 'GET /v8/RestorePoints?organizationId=...&to=2026-09-25T19:30:00Z'
    $r = Invoke-Veeam -Path "/v8/RestorePoints?organizationId=$LabOrgId&from=2026-09-25T19:37:15.2145203Z"
    Show-Call $r; Show-Points $r; Save-Evidence 'w1.4-rp-list-from-exact' $r 'GET /v8/RestorePoints?organizationId=...&from={exactly the latest backupTime} (inclusive or exclusive?)'
    $r = Invoke-Veeam -Path "/v8/RestorePoints?organizationId=$LabOrgId&from=2026-09-26T00:00:00Z"
    Show-Call $r; Show-Points $r; Save-Evidence 'w1.4-rp-list-empty' $r 'GET /v8/RestorePoints?organizationId=...&from=2026-09-26T00:00:00Z (no point after that)'
    $r = Invoke-Veeam -Path "/v8/RestorePoints?organizationId=$LabOrgId&from=yesterday"
    Show-Call $r; Save-Evidence 'w1.4-rp-list-bad-from' $r 'GET /v8/RestorePoints?organizationId=...&from=yesterday (not a date)'
    $r = Invoke-Veeam -Path '/v8/RestorePoints?organizationId=00000000-0000-0000-0000-000000000001'
    Show-Call $r; Show-Points $r; Save-Evidence 'w1.4-rp-list-unknown-org' $r 'GET /v8/RestorePoints?organizationId={an organisation id that does not exist}'

    # One point: by its API id (repository id + point id), by the bare point id, and unknown.
    $latest = Get-LatestRestorePoint
    "latest: $($latest.id) $($latest.backupTime)"
    $r = Invoke-Veeam -Path "/v8/RestorePoints/$($latest.id)"
    Show-Call $r; Save-Evidence 'w1.4-rp-get' $r 'GET /v8/RestorePoints/{id} with the id as listed (repositoryId + pointId)'
    $r = Invoke-Veeam -Path "/v8/RestorePoints/$LabIncPoint"
    Show-Call $r; Save-Evidence 'w1.4-rp-get-bare-id' $r 'GET /v8/RestorePoints/{pointId} with the bare point id (as Get-VBORestorePoint shows it)'
    $r = Invoke-Veeam -Path "/v8/RestorePoints/$($LabRepoId)00000000-0000-0000-0000-000000000001"
    Show-Call $r; Save-Evidence 'w1.4-rp-get-unknown-404' $r 'GET /v8/RestorePoints/{repositoryId + a point id that does not exist}'

    # The guide's path does not exist.
    $r = Invoke-Veeam -Path "/v8/Organizations/$LabOrgId/RestorePoints"
    Show-Call $r; Save-Evidence 'w1.4-rp-guide-path-404' $r "GET /v8/Organizations/{organizationId}/RestorePoints (the guide's path)"
} finally { Disconnect-VeeamAdmin }

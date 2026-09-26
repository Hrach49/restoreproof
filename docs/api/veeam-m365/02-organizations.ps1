# Step 2: organisations, users, sites; paging (docs/api/veeam-notes.md §2).
#   pwsh -File 02-organizations.ps1 [-SaveEvidence]
# Read-only. dataSource=PreferLocalResynced makes Veeam re-read the tenant into its own cache.
param([switch]$SaveEvidence)
. "$PSScriptRoot\VeeamLab.ps1"

Connect-VeeamAdmin | Out-Null
try {
    $r = Invoke-Veeam -Path '/v8/Organizations'
    Show-Call $r; Save-Evidence 'w1.4-org-list' $r 'GET /v8/Organizations (default page)'
    (Get-Body $r).results | ForEach-Object { "  org $($_.id) name=$($_.name) type=$($_.type) msid=$($_.msid)" }

    $r = Invoke-Veeam -Path "/v8/Organizations/$LabOrgId"
    Show-Call $r; Save-Evidence 'w1.4-org-get' $r 'GET /v8/Organizations/{organizationId}'
    $r = Invoke-Veeam -Path "/v8/Organizations/$LabOrgId`?extendedView=true"
    Show-Call $r; Save-Evidence 'w1.4-org-get-extended' $r 'GET /v8/Organizations/{organizationId}?extendedView=true (asks the proxy: isBackedup, firstBackuptime, lastBackuptime)'
    $o = Get-Body $r
    "  isBackedup=$($o.isBackedup) firstBackuptime=$($o.firstBackuptime) lastBackuptime=$($o.lastBackuptime)"

    $r = Invoke-Veeam -Path '/v8/Organizations/00000000-0000-0000-0000-000000000001'
    Show-Call $r; Save-Evidence 'w1.4-org-get-unknown-404' $r 'GET /v8/Organizations/{an organisation id that does not exist}'
    $r = Invoke-Veeam -Path '/v8/Organizations/not-a-guid'
    Show-Call $r; Save-Evidence 'w1.4-org-get-bad-id' $r 'GET /v8/Organizations/not-a-guid'

    # Users: the default page, then paging with limit/offset and the setId of the first page.
    $r = Invoke-Veeam -Path "/v8/Organizations/$LabOrgId/Users"
    Show-Call $r; Save-Evidence 'w1.4-org-users' $r 'GET /v8/Organizations/{organizationId}/Users (default page, default dataSource)'
    $u = Get-Body $r
    "  users: $(@($u.results).Count), limit=$($u.limit), setId=$($u.setId)"
    $u.results | ForEach-Object { "  user $($_.id) name=$($_.name) type=$($_.type) msid=$($_.msid)" }

    $r = Invoke-Veeam -Path "/v8/Organizations/$LabOrgId/Users?limit=2&offset=0"
    Show-Call $r; Save-Evidence 'w1.4-org-users-page1' $r 'GET /v8/Organizations/{organizationId}/Users?limit=2&offset=0'
    $p1 = Get-Body $r
    "  page 1: $(@($p1.results).Count) users, setId=$($p1.setId), links: $(($p1._links.PSObject.Properties.Name) -join ',')"
    $q = "limit=2&offset=2" + $(if ($p1.setId) { "&setId=$($p1.setId)" } else { '' })
    $r = Invoke-Veeam -Path "/v8/Organizations/$LabOrgId/Users?$q"
    Show-Call $r; Save-Evidence 'w1.4-org-users-page2' $r 'GET /v8/Organizations/{organizationId}/Users?limit=2&offset=2&setId={setId of page 1}'
    $p2 = Get-Body $r
    "  page 2: $(@($p2.results).Count) users, setId=$($p2.setId), links: $(($p2._links.PSObject.Properties.Name) -join ',')"
    $r = Invoke-Veeam -Path "/v8/Organizations/$LabOrgId/Users?limit=2&offset=100"
    Show-Call $r; Save-Evidence 'w1.4-org-users-past-end' $r 'GET /v8/Organizations/{organizationId}/Users?limit=2&offset=100 (past the end)'
    "  past the end: $(@((Get-Body $r).results).Count) users"

    $r = Invoke-Veeam -Path "/v8/Organizations/$LabOrgId/Users?userName=alice@$LabOrgName"
    Show-Call $r; Save-Evidence 'w1.4-org-users-by-name' $r 'GET /v8/Organizations/{organizationId}/Users?userName=alice@...'

    foreach ($ds in 'PreferLocal', 'Production', 'PreferLocalResynced') {
        $r = Invoke-Veeam -Path "/v8/Organizations/$LabOrgId/Users?limit=100&dataSource=$ds"
        $names = ((Get-Body $r).results | ForEach-Object name | Sort-Object) -join ', '
        "$(Show-Call $r)`n  $ds -> $names"
        Save-Evidence "w1.4-org-users-$($ds.ToLower())" $r "GET /v8/Organizations/{organizationId}/Users?limit=100&dataSource=$ds"
    }

    # Sites: top level, with personal sites, by filter.
    $r = Invoke-Veeam -Path "/v8/Organizations/$LabOrgId/Sites"
    Show-Call $r; Save-Evidence 'w1.4-org-sites' $r 'GET /v8/Organizations/{organizationId}/Sites (default: no personal sites)'
    (Get-Body $r).results | ForEach-Object { "  site $($_.id) url=$($_.url) personal=$($_.isPersonal)" }
    $r = Invoke-Veeam -Path "/v8/Organizations/$LabOrgId/Sites?includePersonalSites=true&limit=100"
    Show-Call $r; Save-Evidence 'w1.4-org-sites-personal' $r 'GET /v8/Organizations/{organizationId}/Sites?includePersonalSites=true&limit=100'
    "  with personal sites: $(@((Get-Body $r).results).Count)"
    $r = Invoke-Veeam -Path "/v8/Organizations/$LabOrgId/Sites?filter=RestoreTest"
    Show-Call $r; Save-Evidence 'w1.4-org-sites-filter' $r 'GET /v8/Organizations/{organizationId}/Sites?filter=RestoreTest'
    (Get-Body $r).results | ForEach-Object { "  filtered: $($_.id) $($_.url)" }
} finally { Disconnect-VeeamAdmin }

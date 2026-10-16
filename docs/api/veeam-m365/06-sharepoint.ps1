# Step 6: browse and search SharePoint in a Vesp explore session (docs/api/veeam-notes.md §5.2).
#   pwsh -File 06-sharepoint.ps1 [-SaveEvidence]
# Read-only: one explore session at the latest point, stopped in the finally.
param([switch]$SaveEvidence)
. "$PSScriptRoot\VeeamLab.ps1"

$SiteUrl = 'https://restoreprooflab.sharepoint.com/sites/RestoreTest'
$CanaryListId = '7eb0f08a-f57b-418c-8ca6-f2ab81297666'   # RestoreTest library (the canary SOURCE), lab/tenant.md
$TargetListId = '29dfd30b-9223-49fc-ab87-a205a757f896'   # RestoreTarget library (the restore target)

function Show-Results($r) {
    $b = Get-Body $r
    if (-not $b -or -not $b.PSObject.Properties['results']) { return }
    "  $(@($b.results).Count) result(s), limit=$($b.limit) offset=$($b.offset) links=$(($b._links.PSObject.Properties.Name) -join ',')"
    @($b.results) | Select-Object -First 12 | ForEach-Object {
        $extra = if ($_.PSObject.Properties['url']) { " url=$($_.url)" } elseif ($_.PSObject.Properties['isFolder']) { " folder=$($_.isFolder)" } else { '' }
        "    $($_.name)$extra  [$($_.id)]"
    }
}
function Search-Sp([string]$Path, [string]$Query, [string]$Name, [string]$Note) {
    $r = Invoke-Veeam -Method POST -Path $Path -Json (@{ query = $Query } | ConvertTo-Json)
    "search $(Format-PathTemplate $Path) query=$Query -> $($r.Status) ($($r.Ms) ms)$(if ($r.Status -ge 400) { ': ' + (Protect-Text $r.Body) })"
    Show-Results $r
    if ($Name) { Save-Evidence $Name $r $Note }
}

Connect-VeeamAdmin | Out-Null
try {
    $latest = Get-LatestRestorePoint
    $x = New-ExploreSession 'Vesp' $latest.backupTime
    Show-Call $x
    if ($x.Status -ne 201) { throw 'explore failed' }
    Save-Evidence 'w1.4-sp-explore' $x 'POST /v8/Organizations/{organizationId}/explore {type: Vesp} at the latest backupTime'
    $sid = (Get-Body $x).id
    $base = "/v8/RestoreSessions/$sid/Organization"

    # Sites.
    $r = Invoke-Veeam -Path "$base/Sites"
    Show-Call $r; Show-Results $r; Save-Evidence 'w1.4-sp-sites' $r 'GET /v8/RestoreSessions/{restoreSessionId}/Organization/Sites (no parentId)'
    $r = Invoke-Veeam -Path "$base/Sites?parentId=root&limit=100"
    Show-Call $r; Show-Results $r; Save-Evidence 'w1.4-sp-sites-root' $r 'GET .../Organization/Sites?parentId=root&limit=100'
    $site = @((Get-Body $r).results) | Where-Object url -eq $SiteUrl
    "  RestoreTest site id: $($site.id)"
    $r = Invoke-Veeam -Path "$base/Sites/$($site.id)"
    Show-Call $r; Save-Evidence 'w1.4-sp-site-get' $r 'GET .../Organization/Sites/{siteId} (RestoreTest)'
    $r = Invoke-Veeam -Path "$base/Sites?parentId=$($site.id)"
    Show-Call $r; Show-Results $r; Save-Evidence 'w1.4-sp-subsites' $r 'GET .../Organization/Sites?parentId={siteId} (subsites of RestoreTest)'

    # Libraries and lists.
    $r = Invoke-Veeam -Path "$base/Sites/$($site.id)/Libraries"
    Show-Call $r; Show-Results $r; Save-Evidence 'w1.4-sp-libraries' $r 'GET .../Organization/Sites/{siteId}/Libraries'
    $libs = @((Get-Body $r).results)
    $canaryLib = $libs | Where-Object { $_.id -like "*$CanaryListId" }
    $targetLib = $libs | Where-Object { $_.id -like "*$TargetListId" }
    "  canary library: $($canaryLib.name) [$($canaryLib.id)]; target library in the backup: $(if ($targetLib) { "$($targetLib.name) [$($targetLib.id)]" } else { 'no' })"
    $r = Invoke-Veeam -Path "$base/Sites/$($site.id)/Libraries/$($canaryLib.id)"
    Show-Call $r; Save-Evidence 'w1.4-sp-library-get' $r 'GET .../Organization/Sites/{siteId}/Libraries/{libraryId} (RestoreTest library)'
    $r = Invoke-Veeam -Path "$base/Sites/$($site.id)/Lists"
    Show-Call $r; Show-Results $r; Save-Evidence 'w1.4-sp-lists' $r 'GET .../Organization/Sites/{siteId}/Lists'

    # Documents and folders.
    $r = Invoke-Veeam -Path "$base/Sites/$($site.id)/Documents?parentId=$($canaryLib.id)"
    Show-Call $r; Show-Results $r; Save-Evidence 'w1.4-sp-documents' $r 'GET .../Organization/Sites/{siteId}/Documents?parentId={libraryId} (the canary library)'
    $doc = @((Get-Body $r).results) | Where-Object name -ceq 'rp-canary-01.pdf'
    $r = Invoke-Veeam -Path "$base/Sites/$($site.id)/Documents?parentId=$($canaryLib.id)&limit=4&offset=4"
    Show-Call $r; Show-Results $r; Save-Evidence 'w1.4-sp-documents-page' $r 'GET .../Documents?parentId={libraryId}&limit=4&offset=4'
    $r = Invoke-Veeam -Path "$base/Sites/$($site.id)/Documents?parentId=root"
    Show-Call $r; Show-Results $r; Save-Evidence 'w1.4-sp-documents-root' $r 'GET .../Organization/Sites/{siteId}/Documents?parentId=root'
    $r = Invoke-Veeam -Path "$base/Sites/$($site.id)/Documents"
    Show-Call $r; Show-Results $r; Save-Evidence 'w1.4-sp-documents-no-parent' $r 'GET .../Organization/Sites/{siteId}/Documents (no parentId)'
    $r = Invoke-Veeam -Path "$base/Sites/$($site.id)/Folders?parentId=$($canaryLib.id)"
    Show-Call $r; Show-Results $r; Save-Evidence 'w1.4-sp-folders' $r 'GET .../Organization/Sites/{siteId}/Folders?parentId={libraryId}'
    if ($targetLib) {
        $r = Invoke-Veeam -Path "$base/Sites/$($site.id)/Documents?parentId=$($targetLib.id)"
        Show-Call $r; Show-Results $r; Save-Evidence 'w1.4-sp-documents-target' $r 'GET .../Documents?parentId={RestoreTarget libraryId} (the restore target, as backed up)'
    }
    $r = Invoke-Veeam -Path "$base/Sites/$($site.id)/Documents/$($doc.id)"
    Show-Call $r; Save-Evidence 'w1.4-sp-document-get' $r 'GET .../Organization/Sites/{siteId}/Documents/{documentId} (rp-canary-01.pdf)'
    $r = Invoke-Veeam -Path "$base/Sites/$($site.id)/Documents/$($doc.id)/Versions"
    Show-Call $r; Show-Results $r; Save-Evidence 'w1.4-sp-document-versions' $r 'GET .../Documents/{documentId}/Versions (rp-canary-01.pdf)'

    # Search: in the site, in the library, across all sites; query variants.
    Search-Sp "$base/Sites/$($site.id)/search" 'filename:rp-canary-01.pdf' 'w1.4-sp-search-site' 'POST .../Organization/Sites/{siteId}/search {query: "filename:rp-canary-01.pdf"}'
    Search-Sp "$base/Sites/$($site.id)/Libraries/$($canaryLib.id)/search" 'filename:rp-canary-01.pdf' 'w1.4-sp-search-library' 'POST .../Sites/{siteId}/Libraries/{libraryId}/search {query: "filename:rp-canary-01.pdf"}'
    Search-Sp "$base/Sites/search" 'filename:rp-canary-01.pdf' 'w1.4-sp-search-all-sites' 'POST .../Organization/Sites/search {query: "filename:rp-canary-01.pdf"}'
    Search-Sp "$base/Sites/$($site.id)/search?itemType=Items&containerType=Library" 'filename:rp-canary-01.pdf' 'w1.4-sp-search-site-typed' 'POST .../Sites/{siteId}/search?itemType=Items&containerType=Library {query: "filename:rp-canary-01.pdf"}'
    Search-Sp "$base/Sites/$($site.id)/search" 'filename:rp-canary-01' 'w1.4-sp-search-no-extension' 'POST .../Sites/{siteId}/search {query: "filename:rp-canary-01"} (no extension)'
    Search-Sp "$base/Sites/$($site.id)/search" 'filename:"rp-canary-01.pdf"' 'w1.4-sp-search-quoted' 'POST .../Sites/{siteId}/search {query: filename:"rp-canary-01.pdf"}'
    Search-Sp "$base/Sites/$($site.id)/search" 'rp-canary-01.pdf' 'w1.4-sp-search-bare' 'POST .../Sites/{siteId}/search {query: "rp-canary-01.pdf"} (no keyword)'
    Search-Sp "$base/Sites/$($site.id)/search" 'filename:rp-canary-99.pdf' 'w1.4-sp-search-none' 'POST .../Sites/{siteId}/search {query: "filename:rp-canary-99.pdf"} (no such file)'
} finally {
    Stop-OpenedSessions
    Disconnect-VeeamAdmin
}

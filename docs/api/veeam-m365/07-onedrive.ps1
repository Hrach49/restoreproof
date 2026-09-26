# Step 7: browse and search OneDrive in a Veod explore session (docs/api/veeam-notes.md §5.3).
#   pwsh -File 07-onedrive.ps1 [-SaveEvidence]
# Read-only: one explore session at the latest point, stopped in the finally.
param([switch]$SaveEvidence)
. "$PSScriptRoot\VeeamLab.ps1"

$AliceOneDriveUrl = 'https://restoreprooflab-my.sharepoint.com/personal/alice_restoreprooflab_onmicrosoft_com'

function Show-Results($r) {
    $b = Get-Body $r
    if (-not $b -or -not $b.PSObject.Properties['results']) { return }
    "  $(@($b.results).Count) result(s), limit=$($b.limit) offset=$($b.offset) links=$(($b._links.PSObject.Properties.Name) -join ',')"
    @($b.results) | Select-Object -First 12 | ForEach-Object {
        $extra = if ($_.PSObject.Properties['url']) { " url=$($_.url)" } elseif ($_.PSObject.Properties['isFolder']) { " folder=$($_.isFolder)" } else { '' }
        "    $($_.name)$extra  [$($_.id)]"
    }
}
function Search-Od([string]$Path, [string]$Query, [string]$Name, [string]$Note) {
    $r = Invoke-Veeam -Method POST -Path $Path -Json (@{ query = $Query } | ConvertTo-Json)
    "search $(Format-PathTemplate $Path) query=$Query -> $($r.Status) ($($r.Ms) ms)$(if ($r.Status -ge 400) { ': ' + (Protect-Text $r.Body) })"
    Show-Results $r
    if ($Name) { Save-Evidence $Name $r $Note }
}

Connect-VeeamAdmin | Out-Null
try {
    $latest = Get-LatestRestorePoint
    $x = New-ExploreSession 'Veod' $latest.backupTime
    Show-Call $x
    if ($x.Status -ne 201) { throw 'explore failed' }
    Save-Evidence 'w1.4-od-explore' $x 'POST /v8/Organizations/{organizationId}/explore {type: Veod} at the latest backupTime'
    $sid = (Get-Body $x).id
    $base = "/v8/RestoreSessions/$sid/Organization"

    $r = Invoke-Veeam -Path "$base/OneDrives"
    Show-Call $r; Show-Results $r; Save-Evidence 'w1.4-od-onedrives' $r 'GET /v8/RestoreSessions/{restoreSessionId}/Organization/OneDrives'
    $od = @((Get-Body $r).results) | Where-Object url -eq $AliceOneDriveUrl
    "  alice's OneDrive: $($od.name) [$($od.id)]"
    $r = Invoke-Veeam -Path "$base/OneDrives/$($od.id)"
    Show-Call $r; Save-Evidence 'w1.4-od-onedrive-get' $r "GET .../Organization/OneDrives/{oneDriveId} (alice)"

    # Folders: no parentId, parentId=root; the canary folder /RestoreTest and the target /RestoreTarget.
    $r = Invoke-Veeam -Path "$base/OneDrives/$($od.id)/Folders"
    Show-Call $r; Show-Results $r; Save-Evidence 'w1.4-od-folders' $r 'GET .../OneDrives/{oneDriveId}/Folders (no parentId)'
    $r = Invoke-Veeam -Path "$base/OneDrives/$($od.id)/Folders?parentId=root"
    Show-Call $r; Show-Results $r; Save-Evidence 'w1.4-od-folders-root' $r 'GET .../OneDrives/{oneDriveId}/Folders?parentId=root'
    $folders = @((Get-Body $r).results)
    $src = $folders | Where-Object name -ceq 'RestoreTest'
    $tgt = $folders | Where-Object name -ceq 'RestoreTarget'
    "  /RestoreTest: [$($src.id)]; /RestoreTarget in the backup: $(if ($tgt) { "[$($tgt.id)]" } else { 'no' })"
    $r = Invoke-Veeam -Path "$base/OneDrives/$($od.id)/Folders/$($src.id)"
    Show-Call $r; Save-Evidence 'w1.4-od-folder-get' $r 'GET .../OneDrives/{oneDriveId}/Folders/{folderId} (/RestoreTest)'

    # Documents: in the folder, paged, at the root, with folders, one by id.
    $r = Invoke-Veeam -Path "$base/OneDrives/$($od.id)/Documents?parentId=$($src.id)"
    Show-Call $r; Show-Results $r; Save-Evidence 'w1.4-od-documents' $r 'GET .../OneDrives/{oneDriveId}/Documents?parentId={folderId} (/RestoreTest)'
    $doc = @((Get-Body $r).results) | Where-Object name -ceq 'rp-canary-11.pdf'
    $r = Invoke-Veeam -Path "$base/OneDrives/$($od.id)/Documents?parentId=$($src.id)&limit=4&offset=8"
    Show-Call $r; Show-Results $r; Save-Evidence 'w1.4-od-documents-page' $r 'GET .../Documents?parentId={folderId}&limit=4&offset=8'
    $r = Invoke-Veeam -Path "$base/OneDrives/$($od.id)/Documents?parentId=root&includeFolders=true"
    Show-Call $r; Show-Results $r; Save-Evidence 'w1.4-od-documents-root' $r 'GET .../OneDrives/{oneDriveId}/Documents?parentId=root&includeFolders=true'
    $r = Invoke-Veeam -Path "$base/OneDrives/$($od.id)/Documents"
    Show-Call $r; Show-Results $r; Save-Evidence 'w1.4-od-documents-no-parent' $r 'GET .../OneDrives/{oneDriveId}/Documents (no parentId)'
    $r = Invoke-Veeam -Path "$base/OneDrives/$($od.id)/Documents/$($doc.id)"
    Show-Call $r; Save-Evidence 'w1.4-od-document-get' $r 'GET .../OneDrives/{oneDriveId}/Documents/{documentId} (rp-canary-11.pdf)'
    $r = Invoke-Veeam -Path "$base/OneDrives/$($od.id)/Documents/00000000-0000-0000-0000-000000000001"
    Show-Call $r; Save-Evidence 'w1.4-od-document-get-unknown' $r 'GET .../OneDrives/{oneDriveId}/Documents/{a document id that does not exist}'

    # Search: in the OneDrive, in the folder, across all OneDrives; variants.
    Search-Od "$base/OneDrives/$($od.id)/search" 'filename:rp-canary-11.pdf' 'w1.4-od-search-onedrive' 'POST .../OneDrives/{oneDriveId}/search {query: "filename:rp-canary-11.pdf"}'
    Search-Od "$base/OneDrives/$($od.id)/Folders/$($src.id)/search" 'filename:rp-canary-11.pdf' 'w1.4-od-search-folder' 'POST .../OneDrives/{oneDriveId}/Folders/{folderId}/search {query: "filename:rp-canary-11.pdf"}'
    Search-Od "$base/OneDrives/search" 'filename:rp-canary-11.pdf' 'w1.4-od-search-all' 'POST .../Organization/OneDrives/search {query: "filename:rp-canary-11.pdf"}'
    Search-Od "$base/OneDrives/$($od.id)/search?itemType=Documents" 'filename:rp-canary-11.pdf' 'w1.4-od-search-typed' 'POST .../OneDrives/{oneDriveId}/search?itemType=Documents {query: "filename:rp-canary-11.pdf"}'
    Search-Od "$base/OneDrives/$($od.id)/search" 'filename:rp-canary-1' 'w1.4-od-search-prefix' 'POST .../OneDrives/{oneDriveId}/search {query: "filename:rp-canary-1"} (a prefix)'
    Search-Od "$base/OneDrives/$($od.id)/search?itemType=Folders" 'filename:RestoreTest' 'w1.4-od-search-folders' 'POST .../OneDrives/{oneDriveId}/search?itemType=Folders {query: "filename:RestoreTest"}'
    Search-Od "$base/OneDrives/$($od.id)/search" 'filename:rp-canary-01.pdf' 'w1.4-od-search-none' "POST .../OneDrives/{oneDriveId}/search {query: `"filename:rp-canary-01.pdf`"} (a SharePoint canary: no match here)"
} finally {
    Stop-OpenedSessions
    Disconnect-VeeamAdmin
}

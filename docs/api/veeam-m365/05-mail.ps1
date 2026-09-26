# Step 5: browse and search mail in an Exchange (Vex) explore session (docs/api/veeam-notes.md §5.1).
#   pwsh -File 05-mail.ps1 [-SaveEvidence]
# Read-only: one explore session at the latest point, stopped in the finally.
param([switch]$SaveEvidence)
. "$PSScriptRoot\VeeamLab.ps1"

function Show-Items($r) {
    $b = Get-Body $r
    if (-not $b -or -not $b.PSObject.Properties['results']) { return }
    "  $(@($b.results).Count) result(s), limit=$($b.limit) offset=$($b.offset) links=$(($b._links.PSObject.Properties.Name) -join ',')"
    @($b.results) | Select-Object -First 12 | ForEach-Object {
        $label = if ($_.PSObject.Properties['subject']) { $_.subject } else { $_.name }
        "    $label  [$($_.id)]"
    }
}
function Search-Mail([string]$Path, [string]$Query, [string]$Name, [string]$Note) {
    $r = Invoke-Veeam -Method POST -Path $Path -Json (@{ query = $Query } | ConvertTo-Json)
    "search $(Format-PathTemplate $Path) query=$Query -> $($r.Status) ($($r.Ms) ms)$(if ($r.Status -ge 400) { ': ' + (Protect-Text $r.Body) })"
    Show-Items $r
    if ($Name) { Save-Evidence $Name $r $Note }
}

Connect-VeeamAdmin | Out-Null
try {
    $latest = Get-LatestRestorePoint
    $x = New-ExploreSession 'Vex' $latest.backupTime
    Show-Call $x
    if ($x.Status -ne 201) { throw 'explore failed' }
    $sid = (Get-Body $x).id
    $base = "/v8/RestoreSessions/$sid/organization"

    # Mailboxes.
    $r = Invoke-Veeam -Path "$base/mailboxes"
    Show-Call $r; Save-Evidence 'w1.4-mail-mailboxes' $r 'GET /v8/RestoreSessions/{restoreSessionId}/organization/mailboxes (default page)'
    (Get-Body $r).results | ForEach-Object { "  mailbox $($_.id) $($_.email) name=$($_.name -replace "`n",'\n') archive=$($_.isArchive)" }
    $alice = (Get-Body $r).results | Where-Object email -eq "alice@$LabOrgName"
    $r = Invoke-Veeam -Path "$base/mailboxes/$($alice.id)"
    Show-Call $r; Save-Evidence 'w1.4-mail-mailbox-get' $r 'GET .../organization/mailboxes/{mailboxId} (alice)'

    # Folders: no parentId, parentId=root, by name, one folder by id.
    $r = Invoke-Veeam -Path "$base/mailboxes/$($alice.id)/folders?limit=100"
    Show-Call $r; Show-Items $r; Save-Evidence 'w1.4-mail-folders' $r 'GET .../mailboxes/{mailboxId}/folders?limit=100 (no parentId)'
    $r = Invoke-Veeam -Path "$base/mailboxes/$($alice.id)/folders?parentId=root&limit=100"
    Show-Call $r; Show-Items $r; Save-Evidence 'w1.4-mail-folders-root' $r 'GET .../mailboxes/{mailboxId}/folders?parentId=root&limit=100'
    $r = Invoke-Veeam -Path "$base/mailboxes/$($alice.id)/folders?name=Inbox"
    Show-Call $r; Show-Items $r; Save-Evidence 'w1.4-mail-folders-by-name' $r 'GET .../mailboxes/{mailboxId}/folders?name=Inbox'
    $inbox = @((Get-Body $r).results)[0]
    "  Inbox: id=$($inbox.id) type=$($inbox.type)"
    $r = Invoke-Veeam -Path "$base/mailboxes/$($alice.id)/folders/$([uri]::EscapeDataString($inbox.id))"
    Show-Call $r; Save-Evidence 'w1.4-mail-folder-get' $r 'GET .../mailboxes/{mailboxId}/folders/{folderId} (Inbox)'

    # Items: in the Inbox, paged, without parentId, one by id.
    $pid_ = [uri]::EscapeDataString($inbox.id)
    $r = Invoke-Veeam -Path "$base/mailboxes/$($alice.id)/items?parentId=$pid_"
    Show-Call $r; Show-Items $r; Save-Evidence 'w1.4-mail-items' $r 'GET .../mailboxes/{mailboxId}/items?parentId={Inbox folder id} (default page)'
    $canary = @((Get-Body $r).results) | Where-Object subject -ceq 'RP-CANARY-0001'
    $r = Invoke-Veeam -Path "$base/mailboxes/$($alice.id)/items?parentId=$pid_&limit=3&offset=3"
    Show-Call $r; Show-Items $r; Save-Evidence 'w1.4-mail-items-page' $r 'GET .../mailboxes/{mailboxId}/items?parentId={Inbox}&limit=3&offset=3'
    $r = Invoke-Veeam -Path "$base/mailboxes/$($alice.id)/items?limit=100"
    Show-Call $r; Show-Items $r; Save-Evidence 'w1.4-mail-items-no-parent' $r 'GET .../mailboxes/{mailboxId}/items?limit=100 (no parentId)'
    $r = Invoke-Veeam -Path "$base/mailboxes/$($alice.id)/items/$([uri]::EscapeDataString($canary.id))"
    Show-Call $r; Save-Evidence 'w1.4-mail-item-get' $r 'GET .../mailboxes/{mailboxId}/items/{itemId} (RP-CANARY-0001)'
    $r = Invoke-Veeam -Path "$base/mailboxes/$($alice.id)/items/AAAAAJQ40Ee3vkxBk1fd6-4CAU4BAP0LwXmScMJMnrn-sNESuJ8AAAAAAQwAAB"
    Show-Call $r; Save-Evidence 'w1.4-mail-item-get-unknown' $r 'GET .../mailboxes/{mailboxId}/items/{an item id that does not exist}'

    # Search: in one mailbox, in one folder, in all mailboxes, and the organisation-wide searchExchange.
    Search-Mail "$base/mailboxes/$($alice.id)/search" 'subject:RP-CANARY-0001' 'w1.4-mail-search-mailbox' 'POST .../mailboxes/{mailboxId}/search {query: "subject:RP-CANARY-0001"}'
    Search-Mail "$base/mailboxes/$($alice.id)/folders/$pid_/search" 'subject:RP-CANARY-0001' 'w1.4-mail-search-folder' 'POST .../mailboxes/{mailboxId}/folders/{folderId}/search {query: "subject:RP-CANARY-0001"}'
    Search-Mail "$base/mailboxes/search" 'subject:RP-CANARY-0001' 'w1.4-mail-search-all-mailboxes' 'POST .../organization/mailboxes/search {query: "subject:RP-CANARY-0001"}'
    Search-Mail "$base/searchExchange" 'subject:RP-CANARY-0001' 'w1.4-mail-search-exchange' 'POST .../organization/searchExchange {query: "subject:RP-CANARY-0001"}'
    # Query syntax variants.
    Search-Mail "$base/mailboxes/$($alice.id)/search" 'subject:"RP-CANARY-0001"' 'w1.4-mail-search-quoted' 'POST .../mailboxes/{mailboxId}/search {query: subject:"RP-CANARY-0001"}'
    Search-Mail "$base/mailboxes/$($alice.id)/search" 'RP-CANARY-0001' 'w1.4-mail-search-bare' 'POST .../mailboxes/{mailboxId}/search {query: "RP-CANARY-0001"} (no keyword)'
    Search-Mail "$base/mailboxes/$($alice.id)/search" 'subject:RP-CANARY-000' 'w1.4-mail-search-prefix' 'POST .../mailboxes/{mailboxId}/search {query: "subject:RP-CANARY-000"} (a prefix of ten subjects)'
    Search-Mail "$base/mailboxes/$($alice.id)/search" 'subject:rp-canary-0001' 'w1.4-mail-search-lowercase' 'POST .../mailboxes/{mailboxId}/search {query: "subject:rp-canary-0001"} (lower case)'
    Search-Mail "$base/mailboxes/$($alice.id)/search" 'subject:RP-CANARY-0011' 'w1.4-mail-search-none' "POST .../mailboxes/{mailboxId}/search {query: `"subject:RP-CANARY-0011`"} (bob's mail: no match in alice's mailbox)"
    Search-Mail "$base/mailboxes/$($alice.id)/search" 'subject:(RP-CANARY-0001' 'w1.4-mail-search-bad-query' 'POST .../mailboxes/{mailboxId}/search {query: "subject:(RP-CANARY-0001"} (unbalanced parenthesis)'
    Search-Mail "$base/mailboxes/$($alice.id)/search" '' 'w1.4-mail-search-empty' 'POST .../mailboxes/{mailboxId}/search {query: ""}'
} finally {
    Stop-OpenedSessions
    Disconnect-VeeamAdmin
}

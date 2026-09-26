# Step 4: explore (restore) sessions: open, read, list, stop; what dateTime selects
# (docs/api/veeam-notes.md §4). Read-only: opens explore sessions and stops every one in a finally.
#   pwsh -File 04-sessions.ps1 [-SaveEvidence]
param([switch]$SaveEvidence)
. "$PSScriptRoot\VeeamLab.ps1"

# What an Exchange session holds: its mailboxes and the number of items in alice's Inbox.
function Get-MailView([string]$Sid, [string]$EvidenceName) {
    $mb = Get-Body (Invoke-Veeam -Path "/v8/RestoreSessions/$Sid/organization/mailboxes?limit=100")
    if (-not $mb -or -not $mb.PSObject.Properties['results']) { return 'mailboxes: (error)' }
    $alice = @($mb.results) | Where-Object email -eq "alice@$LabOrgName"
    $inbox = if ($alice) {
        $f = Get-Body (Invoke-Veeam -Path "/v8/RestoreSessions/$Sid/organization/mailboxes/$($alice.id)/folders?name=Inbox")
        $fid = @($f.results)[0].id
        $ir = Invoke-Veeam -Path "/v8/RestoreSessions/$Sid/organization/mailboxes/$($alice.id)/items?parentId=$([uri]::EscapeDataString($fid))&limit=1000"
        if ($EvidenceName) { Save-Evidence $EvidenceName $ir "GET .../mailboxes/{alice}/items?parentId={Inbox}&limit=1000 in the session of $EvidenceName (what the session holds)" | Out-Null }
        @((Get-Body $ir).results).Count
    } else { '-' }
    "mailboxes: $(@($mb.results).Count), alice Inbox items: $inbox"
}

Connect-VeeamAdmin | Out-Null
try {
    $latest = Get-LatestRestorePoint
    "latest point: $($latest.backupTime)"

    # 1. Open at the latest point's backupTime, exactly as the API returns it.
    $r = New-ExploreSession 'Vex' $latest.backupTime
    Show-Call $r; Save-Evidence 'w1.4-session-explore' $r 'POST /v8/Organizations/{organizationId}/explore {dateTime: latest backupTime, type: Vex}'
    $s = Get-Body $r
    "  id=$($s.id) name=$($s.name) state=$($s.state) result=$($s.result) creationTime=$($s.creationTime) endTime=$($s.endTime)"

    $r = Invoke-Veeam -Path "/v8/RestoreSessions/$($s.id)"
    Show-Call $r; Save-Evidence 'w1.4-session-get' $r 'GET /v8/RestoreSessions/{restoreSessionId} of the open explore session'
    $r = Invoke-Veeam -Path "/v8/RestoreSessions/$($s.id)/organization"
    Show-Call $r; Save-Evidence 'w1.4-session-organization' $r 'GET /v8/RestoreSessions/{restoreSessionId}/organization'
    $r = Invoke-Veeam -Path "/v8/RestoreSessions/$($s.id)/Statistics"
    Show-Call $r; Save-Evidence 'w1.4-session-statistics-working-409' $r 'GET /v8/RestoreSessions/{restoreSessionId}/Statistics while the explore session is Working'
    $r = Invoke-Veeam -Path "/v8/RestoreSessions/$($s.id)/Events"
    Show-Call $r; Save-Evidence 'w1.4-session-events-working' $r 'GET /v8/RestoreSessions/{restoreSessionId}/Events of an explore session with no restore yet'
    "  $(Get-MailView $s.id 'w1.4-session-content-exact')"

    $r = Invoke-Veeam -Path '/v8/RestoreSessions?limit=5'
    Show-Call $r; Save-Evidence 'w1.4-session-list' $r 'GET /v8/RestoreSessions?limit=5 (default order: newest creationTime first)'
    (Get-Body $r).results | ForEach-Object { "  $($_.creationTime) $($_.type) $($_.state) $($_.result) by $($_.initiatedBy): $($_.name)" }

    # 2. Stop it, read it again, stop it again, use it after the stop.
    $r = Invoke-Veeam -Method POST -Path "/v8/RestoreSessions/$($s.id)/Stop"
    Show-Call $r; Save-Evidence 'w1.4-session-stop' $r 'POST /v8/RestoreSessions/{restoreSessionId}/Stop'
    $r = Invoke-Veeam -Path "/v8/RestoreSessions/$($s.id)"
    Show-Call $r; Save-Evidence 'w1.4-session-get-stopped' $r 'GET /v8/RestoreSessions/{restoreSessionId} after the stop'
    $g = Get-Body $r; "  state=$($g.state) result=$($g.result) endTime=$($g.endTime) details=$($g.details)"
    $r = Invoke-Veeam -Method POST -Path "/v8/RestoreSessions/$($s.id)/Stop"
    Show-Call $r; Save-Evidence 'w1.4-session-stop-again' $r 'POST /v8/RestoreSessions/{restoreSessionId}/Stop on a session already stopped'
    $r = Invoke-Veeam -Path "/v8/RestoreSessions/$($s.id)/organization/mailboxes"
    Show-Call $r; Save-Evidence 'w1.4-session-browse-after-stop' $r 'GET /v8/RestoreSessions/{restoreSessionId}/organization/mailboxes after the stop'
    $r = Invoke-Veeam -Path "/v8/RestoreSessions/$($s.id)/Statistics"
    Show-Call $r; Save-Evidence 'w1.4-session-statistics-stopped' $r 'GET /v8/RestoreSessions/{restoreSessionId}/Statistics of a stopped explore session with no restore'
    $r = Invoke-Veeam -Path '/v8/RestoreSessions/00000000-0000-0000-0000-000000000001'
    Show-Call $r; Save-Evidence 'w1.4-session-get-unknown-404' $r 'GET /v8/RestoreSessions/{a session id that does not exist}'

    # 3. What dateTime selects. Each session is stopped straight after it is looked at.
    $cases = [ordered]@{
        'between'   = '2026-09-25T19:30:00Z'        # between the full (19:24:31) and the incremental (19:37:15)
        'before'    = '2026-09-25T19:00:00Z'        # before the first point
        'after'     = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')   # after the latest point
        'second'    = '2026-09-25T19:37:15Z'        # the latest point, truncated to the second
        'local'     = '2026-09-25T21:37:15+02:00'   # the same instant with an offset
        'nooffset'  = '2026-09-25T19:37:15'         # no offset: UTC or server local time?
        'plus0'     = '2026-09-25T19:37:15.2145203+00:00'   # UTC, but written as an offset
    }
    foreach ($k in $cases.Keys) {
        $r = New-ExploreSession 'Vex' $cases[$k]
        "dateTime $k ($($cases[$k])): $(Show-Call $r)"
        Save-Evidence "w1.4-session-explore-$k" $r "POST /v8/Organizations/{organizationId}/explore {dateTime: $($cases[$k]) ($k), type: Vex}"
        $x = Get-Body $r
        if ($r.Status -eq 201) {
            "  name=$($x.name) $(Get-MailView $x.id "w1.4-session-content-$k")"
            Stop-ExploreSession $x.id
        }
    }

    # 4. Refused bodies.
    $r = New-ExploreSession -RawJson '{"dateTime":"2026-09-25T19:37:15Z","type":"Mail","showDeleted":false,"showAllVersions":false}'
    Show-Call $r; Save-Evidence 'w1.4-session-explore-bad-type-400' $r 'POST /v8/Organizations/{organizationId}/explore with type "Mail" (not in the enum)'
    $r = New-ExploreSession -RawJson '{"dateTime":"yesterday","type":"Vex"}'
    Show-Call $r; Save-Evidence 'w1.4-session-explore-bad-date-400' $r 'POST /v8/Organizations/{organizationId}/explore with dateTime "yesterday"'
    $r = New-ExploreSession -RawJson '{"type":"Vex"}'
    Show-Call $r; Save-Evidence 'w1.4-session-explore-no-date' $r 'POST /v8/Organizations/{organizationId}/explore with no dateTime'
    if ($r.Status -eq 201) { $x = Get-Body $r; "  name=$($x.name) $(Get-MailView $x.id)" }
} finally {
    Stop-OpenedSessions
    Disconnect-VeeamAdmin
}

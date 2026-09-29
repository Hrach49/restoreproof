# Step 8: find and stop leftover explore sessions started by rp-veeam (docs/api/veeam-notes.md §4.4).
#   pwsh -File 08-sweep-sessions.ps1 [-WhatIf] [-Force] [-SaveEvidence]
# Stops only sessions that are Working AND were initiated by the rp-veeam account; sessions of any
# other user (the console, an operator) are listed and left alone.
# A restore session looks like an explore session in this list (same type, same account). Two or more
# of ours Working with one type are most likely a restore still running and the explore session it
# came from; what Stop does to either then is untested (docs/api/veeam-restore-flow.md §18), so the
# sweep stops nothing until they are down to one per type, or -Force is given.
param([switch]$WhatIf, [switch]$Force, [switch]$SaveEvidence)
. "$PSScriptRoot\VeeamLab.ps1"

Connect-VeeamAdmin | Out-Null
try {
    $r = Invoke-Veeam -Path '/v8/RestoreSessions?limit=200'
    Show-Call $r
    Save-Evidence 'w1.4-sweep-list' $r 'GET /v8/RestoreSessions?limit=200 (the sweep: newest first)'
    $all = @((Get-Body $r).results)
    $working = @($all | Where-Object state -eq 'Working')
    "sessions listed: $($all.Count); Working: $($working.Count)"
    # initiatedBy holds the bare account name ("rp-veeam"), without the "DESKTOP-…\" prefix.
    $me = @($script:VeeamUser, ($script:VeeamUser -split '\\')[-1])
    $mine = @($working | Where-Object { $_.initiatedBy -in $me })   # -in ignores case
    $shared = @($mine | Group-Object type | Where-Object Count -gt 1 | ForEach-Object Name)
    if ($shared.Count -and -not $Force) {
        "more than one session of ours Working for type(s) $($shared -join ', '): a restore may still be running."
        "Nothing stopped. Wait until the restore session reads Stopped, or pass -Force."
    }
    foreach ($s in $working) {
        $ours = $s.initiatedBy -in $me
        "  $($s.id) $($s.type) created $($s.creationTime) by $($s.initiatedBy)$(if (-not $ours) { ' (not ours: left alone)' })"
        if ($ours -and -not $WhatIf -and ($Force -or -not $shared.Count)) {
            $x = Invoke-Veeam -Method POST -Path "/v8/RestoreSessions/$($s.id)/Stop"
            "    stop -> $($x.Status)"
        }
    }
} finally { Disconnect-VeeamAdmin }

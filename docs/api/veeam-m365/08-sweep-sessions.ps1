# Step 8: find and stop leftover explore sessions started by rp-veeam (docs/api/veeam-notes.md §4.4).
#   pwsh -File 08-sweep-sessions.ps1 [-WhatIf] [-SaveEvidence]
# Stops only sessions that are Working AND were initiated by the rp-veeam account; sessions of any
# other user (the console, an operator) are listed and left alone.
param([switch]$WhatIf, [switch]$SaveEvidence)
. "$PSScriptRoot\VeeamLab.ps1"

Connect-VeeamAdmin | Out-Null
try {
    $r = Invoke-Veeam -Path '/v8/RestoreSessions?limit=200'
    Show-Call $r
    Save-Evidence 'w1.4-sweep-list' $r 'GET /v8/RestoreSessions?limit=200 (the sweep: newest first)'
    $all = @((Get-Body $r).results)
    $working = @($all | Where-Object state -eq 'Working')
    "sessions listed: $($all.Count); Working: $($working.Count)"
    foreach ($s in $working) {
        # initiatedBy holds the bare account name ("rp-veeam"), without the "DESKTOP-…\" prefix.
        $mine = $s.initiatedBy -in @($script:VeeamUser, ($script:VeeamUser -split '\\')[-1])
        "  $($s.id) $($s.type) created $($s.creationTime) by $($s.initiatedBy)$(if (-not $mine) { ' (not ours: left alone)' })"
        if ($mine -and -not $WhatIf) {
            $x = Invoke-Veeam -Method POST -Path "/v8/RestoreSessions/$($s.id)/Stop"
            "    stop -> $($x.Status)"
        }
    }
} finally { Disconnect-VeeamAdmin }

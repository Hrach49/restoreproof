# W4.8 (#51): the Done-when run, steps (a) to (g) of the decisions entry's point 16, in one go.
# Each step's text is saved as evidence (docs/api/veeam-lab/w4.8-<n>-*.txt) as soon as the step
# has ended, so nothing collected depends on a later step. Run from an elevated PowerShell 7 on
# the lab machine, with nothing installed and no session of rp-veeam Working:
#
#   pwsh -File docs\api\veeam-lab\w4.8-harness\w48-done-when.ps1 [-Prefix w48-job]
param([string]$Prefix = 'w48-job')
. (Join-Path $PSScriptRoot 'w48-run.ps1')

function Wait-W48RecordGone([int]$Minutes = 15) {
    $deadline = [DateTime]::UtcNow.AddMinutes($Minutes)
    while ((Test-Path (Join-Path $script:W48State 'running.json')) -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep 5 }
    Start-Sleep 5
}
function Get-W48StubSince([DateTime]$Since, [string]$Match = '.') {
    $keep = $false
    (Get-W48StubLog | ForEach-Object {
        if ($_ -match '^\d{4}-') { $keep = $_.Substring(0, 19) -ge $Since.ToString('s') }
        if ($keep -and ($_ -match $Match -or $_ -match '^  part')) { $_ }
    }) -join "`n"
}
$commit = git -C $script:Repo rev-parse --short HEAD
$job = { param($n, $m, $s, $o) New-W48Job "$Prefix-$n" $m $s $o }

# (a) install, the grants, start, the first heartbeats
$t = @("W4.8 (#51) live Done-when, step (a): install, the account's grants by hand (W7.1 isn't built), start. $([DateTime]::UtcNow.ToString('s'))Z, commit $commit")
$t += "`n-- before: what is under the three roots (made by hand in W4.2 to W4.6; the service must leave them as they are)`n$(Get-W48Folders)"
$t += "`n-- Veeam before: $(Get-W48Sessions)"
$t += "`n-- the config copy`n$(Initialize-W48Harness)"
$t += "`n-- the stub Cloud`n$(Start-W48Stub)"
$t += "`n$(Invoke-W48 @('service','install','--config',$W48Config))"
$t += "`n-- the grants (after install: the account exists only then)`n$(Grant-W48Account)"
$since = [DateTime]::UtcNow
$t += "`n$(Invoke-W48 @('service','start'))"
Start-Sleep 70
$t += "`n$(Get-W48Process)"
$t += "`n-- worker.log`n$(Get-W48Log -Since $since)"
$t += "`n`n-- the stub's lines (a heartbeat at start and one a minute later)`n$((Get-W48StubLog) -join "`n")"
Save-W48Evidence 'w4.8-1-install-grants-start.txt' ($t -join "`n")

# (b) one job: taken within a poll interval, signed, queued, sent
$since = [DateTime]::UtcNow
$t = @("W4.8 (#51) live Done-when, step (b): a job dropped into the stub file. $($since.ToString('s'))Z, commit $commit")
$t += "`n$(Set-W48Jobs @(& $job 1 5 5 5))"
$t += "`n-- taken: $(Wait-W48Log "run $Prefix-1: starting" $since 90)"
$t += "`n-- the record during the restore`n$(Wait-W48Record 'restore_requested":true' 400)"
Wait-W48Log "run $Prefix-1: ended" $since 900 | Out-Null
Start-Sleep 10
$t += "`n-- worker.log from the drop on`n$(Get-W48Log -Since $since)"
$t += "`n`n-- afterwards`n$(Get-W48Record)`n$(Get-W48Folders)"
$t += "`n-- the stub's lines since the drop`n$(Get-W48StubSince $since)"
$t += "`n-- both verifiers over the sent folder`n$(Test-W48Folder (Join-Path $script:W48Root "sent\$Prefix-1"))"
Save-W48Evidence 'w4.8-2-job-queued-and-sent.txt' ($t -join "`n")

# (c) the same job again: skipped
$since = [DateTime]::UtcNow
Start-Sleep 75
$t = @("W4.8 (#51) live Done-when, step (c): the same jobs file left as it is for two more polls. $([DateTime]::UtcNow.ToString('s'))Z, commit $commit")
$t += "`n-- worker.log from the run's end on, every line`n$(Get-W48Log -Since $since.AddSeconds(-25))"
$t += "`n`n-- runs started in that time: $(@(Get-W48LogLines $since.AddSeconds(-25) | Where-Object { $_ -match ': starting' }).Count)`n$(Get-W48Record)"
Save-W48Evidence 'w4.8-3-same-job-skipped.txt' ($t -join "`n")

# (d) a second job, the process killed during its restore
$since = [DateTime]::UtcNow
$t = @("W4.8 (#51) live Done-when, step (d): a second job, the process killed during its restore. $($since.ToString('s'))Z, commit $commit")
$t += "`n$(Set-W48Jobs @((& $job 1 5 5 5), (& $job 2 5 5 5)))"
$t += "`n-- taken: $(Wait-W48Log "run $Prefix-2: starting" $since 90)"
Wait-W48Record 'restore_requested":true' 400 | Out-Null
Start-Sleep 12
$t += "`n-- the record, 12 s into the restore`n$(Get-W48Record)"
$t += "`n-- Veeam's sessions then`n$(Get-W48Sessions)"
$killedAt = [DateTime]::UtcNow
$t += "`n-- $(Stop-W48Process)"
Start-Sleep 5
$t += "`n-- right after the kill`n$(Get-W48Process)`n$(Get-W48Record)`n$(Get-W48Folders)"
Wait-W48Log "interrupted run $Prefix-2 found" $killedAt 150 | Out-Null
Wait-W48RecordGone
$t += "`n-- the Service Control Manager's events`n$(Get-W48Events $killedAt.AddSeconds(-5))"
$t += "`n-- worker.log from the kill on (the restart, the run found, closed, sent; the hold; the clean; the record gone)`n$(Get-W48Log -Since $killedAt)"
$t += "`n`n-- afterwards`n$(Get-W48Record)`n$(Get-W48Sessions)`n$(Get-W48Folders)"
$t += "`n-- the stub's lines since the kill`n$(Get-W48StubSince $killedAt)"
$t += "`n-- both verifiers over the sent folder`n$(Test-W48Folder (Join-Path $script:W48Root "sent\$Prefix-2"))"
$t += "`n-- its items.csv`n$((Get-Content (Join-Path $script:W48Root "sent\$Prefix-2\items.csv")) -join "`n")"
$t += "`n-- the three restore targets`n$(Get-W48Targets)"
Save-W48Evidence 'w4.8-4-killed-interrupted-held-cleaned.txt' ($t -join "`n")

# (e) a third job, service stop during its restore
$since = [DateTime]::UtcNow
$t = @("W4.8 (#51) live Done-when, step (e): a third job, service stop during its restore. $($since.ToString('s'))Z, commit $commit")
$t += "`n$(Set-W48Jobs @((& $job 1 5 5 5), (& $job 2 5 5 5), (& $job 3 5 5 5)))"
$t += "`n-- taken: $(Wait-W48Log "run $Prefix-3: starting" $since 90)"
Wait-W48Record 'restore_requested":true' 400 | Out-Null
Start-Sleep 12
$t += "`n-- the record, 12 s into the restore`n$(Get-W48Record)"
$stopAt = [DateTime]::UtcNow
$t += "`n$(Invoke-W48 @('service','stop'))"
$t += "`n-- right after the stop: what was in flight`n$(Get-W48Process)`n$(Get-W48Record)`n$(Get-W48Sessions)`n$(Get-W48Folders)"
$t += "`n-- worker.log from the stop on`n$(Get-W48Log -Since $stopAt.AddSeconds(-1))"
$t += "`n`n-- the Service Control Manager's events since the stop: $(Get-W48Events $stopAt.AddSeconds(-2))"
$startAt = [DateTime]::UtcNow
$t += "`n$(Invoke-W48 @('service','start'))"
Wait-W48RecordGone
$t += "`n-- worker.log from the start on (the record found, the queued run sent, the hold, the clean, the record gone)`n$(Get-W48Log -Since $startAt.AddSeconds(-1))"
$t += "`n`n-- afterwards`n$(Get-W48Record)`n$(Get-W48Sessions)"
$t += "`n-- the stub's lines since the stop`n$(Get-W48StubSince $stopAt)"
$t += "`n-- both verifiers over the sent folder`n$(Test-W48Folder (Join-Path $script:W48Root "sent\$Prefix-3"))"
$t += "`n-- the three restore targets`n$(Get-W48Targets)"
Save-W48Evidence 'w4.8-5-stopped-during-a-run.txt' ($t -join "`n")

# (f) a job that isn't valid; a jobs file that isn't JSON
$since = [DateTime]::UtcNow
$t = @("W4.8 (#51) live Done-when, step (f): a job that isn't valid, then a jobs file that isn't JSON. $($since.ToString('s'))Z, commit $commit")
$t += "`n$(Set-W48Jobs @(& $job 4 0 0 0))"
Wait-W48Log "sent $Prefix-4" $since 120 | Out-Null
Start-Sleep 35
$t += "`n-- worker.log since`n$(Get-W48Log -Since $since)"
$t += "`n`n$(Get-W48Record)`n-- the stub's lines for it`n$(Get-W48StubSince $since 'results')"
$t += "`n-- both verifiers over the sent folder`n$(Test-W48Folder (Join-Path $script:W48Root "sent\$Prefix-4"))"
$t += "`n-- Veeam: $(Get-W48Sessions)"
$since = [DateTime]::UtcNow
$t += "`n`n$(Set-W48Jobs -Raw '{"format":"restoreproof.jobs.v1","jobs":[')"
Start-Sleep 130
$t += "`n-- worker.log since (four polls)`n$(Get-W48Log -Since $since)"
$t += "`n`n-- the stub's heartbeats since`n$(Get-W48StubSince $since 'heartbeat')"
Save-W48Evidence 'w4.8-6-invalid-job-and-unreadable-file.txt' ($t -join "`n")

# (g) the teardown
$t = @("W4.8 (#51) live Done-when, step (g): the teardown. $([DateTime]::UtcNow.ToString('s'))Z, commit $commit")
$t += "`n$(Invoke-W48 @('service','stop'))"
$names = 'veeam_password', 'graph_cert_pfx_base64', 'graph_cert_password', 'signing_key_base64'
$secrets = Get-W48Secrets
$logText = (Get-W48LogLines) -join "`n"
$counts = for ($i = 0; $i -lt 4; $i++) { "$($names[$i]) $(([regex]::Matches($logText, [regex]::Escape($secrets[$i]))).Count)" }
$counts += "jwt $(([regex]::Matches($logText, 'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.')).Count)", "pem $(([regex]::Matches($logText, '-----BEGIN')).Count)", "mii $(([regex]::Matches($logText, 'MII[A-Za-z0-9+/]{60,}')).Count)"
$t += "`n-- worker.log ($(@($logText -split "`n").Count) lines) searched for the vault's values and key shapes, counts only: $($counts -join ', ')"
$keep = "C:\restoreproof-runs\$Prefix"
New-Item -ItemType Directory -Force $keep | Out-Null
foreach ($n in 1..4) { Move-Item (Join-Path $script:W48Root "sent\$Prefix-$n") $keep -Force }
Copy-Item (Join-Path $script:W48Logs 'worker.log') $keep -Force
$t += "`n-- the four sent folders and worker.log kept outside the repository ($keep)"
$t += "`n-- the account's entries taken away, before the uninstall`n$(Revoke-W48Account)"
$t += "`n$(Invoke-W48 @('service','uninstall'))"
$t += "`n$(Remove-W48Harness)"
$t += "`n-- afterwards`n> sc query RestoreProof`n$((sc.exe query RestoreProof | Where-Object { $_.Trim() }) -join "`n")"
$t += "`n$(Get-W48Folders)"
$t += "state\: $(Test-Path $script:W48State)  w48\: $(Test-Path $script:W48Dir)  logs\: $(Test-Path $script:W48Logs)"
$paths = @($script:W48Vault) + @('runs', 'outbox', 'sent' | ForEach-Object { Join-Path $script:W48Root $_ })
$t += "`n$(($paths | ForEach-Object { "${_}: $(@((Get-Acl $_).Access | Where-Object { "$($_.IdentityReference)" -match 'RestoreProof|S-1-5-80-' }).Count) entry(ies) of the account or of an unresolved service SID" }) -join "`n")"
$t += "`n-- Veeam: $(Get-W48Sessions)"
Save-W48Evidence 'w4.8-7-teardown.txt' ($t -join "`n")
'done'

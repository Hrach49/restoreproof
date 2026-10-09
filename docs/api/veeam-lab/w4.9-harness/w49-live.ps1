# W4.9 (#52): the live check of the secret audit on the lab machine, in one go. With the real
# vault: (a) one `rpworker test --evidence --outbox --record` run, (b) one short service run
# through the W4.8 harness (install, one job, stop, uninstall), (c) a search of every file both
# wrote for the vault's real values, the values derived from them and the secret shapes, counts
# only, never a value, (d) the teardown: nothing installed, the folders kept outside the repo.
# Each step's text is saved as evidence (docs/api/veeam-lab/w4.9-<n>-*.txt) as soon as the step
# has ended, through Save-W48Evidence, which refuses a text holding a secret or a key shape.
# Run from an elevated PowerShell 7 on the lab machine, with nothing installed and no session of
# rp-veeam Working:
#
#   pwsh -File docs\api\veeam-lab\w4.9-harness\w49-live.ps1 [-Prefix w49] [-SearchOnly [-Teardown]]
param([string]$Prefix = 'w49', [switch]$SearchOnly, [switch]$Teardown)
. (Join-Path $PSScriptRoot '..\w4.8-harness\w48-run.ps1')

$script:W49Dir = Join-Path $script:W48Root 'w49'
$W49Runs = Join-Path $script:W49Dir 'runs'
$W49Box = Join-Path $script:W49Dir 'box'
$W49Rec = Join-Path $script:W49Dir "rec-$Prefix-1"
$W49Kept = Join-Path $script:W49Dir 'sent-by-service'
$W49Scan = Join-Path $script:Repo 'worker\tools\fixture_secret_scan.py'
$commit = git -C $script:Repo rev-parse --short HEAD
function Get-Utc { [DateTime]::UtcNow.ToString('s') + 'Z' }

# Every file under a root, with its size, relative to the root.
function Get-W49Tree([string]$Root) {
    if (-not (Test-Path $Root)) { return "$Root (not there)" }
    $files = @(Get-ChildItem $Root -File -Recurse | Sort-Object FullName)
    "$Root ($($files.Count) file(s)):`n" + (($files | ForEach-Object { "  $($_.FullName.Substring($Root.Length + 1)) $($_.Length)" }) -join "`n")
}

# The values no file may hold, each with a label and never printed: the vault's four secret
# values, the PFX's bytes as hex and its Base64 in 32-character pieces, the signing seed in
# Base64 and hex. The user name is no secret value and is counted apart.
function Get-W49Values {
    $secrets = Get-W48Secrets
    $values = [ordered]@{}
    $values['veeam_password'] = $secrets[0]
    $values['graph_cert_pfx_base64'] = $secrets[1]
    $pfx = [Convert]::FromBase64String($secrets[1])
    $values['graph_cert_pfx (hex)'] = (($pfx | ForEach-Object { $_.ToString('x2') }) -join '')
    for ($at = 0; $at + 32 -le $secrets[1].Length; $at += 32) { $values["graph_cert_pfx_base64 piece @$at"] = $secrets[1].Substring($at, 32) }
    $values['graph_cert_password'] = $secrets[2]
    $values['signing_key_base64'] = $secrets[3]
    $key = [Convert]::FromBase64String($secrets[3])
    if ($key.Length -ne 48) { throw 'the signing key is not 48 bytes of PKCS#8 DER' }
    $seed = $key[16..47]
    $values['signing seed (base64)'] = [Convert]::ToBase64String($seed)
    $values['signing seed (hex)'] = (($seed | ForEach-Object { $_.ToString('x2') }) -join '')
    foreach ($entry in @($values.GetEnumerator())) { if (-not $entry.Value -or $entry.Value.Length -lt 6) { throw "value $($entry.Key) is missing or too short" } }
    $values
}

# Every file under each root searched for every value (counts only) and, through the fixture
# scan with an empty allowlist, for every secret shape. The user name's count is reported apart.
function Search-W49([string[]]$Roots, [string]$UserName) {
    $values = Get-W49Values
    $lines = @("values searched for: $($values.Count) ($(($values.Keys | Where-Object { $_ -notmatch 'piece' }) -join ', '), and the PFX's Base64 in 32-character pieces)")
    $empty = Join-Path $script:W48Temp 'empty-allowlist.json'
    New-Item -ItemType Directory -Force $script:W48Temp | Out-Null
    [IO.File]::WriteAllText($empty, '{"entries": []}', [Text.UTF8Encoding]::new($false))
    $totalFiles = 0; $totalBytes = 0; $totalHits = 0
    foreach ($root in $Roots) {
        if (-not (Test-Path $root)) { $lines += "`n$root : not there"; continue }
        $files = @(Get-ChildItem $root -File -Recurse)
        $hits = [ordered]@{}; $userCount = 0; $bytes = 0
        foreach ($file in $files) {
            # Shared access: the stub's redirected streams are still held while it runs.
            $stream = [IO.File]::Open($file.FullName, 'Open', 'Read', 'ReadWrite, Delete')
            try { $raw = [IO.BinaryReader]::new($stream).ReadBytes([int]$stream.Length) } finally { $stream.Dispose() }
            $text = [Text.Encoding]::Latin1.GetString($raw)
            $bytes += $text.Length
            foreach ($entry in $values.GetEnumerator()) {
                $n = 0; $at = $text.IndexOf($entry.Value, [StringComparison]::Ordinal)
                while ($at -ge 0) { $n++; $at = $text.IndexOf($entry.Value, $at + 1, [StringComparison]::Ordinal) }
                if ($n -gt 0) { $hits["$($file.FullName.Substring($root.Length + 1)): $($entry.Key)"] = $n }
            }
            if ($UserName) {
                $at = $text.IndexOf($UserName, [StringComparison]::Ordinal)
                while ($at -ge 0) { $userCount++; $at = $text.IndexOf($UserName, $at + 1, [StringComparison]::Ordinal) }
            }
        }
        $totalFiles += $files.Count; $totalBytes += $bytes; $totalHits += $hits.Count
        $lines += "`n$root : $($files.Count) file(s), $bytes byte(s) read"
        $lines += "  value hits: $($hits.Count)" + $(if ($hits.Count) { "`n" + (($hits.GetEnumerator() | ForEach-Object { "    $($_.Key): $($_.Value) time(s)" }) -join "`n") } else { '' })
        if ($UserName) { $lines += "  the account name ($UserName, no secret value): $userCount time(s)" }
        $scan = & python $W49Scan --root $root --tree . --allowlist $empty 2>&1
        $lines += "  shape scan (exit $LASTEXITCODE): " + (($scan | ForEach-Object { "$_" }) -join "`n    ")
    }
    $lines += "`nin all: $totalFiles file(s), $totalBytes byte(s), $totalHits value hit(s)"
    $lines -join "`n"
}

if (-not $SearchOnly) {
    # (a) rpworker test --evidence --outbox --record, the lab config, the real vault
    # Test-W48Folder writes the public key file under the W4.8 harness's folder, made here already.
    New-Item -ItemType Directory -Force $script:W49Dir, $script:W48Dir, $script:W48Temp | Out-Null
    $t = @("W4.9 (#52) live check, step (a): rpworker test --evidence --outbox --record with the lab config and the real vault. $(Get-Utc), commit $commit")
    $t += "`n-- Veeam before: $(Get-W48Sessions)"
    $t += "`n-- the three restore targets before`n$(Get-W48Targets)"
    $t += "`n$(Invoke-W48 @('test', '--mail', '2', '--sp', '1', '--od', '1', '--run-id', "$Prefix-1", '--config', $script:LabConfig, '--manifest', (Join-Path $script:Repo 'lab\seed-manifest.json'), '--evidence', $W49Runs, '--outbox', $W49Box, '--record', $W49Rec))"
    $t += "`n-- what was written`n$(Get-W49Tree $script:W49Dir)"
    $t += "`n-- the queued folder`n$(Test-W48Folder (Join-Path $W49Box "outbox\$Prefix-1"))"
    $t += "`n-- Veeam after: $(Get-W48Sessions)"
    Save-W48Evidence 'w4.9-1-test-evidence-outbox-record.txt' ($t -join "`n")

    # (b) a short service run: install, the grants, one small job, stop, uninstall
    $t = @("W4.9 (#52) live check, step (b): a short service run through the W4.8 harness. $(Get-Utc), commit $commit")
    $t += "`n-- the config copy`n$(Initialize-W48Harness)"
    $t += "`n-- the stub Cloud`n$(Start-W48Stub)"
    $t += "`n$(Invoke-W48 @('service', 'install', '--config', $W48Config))"
    $t += "`n-- the grants`n$(Grant-W48Account)"
    $since = [DateTime]::UtcNow
    $t += "`n$(Invoke-W48 @('service', 'start'))"
    $t += "`n$(Set-W48Jobs @(New-W48Job "$Prefix-2" 1 1 1))"
    $t += "`n-- taken: $(Wait-W48Log "run $Prefix-2: starting" $since 120)"
    $t += "`n-- ended: $(Wait-W48Log "run $Prefix-2: ended" $since 900)"
    $t += "`n-- sent: $(Wait-W48Log "sent $Prefix-2" $since 120)"
    Start-Sleep 5
    $t += "`n$(Invoke-W48 @('service', 'stop'))"
    $t += "`n-- worker.log from the start on`n$(Get-W48Log -Since $since)"
    $t += "`n`n-- afterwards`n$(Get-W48Record)`n$(Get-W48Folders)"
    $t += "`n-- the stub's lines`n$((Get-W48StubLog) -join "`n")"
    $t += "`n-- the sent folder`n$(Test-W48Folder (Join-Path $script:W48Root "sent\$Prefix-2"))"
    $t += "`n-- Veeam after: $(Get-W48Sessions)"
    $t += "`n-- the grants taken away, the service uninstalled`n$(Revoke-W48Account)`n$(Invoke-W48 @('service', 'uninstall'))"
    Save-W48Evidence 'w4.9-2-service-run.txt' ($t -join "`n")
}

# (c) the search: every file the two steps wrote
# The vault's veeam_username as fill-worker-vault.ps1 sets it by default: a name, no secret value.
$userName = "$env:COMPUTERNAME\rp-veeam"
$roots = @($script:W49Dir, (Join-Path $script:W48Root "sent\$Prefix-2"), $script:W48Logs, $script:W48State, $script:W48Dir, (Join-Path $script:W48Temp 'stub.log'))
$roots = @($roots | ForEach-Object { if (Test-Path $_ -PathType Leaf) { Split-Path $_ } else { $_ } } | Select-Object -Unique)
$t = @("W4.9 (#52) live check, step (c): every file the two steps wrote, searched for the vault's values, their derived shapes and the secret shapes; counts only. $(Get-Utc), commit $commit")
$t += "`n-- roots`n$(($roots | ForEach-Object { "  $_" }) -join "`n")"
$t += "`n-- the search`n$(Search-W49 $roots $userName)"
Save-W48Evidence 'w4.9-3-search.txt' ($t -join "`n")

if (-not $SearchOnly -or $Teardown) {
    # (d) the teardown: the service's sent folder kept beside the run's, under w49; nothing installed
    $t = @("W4.9 (#52) live check, step (d): the teardown. $(Get-Utc), commit $commit")
    New-Item -ItemType Directory -Force $W49Kept | Out-Null
    Move-Item (Join-Path $script:W48Root "sent\$Prefix-2") (Join-Path $W49Kept "$Prefix-2") -Force
    $t += "`n-- sent\$Prefix-2 moved to $W49Kept"
    $t += "`n$(Remove-W48Harness)"
    $t += "`n-- sc query: $((sc.exe query $script:W48Service 2>&1) -join ' ')"
    $t += "`n-- $(Get-W48Folders)"
    $t += "`n-- Veeam: $(Get-W48Sessions)"
    $t += "`n-- the three restore targets after`n$(Get-W48Targets)"
    $t += "`n-- kept outside the repo: $(Get-W49Tree $script:W49Dir)"
    Save-W48Evidence 'w4.9-4-teardown.txt' ($t -join "`n")
}

# W6.3 (#183): the live Done-when of the content check against the backup's own copy, run by hand
# from an ELEVATED PowerShell 7 on the Veeam server (docs/decisions.md 2026-10-14, W6.3 and W6.2,
# point 15). In order:
#   1. rpworker graph list                  the three restore targets, empty (else it stops, and
#                                           nothing is cleaned: what is in them is not this run's)
#   2. rptests "live backup content*"       worker/tests/backup_content_live_test.cpp: the 14 real
#                                           files of L1.8 restored three times through the guarded
#                                           path, (a) as they are: 14 backup_content, pass; (b) one
#                                           byte of one restored copy changed: that item fail;
#                                           (c) every export over a 1-byte cap: pass, 14 metadata,
#                                           the content_export warning. It cleans after each.
#   3. rpworker graph list                  the targets empty again
#   4. c57-live.ps1 (C5.7's upload harness) the product end to end on the Compose stack: a job the
#                                           Cloud dispatches (no canary_cursor, so no canaries: the
#                                           whole sample is random items, the files backup_content),
#                                           run by the service, both verifiers on the sent folder,
#                                           the bundle posted to POST /v1/results: 202 twice, a
#                                           tampered copy 400. The Worker sends no token until
#                                           W5.1, so the post is by hand with the API token, as
#                                           C5.7's was.
#   5. the shape: step 2's three runs as the Done-when says, and step 4's result pass with files
#      reported backup_content and verified
#   6. the live cleanup test and graph list (in the finally, once step 2 has started)
# Everything is written to a run folder outside the repository first. Only when every step exited
# 0, the shape holds and no file holds a token-, PFX-, PEM- or key-shaped value are the files
# copied into docs/api/veeam-lab/ (w6.3-*), the copy last, so a failed run never replaces committed
# evidence. Docker Desktop must be running (step 4 brings the stack up itself), no RestoreProof
# service installed, no session of rp-veeam Working. Before the commit, also run
# `python tools/fixture_secret_scan.py` from worker/ and `audit-evidence.ps1 -Path ..\veeam-lab\w6.3-*`.
#
#   pwsh -File docs\api\veeam-lab\w6.3-harness\w63-live.ps1
#   pwsh -File docs\api\veeam-lab\w6.3-harness\w63-live.ps1 -NoCopy     # leave the evidence in the run folder
[CmdletBinding()]
param(
    [string]$RunDir = (Join-Path $env:LOCALAPPDATA ("RestoreProof\lab\w6.3-" + (Get-Date -Format 'yyyyMMddTHHmmss'))),
    [string]$Repo = 'C:\restoreproof',
    [switch]$NoCopy
)
Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

$worker = Join-Path $Repo 'worker\build\dev\rpworker.exe'
$tests = Join-Path $Repo 'worker\build\dev\rptests.exe'
$labConfig = Join-Path $env:LOCALAPPDATA 'RestoreProof\lab\config.json'
$caFile = Join-Path $Repo 'worker\tests\fixtures\veeam\rest-certificate.pem'
$upload = Join-Path $Repo 'docs\api\cloud-lab\c5.7-harness\c57-live.ps1'
$evidenceDir = Join-Path $Repo 'docs\api\veeam-lab'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'run from an elevated shell: the restore exports the organisation certificate from LocalMachine\My'
    exit 64
}
foreach ($f in $worker, $tests, $labConfig, $caFile, $upload) { if (-not (Test-Path $f)) { Write-Error "missing: $f"; exit 64 } }
docker info *> $null
if ($LASTEXITCODE -ne 0) { Write-Error 'Docker Desktop is not running: step 4 needs the Compose stack'; exit 64 }
New-Item -ItemType Directory -Force $RunDir | Out-Null
"run folder $RunDir"

# One command's output, as the console shows it, with its exit code, into a run-folder file.
# Returns the exit code alone; progress goes through Write-Host.
function Invoke-Step([string]$Name, [string]$Note, [scriptblock]$Command) {
    $file = Join-Path $RunDir "$Name.txt"
    $started = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    Write-Host "--- $Name started $started"
    $lines = @("$Note", "started $started", '')
    $out = @(& $Command 2>&1 | ForEach-Object { "$_" })
    $code = $LASTEXITCODE
    $lines += $out
    $lines += ''
    $lines += "exit code $code"
    [IO.File]::WriteAllText($file, (($lines -join "`n") -replace "`r", '') + "`n", [Text.UTF8Encoding]::new($false))
    $out | ForEach-Object { Write-Host "  $_" }
    Write-Host "--- $Name exit $code"
    return [int]$code
}

# The shapes no evidence file may hold: a JWT, a PFX or DER blob, a PEM private key, an Ed25519 key.
function Test-Clean([string]$Path) {
    $text = [IO.File]::ReadAllText($Path)
    $bad = @()
    if ($text -match 'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.') { $bad += 'a JWT-shaped value' }
    if ($text -match 'MII[A-Za-z0-9+/]{60,}') { $bad += 'a PFX/DER-shaped value' }
    if ($text -match '-----BEGIN [A-Z ]*PRIVATE KEY-----') { $bad += 'a PEM private key' }
    if ($text -match 'MC4CAQAwBQYDK2VwBCIEI[A-Za-z0-9+/]{43}') { $bad += 'an Ed25519 key' }
    if ($text -match '(?i)"?(password|access_token|refresh_token|applicationCertificate(Password)?)"?\s*[:=]\s*"?(?!\[REDACTED\]|SCRUBBED)[A-Za-z0-9+/=_\-]{8,}') { $bad += 'a secret-named value' }
    $bad
}

# What step 2's JSON and step 4's text must show (the Done-when); each miss one line.
function Test-Shape {
    $misses = @()
    $resultsFile = Join-Path $RunDir 'w6.3-results.json'
    if (-not (Test-Path $resultsFile)) { return @('no w6.3-results.json') }
    $runs = (Get-Content $resultsFile -Raw | ConvertFrom-Json).runs
    if (@($runs).Count -ne 3) { return @("$(@($runs).Count) runs in w6.3-results.json, not 3") }
    $count = { param($run, $field, $value) @($run.items | Where-Object { $_.$field -eq $value }).Count }
    if ($runs[0].status.status -ne 'pass') { $misses += "(a) status $($runs[0].status.status), not pass" }
    if ((& $count $runs[0] 'expected_kind' 'backup_content') -ne 14) { $misses += '(a) not 14 backup_content' }
    if ((& $count $runs[0] 'outcome' 'match') -ne 14) { $misses += '(a) not 14 match' }
    if ($runs[1].status.status -ne 'fail') { $misses += "(b) status $($runs[1].status.status), not fail" }
    if (@($runs[1].status.failed_items).Count -ne 1) { $misses += '(b) not one failed item' }
    if ((& $count $runs[1] 'outcome' 'mismatch') -ne 1) { $misses += '(b) not one mismatch' }
    if ($runs[2].status.status -ne 'pass') { $misses += "(c) status $($runs[2].status.status), not pass" }
    if ((& $count $runs[2] 'export' 'over_cap') -ne 14) { $misses += '(c) not 14 over_cap' }
    if ($runs[2].status.verified.backup_content -ne 0) { $misses += '(c) backup_content verified' }
    if (-not @($runs[2].status.warnings | Where-Object { $_.code -eq 'content_export' })) { $misses += '(c) no content_export warning' }
    $uploadText = Join-Path $RunDir 'w6.3-4-upload.txt'
    if (-not (Test-Path $uploadText)) { $misses += 'no w6.3-4-upload.txt' } else {
        $text = Get-Content $uploadText -Raw
        if ($text -notmatch '"state":"pass"') { $misses += '(4) the upload did not answer state pass' }
        if ($text -notmatch 'verified [0-9a-f]{64} key [0-9a-f]{64}') { $misses += '(4) a verifier did not say verified' }
        if ($text -notmatch 'backup_content [1-9]') { $misses += '(4) no file verified as backup_content' }
    }
    $misses
}

$codes = [ordered]@{}
$env:RP_LIVE = '1'
$env:RP_LIVE_RESTORE = '1'
$env:RP_LIVE_VEEAM_CA_FILE = $caFile
$env:RP_LIVE_EVIDENCE_FILE = Join-Path $RunDir 'w6.3-results.json'
# The cleanup of the finally runs only once the live test has started: before that, what the
# targets hold is not this run's, and step 1's refusal must not delete it.
$testStarted = $false
try {
    $codes['w6.3-1-graph-list-before'] = Invoke-Step 'w6.3-1-graph-list-before' 'W6.3 (#183) step 1: rpworker graph list: the three restore targets must be empty.' {
        & $worker graph list --config $labConfig }
    $before = Get-Content (Join-Path $RunDir 'w6.3-1-graph-list-before.txt') -Raw
    if ($codes['w6.3-1-graph-list-before'] -ne 0 -or $before -notmatch '(?m)^0 item\(s\) in the three restore targets') {
        throw 'the restore targets are not empty (or graph list failed); nothing is cleaned: run the live cleanup test first if what they hold can go'
    }
    $testStarted = $true
    $codes['w6.3-2-backup-content'] = Invoke-Step 'w6.3-2-backup-content' 'W6.3 (#183) step 2: rptests "live backup content*" (worker/tests/backup_content_live_test.cpp): the 14 real files restored three times through the guarded path; (a) as they are, (b) one byte of team-meeting-notes.txt changed in its restored copy, (c) every export over a 1-byte cap. It cleans after each.' {
        & $tests 'live backup content*' }
    Remove-Item Env:RP_LIVE_EVIDENCE_FILE -ErrorAction SilentlyContinue
    $codes['w6.3-3-graph-list-after'] = Invoke-Step 'w6.3-3-graph-list-after' 'W6.3 (#183) step 3: rpworker graph list after the live test: the targets empty again.' {
        & $worker graph list --config $labConfig }
    $codes['w6.3-4-upload'] = Invoke-Step 'w6.3-4-upload-console' 'W6.3 (#183) step 4: C5.7''s upload harness on a job the Cloud dispatches with no canary_cursor: the service runs it, both verifiers on the sent folder, POST /v1/results 202. Its own text is w6.3-4-upload.txt.' {
        & pwsh -NoProfile -File $upload -Prefix 'c63' -Title 'W6.3 (#183) step 4, by C5.7''s upload harness: a run without canaries from a job the Cloud dispatched, its files checked against the backup''s copy, lands in the stack''s DB.' -EvidenceDir $RunDir -Evidence 'w6.3-4-upload.txt' }
} finally {
    Remove-Item Env:RP_LIVE_EVIDENCE_FILE -ErrorAction SilentlyContinue
    if ($testStarted) {
        $codes['w6.3-5-cleanup'] = Invoke-Step 'w6.3-5-cleanup' 'W6.3 (#183) step 6: the live cleanup test empties the three restore targets, then rpworker graph list shows them empty.' {
            & $tests 'live cleanup*'
            $c = $LASTEXITCODE
            & $worker graph list --config $labConfig
            if ($c -ne 0) { $global:LASTEXITCODE = $c }
        }
    } else {
        Write-Host '--- w6.3-5-cleanup not run: the live test did not start, so the targets hold nothing of this run'
    }
    Remove-Item Env:RP_LIVE, Env:RP_LIVE_RESTORE, Env:RP_LIVE_VEEAM_CA_FILE -ErrorAction SilentlyContinue
}

''
'steps:'
$failed = @()
foreach ($k in $codes.Keys) { "  $k exit $($codes[$k])"; if ($codes[$k] -ne 0) { $failed += $k } }
$shape = @(Test-Shape)
"shape: $($shape.Count) miss(es)"
$shape | ForEach-Object { "  $_" }
$files = @(Get-ChildItem $RunDir -File -Recurse | Where-Object { $_.Extension -in '.txt', '.json' })
$dirty = @()
foreach ($f in $files) { foreach ($why in Test-Clean $f.FullName) { $dirty += "$($f.FullName): $why" } }
"files checked by shape: $($files.Count); findings: $($dirty.Count)"
$dirty | ForEach-Object { "  $_" }

if ($failed.Count -gt 0 -or $shape.Count -gt 0 -or $dirty.Count -gt 0) {
    "NOT copied into $evidenceDir (failed steps: $($failed -join ', '); shape misses: $($shape.Count); findings: $($dirty.Count)). The run folder stays: $RunDir"
    exit 1
}
if ($NoCopy) { "not copied (-NoCopy); the run folder stays: $RunDir"; exit 0 }
foreach ($name in 'w6.3-1-graph-list-before.txt', 'w6.3-2-backup-content.txt', 'w6.3-results.json', 'w6.3-3-graph-list-after.txt', 'w6.3-4-upload.txt', 'w6.3-5-cleanup.txt') {
    Copy-Item (Join-Path $RunDir $name) (Join-Path $evidenceDir $name) -Force
}
"copied into $evidenceDir; the run folder stays: $RunDir"
exit 0

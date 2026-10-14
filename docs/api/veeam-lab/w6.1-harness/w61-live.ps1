# W6.1 (#181): the export spike, run by hand from an ELEVATED PowerShell 7 on the Veeam server
# (docs/decisions.md 2026-10-14, W6.1). In order:
#   1. rpworker graph list                      the three restore targets, empty (else it stops)
#   2. rptests "live export spike*"             the spike (worker/tests/export_spike_live_test.cpp):
#                                               14 exports, the restore of the same 14 through the
#                                               guarded path, the read-back and the comparison;
#                                               it does not clean
#   3. rpworker graph list --hash               a second tool's reading of the restored copies
#   4. rptests "live cleanup*" + graph list     the targets emptied again (in the finally)
# Everything is written to a run folder outside the repository first. Only when every step exited 0
# and no file holds a token-, PFX-, PEM- or key-shaped value are the files copied into
# docs/api/veeam-lab/ (w6.1-*.txt, w6.1-results.json, w6.1-recording/), the copy last, so a failed
# run never replaces committed evidence. Secrets: the test and the Worker read the vault; this script
# reads no secret at all, so its check is by shape, and the recording's own scrubber (which knows the
# vault's values) refused any file a value survived in. Before the commit, also run
# `python tools/fixture_secret_scan.py` from worker/ and `audit-evidence.ps1 -Path ..\veeam-lab\w6.1-*`.
#
#   pwsh -File docs\api\veeam-lab\w6.1-harness\w61-live.ps1
#   pwsh -File docs\api\veeam-lab\w6.1-harness\w61-live.ps1 -NoCopy     # leave the evidence in the run folder
[CmdletBinding()]
param(
    [string]$RunDir = (Join-Path $env:LOCALAPPDATA ("RestoreProof\lab\w6.1-" + (Get-Date -Format 'yyyyMMddTHHmmss'))),
    [string]$Repo = 'C:\restoreproof',
    [switch]$NoCopy
)
Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

$worker = Join-Path $Repo 'worker\build\dev\rpworker.exe'
$tests = Join-Path $Repo 'worker\build\dev\rptests.exe'
$labConfig = Join-Path $env:LOCALAPPDATA 'RestoreProof\lab\config.json'
$caFile = Join-Path $Repo 'worker\tests\fixtures\veeam\rest-certificate.pem'
$evidenceDir = Join-Path $Repo 'docs\api\veeam-lab'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'run from an elevated shell: the restore exports the organisation certificate from LocalMachine\My'
    exit 64
}
foreach ($f in $worker, $tests, $labConfig, $caFile) { if (-not (Test-Path $f)) { Write-Error "missing: $f"; exit 64 } }
New-Item -ItemType Directory -Force $RunDir | Out-Null
"run folder $RunDir"

# One command's output, as the console shows it, with its exit code, into a run-folder file.
# Returns the exit code alone; progress goes through Write-Host, so the caller's variable holds
# only the code.
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

$codes = [ordered]@{}
$env:RP_LIVE = '1'
$env:RP_LIVE_RESTORE = '1'
$env:RP_LIVE_VEEAM_CA_FILE = $caFile
$env:RP_LIVE_EVIDENCE_FILE = Join-Path $RunDir 'w6.1-results.json'
$env:RP_LIVE_RECORD_DIR = Join-Path $RunDir 'w6.1-recording'
try {
    $codes['w6.1-1-graph-list-before'] = Invoke-Step 'w6.1-1-graph-list-before' 'W6.1 (#181) step 1: rpworker graph list before the spike: the three restore targets must be empty.' {
        & $worker graph list --config $labConfig }
    $before = Get-Content (Join-Path $RunDir 'w6.1-1-graph-list-before.txt') -Raw
    if ($codes['w6.1-1-graph-list-before'] -ne 0 -or $before -notmatch '(?m)^0 item\(s\) in the three restore targets') {
        throw 'the restore targets are not empty (or graph list failed); run the live cleanup test first'
    }
    $codes['w6.1-2-export-spike'] = Invoke-Step 'w6.1-2-export-spike' 'W6.1 (#181) step 2: rptests "live export spike*" (worker/tests/export_spike_live_test.cpp): the 14 exports, the restore through the guarded path, the read-back and the comparison. The copies are left for step 3.' {
        & $tests 'live export spike*' }
    $codes['w6.1-3-graph-list-hash-after'] = Invoke-Step 'w6.1-3-graph-list-hash-after' 'W6.1 (#181) step 3: rpworker graph list --hash right after the spike: the restored copies as a second tool reads them (bytes SHA-256).' {
        & $worker graph list --hash --config $labConfig }
} finally {
    # The cleanup test records nothing: it refuses a recording folder that isn't new or empty, and
    # the spike's folder holds the spike's exchanges by now.
    Remove-Item Env:RP_LIVE_RECORD_DIR, Env:RP_LIVE_EVIDENCE_FILE -ErrorAction SilentlyContinue
    $codes['w6.1-4-cleanup'] = Invoke-Step 'w6.1-4-cleanup' 'W6.1 (#181) step 4: the live cleanup test empties the three restore targets, then rpworker graph list shows them empty.' {
        & $tests 'live cleanup*'
        $c = $LASTEXITCODE
        & $worker graph list --config $labConfig
        if ($c -ne 0) { $global:LASTEXITCODE = $c }
    }
    Remove-Item Env:RP_LIVE, Env:RP_LIVE_RESTORE, Env:RP_LIVE_VEEAM_CA_FILE, Env:RP_LIVE_EVIDENCE_FILE, Env:RP_LIVE_RECORD_DIR -ErrorAction SilentlyContinue
}

''
'steps:'
$failed = @()
foreach ($k in $codes.Keys) { "  $k exit $($codes[$k])"; if ($codes[$k] -ne 0) { $failed += $k } }
$files = @(Get-ChildItem $RunDir -File -Recurse | Where-Object { $_.Extension -in '.txt', '.json' })
$dirty = @()
foreach ($f in $files) { foreach ($why in Test-Clean $f.FullName) { $dirty += "$($f.FullName): $why" } }
"files checked by shape: $($files.Count); findings: $($dirty.Count)"
$dirty | ForEach-Object { "  $_" }

if ($failed.Count -gt 0 -or $dirty.Count -gt 0) {
    "NOT copied into $evidenceDir (failed steps: $($failed -join ', '); findings: $($dirty.Count)). The run folder stays: $RunDir"
    exit 1
}
if ($NoCopy) { "not copied (-NoCopy); the run folder stays: $RunDir"; exit 0 }
foreach ($name in 'w6.1-1-graph-list-before.txt', 'w6.1-2-export-spike.txt', 'w6.1-3-graph-list-hash-after.txt', 'w6.1-4-cleanup.txt', 'w6.1-results.json') {
    Copy-Item (Join-Path $RunDir $name) (Join-Path $evidenceDir $name) -Force
}
$recordingOut = Join-Path $evidenceDir 'w6.1-recording'
if (Test-Path $recordingOut) { Remove-Item -Recurse -Force $recordingOut }
Copy-Item (Join-Path $RunDir 'w6.1-recording') $recordingOut -Recurse
"copied into $evidenceDir; the run folder stays: $RunDir"
exit 0

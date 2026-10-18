# W7.2 (#81): the live Done-when (docs/decisions.md 2026-10-18, "W7.2 (#81)", points 4 and 5):
# "Removing one Graph permission makes exactly one check fail with the permission's name", and the
# two machine faults doctor exists for, each shown as exactly one problem line whose fix, run as
# printed, makes doctor clean again. Run from an ELEVATED PowerShell 7 on this laptop (the Veeam
# server), with the Worker installed by W7.1's installer (the RestoreProof service from
# %ProgramFiles%\RestoreProof, registered with the Compose stack, which is up), the lab profile at
# %LOCALAPPDATA%\RestoreProof\lab\lab-profile.json, and the Microsoft.Graph.Authentication module:
#
#   pwsh -File docs\api\veeam-lab\w7.2-harness\w72-live.ps1 [-SkipConsent] [-NoCopy]
#
# It asks before it starts, since it takes grants away. In order:
#   1. doctor --client <the lab profile> --json: no problem line
#   2. the service's Read entry taken off Veeam's key file (as a certificate renewal leaves it):
#      doctor shows exactly one problem, veeam.org[n].cert[n].key_file missing_ace, whose fix is the
#      key file's icacls line; that line run as printed; doctor clean
#   3. the service's Read entry taken off the vault: exactly one problem, vault.acl
#      no_service_read, whose fix is `rpworker vault grant`; run as printed; doctor clean
#   4. (not with -SkipConsent) the lab app's admin consent of Lists.SelectedOperations.Selected
#      deleted, signed in as the lab's admin: doctor every 30 s, at most 15 minutes, until the role's
#      line is a problem; exactly one problem, naming the role; then Initialize-RestoreProofTenant.ps1
#      as w70-live.ps1 runs it (it consents the role again: one change); doctor every 30 s until clean
# Every grant taken is put back in the finally, whatever happened. Only when every step held is the
# text copied to docs\api\veeam-lab\w7.2-done-when.txt, the copy last; then run
# `python tools/fixture_secret_scan.py` from worker\ and `audit-evidence.ps1` before the commit.
#Requires -Version 7.4
param([switch]$SkipConsent, [switch]$NoCopy)
. (Join-Path $PSScriptRoot '..\w4.8-harness\w48-run.ps1')

$RunDir = Join-Path $env:LOCALAPPDATA ("RestoreProof\lab\w7.2-" + (Get-Date -Format 'yyyyMMddTHHmmss'))
$LabProfile = Join-Path $env:LOCALAPPDATA 'RestoreProof\lab\lab-profile.json'
$Exe = Join-Path $env:ProgramFiles 'RestoreProof\rpworker.exe'
$Vault = Join-Path $script:W48Root 'vault.bin'
$Setup = Join-Path $script:Repo 'tools\tenant-setup\Initialize-RestoreProofTenant.ps1'
$Lab = @{
    TenantId = 'bcd6bd1a-ea42-489d-aa28-2c19a44ad146'
    SiteUrl = 'https://restoreprooflab.sharepoint.com/sites/RestoreTest'
    OneDriveUser = 'alice@RestoreProofLab.onmicrosoft.com'
}
$GraphAppId = '00000003-0000-0000-c000-000000000000'
$Role = 'Lists.SelectedOperations.Selected'
function Get-Utc { [DateTime]::UtcNow.ToString('s') + 'Z' }

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'run from an elevated shell'; exit 64
}
if (-not (Test-Path -LiteralPath $Exe)) { Write-Error "$Exe is not there: install the Worker with W7.1's installer first"; exit 64 }
if (-not (Get-CimInstance Win32_Service -Filter "Name='$script:W48Service'")) { Write-Error 'the RestoreProof service is not installed'; exit 64 }
if (-not (Test-Path -LiteralPath $LabProfile)) { Write-Error "$LabProfile is not there"; exit 64 }
if (-not $SkipConsent -and -not (Get-Module -ListAvailable Microsoft.Graph.Authentication)) {
    Write-Error 'Microsoft.Graph.Authentication is not installed (or run with -SkipConsent)'; exit 64
}
$answer = Read-Host "This takes the service's entries off Veeam's key file and the vault$(if (-not $SkipConsent) { ", and the lab app's $Role consent" }), and puts them back. Go on? (y/N)"
if ($answer -ne 'y') { exit 64 }
New-Item -ItemType Directory -Force $RunDir | Out-Null
$serviceSid = (& sc.exe showsid $script:W48Service | Where-Object { $_ -match 'SERVICE SID' }) -replace '.*: ', ''

$t = [System.Collections.Generic.List[string]]::new()
function Add-Line { param([Parameter(ValueFromPipeline)]$Line) process { foreach ($l in @($Line)) { $script:t.Add("$l"); Write-Host "$l" } } }
Add-Line ("W7.2 (#81) Done-when, live, on this laptop (the Veeam server): rpworker doctor on a Worker W7.1's installer installed; one fault at a time, each one problem line whose fix, run as printed, makes doctor clean again; the Graph permission by the lab app's consent. $(Get-Utc), commit $(git -C $script:Repo rev-parse --short HEAD), branch $(git -C $script:Repo branch --show-current)")
Add-Line ("Windows, PowerShell $($PSVersionTable.PSVersion); $((& $Exe --version) -join ' ') at $Exe; sc showsid ${script:W48Service}: $serviceSid")

# One doctor run: its lines (the console's, as printed) and its --json (ids, results, codes).
$script:runs = 0
function Invoke-Doctor([string]$Label) {
    $script:runs++
    $json = Join-Path $RunDir ("doctor-{0:d2}.json" -f $script:runs)
    $lines = @(& $Exe doctor --client $LabProfile --json $json 2>&1 | ForEach-Object { "$_" })
    $code = $LASTEXITCODE
    $doc = if (Test-Path -LiteralPath $json) { Get-Content -LiteralPath $json -Raw | ConvertFrom-Json } else { $null }
    $problems = @(if ($doc) { $doc.checks | Where-Object result -eq 'problem' })
    [pscustomobject]@{ Label = $Label; Code = $code; Lines = $lines; Problems = $problems }
}
function Add-Doctor($Run) {
    Add-Line ("-- $(Get-Utc) doctor ($($Run.Label)): exit $($Run.Code); problems: $(@($Run.Problems | ForEach-Object { "$($_.id) $($_.code)" }) -join ', ')")
    Add-Line ($Run.Lines)
}
function Assert-Clean($Run) {
    if ($Run.Code -ne 0 -or $Run.Problems.Count -ne 0) { throw "doctor ($($Run.Label)) is not clean" }
}
# The one problem line of a run, by its id; its fix as printed.
function Get-OneFix($Run, [string]$IdPattern, [string]$Code) {
    if ($Run.Problems.Count -ne 1 -or $Run.Problems[0].id -notmatch $IdPattern -or $Run.Problems[0].code -ne $Code) {
        throw "doctor ($($Run.Label)) did not show exactly one problem $IdPattern $Code"
    }
    $line = @($Run.Lines | Where-Object { $_ -like 'problem: *' })
    if ($line.Count -ne 1) { throw "doctor ($($Run.Label)) printed $($line.Count) problem lines" }
    [regex]::Match($line[0], '\(fix: (.*)\)$').Groups[1].Value
}

$ok = $false
$keyFiles = @()
$keyTaken = $false
$vaultTaken = $false
$consentTaken = $false
try {
    # 1
    Add-Line ("`n== 1. doctor on the Worker as installed ==")
    $first = Invoke-Doctor 'as installed'
    Add-Doctor $first
    Assert-Clean $first

    # 2
    Add-Line ("`n== 2. the service's entry taken off Veeam's key file ==")
    $keyFiles = @(Get-W48KeyFile)
    if ($keyFiles.Count -lt 1) { throw 'no organisation certificate key file found' }
    $key = $keyFiles[0]
    & icacls.exe $key.File /remove:g "*$serviceSid" /Q | Out-Null
    $keyTaken = $true
    Add-Line ("icacls <the key file of certificate $($key.Thumbprint)> /remove:g *$serviceSid")
    $broken = Invoke-Doctor 'key file entry removed'
    Add-Doctor $broken
    $fix = Get-OneFix $broken '^veeam\.org\[\d+\]\.cert\[\d+\]\.key_file$' 'missing_ace'
    if ($fix -notmatch '^icacls "[^"]+" /grant "\*S-1-5-80-[\d-]+:\(R\)"$') { throw "the fix is not the key file's icacls line: $fix" }
    Add-Line ("the fix, run as printed: $($fix -replace '[0-9a-f]{32}_[0-9a-f-]{36}', '<Veeam key file>')")
    Invoke-Expression "& $fix" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'the printed icacls line failed' }
    $keyTaken = $false
    $fixed = Invoke-Doctor 'key file entry granted again'
    Add-Doctor $fixed
    Assert-Clean $fixed

    # 3
    Add-Line ("`n== 3. the service's entry taken off the vault ==")
    & icacls.exe $Vault /remove:g "*$serviceSid" /Q | Out-Null
    $vaultTaken = $true
    Add-Line ("icacls $Vault /remove:g *$serviceSid")
    $broken = Invoke-Doctor 'vault entry removed'
    Add-Doctor $broken
    $fix = Get-OneFix $broken '^vault\.acl$' 'no_service_read'
    if ($fix -ne 'rpworker vault grant "NT SERVICE\RestoreProof"') { throw "the fix is not the vault grant: $fix" }
    Add-Line ("the fix, run as printed (rpworker being $Exe): $fix")
    & $Exe vault grant 'NT SERVICE\RestoreProof' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'rpworker vault grant failed' }
    $vaultTaken = $false
    $fixed = Invoke-Doctor 'vault entry granted again'
    Add-Doctor $fixed
    Assert-Clean $fixed

    # 4
    if ($SkipConsent) {
        Add-Line ("`n== 4. the Graph permission: skipped (-SkipConsent) ==")
    } else {
        Add-Line ("`n== 4. the lab app's $Role consent deleted ==")
        $profileValues = Get-Content -LiteralPath $LabProfile -Raw | ConvertFrom-Json
        Import-Module Microsoft.Graph.Authentication
        Connect-MgGraph -TenantId $Lab.TenantId -Scopes 'AppRoleAssignment.ReadWrite.All', 'Application.Read.All' -NoWelcome
        $app = (Invoke-MgGraphRequest GET "/v1.0/servicePrincipals?`$filter=appId eq '$($profileValues.graph_client_id)'").value
        $graph = (Invoke-MgGraphRequest GET "/v1.0/servicePrincipals?`$filter=appId eq '$GraphAppId'").value
        if (@($app).Count -ne 1 -or @($graph).Count -ne 1) { throw 'the lab app or Graph''s service principal was not found once' }
        $roleId = ($graph[0].appRoles | Where-Object value -eq $Role).id
        $assignment = (Invoke-MgGraphRequest GET "/v1.0/servicePrincipals/$($app[0].id)/appRoleAssignments").value | Where-Object appRoleId -eq $roleId
        if (@($assignment).Count -ne 1) { throw "the app has no single $Role consent to remove" }
        Invoke-MgGraphRequest DELETE "/v1.0/servicePrincipals/$($app[0].id)/appRoleAssignments/$($assignment[0].id)" | Out-Null
        $consentTaken = $true
        $removedAt = [DateTime]::UtcNow
        Add-Line ("$(Get-Utc) DELETE the app's appRoleAssignment of $Role (role $roleId)")
        $seen = $null
        for ($i = 0; $i -lt 30 -and -not $seen; $i++) {
            $run = Invoke-Doctor "the consent removed, attempt $($i + 1)"
            Add-Line ("$(Get-Utc) attempt $($i + 1): exit $($run.Code), problems: $(@($run.Problems | ForEach-Object { "$($_.id) $($_.code)" }) -join ', ')")
            if ($run.Problems | Where-Object { $_.id -eq "client[1].graph.role.$Role" }) { $seen = $run } else { Start-Sleep -Seconds 30 }
        }
        if (-not $seen) { throw "doctor did not see $Role go within 15 minutes" }
        Add-Line ("Entra issued a token without it $([int]([DateTime]::UtcNow - $removedAt).TotalSeconds) s after the DELETE")
        Add-Doctor $seen
        $null = Get-OneFix $seen "^client\[1\]\.graph\.role\.$([regex]::Escape($Role))$" 'role_missing'
        if (-not ($seen.Lines | Where-Object { $_ -like "problem: *the app's token lacks $Role*" })) { throw 'the line does not name the role' }
        Add-Line ("`n-- Initialize-RestoreProofTenant.ps1, as w70-live.ps1 runs it (sign in as the lab's admin)")
        $profileOut = Join-Path $RunDir 'setup-profile.json'
        $setupLines = @(& pwsh -NoProfile -File $Setup -TenantId $Lab.TenantId -SiteUrl $Lab.SiteUrl -OneDriveUser $Lab.OneDriveUser -Worker $Exe -ProfileFile $profileOut 2>&1 | ForEach-Object { "$_" })
        Add-Line ($setupLines)
        if ($LASTEXITCODE -ne 0 -or -not ($setupLines -match '^grants: ok$')) { throw 'the setup script did not end with grants: ok' }
        $consentTaken = $false
        $clean = $null
        for ($i = 0; $i -lt 30 -and -not $clean; $i++) {
            $run = Invoke-Doctor "the consent made again, attempt $($i + 1)"
            Add-Line ("$(Get-Utc) attempt $($i + 1): exit $($run.Code)")
            if ($run.Code -eq 0 -and $run.Problems.Count -eq 0) { $clean = $run } else { Start-Sleep -Seconds 30 }
        }
        if (-not $clean) { throw 'doctor was not clean within 15 minutes of the setup script' }
        Add-Doctor $clean
    }
    $ok = $true
} catch {
    Add-Line ("`n!! FAILED: $($_.Exception.Message)")
} finally {
    Add-Line ("`n== put back ==")
    try {
        if ($keyTaken) { foreach ($k in $keyFiles) { & icacls.exe $k.File /grant "*${serviceSid}:(R)" /Q | Out-Null }; Add-Line ('the key file entry granted again') }
        if ($vaultTaken) { & $Exe vault grant 'NT SERVICE\RestoreProof' | Out-Null; Add-Line ('the vault entry granted again') }
        if ($consentTaken) {
            Add-Line ("the $Role consent is still removed: running the setup script to put it back")
            & pwsh -NoProfile -File $Setup -TenantId $Lab.TenantId -SiteUrl $Lab.SiteUrl -OneDriveUser $Lab.OneDriveUser -Worker $Exe -ProfileFile (Join-Path $RunDir 'putback-profile.json') 2>&1 | ForEach-Object { Add-Line "$_" }
        }
        $last = Invoke-Doctor 'at the end'
        Add-Doctor $last
    } catch { Add-Line ("!! putting back failed: $($_.Exception.Message); put back by hand: the key file's and the vault's entries, the app's $Role consent") }
    $text = ($t -join "`n") -replace '[0-9a-f]{32}_[0-9a-f-]{36}', '<Veeam key file>'
    $runFile = Join-Path $RunDir 'w7.2-done-when.txt'
    [IO.File]::WriteAllText($runFile, $text.Replace("`r`n", "`n") + "`n", [Text.UTF8Encoding]::new($false))
    "run text: $runFile"
}
if (-not $ok) { Write-Error 'the Done-when did not hold; nothing copied into the repository'; exit 1 }
if (-not $NoCopy) { Save-W48Evidence 'w7.2-done-when.txt' $text }

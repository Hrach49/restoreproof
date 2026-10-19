<#
.SYNOPSIS
    Takes the RestoreProof Worker off this machine (W7.3, docs/decisions.md 2026-10-19 point
    4): the service, the entries on Veeam's key files, the exe folder, the Apps & features
    entry, the vault and the run folders; the log stays unless -Full.

.DESCRIPTION
    Run it elevated: from Apps & features, from the unpacked package, or from
    %ProgramFiles%\RestoreProof. It asks nothing. Nothing is removed before step 6: every stop
    before it leaves the Worker installed (stopped from step 3 on; `rpworker service start`
    brings it back).

    In order: the checks (a service installed from another exe is refused); the wait for a run
    in progress (state\running.json, up to -WaitMinutes); `rpworker service stop`; a record
    still there after the stop makes one `service start`, the wait again and one more stop, so
    the service's own recovery cleans the restore targets (no restore is ever cut in half);
    one `rpworker outbox flush`, then the runs that never reached the Cloud named; `rpworker
    cloud revoke`; the service account's Read entry taken off each organisation certificate's
    key file (`rpworker veeam list`); `rpworker service uninstall`; vault.bin and every file
    under state\, runs\, outbox\, sent\ and failed\ overwritten once and deleted (no erasure is
    guaranteed on an SSD or inside a volume snapshot: the secrets are worthless once the Worker
    is revoked); config.json and the two PEM files deleted; %ProgramFiles%\RestoreProof and the
    Apps entry removed; anything else under the data folder named and left. -Full also removes
    logs\ and the data folder whole. -WhatIf prints `would: ...` lines and removes nothing.

.PARAMETER Full
    Remove logs\ and the data folder itself too (everything of RestoreProof).
.PARAMETER WaitMinutes
    How long to wait for a run in progress before stopping with nothing changed: 30.
.PARAMETER ProgramDir
    Where the exe is: %ProgramFiles%\RestoreProof.
.PARAMETER Root
    The Worker's data folder: %ProgramData%\RestoreProof.
.PARAMETER Worker
    The rpworker to run; default <ProgramDir>\rpworker.exe. The tests name a fake.
.PARAMETER MachineModule
    The module that reads this machine (WorkerMachine.psm1 beside this script); the tests give
    tests\FakeMachine.psm1.

.EXAMPLE
    pwsh -NoProfile -File Uninstall-RestoreProofWorker.ps1
.EXAMPLE
    pwsh -NoProfile -File Uninstall-RestoreProofWorker.ps1 -Full -WhatIf
#>
#Requires -Version 7.4
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ProgramDir = '',
    [string]$Root = '',
    [string]$Worker = '',
    [string]$ServiceName = 'RestoreProof',
    [string]$MachineModule = '',
    [switch]$Full,
    [double]$WaitMinutes = 30,
    # How often the run record is read while waiting (the tests shorten it).
    [int]$PollSeconds = 10,
    [switch]$SkipElevationCheck
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$OutputEncoding = [Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)

Import-Module (Join-Path $PSScriptRoot 'RestoreProofWorker.psm1') -Force
if (-not $MachineModule) { $MachineModule = Join-Path $PSScriptRoot 'WorkerMachine.psm1' }
Import-Module $MachineModule -Force

if (-not $ProgramDir) { $ProgramDir = Join-Path $env:ProgramFiles 'RestoreProof' }
if (-not $Root) { $Root = Join-Path $env:ProgramData 'RestoreProof' }
$Exe = Join-Path $ProgramDir 'rpworker.exe'
if (-not $Worker) { $Worker = $Exe }
$ConfigPath = Join-Path $Root 'config.json'
# Never in the folder this removes.
Set-Location $env:SystemRoot

$script:Changes = 0
$script:ProblemCount = 0

function Say([string]$Line) { Write-Output $Line }
function Changed([string]$What) { $script:Changes++; Say "change: $What" }
function Would([string]$What) { Say "would: $What" }
function Problem([string]$What) { $script:ProblemCount++; Say "problem: $What" }
function Stop-Uninstall([string]$Why) { throw "problem: $Why Nothing was removed; the Worker is installed as it was." }

# As the installer's: the Worker run with `Arguments`, both streams merged and told apart by
# kind; nothing of its output touches a file.
function Invoke-Worker([string[]]$Arguments) {
    $all = @(& $Worker @Arguments 2>&1)
    $code = $LASTEXITCODE
    $out = @($all | Where-Object { $_ -is [string] })
    $err = @($all | Where-Object { $_ -isnot [string] } | ForEach-Object { "$_" })
    [pscustomobject]@{
        Code = $code
        Out  = ($out -join "`n") + $(if ($out.Count) { "`n" })
        Err  = ($err -join "`n") + $(if ($err.Count) { "`n" })
    }
}

function Get-FirstLine([string]$Text) {
    $lines = @(($Text -split "`r?`n") | Where-Object { $_ -ne '' })
    if ($lines.Count -eq 0) { return '(no output)' }
    $lines[0]
}

function Get-PathAcl([string]$Path) {
    [IO.FileSystemAclExtensions]::GetAccessControl([IO.FileInfo]::new($Path), [Security.AccessControl.AccessControlSections]'Access')
}

function Set-PathAcl([string]$Path, $Acl) {
    [IO.FileSystemAclExtensions]::SetAccessControl([IO.FileInfo]::new($Path), $Acl)
}

function Test-KeyFileEntry([string]$Path, [string]$Sid) {
    $rules = @((Get-PathAcl $Path).GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]))
    @($rules | Where-Object { $_.IdentityReference.Value -eq $Sid -and $_.AccessControlType -eq 'Allow' }).Count -gt 0
}

# The wait for the run in progress (point 4 steps 2 and 4): the record read every PollSeconds
# until it is gone, one line a minute; past the budget the uninstall stops with nothing removed.
function Wait-ForNoRun([string]$Stage) {
    $budget = $WaitMinutes * 60
    $waited = 0.0
    $said = -1
    while ($true) {
        $record = Get-RunRecord -Root $Root
        $plan = Get-RunPlan -RecordPresent ($null -ne $record) -WaitedSeconds $waited -BudgetSeconds $budget
        if ($plan -eq 'go') { return }
        if ($WhatIfPreference) { Would "wait for run $($record.RunId) to end ($Stage)"; return }
        if ($plan -eq 'stop') {
            Stop-Uninstall "run $($record.RunId) is still in progress after $WaitMinutes min ($Stage); rpworker doctor shows it, and docs/worker-config.md ""The operator's two ways out"" says what to do."
        }
        $minute = [int][Math]::Floor($waited / 60)
        if ($minute -ne $said) { Say "waiting: run $($record.RunId) in progress for $minute min ($Stage; up to $WaitMinutes min)"; $said = $minute }
        Start-Sleep -Seconds $PollSeconds
        $waited += $PollSeconds
    }
}

function Invoke-ServiceStop {
    if (-not $PSCmdlet.ShouldProcess($ServiceName, 'rpworker service stop')) { Would 'rpworker service stop'; return }
    $stop = Invoke-Worker @('service', 'stop')
    if ($stop.Code -ne 0) { Stop-Uninstall "rpworker service stop failed: $(Get-FirstLine ($stop.Err + $stop.Out))" }
    if ($stop.Out -match '(?m)^stopped ') { Changed "rpworker service stop ($(Get-FirstLine $stop.Out))" } else { Say "ok: $(Get-FirstLine $stop.Out)" }
}

# Every file under `Folder` overwritten and deleted, then the folder; a file that can't be is
# one problem line (counted in $script:ProblemCount) and the rest goes on. Its lines are its
# output: the caller reads the count, not a return value.
function Remove-FolderOverwritten([string]$Folder) {
    $before = $script:ProblemCount
    foreach ($file in @(Get-ChildItem -LiteralPath $Folder -File -Recurse -Force)) {
        try { Remove-FileOverwritten -Path $file.FullName } catch { Problem "$($file.FullName) couldn't be overwritten and deleted ($($_.Exception.Message)); it stays" }
    }
    if ($script:ProblemCount -eq $before) { Remove-Item -LiteralPath $Folder -Recurse -Force; Changed "$Folder overwritten once and deleted" }
}

# ======================================================================================
try {
    $ServiceSid = Get-ServiceSid -ServiceName $ServiceName
    Say "RestoreProof Worker uninstaller: program folder $ProgramDir, data folder $Root, service $ServiceName ($ServiceSid)$(if ($Full) { ', -Full' })"

    # -- 1. the checks ------------------------------------------------------------------
    $facts = Get-MachineFacts
    $elevated = $SkipElevationCheck -or (Test-IsElevated)
    $problems = @(Test-Prerequisites -PSVersion $facts.PSVersion -Elevated $elevated -Is64Bit $facts.Is64Bit -IsWindows $facts.IsWindows)
    if ($problems.Count -gt 0) { throw ($problems -join "`n") }
    $service = Get-InstalledService -Name $ServiceName
    $serviceState = Test-InstalledService -Service $service -ExpectedCommandLine (Get-ServiceCommandLine -Exe $Exe)
    if ($serviceState -eq 'other') {
        Stop-Uninstall "the service $ServiceName runs $($service.PathName), not $Exe; this uninstall takes away only what Install-RestoreProofWorker.ps1 put there: rpworker service stop, then rpworker service uninstall by hand first."
    }
    $haveWorker = Test-Path -LiteralPath $Worker -PathType Leaf
    if ($haveWorker) {
        try { Say "ok: rpworker $(Get-WorkerVersion -Exe $Exe) at $Exe" } catch { Say "note: $($_.Exception.Message); the files are removed all the same" }
    } else {
        Say "note: no rpworker at ${Worker}: the Cloud isn't told, the outbox isn't sent and the key-file entries stay; the files are removed"
    }
    Say "ok: service $ServiceName is $(if ($serviceState -eq 'ok') { 'installed from ' + $Exe } else { 'not installed' })"

    # -- 2. and 3. the wait, the stop ----------------------------------------------------------
    if ($serviceState -eq 'ok') {
        Wait-ForNoRun 'before the stop'
        Invoke-ServiceStop
        # -- 4. a record the stop still caught: the service's own recovery, once ---------------
        if ($null -ne (Get-RunRecord -Root $Root) -and -not $WhatIfPreference) {
            Say 'note: a run was taken as the service stopped: it is started once more so its own recovery closes the run, waits for Veeam and cleans the restore targets'
            if ($PSCmdlet.ShouldProcess($ServiceName, 'rpworker service start')) {
                $start = Invoke-Worker @('service', 'start')
                if ($start.Code -ne 0) { Stop-Uninstall "rpworker service start failed: $(Get-FirstLine ($start.Err + $start.Out)); the run record state\running.json is still there." }
                Say "ok: $(Get-FirstLine $start.Out)"
            }
            Wait-ForNoRun 'after the restart'
            Invoke-ServiceStop
        }
    }

    # -- 5. the outbox, once -------------------------------------------------------------------
    $held = @()
    $unsent = @()
    if ($haveWorker) {
        $listed = Invoke-Worker @('vault', 'list')
        if ($listed.Code -eq 0) { $held = @(($listed.Out -split "`r?`n") | Where-Object { $_ -ne '' } | ForEach-Object { $_.Trim() }) }
        elseif ($listed.Err -notmatch ': vault file not found') { Say "note: rpworker vault list failed: $(Get-FirstLine ($listed.Err + $listed.Out))" }
        if ($held -ccontains 'cloud_api_token' -and (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
            if ($PSCmdlet.ShouldProcess('the outbox', 'rpworker outbox flush')) {
                $flush = Invoke-Worker @('outbox', 'flush', '--config', $ConfigPath, '--outbox', $Root)
                $summary = Read-OutboxSummary -Text $flush.Out
                if ($summary) { Say "ok: rpworker outbox flush: $($summary.Queued) queued, $($summary.Sent) sent, $($summary.Failed) failed" }
                else { Say "note: rpworker outbox flush: $(Get-FirstLine ($flush.Err + $flush.Out))" }
            } else { Would 'rpworker outbox flush' }
        } else { Say 'note: no API token in the vault: nothing of the outbox is sent' }
        $list = Invoke-Worker @('outbox', 'list', '--outbox', $Root)
        $summary = Read-OutboxSummary -Text $list.Out
        if ($summary) {
            $unsent = @($summary.Runs)
            if ($summary.Queued -gt 0 -or $summary.Failed -gt 0) {
                Say "note: $($summary.Queued + $summary.Failed) run(s) never reached the Cloud and go with the folder$(if ($unsent.Count) { ': ' + ($unsent -join ', ') })"
            } else { Say 'ok: the outbox holds no run that never reached the Cloud' }
        } else { Say "note: rpworker outbox list: $(Get-FirstLine ($list.Err + $list.Out))" }
    }

    # -- 6. the Cloud told ---------------------------------------------------------------------
    $workerId = '<worker id>'
    $recordPath = Join-Path $Root 'state\worker.json'
    if (Test-Path -LiteralPath $recordPath -PathType Leaf) {
        try { $workerId = [string](Get-Content -LiteralPath $recordPath -Raw | ConvertFrom-Json).worker_id } catch { $workerId = '<worker id>' }
    }
    $revokeByHand = "revoke this Worker in the Cloud: manage.py revoke-worker --worker-id $workerId, or the Workers page"
    $revoked = $false
    if ($haveWorker -and $held -ccontains 'cloud_api_token') {
        if ($PSCmdlet.ShouldProcess('the Cloud', 'rpworker cloud revoke')) {
            $revoke = Invoke-Worker @('cloud', 'revoke', '--config', $ConfigPath)
            switch (Get-RevokeOutcome -Code $revoke.Code) {
                'revoked' { Changed "rpworker cloud revoke ($(Get-FirstLine $revoke.Out))"; $revoked = $true }
                'unknown' { Say "ok: $(Get-FirstLine ($revoke.Err + $revoke.Out))"; $revoked = $true }
                'unreachable' { Say "note: the Cloud wasn't reached ($(Get-FirstLine ($revoke.Err + $revoke.Out))): $revokeByHand" }
                default { Say "note: rpworker cloud revoke failed ($(Get-FirstLine ($revoke.Err + $revoke.Out))): $revokeByHand" }
            }
        } else { Would 'rpworker cloud revoke' }
    } elseif ($haveWorker) { Say "note: no API token in the vault: the Cloud isn't told; $revokeByHand" }

    # -- 7. the key files ----------------------------------------------------------------------
    if ($haveWorker -and (Test-Path -LiteralPath $ConfigPath -PathType Leaf) -and $held -ccontains 'veeam_username') {
        $list = Invoke-Worker @('veeam', 'list', '--config', $ConfigPath)
        if ($list.Code -ne 0) {
            Say "note: rpworker veeam list failed: $(Get-FirstLine ($list.Err + $list.Out)); the account's entries on the organisation certificates' key files stay (icacls <key file> /remove:g *$ServiceSid)"
        } else {
            foreach ($organisation in @(Read-OrganisationThumbprints -Text $list.Out)) {
                foreach ($thumbprint in $organisation.Thumbprints) {
                    $keyFile = Get-CertificateKeyFile -Thumbprint $thumbprint
                    if (-not $keyFile) { Say "ok: $($organisation.Organisation): certificate $thumbprint has no key file on this machine"; continue }
                    if (-not (Test-KeyFileEntry -Path $keyFile -Sid $ServiceSid)) { Say "ok: $($organisation.Organisation): no entry of the account on the key file of $thumbprint"; continue }
                    if (-not $PSCmdlet.ShouldProcess($keyFile, "icacls /remove:g *$ServiceSid")) { Would "icacls `"$keyFile`" /remove:g *$ServiceSid ($($organisation.Organisation), $thumbprint)"; continue }
                    Set-PathAcl $keyFile (Remove-FileReadRule -Acl (Get-PathAcl $keyFile) -Sid $ServiceSid)
                    if (Test-KeyFileEntry -Path $keyFile -Sid $ServiceSid) { Problem "the key file of $thumbprint kept the account's entry (icacls `"$keyFile`" /remove:g *$ServiceSid)"; continue }
                    Changed "$($organisation.Organisation): the account's entry taken off the key file of $thumbprint (as icacls `"$keyFile`" /remove:g *$ServiceSid)"
                }
            }
        }
    } elseif ($haveWorker) { Say "note: no config or no Veeam account in the vault: the account's entries on the organisation certificates' key files stay" }

    # -- 8. the service ------------------------------------------------------------------------
    if ($serviceState -eq 'ok') {
        if ($PSCmdlet.ShouldProcess($ServiceName, 'rpworker service uninstall')) {
            $gone = Invoke-Worker @('service', 'uninstall')
            if ($gone.Code -ne 0) { Stop-Uninstall "rpworker service uninstall failed: $(Get-FirstLine ($gone.Err + $gone.Out))" }
            Changed "rpworker service uninstall ($(Get-FirstLine $gone.Out))"
        } else { Would 'rpworker service uninstall' }
    } else { Say "ok: no service $ServiceName to uninstall" }

    # -- 9. the data ---------------------------------------------------------------------------
    $present = @()
    # The script-block form: `ForEach-Object Name` honours -WhatIf and retrieves nothing.
    if (Test-Path -LiteralPath $Root -PathType Container) { $present = @(Get-ChildItem -LiteralPath $Root -Force | ForEach-Object { $_.Name }) }
    $plan = Get-UninstallPlan -Present $present -Full $Full.IsPresent
    foreach ($name in $plan.Overwrite) {
        $path = Join-Path $Root $name
        if (-not $PSCmdlet.ShouldProcess($path, 'overwrite once and delete')) { Would "overwrite once and delete $path"; continue }
        if (Test-Path -LiteralPath $path -PathType Container) {
            Remove-FolderOverwritten $path
        } else {
            try { Remove-FileOverwritten -Path $path; Changed "$path overwritten once and deleted" }
            catch { Problem "$path couldn't be overwritten and deleted ($($_.Exception.Message)); it stays" }
        }
    }
    foreach ($name in $plan.Delete) {
        $path = Join-Path $Root $name
        if (-not $PSCmdlet.ShouldProcess($path, 'delete')) { Would "delete $path"; continue }
        Remove-Item -LiteralPath $path -Force
        Changed "$path deleted"
    }
    foreach ($name in $plan.Left) { Say "note: $(Join-Path $Root $name) left: not the installer's" }

    # -- 10. the program folder and the Apps entry ---------------------------------------------
    if (Test-Path -LiteralPath $ProgramDir -PathType Container) {
        if ($PSCmdlet.ShouldProcess($ProgramDir, 'remove')) { Remove-Item -LiteralPath $ProgramDir -Recurse -Force; Changed "$ProgramDir removed" }
        else { Would "remove $ProgramDir" }
    } else { Say "ok: no $ProgramDir" }
    $entryName = Get-UninstallEntryName
    if ($null -ne (Get-UninstallEntry -Name $entryName)) {
        if ($PSCmdlet.ShouldProcess("Apps & features: $entryName", 'remove')) { Remove-UninstallEntry -Name $entryName; Changed 'the Apps & features entry removed' }
        else { Would 'remove the Apps & features entry' }
    } else { Say 'ok: no Apps & features entry' }

    # -- 11. the log and the folder ------------------------------------------------------------
    $leftLine = ''
    foreach ($name in $plan.Logs) {
        $path = Join-Path $Root $name
        if (-not $PSCmdlet.ShouldProcess($path, 'remove')) { Would "remove $path"; continue }
        Remove-Item -LiteralPath $path -Recurse -Force
        Changed "$path removed"
    }
    if ($plan.RemoveRoot -and (Test-Path -LiteralPath $Root -PathType Container)) {
        if ($PSCmdlet.ShouldProcess($Root, 'remove')) {
            if ($script:ProblemCount -eq 0) { Remove-Item -LiteralPath $Root -Recurse -Force; Changed "$Root removed" }
            else { Problem "$Root kept: a file in it couldn't be removed (above)" }
        } else { Would "remove $Root" }
    } elseif (-not $plan.RemoveRoot -and (Test-Path -LiteralPath (Join-Path $Root 'logs') -PathType Container)) {
        $leftLine = "left: $(Join-Path $Root 'logs') (the service's log; -Full removes it and the folder)"
    }

    # -- the summary ---------------------------------------------------------------------------
    Say "changes: $script:Changes"
    if ($leftLine) { Say $leftLine }
    Say 'vault.bin and the run folders: each file overwritten once, then deleted (no erasure is guaranteed on an SSD or inside a volume snapshot; the secrets are worthless once the Worker is revoked, the Graph certificate''s credential removed from the clients'' apps and the Veeam account''s password changed)'
    if (-not $revoked -and $haveWorker) { Say "next: $revokeByHand" }
    Say "next: the Worker's Graph certificate stays as a credential of each client's ""RestoreProof Worker"" app, its private key gone: the client's admin may remove it (docs/tenant-setup.md); the Veeam account is Veeam's console's"
    if ($script:ProblemCount -gt 0) { Say "problems: $script:ProblemCount"; exit 1 }
} finally {
    $held = $null
}

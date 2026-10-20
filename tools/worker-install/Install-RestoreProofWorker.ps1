<#
.SYNOPSIS
    Installs the RestoreProof Worker on this machine (W7.1, docs/decisions.md 2026-10-16): the
    exe, the folders and their ACLs, the config, the vault, the signing key, the Graph
    certificate, the grants, the service, its registration with the Cloud, its start.

.DESCRIPTION
    Run it elevated, from the unpacked release package, on the Veeam Backup for Microsoft 365
    server. It asks for what the Worker needs and nothing more: the Cloud URL, the Veeam URL, the
    Veeam account and its password, the install token (manage.py create-worker-token). The three
    secrets are read without echo and handed to `rpworker vault set` on stdin, never on a command
    line. The signing key and the Graph certificate are made, not asked. No client is named:
    each client's profile comes with its job from the Cloud.

    Every step reads first, prints `ok: ...` when nothing differs and `change: ...` when it
    wrote, and the run ends `changes: <n>`; a step that fails stops the run with its own line,
    the steps before it stay, and running it again continues from the first thing that differs.
    -WhatIf prints `would: ...` lines and writes nothing. -Upgrade (W7.4, docs/decisions.md
    2026-10-19 point 3) replaces an installed Worker with the package's: it waits for a run in
    progress to end, stops the service, keeps the installed files as <ProgramDir>\previous and
    starts the new ones; the config, the vault, the grants and the registration are not
    touched. A rollback (-Package "<ProgramDir>\previous") leaves previous\ as it is, so the same
    line run again continues. Without -Upgrade an exe that differs from the installed one stops
    the install; one that is missing (quarantined) is copied in again. Any stop after the
    service was stopped says so, with the line that starts it and the rollback. The uninstall
    is Uninstall-RestoreProofWorker.ps1 (W7.3). A service installed from another exe stops both.

    In order: the checks; the exe, its DLLs and the scripts into -ProgramDir, and the Apps &
    features entry; -Root and its six folders with
    their ACLs (the service account by its SID, Users nothing); config.json (kept when it is
    there and passes `rpworker config check`); the vault's names; `rpworker signer new-key`;
    New-WorkerGraphCertificate.ps1; `rpworker veeam list` and the Read ACE on each organisation
    certificate's key file; `rpworker service install`; `rpworker cloud register`; `rpworker
    service start`; the summary with the Worker's id.

.PARAMETER Package
    The folder holding rpworker.exe and its DLLs (the unpacked zip): this script's own folder.
.PARAMETER ProgramDir
    Where the exe goes: %ProgramFiles%\RestoreProof.
.PARAMETER Root
    The Worker's data folder: %ProgramData%\RestoreProof.
.PARAMETER Worker
    The rpworker to run; default <ProgramDir>\rpworker.exe once copied. The tests name a fake.
.PARAMETER MachineModule
    The module that reads this machine (WorkerMachine.psm1 beside this script); the tests give
    tests\FakeMachine.psm1.
.PARAMETER Answers
    The secrets for a run without a console (the tests'): keys veeam_password and
    cloud_install_token. At a console they are asked without echo.
.PARAMETER AllowRemoteVeeam
    Go on when Veeam's REST service is not on this machine (asked otherwise). No organisation
    certificate's key file is granted then: that Worker runs no restore until it is.
.PARAMETER VeeamThumbprint
    The SHA-1 thumbprint of Veeam's REST certificate, to confirm a certificate this machine
    doesn't hold without a question.
.PARAMETER Upgrade
    Replace the installed exe, DLLs and scripts with the package's (above); the rollback is
    -Upgrade -Package "<ProgramDir>\previous". Given with no service installed it is a plain
    install. A package without Uninstall-RestoreProofWorker.ps1 (0.1.0's) brings no script: the
    installed ones stay.
.PARAMETER WaitMinutes
    How long -Upgrade waits for a run in progress (state\running.json) before stopping with
    nothing changed: 30.
.PARAMETER Replace
    Write config.json again from the answers and ask the Veeam account and its password again,
    though they are there: the way to correct a URL or a password that step 8 or 10 found
    wrong, and to replace a config.json that fails `rpworker config check` or that someone
    other than SYSTEM, Administrators or this account owns. The signing key, the Graph
    certificate and the registration are kept.

.EXAMPLE
    pwsh -NoProfile -File Install-RestoreProofWorker.ps1
.EXAMPLE
    pwsh -NoProfile -File Install-RestoreProofWorker.ps1 -CloudUrl https://cloud.example.invalid -VeeamUrl https://localhost:4443 -WhatIf
#>
#Requires -Version 7.4
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$Package = '',
    [string]$ProgramDir = '',
    [string]$Root = '',
    [string]$Worker = '',
    [string]$ServiceName = 'RestoreProof',
    [string]$MachineModule = '',
    [string]$CloudUrl = '',
    [string]$CloudCaFile = '',
    [string]$WorkerName = '',
    [string]$VeeamUrl = '',
    [string]$VeeamCertificateFile = '',
    [string]$VeeamThumbprint = '',
    [switch]$AllowRemoteVeeam,
    [string]$VeeamUsername = '',
    [hashtable]$Answers = @{},
    [switch]$Replace,
    [switch]$Upgrade,
    [ValidateRange(0, 1440)][double]$WaitMinutes = 30,
    # How often the run record is read while waiting (the tests shorten it); 0 would never wait.
    [ValidateRange(1, 3600)][int]$PollSeconds = 10,
    [switch]$SkipElevationCheck,
    # Full control on the data folder for these SIDs too: the tests' own account (which would
    # otherwise lock itself out of its temporary root). Never given by a deployment.
    [string[]]$AlsoFullControl = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# What a native program reads from a pipe and what its output is read as: UTF-8.
$OutputEncoding = [Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)

Import-Module (Join-Path $PSScriptRoot 'RestoreProofWorker.psm1') -Force
if (-not $MachineModule) { $MachineModule = Join-Path $PSScriptRoot 'WorkerMachine.psm1' }
Import-Module $MachineModule -Force

if (-not $Package) { $Package = $PSScriptRoot }
if (-not $ProgramDir) { $ProgramDir = Join-Path $env:ProgramFiles 'RestoreProof' }
if (-not $Root) { $Root = Join-Path $env:ProgramData 'RestoreProof' }
$Exe = Join-Path $ProgramDir 'rpworker.exe'
if (-not $Worker) { $Worker = $Exe }
$ConfigPath = Join-Path $Root 'config.json'
$VeeamPemPath = Join-Path $Root 'veeam-rest.pem'
$CloudPemPath = Join-Path $Root 'cloud-ca.pem'
$CertificateScript = @((Join-Path $PSScriptRoot 'New-WorkerGraphCertificate.ps1'), (Join-Path $PSScriptRoot '..\tenant-setup\New-WorkerGraphCertificate.ps1')) |
    Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
$Interactive = -not [Console]::IsInputRedirected -and [Environment]::UserInteractive -and -not ([Environment]::GetCommandLineArgs() -contains '-NonInteractive')
$SecretNames = @('veeam_password', 'cloud_install_token')

# Who may own the data folder and a config.json kept there: SYSTEM, Administrators and the
# account running this (an owner may always rewrite the DACL, so anyone else's folder or file is
# theirs whatever its rules say).
$TrustedOwners = @('S-1-5-18', 'S-1-5-32-544', [Security.Principal.WindowsIdentity]::GetCurrent().User.Value)

$script:Changes = 0
$started = [DateTime]::UtcNow
$lastAnswerAt = $started
# Why this run stopped the service ('' while it hasn't, or once it started it again): a stop
# after that says the service is stopped and how to start it (the W7.3 review's second pass).
$script:StoppedFor = ''
# Not $script:Rollback: a variable's name ignores case, and $rollback is the rollback line.
$script:RollbackWhere = ''

function Say([string]$Line) { Write-Output $Line }
function Changed([string]$What) { $script:Changes++; Say "change: $What" }
function Would([string]$What) { Say "would: $What" }
function Stop-Install([string]$Why) {
    $state = ''
    if ($script:StoppedFor -eq 'upgrade') { $state = " The service $ServiceName is stopped, on the new files: rpworker service start starts it as it is, and the previous version is $($script:RollbackWhere)." }
    elseif ($script:StoppedFor) { $state = " The service $ServiceName is stopped: rpworker service start starts it." }
    throw "problem: $Why Nothing after this step was done; run the installer again once it is fixed.$state"
}

# Runs the Worker with `Arguments`, `Stdin` as one line when given (a secret: never an
# argument, as lab\entra\fill-worker-vault.ps1 and New-WorkerGraphCertificate.ps1 do); its exit
# code, stdout and stderr. Both streams are merged and told apart by kind (a native stderr line
# arrives as an error record, a stdout line as a string): no file, which a `2>file` redirection
# would be, and which -WhatIf would then refuse to write.
function Invoke-Worker([string[]]$Arguments, [string]$Stdin = $null) {
    # An exe that can't be run at all (gone, quarantined) is a failed run of its own (code -1),
    # never the script's exception.
    try {
        if ($null -ne $Stdin) { $all = @($Stdin | & $Worker @Arguments 2>&1) }
        else { $all = @(& $Worker @Arguments 2>&1) }
    } catch { return [pscustomobject]@{ Code = -1; Out = ''; Err = "$Worker couldn't be run ($($_.Exception.Message))`n" } }
    $code = $LASTEXITCODE
    $out = @($all | Where-Object { $_ -is [string] })
    $err = @($all | Where-Object { $_ -isnot [string] } | ForEach-Object { "$_" })
    [pscustomobject]@{
        Code = $code
        Out  = ($out -join "`n") + $(if ($out.Count) { "`n" })
        Err  = ($err -join "`n") + $(if ($err.Count) { "`n" })
    }
}

# One line of a Worker's answer for a message: its stderr's first line, else its stdout's.
function Get-FirstLine([string]$Text) {
    $lines = @(($Text -split "`r?`n") | Where-Object { $_ -ne '' })
    if ($lines.Count -eq 0) { return '(no output)' }
    $lines[0]
}

function Read-Answer([string]$Name, [string]$Prompt, [string]$Given, [bool]$Secret) {
    if ($Given) { return $Given }
    if ($Answers.ContainsKey($Name)) { return [string]$Answers[$Name] }
    if (-not $Interactive) { Stop-Install "$Name is needed and there is no console to ask it on: give -$Name (or -Answers for a secret)." }
    $value = if ($Secret) { Read-Host -Prompt $Prompt -MaskInput } else { Read-Host -Prompt $Prompt }
    $script:lastAnswerAt = [DateTime]::UtcNow
    if (-not $value) { Stop-Install "$Name was empty." }
    $value
}

function Ask-YesNo([string]$Question) {
    if (-not $Interactive) { return $false }
    $answer = Read-Host -Prompt "$Question (y/N)"
    $script:lastAnswerAt = [DateTime]::UtcNow
    $answer -match '^[Yy]'
}

# A path's owner and DACL, read and written through .NET (FileSystemAclExtensions) by SID:
# icacls refuses a service SID the machine can't map yet (error 1332 before `service install`),
# and the ACL cmdlets, run elevated, write the SACL back too and drop its audit entries. .NET writes
# only the sections that were changed. The icacls line it amounts to is the record.
function Get-PathAcl([string]$Path) {
    $sections = [Security.AccessControl.AccessControlSections]'Access, Owner'
    if (Test-Path -LiteralPath $Path -PathType Container) { [IO.FileSystemAclExtensions]::GetAccessControl([IO.DirectoryInfo]::new($Path), $sections) }
    else { [IO.FileSystemAclExtensions]::GetAccessControl([IO.FileInfo]::new($Path), $sections) }
}

function Set-PathAcl([string]$Path, $Acl) {
    if (Test-Path -LiteralPath $Path -PathType Container) { [IO.FileSystemAclExtensions]::SetAccessControl([IO.DirectoryInfo]::new($Path), $Acl) }
    else { [IO.FileSystemAclExtensions]::SetAccessControl([IO.FileInfo]::new($Path), $Acl) }
}

function Set-FolderAcl([string]$Path, $Wanted) {
    $acl = Get-PathAcl $Path
    $difference = Get-AclDifference -Acl $acl -Wanted $Wanted -TrustedOwners $TrustedOwners
    if ($difference.Ok) { Say "ok: ACL of $Path"; return }
    $records = @()
    if ($difference.OwnerWrong) { $records += "icacls $Path /setowner *S-1-5-32-544 /Q (owned by $(if ($difference.Owner) { $difference.Owner } else { 'nobody' }))" }
    $arguments = @(Get-IcaclsArguments -Path $Path -Wanted $Wanted -Difference $difference)
    if ($arguments.Count -gt 0) { $records += "icacls $($arguments -join ' ')" }
    $line = $records -join '; '
    if (-not $PSCmdlet.ShouldProcess($Path, $line)) { Would $line; return }
    $updated = Update-AclObject -Acl $acl -Wanted $Wanted -Difference $difference
    Set-PathAcl $Path $updated
    $after = Get-AclDifference -Acl (Get-PathAcl $Path) -Wanted $Wanted -TrustedOwners $TrustedOwners
    if (-not $after.Ok) { Stop-Install "the ACL of $Path is not what was set (missing $($after.Missing.Count), extra $($after.Extra.Count), owner $($after.Owner))." }
    Changed "ACL of $Path (as $line)"
}

# A file the installer writes, made new beside its place and moved over it: the new file has
# its folder's inherited rules and this account as its owner, whatever the old one had.
function Write-NewFile([string]$Path, [byte[]]$Bytes) {
    $temporary = "$Path.new-$([Guid]::NewGuid().ToString('N'))"
    [IO.File]::WriteAllBytes($temporary, $Bytes)
    [IO.File]::Move($temporary, $Path, $true)
}

function Get-Utf8Bytes([string]$Text) { [Text.UTF8Encoding]::new($false).GetBytes($Text) }

function Test-KeyFileRead([string]$Path, [string]$Sid) {
    $rules = @((Get-PathAcl $Path).GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]))
    $read = [Security.AccessControl.FileSystemRights]::Read
    @($rules | Where-Object {
        $_.IdentityReference.Value -eq $Sid -and $_.AccessControlType -eq 'Allow' -and (($_.FileSystemRights -band $read) -eq $read)
    }).Count -gt 0
}

# The swap (W7.4 point 3 step 4). The package's files are copied into a folder of their own
# first, so a copy that fails leaves the installed files untouched; then the installed files
# are moved to a staging folder and the new ones in (moves on one volume), and previous\ is
# replaced through a rename, so no step loses both copies. A failure while the files move puts
# the installed files back and says so; a file that couldn't be put back keeps the staging
# folder and is named. A rollback (`Rollback`: the package is previous\ itself) leaves previous\
# as it is and drops the files it replaced, so the same rollback line run again finds the files
# the same instead of swapping back. `Keep` names files that stay in place.
function Invoke-Swap([object[]]$Files, [string[]]$Keep = @(), [bool]$Rollback = $false) {
    $guid = [Guid]::NewGuid().ToString('N')
    $incoming = Join-Path $ProgramDir "incoming-$guid"
    $staging = Join-Path $ProgramDir "previous.new-$guid"
    $null = New-Item -ItemType Directory -Path $incoming
    try {
        foreach ($file in $Files) {
            Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $incoming $file.Name) -Force
            if ((Get-FileHash -LiteralPath (Join-Path $incoming $file.Name) -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash) { throw "$($file.Name) was not copied whole" }
        }
    } catch {
        Remove-Item -LiteralPath $incoming -Recurse -Force -ErrorAction SilentlyContinue
        throw "the package's files couldn't be copied ($($_.Exception.Message)); the installed files are untouched"
    }
    $null = New-Item -ItemType Directory -Path $staging
    $moved = @()
    try {
        foreach ($old in @(Get-ChildItem -LiteralPath $ProgramDir -File)) {
            if ($Keep -contains $old.Name) { continue }
            Move-Item -LiteralPath $old.FullName -Destination (Join-Path $staging $old.Name)
            $moved += $old.Name
        }
        foreach ($file in $Files) {
            Move-Item -LiteralPath (Join-Path $incoming $file.Name) -Destination (Join-Path $ProgramDir $file.Name) -Force
            Changed "copied $($file.Name) to $ProgramDir"
        }
    } catch {
        $why = $_.Exception.Message
        $stuck = @()
        foreach ($name in $moved) {
            try { Move-Item -LiteralPath (Join-Path $staging $name) -Destination (Join-Path $ProgramDir $name) -Force } catch { $stuck += $name }
        }
        Remove-Item -LiteralPath $incoming -Recurse -Force -ErrorAction SilentlyContinue
        if ($stuck.Count -gt 0) { throw "the swap failed ($why), and $($stuck -join ', ') couldn't be put back: they are in $staging; move them into $ProgramDir by hand" }
        Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
        throw "the swap failed ($why); the installed files were put back"
    }
    Remove-Item -LiteralPath $incoming -Recurse -Force -ErrorAction SilentlyContinue
    if ($Rollback) {
        Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
        Changed "the files of $installedVersion rolled back from dropped; $previous is left as it is (the version now installed)"
        return
    }
    # The new files are in place from here: a rename that fails says where the replaced ones are.
    $retired = "$previous.old-$guid"
    $hadPrevious = Test-Path -LiteralPath $previous -PathType Container
    try {
        if ($hadPrevious) { Rename-Item -LiteralPath $previous -NewName (Split-Path -Leaf $retired) }
        try { Rename-Item -LiteralPath $staging -NewName 'previous' }
        catch { if ($hadPrevious) { Rename-Item -LiteralPath $retired -NewName 'previous' -ErrorAction SilentlyContinue }; throw }
    } catch { throw "the new files are in place, but $previous couldn't be replaced ($($_.Exception.Message)): the files of $installedVersion they replaced are in $staging" }
    if ($hadPrevious) { Remove-Item -LiteralPath $retired -Recurse -Force -ErrorAction SilentlyContinue }
    Changed "the previous files ($installedVersion) kept as $previous"
}

# The scripts copied in from a downloaded zip keep its mark of the web, which RemoteSigned
# refuses: taken off, as the operator who unpacked the package trusted it.
function Unblock-Scripts {
    foreach ($script in @(Get-ChildItem -LiteralPath $ProgramDir -File | Where-Object { $_.Extension -in '.ps1', '.psm1' })) { Unblock-File -LiteralPath $script.FullName }
}

# Whether the service runs now (a query that fails counts as running: the wait goes on).
function Test-ServiceRunning {
    try { $now = Get-InstalledService -Name $ServiceName } catch { return $true }
    $null -ne $now -and "$($now.State)" -ne 'Stopped'
}

# The wait for the run in progress (W7.4 point 3 step 2): the record read every PollSeconds,
# one line a minute, until it is gone, names another run than the first read (that run ended),
# or the service isn't running (the new version's first start closes it); past the budget the
# install stops with nothing changed.
function Wait-ForNoRun([string]$Stage) {
    $budget = $WaitMinutes * 60
    $waited = 0.0
    $said = -1
    $first = $null
    while ($true) {
        $record = Get-RunRecord -Root $Root
        if ($null -ne $record -and $null -eq $first) { $first = $record.RunId }
        $running = if ($null -ne $record) { Test-ServiceRunning } else { $true }
        $plan = Get-RunPlan -RecordPresent ($null -ne $record) -WaitedSeconds $waited -BudgetSeconds $budget -ServiceRunning $running -RunChanged ($null -ne $record -and $record.RunId -cne $first)
        if ($plan -eq 'go') { return }
        if ($WhatIfPreference) { Would "wait for run $($record.RunId) to end ($Stage)"; return }
        if ($plan -eq 'stop') {
            Stop-Install "run $($record.RunId) is still in progress after $WaitMinutes min ($Stage); rpworker doctor shows it. Give a longer -WaitMinutes, or stop the service (rpworker service stop) and run this again: the new version's first start closes a run the service stopped in (its own recovery)."
        }
        $minute = [int][Math]::Floor($waited / 60)
        if ($minute -ne $said) { Say "waiting: run $($record.RunId) in progress for $minute min ($Stage; up to $WaitMinutes min)"; $said = $minute }
        Start-Sleep -Seconds $PollSeconds
        $waited += $PollSeconds
    }
}

# ======================================================================================
try {
    $ServiceSid = Get-ServiceSid -ServiceName $ServiceName
    Say "RestoreProof Worker installer: package $Package, program folder $ProgramDir, data folder $Root, service $ServiceName ($ServiceSid)"

    # -- 1. the checks ------------------------------------------------------------------
    $facts = Get-MachineFacts
    $elevated = $SkipElevationCheck -or (Test-IsElevated)
    $problems = @(Test-Prerequisites -PSVersion $facts.PSVersion -Elevated $elevated -Is64Bit $facts.Is64Bit -IsWindows $facts.IsWindows)
    if ($problems.Count -gt 0) { throw ($problems -join "`n") }
    $packageExe = Join-Path $Package 'rpworker.exe'
    if (-not (Test-Path -LiteralPath $packageExe -PathType Leaf)) { Stop-Install "no rpworker.exe in ${Package}: run this from the unpacked package, or give -Package." }
    $veeamHere = Test-VeeamOnThisMachine
    if (-not $veeamHere) {
        Say 'note: Veeam Backup for Microsoft 365 (its REST service) is not on this machine. The Worker runs on the Veeam server: only there can it be granted read on the organisation certificates'' key files, without which it runs no restore.'
        if (-not $AllowRemoteVeeam -and -not (Ask-YesNo 'Install anyway?')) { Stop-Install 'Veeam is not on this machine (give -AllowRemoteVeeam to install anyway).' }
    } else { Say 'ok: Veeam Backup for Microsoft 365 is on this machine' }
    $expectedCommandLine = Get-ServiceCommandLine -Exe $Exe
    try { $service = Get-InstalledService -Name $ServiceName }
    catch { Stop-Install "the installed services couldn't be read ($($_.Exception.Message)); fix Windows Management Instrumentation (winmgmt) first." }
    $serviceState = Test-InstalledService -Service $service -ExpectedCommandLine $expectedCommandLine
    if ($serviceState -eq 'other') { Stop-Install "the service $ServiceName is installed with another command line ($($service.PathName)), not this installer's; it is neither upgraded nor replaced: stop and uninstall it first (rpworker service stop; rpworker service uninstall, or that installation's Uninstall-RestoreProofWorker.ps1)." }
    Say "ok: service $ServiceName is $(if ($serviceState -eq 'ok') { 'installed from ' + $Exe } else { 'not installed' })"

    # -- 2. the exe, its DLLs and the scripts; the upgrade (W7.4 point 3) ----------------------
    $files = @(Get-ChildItem -LiteralPath $Package -File | Where-Object { $_.Name -eq 'rpworker.exe' -or $_.Extension -in '.dll', '.ps1', '.psm1' })
    # A package without the uninstall script (0.1.0's carried the installer and its modules but
    # not it) brings no script: its modules would break the installed uninstall script, and the
    # Apps entry names that script. The installed scripts stay (the W7.3 review's second pass).
    $keep = @()
    if (@($files | Where-Object { $_.Name -eq 'Uninstall-RestoreProofWorker.ps1' }).Count -eq 0) {
        $files = @($files | Where-Object { $_.Extension -notin '.ps1', '.psm1' })
        if (Test-Path -LiteralPath $ProgramDir -PathType Container) {
            $keep = @(Get-ChildItem -LiteralPath $ProgramDir -File | Where-Object { $_.Extension -in '.ps1', '.psm1' } | ForEach-Object { $_.Name })
        }
    }
    # Which of the package's files are missing from the program folder, and which are there with
    # another SHA-256, hashed once. Missing alone (a quarantined exe) is copied in again whatever
    # -Upgrade says, as before W7.4; only another file is an upgrade.
    try {
        $missing = @()
        $changed = @()
        foreach ($file in $files) {
            $target = Join-Path $ProgramDir $file.Name
            if (-not (Test-Path -LiteralPath $target -PathType Leaf)) { $missing += $file.Name }
            elseif ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash) { $changed += $file.Name }
        }
        $differing = @(@($missing) + @($changed) | Sort-Object)
    } catch { Stop-Install "a file of the package or of $ProgramDir couldn't be read ($($_.Exception.Message)); nothing was changed." }
    try { $packageVersion = Get-WorkerVersion -Exe $packageExe } catch { Stop-Install "$($_.Exception.Message)" }
    $installedVersion = ''
    if (Test-Path -LiteralPath $Exe -PathType Leaf) { try { $installedVersion = Get-WorkerVersion -Exe $Exe } catch { $installedVersion = '' } }
    $upgradePlan = Get-UpgradePlan -ServiceState $serviceState -InstalledVersion $installedVersion -PackageVersion $packageVersion -SameFiles ($changed.Count -eq 0) -Upgrade $Upgrade.IsPresent
    $previous = Join-Path $ProgramDir 'previous'
    $rollback = "pwsh -ExecutionPolicy Bypass -File `"$(Join-Path $ProgramDir 'Install-RestoreProofWorker.ps1')`" -Upgrade -Package `"$previous`""
    $script:RollbackWhere = "in ${previous}: $rollback"
    # A rollback is the package previous\ itself (as the rollback line gives it).
    $isRollback = [string]::Equals([IO.Path]::TrimEndingDirectorySeparator([IO.Path]::GetFullPath($Package)), [IO.Path]::GetFullPath($previous), [StringComparison]::OrdinalIgnoreCase)
    $upgraded = $false
    $swapped = $false
    switch ($upgradePlan.Action) {
        'stop' {
            $what = if ($changed.Count -eq 1) { "$($changed[0]) differs" } else { "$($changed -join ', ') differ" }
            $holds = if ($installedVersion) { "rpworker $installedVersion" } else { 'an rpworker whose version can''t be read' }
            Stop-Install "$ProgramDir holds $holds and the package is $packageVersion$(if ($installedVersion -eq $packageVersion) { ' with other files' }) ($what) while the service is installed from it; give -Upgrade to replace $(if ($changed.Count -eq 1) { 'it' } else { 'them' }) (docs/upgrade.md)."
        }
        'same' {
            if ($missing.Count -gt 0) { Say "note: $($missing -join ', ') missing from ${ProgramDir}: copied in again from the package" }
            else { Say "ok: rpworker $packageVersion is installed already" }
        }
        'install' { if ($Upgrade) { Say 'note: -Upgrade given and no service is installed: a plain install' } }
        'swap' {
            Say $upgradePlan.Line
            Wait-ForNoRun 'the upgrade'
            if ($PSCmdlet.ShouldProcess($ServiceName, 'rpworker service stop')) {
                if (Test-Path -LiteralPath $Worker -PathType Leaf) {
                    $stop = Invoke-Worker @('service', 'stop')
                    if ($stop.Code -ne 0) { Stop-Install "rpworker service stop failed: $(Get-FirstLine ($stop.Err + $stop.Out))" }
                    $script:StoppedFor = 'upgrade'
                    if ($stop.Out -match '(?m)^stopped ') { Changed "rpworker service stop ($(Get-FirstLine $stop.Out)), for the upgrade" } else { Say "ok: $(Get-FirstLine $stop.Out)" }
                } else {
                    $script:StoppedFor = 'upgrade'
                    Say "note: no rpworker at ${Worker}: the service can't be running it; nothing to stop"
                }
                if ($null -ne (Get-RunRecord -Root $Root)) { Say "note: a run was taken as the service stopped; the new version's first start closes it, waits for Veeam and cleans the restore targets (the service's own recovery)" }
                try { Invoke-Swap -Files $files -Keep $keep -Rollback $isRollback } catch { Stop-Install "$($_.Exception.Message)" }
                Unblock-Scripts
                $upgraded = $true
            } else {
                Would 'rpworker service stop'
                Would "move the installed files to $previous$(if ($keep.Count) { " (but $($keep -join ', '), which the package doesn't carry)" }) and copy the package's in: $($differing -join ', ')"
            }
            $swapped = $true
        }
    }
    if (-not $swapped) {
        foreach ($file in $files) {
            $target = Join-Path $ProgramDir $file.Name
            if ($file.Name -notin $differing) { Say "ok: $target"; continue }
            if (-not $PSCmdlet.ShouldProcess($target, "copy from $($file.FullName)")) { Would "copy $($file.Name) to $ProgramDir"; continue }
            if (-not (Test-Path -LiteralPath $ProgramDir -PathType Container)) { $null = New-Item -ItemType Directory -Path $ProgramDir }
            Copy-Item -LiteralPath $file.FullName -Destination $target -Force
            if ($file.Extension -in '.ps1', '.psm1') { Unblock-File -LiteralPath $target }
            Changed "copied $($file.Name) to $ProgramDir"
        }
    }
    $version = $packageVersion
    if (Test-Path -LiteralPath $Exe -PathType Leaf) {
        try { $version = Get-WorkerVersion -Exe $Exe } catch { Stop-Install "$($_.Exception.Message)" }
        Say "ok: rpworker $version"
    } elseif ($WhatIfPreference) {
        Say "would: run $Exe --version"
    } else { Stop-Install "no rpworker at $Exe." }

    # -- 2b. the Apps & features entry (W7.3 point 2) --------------------------------------------
    $entryName = Get-UninstallEntryName
    $entry = Get-UninstallEntry -Name $entryName
    $installDate = [DateTime]::UtcNow.ToString('yyyyMMdd', [Globalization.CultureInfo]::InvariantCulture)
    if ($null -ne $entry -and $entry.ContainsKey('InstallDate') -and "$($entry['InstallDate'])" -match '^\d{8}$') { $installDate = "$($entry['InstallDate'])" }
    $wantedEntry = New-UninstallEntryValues -Version $version -ProgramDir $ProgramDir -Pwsh (Get-PwshPath) -InstallDate $installDate
    $entryOk = $null -ne $entry
    if ($entryOk) { foreach ($key in $wantedEntry.Keys) { if (-not $entry.ContainsKey($key) -or "$($entry[$key])" -ne "$($wantedEntry[$key])") { $entryOk = $false } } }
    if ($entryOk) { Say "ok: Apps & features entry (RestoreProof Worker $version)" }
    elseif ($PSCmdlet.ShouldProcess("Apps & features: $entryName", 'write')) { Set-UninstallEntry -Name $entryName -Values $wantedEntry; Changed "Apps & features entry (RestoreProof Worker $version)" }
    else { Would "write the Apps & features entry (RestoreProof Worker $version)" }

    # -- 3. the folders and their ACLs ------------------------------------------------------
    $wanted = Get-WantedAcls -ServiceSid $ServiceSid -AlsoFullControl $AlsoFullControl
    foreach ($name in $wanted.Keys) {
        $path = if ($name -eq '') { $Root } else { Join-Path $Root $name }
        if (-not (Test-Path -LiteralPath $path -PathType Container)) {
            if (-not $PSCmdlet.ShouldProcess($path, 'make the folder')) { Would "make $path and set its ACL"; continue }
            $null = New-Item -ItemType Directory -Path $path
            Changed "made $path"
        }
        Set-FolderAcl -Path $path -Wanted $wanted[$name]
    }

    # -- 4. config.json -------------------------------------------------------------------
    # `config check` before the vault is made (step 5) ends on the vault's line: Test-ConfigCheck
    # takes that as the config's pass.
    $configKept = $false
    $configWritten = $false
    $configCloudUrl = ''
    $configExists = Test-Path -LiteralPath $ConfigPath -PathType Leaf
    $checkOk = $true
    $checkLine = ''
    $untrusted = ''
    $kept = $null
    if ($configExists) {
        if (Test-Path -LiteralPath $Worker -PathType Leaf) {
            $check = Invoke-Worker @('config', 'check', '--config', $ConfigPath)
            $checkOk = Test-ConfigCheck -Code $check.Code -Out $check.Out -Err $check.Err
            $checkLine = Get-FirstLine ($check.Err + $check.Out)
        }
        $fileAcl = Get-PathAcl $ConfigPath
        $explicit = @($fileAcl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]) | ForEach-Object { $_.IdentityReference.Value })
        $untrusted = Test-TrustedFile -Owner "$($fileAcl.GetOwner([Security.Principal.SecurityIdentifier]))" -ExplicitSids $explicit -TrustedOwners $TrustedOwners
        try { $kept = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json } catch { $kept = $null }
    }
    $keptValue = { param($name) if ($null -ne $kept -and $kept.PSObject.Properties[$name]) { [string]$kept.$name } else { '' } }
    $configPlan = Get-ConfigPlan -Exists $configExists -CheckOk $checkOk -Untrusted "$untrusted" -Replace $Replace.IsPresent `
        -KeptCloudUrl (& $keptValue 'cloud_url') -KeptVeeamUrl (& $keptValue 'veeam_url') -CloudUrl $CloudUrl -VeeamUrl $VeeamUrl -CheckLine $checkLine
    if ($configPlan.Action -eq 'stop') { Stop-Install "$ConfigPath $($configPlan.Why)" }
    if ($configPlan.Action -eq 'keep') {
        $configKept = $true
        $configCloudUrl = & $keptValue 'cloud_url'
        Say "ok: $ConfigPath (kept; its values are not asked again)"
    } else {
        $CloudUrl = Read-Answer 'CloudUrl' 'Cloud URL (https://...)' $CloudUrl $false
        if (-not $VeeamUrl -and $veeamHere) { $VeeamUrl = 'https://localhost:4443'; Say "ok: Veeam is on this machine: veeam_url $VeeamUrl" }
        $VeeamUrl = Read-Answer 'VeeamUrl' 'Veeam REST URL (https://<server>:4443)' $VeeamUrl $false
        $veeamCaFile = ''
        $veeamPin = ''
        $pem = $null
        if ($VeeamCertificateFile) {
            $given = [Security.Cryptography.X509Certificates.X509Certificate2]::new($VeeamCertificateFile)
            $pem = ConvertTo-Pem -Der $given.RawData
            $veeamPin = $given.GetCertHashString('SHA256')
            Say "ok: Veeam's certificate from $VeeamCertificateFile ($($given.Subject), thumbprint $($given.Thumbprint)) will be pinned"
        } else {
            try { $remote = Get-RemoteCertificate -Url $VeeamUrl } catch { Stop-Install "$VeeamUrl could not be reached for its certificate ($($_.Exception.Message))." }
            $verdict = Test-VeeamCertificate -InLocalStoreWithKey $remote.InLocalStoreWithKey -ChainsToStore $remote.ChainsToStore -NamesHost $remote.NamesHost
            Say "Veeam's certificate: $($remote.Subject), thumbprint $($remote.Thumbprint), SHA-256 $($remote.Sha256), valid to $($remote.NotAfter.ToString('yyyy-MM-ddTHH:mm:ssZ'))"
            switch ($verdict) {
                'pin' { Say "ok: it is this machine's own (LocalMachine\My, with its key): pinned"; $pem = ConvertTo-Pem -Der $remote.Der; $veeamPin = $remote.Sha256 }
                'store' { Say 'ok: it chains to the Windows certificate store and names the host: nothing to pin' }
                'confirm' {
                    $confirmed = $false
                    if ($VeeamThumbprint) { $confirmed = ($VeeamThumbprint -replace '[^0-9A-Fa-f]', '').ToUpperInvariant() -eq $remote.Thumbprint }
                    elseif ($Interactive) {
                        $typed = Read-Host -Prompt 'Confirm it against the Veeam console (General Options > REST API): type the first 8 characters of the thumbprint'
                        $script:lastAnswerAt = [DateTime]::UtcNow
                        $confirmed = $typed.Length -ge 8 -and $remote.Thumbprint.StartsWith($typed.Trim().ToUpperInvariant())
                    }
                    if (-not $confirmed) { Stop-Install "Veeam's certificate was not confirmed (give -VeeamThumbprint <its SHA-1 thumbprint>, or -VeeamCertificateFile <its PEM>)." }
                    Say 'ok: thumbprint confirmed: pinned'
                    $pem = ConvertTo-Pem -Der $remote.Der; $veeamPin = $remote.Sha256
                }
            }
        }
        if ($pem) { $veeamCaFile = $VeeamPemPath }
        $cloudCa = ''
        if ($CloudCaFile) {
            $null = [Security.Cryptography.X509Certificates.X509Certificate2]::new($CloudCaFile)
            $cloudCa = $CloudPemPath
        }
        $document = New-ConfigDocument -CloudUrl $CloudUrl -VeeamUrl $VeeamUrl -VeeamCaFile $veeamCaFile -VeeamCertSha256 $veeamPin -CloudCaFile $cloudCa
        $json = ($document | ConvertTo-Json) -replace "`r`n", "`n"
        if (-not $PSCmdlet.ShouldProcess($ConfigPath, 'write')) {
            Would "write $ConfigPath (cloud_url $CloudUrl, veeam_url $VeeamUrl$(if ($veeamPin) { ', veeam_ca_file, veeam_cert_sha256' })$(if ($cloudCa) { ', cloud_ca_file' }))"
        } else {
            if ($pem) { Write-NewFile $VeeamPemPath (Get-Utf8Bytes $pem); Changed "wrote $VeeamPemPath" }
            if ($cloudCa) { Write-NewFile $CloudPemPath ([IO.File]::ReadAllBytes($CloudCaFile)); Changed "copied $CloudCaFile to $CloudPemPath" }
            Write-NewFile $ConfigPath (Get-Utf8Bytes ($json + "`n"))
            Changed "wrote $ConfigPath"
            $configWritten = $true
            $configCloudUrl = $CloudUrl
            $check = Invoke-Worker @('config', 'check', '--config', $ConfigPath)
            if (-not (Test-ConfigCheck -Code $check.Code -Out $check.Out -Err $check.Err)) { Stop-Install "the config written fails rpworker config check: $(Get-FirstLine ($check.Err + $check.Out))" }
            Say 'ok: rpworker config check'
        }
    }

    # -- 5. the vault -------------------------------------------------------------------
    $listed = Invoke-Worker @('vault', 'list')
    $held = @()
    if ($listed.Code -eq 0) { $held = @(($listed.Out -split "`r?`n") | Where-Object { $_ -ne '' } | ForEach-Object { $_.Trim() }) }
    elseif ($listed.Err -notmatch ': vault file not found') { Stop-Install "rpworker vault list failed: $(Get-FirstLine ($listed.Err + $listed.Out))" }
    $plan = Get-VaultPlan -Held $held -Replace $Replace.IsPresent
    $credentialsSet = $false
    foreach ($name in $plan.Ask) {
        $prompt = switch ($name) {
            'veeam_username' { 'Veeam account (MACHINE\user, a Veeam Backup Administrator)' }
            'veeam_password' { 'its password (not shown)' }
            'cloud_install_token' { 'install token from manage.py create-worker-token (not shown)' }
        }
        $given = if ($name -eq 'veeam_username') { $VeeamUsername } else { '' }
        $value = Read-Answer $name $prompt $given ($SecretNames -contains $name)
        if (-not $PSCmdlet.ShouldProcess('the vault', "rpworker vault set $name")) { Would "rpworker vault set $name"; $value = $null; continue }
        $set = Invoke-Worker @('vault', 'set', $name) -Stdin $value
        $value = $null
        if ($set.Code -ne 0) { Stop-Install "rpworker vault set $name failed: $(Get-FirstLine ($set.Err + $set.Out))" }
        Changed "rpworker vault set $name"
        if ($name -like 'veeam_*') { $credentialsSet = $true }
    }
    foreach ($name in 'veeam_username', 'veeam_password') { if ($plan.Ask -notcontains $name) { Say "ok: $name is in the vault" } }
    if ($plan.Registered) { Say 'ok: cloud_api_token is in the vault (registered already)' }
    elseif ($plan.HasInstallToken) { Say 'ok: cloud_install_token is in the vault' }
    if ($PSCmdlet.ShouldProcess('the vault', "rpworker vault grant $ServiceSid")) {
        $grant = Invoke-Worker @('vault', 'grant', $ServiceSid)
        if ($grant.Code -ne 0) { Stop-Install "rpworker vault grant failed: $(Get-FirstLine ($grant.Err + $grant.Out))" }
        Say "ok: rpworker vault grant $ServiceSid"
    } else { Would "rpworker vault grant $ServiceSid" }

    # -- 6. the signing key ----------------------------------------------------------------
    $keyId = ''
    if ($plan.NeedsSigningKey) {
        if ($PSCmdlet.ShouldProcess('the vault', 'rpworker signer new-key')) {
            $made = Invoke-Worker @('signer', 'new-key')
            if ($made.Code -ne 0) { Stop-Install "rpworker signer new-key failed: $(Get-FirstLine ($made.Err + $made.Out))" }
            $keyId = ([regex]::Match($made.Err, '(?m)^key ([0-9a-f]{64})')).Groups[1].Value
            Changed "rpworker signer new-key (key $keyId)"
        } else { Would 'rpworker signer new-key' }
    } else { Say 'ok: signing_key_base64 is in the vault' }

    # -- 7. the Graph certificate -------------------------------------------------------------
    if ($plan.NeedsCertificate) {
        if (-not $CertificateScript) { Stop-Install 'New-WorkerGraphCertificate.ps1 is not beside this script.' }
        # Half a certificate (one of its two names, left by that script's own failure half-way)
        # is made again over it, as that failure's line says: -Replace.
        $certificateArguments = @{ Worker = $Worker; ServiceName = $ServiceName }
        if ($plan.CertificateHalf) { $certificateArguments['Replace'] = $true; Say 'note: the vault holds half the Graph certificate (one of graph_cert_pfx_base64 and graph_cert_password): it is made again' }
        if ($PSCmdlet.ShouldProcess('the vault', 'New-WorkerGraphCertificate.ps1')) {
            # Its lines are Write-Host's (the information stream, 6) and rpworker's stderr (2).
            try { $certificateLines = @(& $CertificateScript @certificateArguments 2>&1 6>&1 | ForEach-Object { "$_" }) }
            catch { Stop-Install "New-WorkerGraphCertificate.ps1 failed: $($_.Exception.Message)" }
            $thumbLine = [regex]::Match(($certificateLines -join "`n"), 'thumbprint [0-9A-Fa-f]{40}[^\r\n]*').Value
            if (-not $thumbLine) { $thumbLine = 'thumbprint not printed' }
            Changed "New-WorkerGraphCertificate.ps1 ($thumbLine)"
        } else { Would "New-WorkerGraphCertificate.ps1 -Worker <rpworker>$(if ($plan.CertificateHalf) { ' -Replace' })" }
    } else { Say 'ok: the Graph certificate is in the vault' }

    # -- 8. Veeam, and the organisation certificates' key files ---------------------------------
    $granted = @()
    if ($configKept -or -not $WhatIfPreference) {
        $list = Invoke-Worker @('veeam', 'list', '--config', $ConfigPath)
        if ($list.Code -eq 3) { Stop-Install "rpworker veeam list failed: $(Get-FirstLine ($list.Err + $list.Out)) (Veeam wasn't reached: run the installer again once its REST service answers)." }
        if ($list.Code -ne 0) { Stop-Install "rpworker veeam list failed: $(Get-FirstLine ($list.Err + $list.Out)) (the Veeam URL, its certificate or the account: run the installer again with -Replace to give them again)." }
        $organisations = @(Read-OrganisationThumbprints -Text $list.Out)
        Say "ok: rpworker veeam list ($($organisations.Count) organisation(s))"
        if ($veeamHere) {
            foreach ($organisation in $organisations) {
                foreach ($problem in $organisation.Problems) { Say "problem: $($organisation.Organisation): $problem" }
                foreach ($thumbprint in $organisation.Thumbprints) {
                    $keyFile = Get-CertificateKeyFile -Thumbprint $thumbprint
                    if (-not $keyFile) { Say "problem: $($organisation.Organisation): certificate $thumbprint has no private key file on this machine; its restores will fail until the service account can read it (W4.12)"; continue }
                    if (Test-KeyFileRead -Path $keyFile -Sid $ServiceSid) { Say "ok: $($organisation.Organisation): read on the key file of $thumbprint"; $granted += $thumbprint; continue }
                    if (-not $PSCmdlet.ShouldProcess($keyFile, "icacls /grant:r *${ServiceSid}:(R)")) { Would "icacls `"$keyFile`" /grant:r *${ServiceSid}:(R) ($($organisation.Organisation), $thumbprint)"; continue }
                    Set-PathAcl $keyFile (Add-FileReadRule -Acl (Get-PathAcl $keyFile) -Sid $ServiceSid)
                    if (-not (Test-KeyFileRead -Path $keyFile -Sid $ServiceSid)) { Stop-Install "the key file of $thumbprint did not take the account's Read entry." }
                    Changed "$($organisation.Organisation): read on the key file of $thumbprint granted to $ServiceSid"
                    $granted += $thumbprint
                }
            }
        } else { Say 'note: Veeam is on another machine: no organisation certificate key file is granted here' }
    } else { Would 'rpworker veeam list, and grant read on each organisation certificate''s key file' }

    # -- 9. service install ---------------------------------------------------------------------
    if ($serviceState -eq 'ok') { Say "ok: rpworker service install" }
    elseif ($PSCmdlet.ShouldProcess($ServiceName, 'rpworker service install')) {
        $install = Invoke-Worker @('service', 'install')
        if ($install.Code -ne 0) { Stop-Install "rpworker service install failed: $(Get-FirstLine ($install.Err + $install.Out))" }
        Changed "rpworker service install ($(Get-FirstLine $install.Out))"
    } else { Would 'rpworker service install' }

    # -- 10. cloud register ----------------------------------------------------------------------
    $registration = $null
    if ($plan.Registered) {
        $recordPath = Join-Path $Root 'state\worker.json'
        if (Test-Path -LiteralPath $recordPath -PathType Leaf) {
            $record = Get-Content -LiteralPath $recordPath -Raw | ConvertFrom-Json
            $registration = [pscustomobject]@{ WorkerId = $record.worker_id; KeyId = $record.key_id }
            $registeredWith = if ($record.PSObject.Properties['cloud_url']) { [string]$record.cloud_url } else { '' }
            if ($registeredWith -and $configCloudUrl -and $registeredWith -cne $configCloudUrl) {
                Stop-Install "this Worker is registered with $registeredWith ($recordPath) and the config names $configCloudUrl; its API token is the first Cloud's. To register with ${configCloudUrl}: rpworker vault remove cloud_api_token, then run the installer again with an install token of that Cloud."
            }
        }
        Say "ok: registered with the Cloud$(if ($registration) { ' as worker ' + $registration.WorkerId })"
    } elseif ($PSCmdlet.ShouldProcess('the Cloud', 'rpworker cloud register')) {
        $arguments = @('cloud', 'register')
        if ($WorkerName) { $arguments += @('--name', $WorkerName) }
        $register = Invoke-Worker $arguments
        if (Test-KeyAlreadyRegistered -Code $register.Code -Err $register.Err) {
            # The Cloud holds this key from a registration whose answer never reached the vault;
            # the 409 rolled back, so the install token is unused: a new key, and again.
            $made = Invoke-Worker @('signer', 'new-key', '--replace')
            if ($made.Code -ne 0) { Stop-Install "rpworker signer new-key --replace failed: $(Get-FirstLine ($made.Err + $made.Out))" }
            $keyId = ([regex]::Match($made.Err, '(?m)^key ([0-9a-f]{64})')).Groups[1].Value
            Changed "rpworker signer new-key --replace (key $keyId): the Cloud already held this Worker's old key, from a registration whose answer never reached this machine; that Worker is unused on the Cloud: revoke it (manage.py revoke-worker)"
            $register = Invoke-Worker $arguments
        }
        if ($register.Code -eq 2) {
            $null = Invoke-Worker @('vault', 'remove', 'cloud_install_token')
            Stop-Install "the Cloud refused the install token (unknown, used or expired); it was removed from the vault: make a new one (manage.py create-worker-token) and run the installer again."
        }
        if ($register.Code -ne 0) { Stop-Install "rpworker cloud register failed: $(Get-FirstLine ($register.Err + $register.Out))$(if ($register.Code -eq 3) { ' (a wrong cloud_url: run the installer again with -Replace to give it again)' })" }
        $registration = Read-RegistrationLine -Text $register.Out
        if (-not $registration) { Stop-Install "rpworker cloud register printed no registration line." }
        Changed "rpworker cloud register (worker $($registration.WorkerId))"
    } else { Would 'rpworker cloud register' }

    # -- 11. service start ----------------------------------------------------------------------
    # A running service read its config and the vault's Veeam account at its start: when this run
    # changed either, it is stopped first so the start takes them.
    if ($serviceState -eq 'ok' -and ($configWritten -or $credentialsSet)) {
        if ($PSCmdlet.ShouldProcess($ServiceName, 'rpworker service stop')) {
            $stop = Invoke-Worker @('service', 'stop')
            if ($stop.Code -ne 0) { Stop-Install "rpworker service stop failed: $(Get-FirstLine ($stop.Err + $stop.Out))" }
            if (-not $script:StoppedFor) { $script:StoppedFor = 'config' }
            if ($stop.Out -match '(?m)^stopped ') { Changed "rpworker service stop ($(Get-FirstLine $stop.Out)), so the start takes the new config and account" } else { Say "ok: $(Get-FirstLine $stop.Out)" }
        } else { Would 'rpworker service stop' }
    }
    if ($PSCmdlet.ShouldProcess($ServiceName, 'rpworker service start')) {
        $start = Invoke-Worker @('service', 'start')
        if ($start.Code -ne 0) { Stop-Install "rpworker service start failed: $(Get-FirstLine ($start.Err + $start.Out))" }
        $script:StoppedFor = ''
        if ($start.Out -match '(?m)^started ') { Changed "rpworker service start ($(Get-FirstLine $start.Out))" } else { Say "ok: $(Get-FirstLine $start.Out)" }
    } else { Would 'rpworker service start' }

    # -- 12. the summary ------------------------------------------------------------------------
    $seconds = [int][Math]::Ceiling(([DateTime]::UtcNow - $lastAnswerAt).TotalSeconds)
    Say "changes: $script:Changes"
    Say "installed in $seconds s (from the last answer typed)"
    if ($upgraded -and $isRollback) { Say "rolled back $installedVersion -> $packageVersion; $previous holds $packageVersion too (to go forward again: the newer package's installer with -Upgrade)" }
    elseif ($upgraded) { Say "upgraded $installedVersion -> $packageVersion; the previous version is in $previous (rollback: $rollback)" }
    if ($registration) { Say "worker $($registration.WorkerId) key $($registration.KeyId)" }
    if ($granted.Count -gt 0) { Say "organisation certificates granted: $($granted -join ', ')" }
    Say "next: rpworker graph certificate > worker-graph.pem (the public half for each client's tenant setup); manage.py create-connector --worker-id $(if ($registration) { $registration.WorkerId } else { '<worker id>' }) ..."
} finally {
    $Answers = $null
}

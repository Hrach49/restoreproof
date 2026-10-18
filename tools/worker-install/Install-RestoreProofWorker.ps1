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
    -WhatIf prints `would: ...` lines and writes nothing. Upgrades (W7.3) and uninstall (W7.4)
    are not here: a service installed from another exe stops the install.

    In order: the checks; the exe and its DLLs into -ProgramDir; -Root and its six folders with
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

function Say([string]$Line) { Write-Output $Line }
function Changed([string]$What) { $script:Changes++; Say "change: $What" }
function Would([string]$What) { Say "would: $What" }
function Stop-Install([string]$Why) { throw "problem: $Why Nothing after this step was done; run the installer again once it is fixed." }

# Runs the Worker with `Arguments`, `Stdin` as one line when given (a secret: never an
# argument, as lab\entra\fill-worker-vault.ps1 and New-WorkerGraphCertificate.ps1 do); its exit
# code, stdout and stderr. Both streams are merged and told apart by kind (a native stderr line
# arrives as an error record, a stdout line as a string): no file, which a `2>file` redirection
# would be, and which -WhatIf would then refuse to write.
function Invoke-Worker([string[]]$Arguments, [string]$Stdin = $null) {
    if ($null -ne $Stdin) { $all = @($Stdin | & $Worker @Arguments 2>&1) }
    else { $all = @(& $Worker @Arguments 2>&1) }
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
    $service = Get-InstalledService -Name $ServiceName
    $serviceState = Test-InstalledService -Service $service -ExpectedCommandLine $expectedCommandLine
    if ($serviceState -eq 'other') { Stop-Install "the service $ServiceName is installed with another command line ($($service.PathName)); an upgrade in place is W7.3's: stop and uninstall it first (rpworker service stop; rpworker service uninstall)." }
    Say "ok: service $ServiceName is $(if ($serviceState -eq 'ok') { 'installed from ' + $Exe } else { 'not installed' })"

    # -- 2. the exe ---------------------------------------------------------------------
    $files = @(Get-ChildItem -LiteralPath $Package -File | Where-Object { $_.Name -eq 'rpworker.exe' -or $_.Extension -eq '.dll' })
    foreach ($file in $files) {
        $target = Join-Path $ProgramDir $file.Name
        if ((Test-Path -LiteralPath $target -PathType Leaf) -and (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -eq (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash) {
            Say "ok: $target"; continue
        }
        if ($serviceState -eq 'ok' -and (Test-Path -LiteralPath $target -PathType Leaf)) { Stop-Install "$target differs from the package's while the service is installed from it; an upgrade in place is W7.3's." }
        if (-not $PSCmdlet.ShouldProcess($target, "copy from $($file.FullName)")) { Would "copy $($file.Name) to $ProgramDir"; continue }
        if (-not (Test-Path -LiteralPath $ProgramDir -PathType Container)) { $null = New-Item -ItemType Directory -Path $ProgramDir }
        Copy-Item -LiteralPath $file.FullName -Destination $target -Force
        Changed "copied $($file.Name) to $ProgramDir"
    }
    if (Test-Path -LiteralPath $Worker -PathType Leaf) {
        $version = Invoke-Worker @('--version')
        if ($version.Code -ne 0) { Stop-Install "$Worker --version failed: $(Get-FirstLine ($version.Err + $version.Out))" }
        Say "ok: rpworker $($version.Out.Trim())"
    } elseif ($WhatIfPreference) {
        Say "would: run $Worker --version"
    } else { Stop-Install "no rpworker at $Worker." }

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
            if ($stop.Out -match '(?m)^stopped ') { Changed "rpworker service stop ($(Get-FirstLine $stop.Out)), so the start takes the new config and account" } else { Say "ok: $(Get-FirstLine $stop.Out)" }
        } else { Would 'rpworker service stop' }
    }
    if ($PSCmdlet.ShouldProcess($ServiceName, 'rpworker service start')) {
        $start = Invoke-Worker @('service', 'start')
        if ($start.Code -ne 0) { Stop-Install "rpworker service start failed: $(Get-FirstLine ($start.Err + $start.Out))" }
        if ($start.Out -match '(?m)^started ') { Changed "rpworker service start ($(Get-FirstLine $start.Out))" } else { Say "ok: $(Get-FirstLine $start.Out)" }
    } else { Would 'rpworker service start' }

    # -- 12. the summary ------------------------------------------------------------------------
    $seconds = [int][Math]::Ceiling(([DateTime]::UtcNow - $lastAnswerAt).TotalSeconds)
    Say "changes: $script:Changes"
    Say "installed in $seconds s (from the last answer typed)"
    if ($registration) { Say "worker $($registration.WorkerId) key $($registration.KeyId)" }
    if ($granted.Count -gt 0) { Say "organisation certificates granted: $($granted -join ', ')" }
    Say "next: rpworker graph certificate > worker-graph.pem (the public half for each client's tenant setup); manage.py create-connector --worker-id $(if ($registration) { $registration.WorkerId } else { '<worker id>' }) ..."
} finally {
    $Answers = $null
}

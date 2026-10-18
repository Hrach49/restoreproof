<#
    The rules of the Worker installer (W7.1, docs/decisions.md 2026-10-16): every decision
    Install-RestoreProofWorker.ps1 makes, as a function that takes what was read and answers what
    to do, with nothing of the machine in it. The script reads the machine (through
    WorkerMachine.psm1), asks these, and writes. tests/test_rules.py holds each row.
#>
Set-StrictMode -Version Latest

# --- the service account ---------------------------------------------------------------

<#
.SYNOPSIS
    The SID of the virtual account NT SERVICE\<name>: S-1-5-80 and the five DWORDs of the
    SHA-1 of the upper-cased UTF-16 name, what `sc showsid <name>` prints, with or without the
    service installed. Every grant is made by this SID, so none waits for `service install`
    (decision point 8).
#>
function Get-ServiceSid {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ServiceName)
    if ($ServiceName -notmatch '^[A-Za-z0-9_.-]{1,256}$') { throw "Not a service name: '$ServiceName'" }
    $hash = [Security.Cryptography.SHA1]::HashData([Text.Encoding]::Unicode.GetBytes($ServiceName.ToUpperInvariant()))
    $parts = foreach ($i in 0..4) { [BitConverter]::ToUInt32($hash, $i * 4) }
    'S-1-5-80-' + ($parts -join '-')
}

# --- the ACLs (decision point 7) -------------------------------------------------------

$script:SidSystem = 'S-1-5-18'
$script:SidAdministrators = 'S-1-5-32-544'
# icacls' simple rights and the .NET rights they are (Synchronize comes with each).
$script:RightsByName = @{
    FullControl    = [Security.AccessControl.FileSystemRights]::FullControl
    ReadAndExecute = [Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [Security.AccessControl.FileSystemRights]::Synchronize
    Modify         = [Security.AccessControl.FileSystemRights]::Modify -bor [Security.AccessControl.FileSystemRights]::Synchronize
}
$script:IcaclsByName = @{ FullControl = 'F'; ReadAndExecute = 'RX'; Modify = 'M' }
$script:ServiceFolders = @('state', 'runs', 'outbox', 'sent', 'failed', 'logs')

function New-AclRule([string]$Sid, [string]$Rights) {
    if (-not $script:RightsByName.ContainsKey($Rights)) { throw "Not a right: $Rights" }
    [pscustomobject]@{ Sid = $Sid; Rights = $Rights }
}

<#
.SYNOPSIS
    What each folder under the root must hold, keyed by the folder's relative path ('' is the
    root): whether its DACL is protected (no inheritance) and the explicit (OI)(CI) Allow rules
    it must have, each by SID. The root: SYSTEM and Administrators Full, the service account
    Read and execute, nothing else (Users gone). The six folders the service writes in inherit
    the root's three and add Modify for the account.
#>
function Get-WantedAcls {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ServiceSid,
        # Full control for these SIDs too, on the root: the tests' own account, which would
        # otherwise lock itself out of its temporary root. Never given by a deployment.
        [string[]]$AlsoFullControl = @()
    )
    $rules = [System.Collections.Generic.List[object]]::new()
    $rules.Add((New-AclRule $script:SidSystem 'FullControl'))
    $rules.Add((New-AclRule $script:SidAdministrators 'FullControl'))
    foreach ($sid in $AlsoFullControl) { $rules.Add((New-AclRule $sid 'FullControl')) }
    $rules.Add((New-AclRule $ServiceSid 'ReadAndExecute'))
    $wanted = [ordered]@{}
    $wanted[''] = [pscustomobject]@{ Protected = $true; Rules = @($rules) }
    foreach ($name in $script:ServiceFolders) {
        $wanted[$name] = [pscustomobject]@{ Protected = $false; Rules = @((New-AclRule $ServiceSid 'Modify')) }
    }
    $wanted
}

function Get-ServiceFolderNames { $script:ServiceFolders }

<#
.SYNOPSIS
    What a folder's DACL (Get-Acl's DirectorySecurity, or any object with
    AreAccessRulesProtected and GetAccessRules) lacks or has too much of, against one entry of
    Get-WantedAcls: Missing (rules to grant: absent, or there with other rights, inheritance
    flags or type), Extra (explicit rules to take away, each a SID and Allow or Deny: every
    Deny, and on a protected folder every Allow for a SID nobody wanted; a folder that inherits
    is judged on its own rules only), ProtectionWrong, and OwnerWrong: the owner is none of
    `TrustedOwners` (SYSTEM, Administrators and the account running the installer, which the
    script passes). An owner may always rewrite the DACL (READ_CONTROL and WRITE_DAC come with
    ownership), so a folder a local user made before the install stays theirs until its owner
    is changed. DaclOk is true when the first three are empty, Ok when all four are.
#>
function Get-AclDifference {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Acl, [Parameter(Mandatory)]$Wanted, [string[]]$TrustedOwners = @($script:SidSystem, $script:SidAdministrators))
    $rules = @($Acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]))
    $missing = [System.Collections.Generic.List[object]]::new()
    $extra = [System.Collections.Generic.List[string]]::new()
    $wantedSids = @($Wanted.Rules | ForEach-Object Sid)
    foreach ($rule in $Wanted.Rules) {
        $rights = $script:RightsByName[$rule.Rights]
        $found = @($rules | Where-Object {
            $_.IdentityReference.Value -eq $rule.Sid -and
            $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
            $_.FileSystemRights -eq $rights -and
            $_.InheritanceFlags -eq ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit) -and
            $_.PropagationFlags -eq [Security.AccessControl.PropagationFlags]::None
        })
        if ($found.Count -ne 1) { $missing.Add($rule) }
    }
    foreach ($rule in $rules) {
        $sid = $rule.IdentityReference.Value
        $type = "$($rule.AccessControlType)"
        $unwanted = ($type -eq 'Deny') -or ($Wanted.Protected -and $wantedSids -notcontains $sid)
        if ($unwanted -and -not $extra.Contains("$type $sid")) { $extra.Add("$type $sid") }
    }
    $protectionWrong = [bool]$Acl.AreAccessRulesProtected -ne [bool]$Wanted.Protected
    $owner = $Acl.GetOwner([Security.Principal.SecurityIdentifier])
    $ownerWrong = ($null -eq $owner) -or ($TrustedOwners -notcontains $owner.Value)
    $daclOk = ($missing.Count -eq 0 -and $extra.Count -eq 0 -and -not $protectionWrong)
    [pscustomobject]@{
        Missing         = @($missing)
        Extra           = @($extra | ForEach-Object { $type, $sid = $_ -split ' ', 2; [pscustomobject]@{ Sid = $sid; Type = $type } })
        ProtectionWrong = $protectionWrong
        Owner           = $(if ($owner) { $owner.Value } else { '' })
        OwnerWrong      = $ownerWrong
        DaclOk          = $daclOk
        Ok              = ($daclOk -and -not $ownerWrong)
    }
}

<#
.SYNOPSIS
    The one icacls command line that makes a folder's DACL what Get-WantedAcls says, from the
    difference: /inheritance:r or :e when the protection is wrong, /grant:r (replace that SID's
    rights) for each missing rule, /remove:g or /remove:d for each extra rule. Every SID as
    icacls takes it, with the asterisk. Empty when the DACL is right (an owner to change is its
    own line, `icacls <path> /setowner *S-1-5-32-544`, which icacls takes alone).
#>
function Get-IcaclsArguments {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)]$Wanted, [Parameter(Mandatory)]$Difference)
    if ($Difference.DaclOk) { return @() }
    $arguments = [System.Collections.Generic.List[string]]::new()
    $arguments.Add($Path)
    if ($Difference.ProtectionWrong) { $arguments.Add($(if ($Wanted.Protected) { '/inheritance:r' } else { '/inheritance:e' })) }
    if ($Difference.Missing.Count -gt 0) {
        $arguments.Add('/grant:r')
        foreach ($rule in $Difference.Missing) { $arguments.Add("*$($rule.Sid):(OI)(CI)$($script:IcaclsByName[$rule.Rights])") }
    }
    # Grants first, then denies, each by SID: one order whatever the DACL's.
    foreach ($extra in ($Difference.Extra | Sort-Object { $_.Type -eq 'Deny' }, Sid)) {
        $arguments.Add($(if ($extra.Type -eq 'Deny') { '/remove:d' } else { '/remove:g' }))
        $arguments.Add("*$($extra.Sid)")
    }
    $arguments.Add('/Q')
    @($arguments)
}

<#
.SYNOPSIS
    The DACL object changed to what Get-WantedAcls says, from the difference, and given back
    to the script, which sets it on the folder: the protection set (inherited rules dropped, not copied), each missing rule
    added after that SID's Allow rules are taken away (icacls' /grant:r), each extra rule taken
    away, and an owner nobody trusts replaced by Administrators. By SID throughout: .NET needs
    no account name, where icacls refuses a service SID the machine can't map yet (error 1332
    before `service install`). Get-IcaclsArguments is the same change as the icacls line, for
    the record.
#>
function Update-AclObject {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Acl, [Parameter(Mandatory)]$Wanted, [Parameter(Mandatory)]$Difference)
    if ($Difference.OwnerWrong) { $Acl.SetOwner([Security.Principal.SecurityIdentifier]$script:SidAdministrators) }
    if ($Difference.ProtectionWrong) { $Acl.SetAccessRuleProtection([bool]$Wanted.Protected, $false) }
    $inherit = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($extra in $Difference.Extra) {
        $type = [Security.AccessControl.AccessControlType]$extra.Type
        $template = [Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]$extra.Sid, [Security.AccessControl.FileSystemRights]::FullControl, $type)
        $null = $Acl.RemoveAccessRuleAll($template)
    }
    foreach ($rule in $Difference.Missing) {
        $sid = [Security.Principal.SecurityIdentifier]$rule.Sid
        $null = $Acl.RemoveAccessRuleAll([Security.AccessControl.FileSystemAccessRule]::new($sid, [Security.AccessControl.FileSystemRights]::FullControl, [Security.AccessControl.AccessControlType]::Allow))
        $Acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, $script:RightsByName[$rule.Rights], $inherit, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow))
    }
    $Acl
}

<#
.SYNOPSIS
    A file's DACL object with one Read Allow rule for `Sid` added (a key file's ACE, W4.12:
    `icacls <file> /grant:r *<sid>:(R)`), given back to the script, which sets it on the file.
#>
function Add-FileReadRule {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Acl, [Parameter(Mandatory)][string]$Sid)
    $Acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]$Sid, [Security.AccessControl.FileSystemRights]::Read, [Security.AccessControl.AccessControlType]::Allow))
    $Acl
}

# --- the config (decision point 3) -----------------------------------------------------

<#
.SYNOPSIS
    Whether a file the installer would keep (config.json) may be trusted: its owner one of
    `TrustedOwners` and no explicit rule for anyone else (a file the installer wrote has its
    folder's inherited rules alone). $null when it may, else the reason in a few words. A
    config.json a local user put there before the install names the URLs the service sends the
    Veeam password and the Cloud token to.
#>
function Test-TrustedFile {
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Owner, [string[]]$ExplicitSids = @(), [Parameter(Mandatory)][string[]]$TrustedOwners)
    if ($TrustedOwners -notcontains $Owner) { return "is owned by $(if ($Owner) { $Owner } else { 'nobody' }), not by SYSTEM, Administrators or this account" }
    $others = @($ExplicitSids | Where-Object { $TrustedOwners -notcontains $_ } | Sort-Object -Unique)
    if ($others.Count -gt 0) { return "has rules of its own for $($others -join ', ')" }
    $null
}

<#
.SYNOPSIS
    Whether `rpworker config check` passed on the config: exit 0, or exit 1 with the settings
    printed (`config file: ...` first) and the one line naming a vault that isn't there yet,
    which is every first install's (the vault is made after the config). Any other failure is
    the config's.
#>
function Test-ConfigCheck {
    [CmdletBinding()]
    param([int]$Code, [AllowEmptyString()][string]$Out = '', [AllowEmptyString()][string]$Err = '')
    if ($Code -eq 0) { return $true }
    $errLines = @($Err -split "`r?`n" | Where-Object { $_ -ne '' })
    $Code -eq 1 -and $Out -match '(?m)^config file: ' -and $errLines.Count -eq 1 -and $errLines[0] -match '^config error: .+: vault file not found$'
}

<#
.SYNOPSIS
    What step 4 does with config.json: 'keep' it, 'write' a new one from the answers, or
    'stop' with `Why`. Absent, or -Replace: write (-Replace is the way to correct a URL found
    wrong at step 8 or 10). There, trusted and passing the check: keep, unless a URL given on
    the command line differs from the kept one's (stop, naming -Replace: a given URL is never
    dropped without a word). There and untrusted (Test-TrustedFile) or failing the check: stop.
#>
function Get-ConfigPlan {
    [CmdletBinding()]
    param(
        [bool]$Exists,
        [bool]$CheckOk,
        [AllowEmptyString()][string]$Untrusted = '',
        [bool]$Replace,
        [AllowEmptyString()][string]$KeptCloudUrl = '',
        [AllowEmptyString()][string]$KeptVeeamUrl = '',
        [AllowEmptyString()][string]$CloudUrl = '',
        [AllowEmptyString()][string]$VeeamUrl = '',
        [AllowEmptyString()][string]$CheckLine = ''
    )
    function New-Plan([string]$Action, [string]$Why = '') { [pscustomobject]@{ Action = $Action; Why = $Why } }
    if (-not $Exists -or $Replace) { return New-Plan 'write' }
    if ($Untrusted) { return New-Plan 'stop' "is there and ${Untrusted}: someone else may have written it; read it, then give -Replace to write a new one." }
    if (-not $CheckOk) { return New-Plan 'stop' "is there and fails rpworker config check ($CheckLine); fix it, or give -Replace to write a new one." }
    foreach ($pair in @(@('cloud_url', $KeptCloudUrl, $CloudUrl), @('veeam_url', $KeptVeeamUrl, $VeeamUrl))) {
        if ($pair[2] -and $pair[2] -cne $pair[1]) { return New-Plan 'stop' "has $($pair[0]) $($pair[1]), not $($pair[2]): give -Replace to write the new one." }
    }
    New-Plan 'keep'
}

<#
.SYNOPSIS
    The config.json the installer writes: the two URLs, the Veeam certificate's file and pin
    when pinned, the Cloud's CA file when given, nothing else (the defaults stay the Worker's;
    the client keys and jobs_file are never written). Keys in the Worker's documented order.
#>
function New-ConfigDocument {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CloudUrl,
        [Parameter(Mandatory)][string]$VeeamUrl,
        [string]$VeeamCaFile = '',
        [string]$VeeamCertSha256 = '',
        [string]$CloudCaFile = ''
    )
    foreach ($url in $CloudUrl, $VeeamUrl) {
        if ($url -notmatch '^https://[\x21-\x7e]+$' -or $url -match '[?#@]') { throw "Not an https:// URL: $url" }
    }
    if (($VeeamCaFile -eq '') -ne ($VeeamCertSha256 -eq '')) { throw 'veeam_ca_file and veeam_cert_sha256 go together' }
    if ($VeeamCertSha256 -ne '' -and $VeeamCertSha256 -notmatch '^[0-9A-Fa-f]{64}$') { throw 'veeam_cert_sha256 is 64 hexadecimal digits' }
    $config = [ordered]@{ cloud_url = $CloudUrl; veeam_url = $VeeamUrl }
    if ($VeeamCaFile) { $config['veeam_ca_file'] = $VeeamCaFile; $config['veeam_cert_sha256'] = $VeeamCertSha256.ToUpperInvariant() }
    if ($CloudCaFile) { $config['cloud_ca_file'] = $CloudCaFile }
    $config
}

# --- the vault (decision point 9, step 5) ----------------------------------------------

<#
.SYNOPSIS
    From the names `rpworker vault list` printed: which to ask for (veeam_username and
    veeam_password when absent, or always with -Replace, the way to correct a password found
    wrong at step 8; cloud_install_token only when neither it nor cloud_api_token is there),
    whether the signing key and the Graph certificate must be made, and whether the Worker is
    registered already. The certificate is two names: with one of them alone it is made again
    over it (CertificateHalf: New-WorkerGraphCertificate.ps1 -Replace, as that script's own
    failure half-way says).
#>
function Get-VaultPlan {
    [CmdletBinding()]
    param([string[]]$Held = @(), [bool]$Replace = $false)
    $ask = [System.Collections.Generic.List[string]]::new()
    foreach ($name in 'veeam_username', 'veeam_password') { if ($Replace -or $Held -cnotcontains $name) { $ask.Add($name) } }
    $registered = $Held -ccontains 'cloud_api_token'
    if (-not $registered -and $Held -cnotcontains 'cloud_install_token') { $ask.Add('cloud_install_token') }
    [pscustomobject]@{
        Ask              = @($ask)
        NeedsSigningKey  = $Held -cnotcontains 'signing_key_base64'
        NeedsCertificate = ($Held -cnotcontains 'graph_cert_pfx_base64') -or ($Held -cnotcontains 'graph_cert_password')
        CertificateHalf  = ($Held -ccontains 'graph_cert_pfx_base64') -ne ($Held -ccontains 'graph_cert_password')
        Registered       = $registered
        HasInstallToken  = $Held -ccontains 'cloud_install_token'
    }
}

# --- Veeam's certificate (decision point 5) --------------------------------------------

<#
.SYNOPSIS
    What to do with the certificate veeam_url presented: 'pin' when it is in this machine's
    LocalMachine\My with its private key (Veeam's own, on this server), 'store' when it chains
    to the Windows store and names the host (nothing to set), 'confirm' otherwise (shown, the
    operator confirms its thumbprint before it is pinned).
#>
function Test-VeeamCertificate {
    [CmdletBinding()]
    param([bool]$InLocalStoreWithKey, [bool]$ChainsToStore, [bool]$NamesHost)
    if ($InLocalStoreWithKey) { return 'pin' }
    if ($ChainsToStore -and $NamesHost) { return 'store' }
    'confirm'
}

function Test-Thumbprint([string]$Text) { $Text -match '^[0-9A-Fa-f]{40}$' }

<#
.SYNOPSIS
    A certificate's DER as PEM, as the Worker's veeam_ca_file takes it.
#>
function ConvertTo-Pem([Parameter(Mandatory)][byte[]]$Der) {
    $body = [Convert]::ToBase64String($Der)
    $lines = for ($i = 0; $i -lt $body.Length; $i += 64) { $body.Substring($i, [Math]::Min(64, $body.Length - $i)) }
    "-----BEGIN CERTIFICATE-----`n" + ($lines -join "`n") + "`n-----END CERTIFICATE-----`n"
}

# --- the organisation certificates' key files (decision point 6) -----------------------

<#
.SYNOPSIS
    The organisations and their app certificate thumbprints from `rpworker veeam list`'s
    table: the APP CERTIFICATE column, one or more thumbprints joined by commas, or '-'. A cell
    that isn't 40 hexadecimal digits is a problem naming the organisation, never a thumbprint.
#>
function Read-OrganisationThumbprints {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $lines = @($Text -split "`r?`n" | Where-Object { $_ -ne '' })
    if ($lines.Count -eq 0 -or $lines[0] -notmatch '^  ORGANIZATION\s+APP CERTIFICATE\s+BACKUP TIME') {
        throw 'Not the table rpworker veeam list prints (no APP CERTIFICATE column: an older Worker?)'
    }
    $seen = [ordered]@{}
    foreach ($line in $lines | Select-Object -Skip 1) {
        if ($line -match '^\d+ organisation\(s\), ') { break }
        if ($line.Length -lt 3) { continue }
        $cells = @($line.Substring(2) -split '  +')
        if ($cells.Count -lt 2) { continue }
        $name = $cells[0]
        if ($seen.Contains($name)) { continue }
        $thumbprints = [System.Collections.Generic.List[string]]::new()
        $problems = [System.Collections.Generic.List[string]]::new()
        if ($cells[1] -ne '-') {
            foreach ($cell in $cells[1] -split ',') {
                if (Test-Thumbprint $cell) { $thumbprints.Add($cell.ToUpperInvariant()) } else { $problems.Add("not a thumbprint: $cell") }
            }
        }
        $seen[$name] = [pscustomobject]@{ Organisation = $name; Thumbprints = @($thumbprints); Problems = @($problems) }
    }
    @($seen.Values)
}

<#
.SYNOPSIS
    Where a machine key's file can be: a CAPI key under Crypto\RSA\MachineKeys, a CNG key
    under Crypto\Keys (W4.12). The script grants on the one that exists.
#>
function Get-KeyFileCandidates {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$UniqueName, [string]$ProgramData = $env:ProgramData)
    if ($UniqueName -match '[\\/]' -or $UniqueName -in '', '.', '..') { throw "Not a key container name: '$UniqueName'" }
    @(
        (Join-Path $ProgramData "Microsoft\Crypto\RSA\MachineKeys\$UniqueName"),
        (Join-Path $ProgramData "Microsoft\Crypto\Keys\$UniqueName")
    )
}

# --- the checks before anything is written (decision point 9, step 1) -------------------

<#
.SYNOPSIS
    The problems that stop the install before it writes: not elevated, PowerShell before 7.4,
    not 64-bit, not Windows. Each one line; none means go.
#>
function Test-Prerequisites {
    [CmdletBinding()]
    param([Parameter(Mandatory)][version]$PSVersion, [bool]$Elevated, [bool]$Is64Bit, [bool]$IsWindows)
    $problems = [System.Collections.Generic.List[string]]::new()
    if (-not $IsWindows) { $problems.Add('problem: the Worker runs on Windows alone') }
    if ($PSVersion -lt [version]'7.4') { $problems.Add("problem: PowerShell 7.4 or later is needed (this is $PSVersion)") }
    if (-not $Is64Bit) { $problems.Add('problem: a 64-bit Windows is needed') }
    if (-not $Elevated) { $problems.Add('problem: run this from an elevated PowerShell (Run as administrator)') }
    @($problems)
}

<#
.SYNOPSIS
    The command line `rpworker service install` registers for the exe at `Exe` with no --config
    (the default config path is the one the installer writes).
#>
function Get-ServiceCommandLine([Parameter(Mandatory)][string]$Exe) { "`"$Exe`" service run" }

<#
.SYNOPSIS
    Whether the installed service (an object with PathName, or $null) is ours: 'absent',
    'ok' (the same command line), or 'other' (another exe or another command line: an upgrade
    in place is W7.3's, so the install stops).
#>
function Test-InstalledService {
    [CmdletBinding()]
    param($Service, [Parameter(Mandatory)][string]$ExpectedCommandLine)
    if ($null -eq $Service) { return 'absent' }
    if ("$($Service.PathName)" -eq $ExpectedCommandLine) { return 'ok' }
    'other'
}

<#
.SYNOPSIS
    Whether `rpworker cloud register` was refused because the Cloud already holds this
    Worker's key: a registration whose 201 never reached this machine, or whose API token the
    vault could not take. The install token stays unused (the 409's transaction is rolled back),
    so a new key and a second register with the same token is the way out.
#>
function Test-KeyAlreadyRegistered([int]$Code, [AllowEmptyString()][string]$Err = '') {
    $Code -eq 4 -and $Err -match "(?m)^cloud register: this Worker's key is already registered\s*$"
}

<#
.SYNOPSIS
    The worker id and key id from `rpworker cloud register`'s line, or $null.
#>
function Read-RegistrationLine([AllowEmptyString()][string]$Text) {
    $m = [regex]::Match($Text, '(?m)^registered worker ([0-9a-f-]{36}) key ([0-9a-f]{64})\s*$')
    if (-not $m.Success) { return $null }
    [pscustomobject]@{ WorkerId = $m.Groups[1].Value; KeyId = $m.Groups[2].Value }
}

Export-ModuleMember -Function Get-ServiceSid, Get-WantedAcls, Get-ServiceFolderNames, Get-AclDifference, Get-IcaclsArguments, Update-AclObject, Add-FileReadRule,
    Test-TrustedFile, Test-ConfigCheck, Get-ConfigPlan, New-ConfigDocument, Get-VaultPlan, Test-VeeamCertificate, Test-Thumbprint, ConvertTo-Pem,
    Read-OrganisationThumbprints, Get-KeyFileCandidates, Test-Prerequisites, Get-ServiceCommandLine,
    Test-InstalledService, Test-KeyAlreadyRegistered, Read-RegistrationLine

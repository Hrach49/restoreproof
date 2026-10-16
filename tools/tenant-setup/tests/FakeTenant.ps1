<#
    A fake Microsoft 365 tenant for Initialize-RestoreProofTenant.ps1's tests (W7.0). Dot-source
    it with a state file: it defines functions named like the Graph and Exchange cmdlets the
    script calls (a function wins over a cmdlet of the same name), answers from the state, applies
    writes to it, and logs every request. Save-FakeTenant writes the state and the log back.

    The state is JSON (tests/fake_tenant.py builds it). Graph routes that the script has no
    business calling answer 400 "fake: no such route", so a request outside the expected set
    fails the test that made it. `failures` forces an answer: { "<METHOD> <path regex>": status }.
#>
param([Parameter(Mandatory)][string]$StatePath)

$global:FakeState = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json -AsHashtable
$global:FakeLog = [System.Collections.Generic.List[object]]::new()
$global:FakeIds = [int]($global:FakeState['nextId'] ?? 0)

function global:New-FakeId([string]$Prefix = '') {
    $global:FakeIds++
    if ($Prefix -eq 'item') { return ('01FAKE{0:D28}' -f $global:FakeIds) }
    if ($Prefix -eq 'drive') { return ('b!fake{0:D58}' -f $global:FakeIds) }
    if ($Prefix -eq 'perm') { return ('aTowaS50fGZake{0:D10}' -f $global:FakeIds) }
    ('fa4e0000-0000-4000-8000-{0:D12}' -f $global:FakeIds)
}

function global:Get-FakeField($Object, [string]$Name) {
    if ($Object -is [System.Collections.IDictionary] -and $Object.Contains($Name)) { return $Object[$Name] }
    $null
}

# A deep copy, so a reply the script keeps never aliases the state.
function global:Copy-Fake($Value) {
    if ($null -eq $Value) { return $null }
    ConvertTo-Json -InputObject $Value -Depth 50 -Compress | ConvertFrom-Json -AsHashtable
}

# What Graph keeps of an uploaded certificate: its SHA-1 thumbprint as customKeyIdentifier, no key.
function global:Get-FakeThumbprint([string]$Base64) {
    [Convert]::ToBase64String([Security.Cryptography.SHA1]::HashData([Convert]::FromBase64String($Base64)))
}
function global:Throw-FakeHttp([int]$Status, [string]$Code = 'fake') {
    $exception = [System.Net.Http.HttpRequestException]::new("Response status code does not indicate success: $Status ($Code).", $null, [System.Net.HttpStatusCode]$Status)
    throw $exception
}

function global:Save-FakeTenant([string]$Path) {
    $global:FakeState['nextId'] = $global:FakeIds
    $doc = @{ state = $global:FakeState; log = $global:FakeLog }
    [IO.File]::WriteAllText($Path, (ConvertTo-Json -InputObject $doc -Depth 50), [Text.UTF8Encoding]::new($false))
}

# ---- the modules and the sign-ins -----------------------------------------------------------------

function global:Get-Module {
    param([switch]$ListAvailable, [string[]]$Name)
    $installed = Get-FakeField $global:FakeState 'modules'
    if ($ListAvailable -and $Name -and @('Microsoft.Graph.Authentication', 'ExchangeOnlineManagement') -contains $Name[0]) {
        $version = Get-FakeField $installed $Name[0]
        if ($version) { return [pscustomobject]@{ Name = $Name[0]; Version = [version]$version } }
        return $null
    }
    Microsoft.PowerShell.Core\Get-Module @PSBoundParameters
}

function global:Import-Module {
    param([Parameter(Position = 0)][string]$Name, [version]$MinimumVersion, [switch]$Force)
    if (@('Microsoft.Graph.Authentication', 'ExchangeOnlineManagement') -contains $Name) { return }
    Microsoft.PowerShell.Core\Import-Module $Name -Force:$Force -Global
}

function global:Connect-MgGraph {
    param([string]$TenantId, [string[]]$Scopes, [switch]$NoWelcome, [string]$ContextScope)
    $global:FakeLog.Add(@{ call = 'Connect-MgGraph'; tenant = $TenantId; scopes = @($Scopes) })
}
function global:Get-MgContext {
    [pscustomobject]@{ TenantId = $global:FakeState.signedInTenant; Account = $global:FakeState.account }
}
function global:Disconnect-MgGraph { $global:FakeLog.Add(@{ call = 'Disconnect-MgGraph' }) }
# The real module imports every cmdlet the admin may run into a generated module of functions,
# which shadow a function of the same name imported before it: Exchange's own Get-MailboxPlan
# shadowed the setup module's (the first live run, 2026-10-16). Without -CommandName the fake
# does the same with that one; with it, only the named cmdlets come in (the fakes below).
function global:Connect-ExchangeOnline {
    param([string]$UserPrincipalName, [switch]$ShowBanner, [switch]$DisableWAM, [string[]]$CommandName)
    $global:FakeLog.Add(@{ call = 'Connect-ExchangeOnline'; user = $UserPrincipalName; commands = @($CommandName) })
    if (-not $CommandName) {
        function global:Get-MailboxPlan { param([Parameter(Position = 0)]$Identity) throw 'Exchange''s Get-MailboxPlan, not the setup module''s' }
    }
    if (Get-FakeField $global:FakeState 'exchangeConnectFails') { throw 'fake: the Exchange sign-in was cancelled' }
}
# The organisation Exchange connected to: `exchangeTenant`, else the Graph session's.
function global:Get-ConnectionInformation {
    [pscustomobject]@{ TenantID = (Get-FakeField $global:FakeState 'exchangeTenant') ?? $global:FakeState.signedInTenant; State = 'Connected' }
}
# Waits are logged, never slept.
function global:Start-Sleep { param([int]$Seconds) $global:FakeLog.Add(@{ call = 'sleep'; seconds = $Seconds }) }
function global:Disconnect-ExchangeOnline { param([switch]$Confirm) $global:FakeLog.Add(@{ call = 'Disconnect-ExchangeOnline' }) }

# ---- Microsoft Graph --------------------------------------------------------------------------------

function global:Find-FakeSite([string]$Key) {
    foreach ($site in $global:FakeState.sites) {
        if ($site.id -eq $Key -or $site.path -ieq $Key) { return $site }
    }
    $null
}
function global:Find-FakeList($Site, [string]$Id) { ($Site.lists | Where-Object { $_.id -eq $Id } | Select-Object -First 1) }
function global:Find-FakeDrive([string]$Id) { ($global:FakeState.drives | Where-Object { $_.id -eq $Id } | Select-Object -First 1) }
function global:Find-FakeUser([string]$Key) { ($global:FakeState.users | Where-Object { $_.userPrincipalName -ieq $Key -or $_.id -eq $Key } | Select-Object -First 1) }

# The public form of a list (no state of the fake's own).
function global:Get-FakeListReply($List) {
    @{ id = $List.id; displayName = $List.displayName; webUrl = $List.webUrl; list = @{ template = $List.template } }
}
function global:Get-FakeItemReply($Drive, $Item) {
    $reply = @{ id = $Item.id; name = $Item.name; parentReference = @{ driveId = $Drive.id; path = $Item.parentPath } }
    if ($Item.kind -eq 'folder') { $reply.folder = @{ childCount = 0 } } else { $reply.file = @{ mimeType = 'application/octet-stream' } }
    $reply
}

# A permission collection: GET (list), POST (add), and one permission: GET, PATCH, DELETE.
function global:Invoke-FakePermissions($Holder, [string]$Method, [string]$PermissionId, $Body) {
    if (-not $Holder.Contains('permissions')) { $Holder.permissions = @() }
    if (-not $PermissionId) {
        if ($Method -eq 'GET') { return @{ value = @(Copy-Fake $Holder.permissions | Where-Object { $_ }) } }
        if ($Method -eq 'POST') {
            $grant = Copy-Fake $Body
            $grant.id = New-FakeId 'perm'
            $Holder.permissions = @($Holder.permissions) + @($grant)
            return Copy-Fake $grant
        }
    }
    else {
        $grant = ($Holder.permissions | Where-Object { $_.id -eq $PermissionId } | Select-Object -First 1)
        if (-not $grant) { Throw-FakeHttp 404 'itemNotFound' }
        if ($Method -eq 'GET') { return Copy-Fake $grant }
        if ($Method -eq 'PATCH') { $grant.roles = @($Body.roles); return Copy-Fake $grant }
        if ($Method -eq 'DELETE') { $Holder.permissions = @($Holder.permissions | Where-Object { $_.id -ne $PermissionId }); return $null }
    }
    Throw-FakeHttp 400 'fake: no such route'
}

function global:Invoke-MgGraphRequest {
    param([string]$Method, [string]$Uri, $Body, [string]$ContentType, [string]$OutputType)
    $base = 'https://graph.microsoft.com/v1.0/'
    if (-not $Uri.StartsWith($base)) { Throw-FakeHttp 400 'fake: not Graph v1.0' }
    $relative = $Uri.Substring($base.Length)
    $path, $query = $relative.Split('?', 2)
    $data = if ($Body) { $Body | ConvertFrom-Json -AsHashtable } else { $null }
    $global:FakeLog.Add(@{ call = 'graph'; method = $Method; path = $relative; body = $data })
    # A failure is a status (every time) or { status; times } (that many times, then the route).
    $failures = (Get-FakeField $global:FakeState 'failures') ?? @{}
    foreach ($rule in @($failures.Keys)) {
        $m, $pattern = $rule.Split(' ', 2)
        if ($m -ne $Method -or $path -notmatch $pattern) { continue }
        $failure = $failures[$rule]
        if ($failure -isnot [System.Collections.IDictionary]) { Throw-FakeHttp ([int]$failure) 'forced' }
        if ([int]$failure.times -gt 0) { $failure.times = [int]$failure.times - 1; Throw-FakeHttp ([int]$failure.status) 'forced' }
    }
    $s = $global:FakeState
    switch -Regex ($path) {
        '^organization$' { return @{ value = @(Copy-Fake $s.organization) } }
        "^servicePrincipals\(appId='([^']+)'\)$" {
            if ($Matches[1] -ne '00000003-0000-0000-c000-000000000000') { Throw-FakeHttp 404 }
            return Copy-Fake $s.graphServicePrincipal
        }
        '^sites/([^/]+:/[^/]+/[^/:]+)$' {
            $site = Find-FakeSite $Matches[1]
            if (-not $site -or $Method -ne 'GET') { Throw-FakeHttp 404 'itemNotFound' }
            return @{ id = $site.id; webUrl = $site.webUrl; displayName = $site.displayName }
        }
        '^sites/([^/]+)/lists$' {
            $site = Find-FakeSite $Matches[1]
            if (-not $site) { Throw-FakeHttp 404 }
            if ($Method -eq 'GET') { return @{ value = @($site.lists | ForEach-Object { Get-FakeListReply $_ }) } }
            if ($Method -eq 'POST') {
                $id = New-FakeId
                $list = @{ id = $id; displayName = $data.displayName; webUrl = "$($site.webUrl)/$($data.displayName)"; template = $data.list.template; driveId = (New-FakeId 'drive'); permissions = @() }
                $site.lists = @($site.lists) + @($list)
                return Get-FakeListReply $list
            }
        }
        '^sites/([^/]+)/lists/([^/]+)$' {
            $list = Find-FakeList (Find-FakeSite $Matches[1]) $Matches[2]
            if (-not $list -or $Method -ne 'GET') { Throw-FakeHttp 404 }
            return Get-FakeListReply $list
        }
        '^sites/([^/]+)/lists/([^/]+)/drive$' {
            $list = Find-FakeList (Find-FakeSite $Matches[1]) $Matches[2]
            if (-not $list) { Throw-FakeHttp 404 }
            return @{ id = $list.driveId }
        }
        '^sites/([^/]+)/lists/([^/]+)/permissions(?:/([^/]+))?$' {
            $list = Find-FakeList (Find-FakeSite $Matches[1]) $Matches[2]
            if (-not $list) { Throw-FakeHttp 404 }
            return Invoke-FakePermissions $list $Method $Matches[3] $data
        }
        '^sites/([^/]+)/permissions(?:/([^/]+))?$' {
            $site = Find-FakeSite $Matches[1]
            if (-not $site) { Throw-FakeHttp 404 }
            return Invoke-FakePermissions $site $Method ([Uri]::UnescapeDataString("$($Matches[2])")) $data
        }
        '^users/([^/]+)/drive$' {
            $user = Find-FakeUser $Matches[1]
            if (-not $user -or -not $user.driveId) { Throw-FakeHttp 404 }
            $drive = Find-FakeDrive $user.driveId
            if ($drive.forbidden) { Throw-FakeHttp 403 'accessDenied' }
            return @{ id = $drive.id; webUrl = $drive.webUrl }
        }
        '^drives/([^/]+)/root:/([^/:]+)$' {
            $drive = Find-FakeDrive $Matches[1]
            if (-not $drive) { Throw-FakeHttp 404 }
            if ($drive.forbidden) { Throw-FakeHttp 403 'accessDenied' }
            $name = $Matches[2]
            $item = ($drive.items | Where-Object { $_.name -ieq $name -and $_.parentPath -eq '/drive/root:' } | Select-Object -First 1)
            if (-not $item) { Throw-FakeHttp 404 'itemNotFound' }
            return Get-FakeItemReply $drive $item
        }
        '^drives/([^/]+)/root/children$' {
            $drive = Find-FakeDrive $Matches[1]
            if (-not $drive -or $Method -ne 'POST') { Throw-FakeHttp 404 }
            if (@($drive.items | Where-Object { $_.name -ieq $data.name -and $_.parentPath -eq '/drive/root:' }).Count -gt 0) { Throw-FakeHttp 409 'nameAlreadyExists' }
            $item = @{ id = (New-FakeId 'item'); name = $data.name; kind = 'folder'; parentPath = '/drive/root:'; permissions = @() }
            $drive.items = @($drive.items) + @($item)
            return Get-FakeItemReply $drive $item
        }
        '^drives/([^/]+)/root$' {
            $drive = Find-FakeDrive $Matches[1]
            if (-not $drive) { Throw-FakeHttp 404 }
            return @{ id = $drive.root.id; name = 'root'; sharepointIds = @{ siteUrl = $drive.siteUrl } }
        }
        '^drives/([^/]+)/root/permissions$' {
            $drive = Find-FakeDrive $Matches[1]
            if (-not $drive) { Throw-FakeHttp 404 }
            return Invoke-FakePermissions $drive.root $Method '' $data
        }
        '^drives/([^/]+)/items/([^/]+)$' {
            $drive = Find-FakeDrive $Matches[1]
            $item = ($drive.items | Where-Object { $_.id -eq $Matches[2] } | Select-Object -First 1)
            if (-not $item -or $Method -ne 'GET') { Throw-FakeHttp 404 }
            return Get-FakeItemReply $drive $item
        }
        '^drives/([^/]+)/items/([^/]+)/permissions(?:/([^/]+))?$' {
            $drive = Find-FakeDrive $Matches[1]
            $item = ($drive.items | Where-Object { $_.id -eq $Matches[2] } | Select-Object -First 1)
            if (-not $item) { Throw-FakeHttp 404 }
            return Invoke-FakePermissions $item $Method $Matches[3] $data
        }
        '^applications$' {
            if ($Method -eq 'GET') {
                if ($query -notmatch "filter=displayName eq '([^']+)'") { Throw-FakeHttp 400 'fake: no filter' }
                $name = $Matches[1]
                return @{ value = @($s.applications | Where-Object { $_.displayName -eq $name } | ForEach-Object { Copy-Fake $_ }) }
            }
            if ($Method -eq 'POST') {
                $app = Copy-Fake $data
                $app.id = New-FakeId; $app.appId = New-FakeId; $app.passwordCredentials = @()
                $app.keyCredentials = @($app.keyCredentials | ForEach-Object { @{ keyId = (New-FakeId); displayName = $_.displayName; type = $_.type; usage = $_.usage; customKeyIdentifier = (Get-FakeThumbprint $_.key); key = $null } })
                $s.applications = @($s.applications) + @($app)
                return Copy-Fake $app
            }
        }
        '^applications/([^/]+)$' {
            $app = ($s.applications | Where-Object { $_.id -eq $Matches[1] } | Select-Object -First 1)
            if (-not $app -or $Method -ne 'PATCH') { Throw-FakeHttp 404 }
            foreach ($key in $data.Keys) {
                if ($key -eq 'keyCredentials') {
                    $app.keyCredentials = @($data.keyCredentials | ForEach-Object { @{ keyId = (New-FakeId); displayName = $_.displayName; type = $_.type; usage = $_.usage; customKeyIdentifier = (Get-FakeThumbprint $_.key); key = $null } })
                }
                else { $app[$key] = $data[$key] }
            }
            return $null
        }
        '^applications/([^/]+)/removePassword$' {
            $app = ($s.applications | Where-Object { $_.id -eq $Matches[1] } | Select-Object -First 1)
            if (-not $app) { Throw-FakeHttp 404 }
            $app.passwordCredentials = @($app.passwordCredentials | Where-Object { $_.keyId -ne $data.keyId })
            return $null
        }
        '^applications/([^/]+)/federatedIdentityCredentials$' {
            $app = ($s.applications | Where-Object { $_.id -eq $Matches[1] } | Select-Object -First 1)
            if (-not $app) { Throw-FakeHttp 404 }
            return @{ value = @(Copy-Fake (Get-FakeField $app 'federated') | Where-Object { $_ }) }
        }
        '^servicePrincipals$' {
            if ($Method -eq 'GET') {
                if ($query -notmatch "filter=appId eq '([^']+)'") { Throw-FakeHttp 400 'fake: no filter' }
                $appId = $Matches[1]
                return @{ value = @($s.servicePrincipals | Where-Object { $_.appId -eq $appId } | ForEach-Object { Copy-Fake $_ }) }
            }
            if ($Method -eq 'POST') {
                $sp = @{ id = (New-FakeId); appId = $data.appId; displayName = 'RestoreProof Worker' }
                $s.servicePrincipals = @($s.servicePrincipals) + @($sp)
                return Copy-Fake $sp
            }
        }
        '^servicePrincipals/([^/]+)/appRoleAssignments(?:/([^/]+))?$' {
            $spId = $Matches[1]; $assignmentId = $Matches[2]
            if ($Method -eq 'GET' -and -not $assignmentId) { return @{ value = @($s.appRoleAssignments | Where-Object { $_.principalId -eq $spId } | ForEach-Object { Copy-Fake $_ }) } }
            if ($Method -eq 'POST') {
                $a = @{ id = (New-FakeId); principalId = $spId; resourceId = $data.resourceId; appRoleId = $data.appRoleId; resourceDisplayName = 'Microsoft Graph' }
                $s.appRoleAssignments = @($s.appRoleAssignments) + @($a)
                return Copy-Fake $a
            }
            if ($Method -eq 'DELETE') { $s.appRoleAssignments = @($s.appRoleAssignments | Where-Object { $_.id -ne $assignmentId }); return $null }
        }
        '^servicePrincipals/([^/]+)/oauth2PermissionGrants$' {
            $spId = $Matches[1]
            return @{ value = @($s.oauth2PermissionGrants | Where-Object { $_.clientId -eq $spId } | ForEach-Object { Copy-Fake $_ }) }
        }
        '^oauth2PermissionGrants/([^/]+)$' {
            if ($Method -ne 'DELETE') { Throw-FakeHttp 400 }
            $grantId = $Matches[1]
            $s.oauth2PermissionGrants = @($s.oauth2PermissionGrants | Where-Object { $_.id -ne $grantId })
            return $null
        }
        '^servicePrincipals/([^/]+)/memberOf$' {
            $spId = $Matches[1]
            return @{ value = @(Copy-Fake (Get-FakeField $s.memberOf $spId) | Where-Object { $_ }) }
        }
    }
    Throw-FakeHttp 400 'fake: no such route'
}

# ---- Exchange Online --------------------------------------------------------------------------------

function global:Add-FakeExchangeLog([string]$Cmdlet, $Arguments) { $global:FakeLog.Add(@{ call = 'exchange'; cmdlet = $Cmdlet; args = $Arguments }) }
function global:Get-FakeExchange { $global:FakeState.exchange }

function global:Get-Recipient {
    param([string]$Identity, $ErrorAction)
    Add-FakeExchangeLog 'Get-Recipient' @{ Identity = $Identity }
    # Exchange's own words, as the REST cmdlets throw them: none found, several found, or a forced
    # failure (`recipientErrors`: { address: text }).
    $forced = Get-FakeField (Get-FakeField (Get-FakeExchange) 'recipientErrors') $Identity
    if ($forced) { throw $forced }
    $found = @((Get-FakeExchange).recipients | Where-Object { $_.PrimarySmtpAddress -ieq $Identity -or @($_.EmailAddresses) -icontains "smtp:$Identity" } | ForEach-Object { Copy-Fake $_ })
    if ($found.Count -eq 0) { throw "|Microsoft.Exchange.Configuration.Tasks.ManagementObjectNotFoundException|The operation couldn't be performed because object '$Identity' couldn't be found on 'FAKEPR01A001.PROD.OUTLOOK.COM'." }
    if ($found.Count -gt 1) { throw "|Microsoft.Exchange.Configuration.Tasks.ManagementObjectAmbiguousException|The operation couldn't be performed because '$Identity' matches multiple entries." }
    $found
}
function global:New-Mailbox {
    param([switch]$Shared, [string]$Name, [string]$DisplayName, [string]$Alias, [string]$PrimarySmtpAddress, $ErrorAction)
    Add-FakeExchangeLog 'New-Mailbox' @{ Shared = [bool]$Shared; Name = $Name; Alias = $Alias; PrimarySmtpAddress = $PrimarySmtpAddress }
    $x = Get-FakeExchange
    $x.recipients = @($x.recipients) + @(@{ Name = $Name; Alias = $Alias; RecipientTypeDetails = 'SharedMailbox'; PrimarySmtpAddress = $PrimarySmtpAddress; EmailAddresses = @("SMTP:$PrimarySmtpAddress") })
}
function global:Get-OrganizationConfig { param($ErrorAction) Add-FakeExchangeLog 'Get-OrganizationConfig' @{}; [pscustomobject]@{ IsDehydrated = [bool](Get-FakeExchange).isDehydrated } }
function global:Enable-OrganizationCustomization { param($ErrorAction) Add-FakeExchangeLog 'Enable-OrganizationCustomization' @{}; (Get-FakeExchange).isDehydrated = $false }
function global:Get-ServicePrincipal {
    param([string]$Identity, $ErrorAction)
    Add-FakeExchangeLog 'Get-ServicePrincipal' @{ Identity = $Identity }
    ((Get-FakeExchange).pointers | Where-Object { $_.AppId -eq $Identity -or $_.ObjectId -eq $Identity } | ForEach-Object { Copy-Fake $_ } | Select-Object -First 1)
}
function global:New-ServicePrincipal {
    param([string]$AppId, [string]$ObjectId, [string]$DisplayName, $ErrorAction)
    Add-FakeExchangeLog 'New-ServicePrincipal' @{ AppId = $AppId; ObjectId = $ObjectId }
    $x = Get-FakeExchange
    # Exchange sees a new Entra service principal minutes after Graph made it: `pointerNotFound`
    # answers with its words that many times first (the second live run, 2026-10-16).
    $pending = [int](Get-FakeField $x 'pointerNotFound')
    if ($pending -gt 0) {
        $x.pointerNotFound = $pending - 1
        throw "||Error: AADServicePrincipalNotFound. No ServicePrincipal with Object Id '$ObjectId' for Client Application Id '$AppId' is registered in this tenant. Exchange Service Principals"
    }
    $x.pointers = @($x.pointers) + @(@{ AppId = $AppId; ObjectId = $ObjectId; DisplayName = $DisplayName })
}
function global:Remove-ServicePrincipal {
    param([string]$Identity, [switch]$Confirm, $ErrorAction)
    Add-FakeExchangeLog 'Remove-ServicePrincipal' @{ Identity = $Identity }
    $x = Get-FakeExchange
    if (@($x.assignments | Where-Object { $_.RoleAssigneeName -eq $Identity }).Count -gt 0) { throw 'fake: the pointer still has role assignments' }
    $x.pointers = @($x.pointers | Where-Object { $_.ObjectId -ne $Identity })
}
function global:Get-ManagementScope {
    param([string]$Identity, $ErrorAction)
    Add-FakeExchangeLog 'Get-ManagementScope' @{ Identity = $Identity }
    ((Get-FakeExchange).scopes | Where-Object { $_.Name -eq $Identity } | ForEach-Object { Copy-Fake $_ } | Select-Object -First 1)
}
function global:New-ManagementScope {
    param([string]$Name, [string]$RecipientRestrictionFilter, $ErrorAction)
    Add-FakeExchangeLog 'New-ManagementScope' @{ Name = $Name; RecipientRestrictionFilter = $RecipientRestrictionFilter }
    $x = Get-FakeExchange
    if ($x.isDehydrated) { throw 'Run Enable-OrganizationCustomization first' }
    $x.scopes = @($x.scopes) + @(@{ Name = $Name; RecipientFilter = $RecipientRestrictionFilter })
}
function global:Set-ManagementScope {
    param([string]$Identity, [string]$RecipientRestrictionFilter, $ErrorAction)
    Add-FakeExchangeLog 'Set-ManagementScope' @{ Identity = $Identity; RecipientRestrictionFilter = $RecipientRestrictionFilter }
    ((Get-FakeExchange).scopes | Where-Object { $_.Name -eq $Identity } | Select-Object -First 1).RecipientFilter = $RecipientRestrictionFilter
}
function global:Get-ManagementRoleAssignment {
    param($ErrorAction)
    Add-FakeExchangeLog 'Get-ManagementRoleAssignment' @{}
    @((Get-FakeExchange).assignments | ForEach-Object { Copy-Fake $_ })
}
function global:New-ManagementRoleAssignment {
    param([string]$Name, [string]$App, [string]$Role, [string]$CustomResourceScope, $ErrorAction)
    Add-FakeExchangeLog 'New-ManagementRoleAssignment' @{ Name = $Name; App = $App; Role = $Role; CustomResourceScope = $CustomResourceScope }
    $x = Get-FakeExchange
    $x.assignments = @($x.assignments) + @(@{ Name = $Name; Role = $Role; RoleAssigneeType = 'ServicePrincipal'; RoleAssigneeName = $App; CustomResourceScope = $CustomResourceScope; Identity = $Name })
}
function global:Remove-ManagementRoleAssignment {
    param([string]$Identity, [switch]$Confirm, $ErrorAction)
    Add-FakeExchangeLog 'Remove-ManagementRoleAssignment' @{ Identity = $Identity }
    $x = Get-FakeExchange
    $x.assignments = @($x.assignments | Where-Object { $_.Identity -ne $Identity })
}
# In scope: an assignment of the app (by its service principal's ID) whose scope's filter names
# the mailbox's primary address. As Exchange answers it: one row per role the app holds.
function global:Test-ServicePrincipalAuthorization {
    param([string]$Identity, [string]$Resource, $ErrorAction)
    Add-FakeExchangeLog 'Test-ServicePrincipalAuthorization' @{ Identity = $Identity; Resource = $Resource }
    $x = Get-FakeExchange
    $pointer = ($x.pointers | Where-Object { $_.AppId -eq $Identity } | Select-Object -First 1)
    if (-not $pointer) { throw "The service principal $Identity couldn't be found" }
    foreach ($a in @($x.assignments | Where-Object { $_.RoleAssigneeName -eq $pointer.ObjectId })) {
        $scope = ($x.scopes | Where-Object { $_.Name -eq $a.CustomResourceScope } | Select-Object -First 1)
        $in = $scope -and $scope.RecipientFilter -ieq "PrimarySmtpAddress -eq '$Resource'"
        if (-not $scope) { $in = $true }
        [pscustomobject]@{ RoleName = $a.Role; InScope = "$([bool]$in)" }
    }
}

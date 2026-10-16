<#
.SYNOPSIS
    Read-only: records the answers Graph and Exchange Online give about a tenant set up for
    RestoreProof, as the fixtures of tools/tenant-setup's tests (W7.0, docs/decisions.md
    2026-10-16, point 10).

.DESCRIPTION
    Sends GETs to Microsoft Graph and runs Get-* and Test-ServicePrincipalAuthorization cmdlets
    in Exchange Online, nothing else: it changes nothing in the tenant. Run it as the tenant's
    global admin, in PowerShell 7.4 or later, while the tenant still holds the RestoreProof Worker
    app and its three restore targets (the lab tenant before W7.0's teardown).

    Each answer is one JSON file in -Out: { source, request, status, reply }. A refused GET is
    recorded with its status and Graph's error body. The signed-in admin's address and name (and
    each half of the name) are replaced by "admin" before anything is written, since a fixture
    names no person but the test accounts (the W4.1 rule). Microsoft Graph's own service
    principal is trimmed to the application roles the tests name. Nothing the tenant answers here
    is secret: a certificate credential comes back without its key.

    Writes nothing but the files in -Out, which must be empty or absent.

.EXAMPLE
    pwsh -NoProfile -File tools\tenant-setup\tests\record\Record-TenantAnswers.ps1 `
        -TenantId bcd6bd1a-ea42-489d-aa28-2c19a44ad146 `
        -SiteUrl https://restoreprooflab.sharepoint.com/sites/RestoreTest `
        -OneDriveUser alice@RestoreProofLab.onmicrosoft.com `
        -Out tools\tenant-setup\tests\fixtures\lab
#>
#Requires -Version 7.4
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$SiteUrl,
    [Parameter(Mandatory)][string]$OneDriveUser,
    [string]$MailboxAddress = '',
    [string]$AppName = 'RestoreProof Worker',
    [Parameter(Mandatory)][string]$Out
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$GraphBase = 'https://graph.microsoft.com/v1.0/'
$GraphAppId = '00000003-0000-0000-c000-000000000000'
$MailScopeName = 'RestoreProof Worker - restoretest mailbox'
# The application roles kept from Graph's service principal: the Worker's three and the ones a
# test names as never allowed.
$KeptGraphRoles = @(
    'Sites.Selected', 'Files.SelectedOperations.Selected', 'Lists.SelectedOperations.Selected',
    'Mail.Read', 'Mail.ReadWrite', 'Mail.Send', 'Sites.Read.All', 'Sites.ReadWrite.All', 'Sites.FullControl.All',
    'Files.Read.All', 'Files.ReadWrite.All', 'User.Read.All', 'Directory.Read.All'
)
$Recorded = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd')
$Source = "recorded read-only from the lab tenant on $Recorded by tests/record/Record-TenantAnswers.ps1"

if ((Test-Path -LiteralPath $Out) -and @(Get-ChildItem -LiteralPath $Out -Force).Count -gt 0) {
    throw "$Out is not empty: record into an empty folder."
}
New-Item -ItemType Directory -Force -Path $Out | Out-Null

$script:Count = 0
$script:Scrub = @()

# The admin's address and name, and each half of the name, as "admin" (any case), in plain text
# and inside a base64 ID: SharePoint's permission IDs are a claim login name
# (i:0#.f|membership|<upn>) in base64url, so the admin's address is in them encoded.
function Get-ScrubbedPlain([string]$Text) {
    foreach ($pair in $script:Scrub) { $Text = [regex]::Replace($Text, [regex]::Escape($pair[0]), $pair[1], 'IgnoreCase') }
    $Text
}

# One base64 or base64url token: decoded, scrubbed and encoded again in its own alphabet and
# padding when it is UTF-8 text naming the admin; left as it was otherwise.
function Get-ScrubbedToken([string]$Token) {
    $url = $Token -notmatch '[+/]'
    $bare = $Token.TrimEnd('=')
    $padded = ($url ? $bare.Replace('-', '+').Replace('_', '/') : $bare) + ('=' * ((4 - $bare.Length % 4) % 4))
    try { $text = [Text.UTF8Encoding]::new($false, $true).GetString([Convert]::FromBase64String($padded)) } catch { return $Token }
    $clean = Get-ScrubbedPlain $text
    if ($clean -ceq $text) { return $Token }
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($clean))
    if ($url) { $encoded = $encoded.Replace('+', '-').Replace('/', '_') }
    if ($Token -notmatch '=$') { $encoded = $encoded.TrimEnd('=') }
    $encoded
}

function Get-Scrubbed([string]$Text) {
    $Text = [regex]::Replace($Text, '[A-Za-z0-9+/_-]{16,}={0,2}', { param($m) Get-ScrubbedToken $m.Value })
    Get-ScrubbedPlain $Text
}

function Save-Answer([string]$Name, [string]$Request, [int]$Status, $Reply) {
    $script:Count++
    $file = Join-Path $Out ('{0:D3}-{1}.json' -f $script:Count, $Name)
    $doc = [ordered]@{ source = $Source; request = $Request; status = $Status; reply = $Reply }
    $json = Get-Scrubbed (ConvertTo-Json -InputObject $doc -Depth 50)
    [IO.File]::WriteAllText($file, $json + "`n", [Text.UTF8Encoding]::new($false))
    Write-Host ('{0,3} {1} {2}' -f $Status, $Request, (Split-Path -Leaf $file))
}

# One GET, recorded whatever its status; returns the reply on a 2xx, else $null.
function Get-Graph([string]$Name, [string]$Path) {
    $uri = $GraphBase + $Path
    try {
        $reply = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType HashTable
        Save-Answer $Name "GET /v1.0/$Path" 200 $reply
        return $reply
    }
    catch {
        $response = $_.Exception.PSObject.Properties['Response']
        $status = if ($response -and $response.Value) { [int]$response.Value.StatusCode } else { 0 }
        $body = $null
        try { $body = "$($_.ErrorDetails.Message)" | ConvertFrom-Json -AsHashtable } catch { $body = $null }
        Save-Answer $Name "GET /v1.0/$Path" $status $body
        return $null
    }
}

function Get-Field($Object, [string]$Name) {
    if ($Object -is [System.Collections.IDictionary] -and $Object.Contains($Name)) { return $Object[$Name] }
    return $null
}

# Exchange objects as plain strings, the form the setup script reads them in.
function ConvertTo-Plain($Objects, [string[]]$Properties) {
    @(foreach ($o in @($Objects | Where-Object { $_ })) {
            $row = [ordered]@{}
            foreach ($p in $Properties) {
                $value = $o.$p
                $row[$p] = if ($value -is [System.Collections.IEnumerable] -and $value -isnot [string]) { @($value | ForEach-Object { "$_" }) } else { "$value" }
            }
            $row
        })
}

# ---- Microsoft Graph ------------------------------------------------------------------------------
Connect-MgGraph -TenantId $TenantId -NoWelcome -ContextScope Process `
    -Scopes 'Application.Read.All', 'Sites.FullControl.All', 'Files.Read.All', 'User.Read.All', 'Organization.Read.All'
try {
    $me = Invoke-MgGraphRequest -Method GET -Uri "${GraphBase}me?`$select=userPrincipalName,displayName,mail" -OutputType HashTable
    $upn = "$($me['userPrincipalName'])"
    $local = $upn.Split('@')[0]
    $script:Scrub = @(, @($upn, "admin@$($upn.Split('@')[1])"))
    if ("$($me['mail'])") { $script:Scrub += , @("$($me['mail'])", "admin@$($upn.Split('@')[1])") }
    $script:Scrub += , @($local, 'admin')
    foreach ($part in @("$($me['displayName'])") + "$($me['displayName'])".Split(' ', [StringSplitOptions]::RemoveEmptyEntries)) {
        if ($part.Length -ge 3) { $script:Scrub += , @($part, 'Admin') }
    }

    $org = Get-Graph 'organization' 'organization?$select=id,displayName,verifiedDomains'
    $initial = @((Get-Field $org 'value') | ForEach-Object { Get-Field $_ 'verifiedDomains' } | Where-Object { $_['isInitial'] })[0]['name']
    if (-not $MailboxAddress) { $MailboxAddress = "restoretest@$initial" }

    $null = Get-Graph 'root-site' 'sites/root?$select=id,webUrl,displayName'
    $uri = [Uri]$SiteUrl
    $site = Get-Graph 'site' "sites/$($uri.Host):$($uri.AbsolutePath.TrimEnd('/'))?`$select=id,webUrl,displayName"
    $siteId = "$(Get-Field $site 'id')"
    $lists = Get-Graph 'site-lists' "sites/$siteId/lists?`$select=id,displayName,webUrl,list"
    foreach ($p in @(Get-Field (Get-Graph 'site-permissions' "sites/$siteId/permissions") 'value')) {
        $null = Get-Graph 'site-permission' "sites/$siteId/permissions/$([Uri]::EscapeDataString("$(Get-Field $p 'id')"))"
    }
    foreach ($list in @(Get-Field $lists 'value')) {
        $listId = "$(Get-Field $list 'id')"
        $slug = ("$(Get-Field $list 'displayName')" -replace '[^A-Za-z0-9]+', '-').Trim('-').ToLowerInvariant()
        $null = Get-Graph "list-$slug" "sites/$siteId/lists/${listId}?`$select=id,displayName,webUrl,list"
        $null = Get-Graph "list-$slug-drive" "sites/$siteId/lists/$listId/drive?`$select=id,name,webUrl"
        $null = Get-Graph "list-$slug-permissions" "sites/$siteId/lists/$listId/permissions"
    }

    $null = Get-Graph 'user' "users/${OneDriveUser}?`$select=id,userPrincipalName"
    $drive = Get-Graph 'user-drive' "users/$OneDriveUser/drive?`$select=id,webUrl,driveType"
    $driveId = "$(Get-Field $drive 'id')"
    $root = Get-Graph 'user-drive-root' "drives/$driveId/root?`$select=id,name,sharepointIds"
    $null = Get-Graph 'user-drive-root-permissions' "drives/$driveId/root/permissions"
    $folder = Get-Graph 'user-folder' "drives/$driveId/root:/RestoreTarget?`$select=id,name,folder,file,parentReference"
    if ($folder) { $null = Get-Graph 'user-folder-permissions' "drives/$driveId/items/$(Get-Field $folder 'id')/permissions" }
    $null = Get-Graph 'user-folder-missing' "drives/$driveId/root:/RestoreProof-no-such-folder?`$select=id,name"
    $oneDriveSiteId = "$(Get-Field (Get-Field $root 'sharepointIds') 'siteId')"
    $oneDriveSiteUrl = [Uri]"$(Get-Field (Get-Field $root 'sharepointIds') 'siteUrl')"
    if ($oneDriveSiteId) {
        $null = Get-Graph 'user-onedrive-site-permissions' "sites/$($oneDriveSiteUrl.Host):$($oneDriveSiteUrl.AbsolutePath.TrimEnd('/')):/permissions"
    }

    $apps = Get-Graph 'applications' "applications?`$filter=displayName eq '$AppName'&`$select=id,appId,displayName,signInAudience,keyCredentials,passwordCredentials,requiredResourceAccess"
    $app = @(Get-Field $apps 'value')[0]
    $null = Get-Graph 'applications-none' "applications?`$filter=displayName eq 'RestoreProof no such app'&`$select=id,appId"
    if ($app) {
        $null = Get-Graph 'application-federated' "applications/$(Get-Field $app 'id')/federatedIdentityCredentials"
        $sps = Get-Graph 'service-principals' "servicePrincipals?`$filter=appId eq '$(Get-Field $app 'appId')'&`$select=id,appId,displayName"
        $sp = @(Get-Field $sps 'value')[0]
        if ($sp) {
            $spId = "$(Get-Field $sp 'id')"
            $null = Get-Graph 'sp-app-role-assignments' "servicePrincipals/$spId/appRoleAssignments"
            $null = Get-Graph 'sp-oauth2-grants' "servicePrincipals/$spId/oauth2PermissionGrants"
            $null = Get-Graph 'sp-member-of' "servicePrincipals/$spId/memberOf"
        }
    }

    # Graph's own service principal, trimmed to the roles the tests name (it lists hundreds).
    $graphSp = Invoke-MgGraphRequest -Method GET -Uri "${GraphBase}servicePrincipals(appId='$GraphAppId')?`$select=id,appId,appRoles" -OutputType HashTable
    $graphSp['appRoles'] = @($graphSp['appRoles'] | Where-Object { $KeptGraphRoles -ccontains $_['value'] } |
            ForEach-Object { [ordered]@{ id = $_['id']; value = $_['value']; allowedMemberTypes = @($_['allowedMemberTypes']) } })
    Save-Answer 'graph-service-principal' "GET /v1.0/servicePrincipals(appId='$GraphAppId')?`$select=id,appId,appRoles (appRoles trimmed to $($KeptGraphRoles.Count) roles)" 200 $graphSp
}
finally {
    Disconnect-MgGraph | Out-Null
}

# ---- Exchange Online ------------------------------------------------------------------------------
Import-Module ExchangeOnlineManagement -MinimumVersion 3.7.2
Connect-ExchangeOnline -UserPrincipalName $upn -ShowBanner:$false -DisableWAM -ErrorAction Stop
try {
    $recipientProperties = @('Name', 'Alias', 'RecipientType', 'RecipientTypeDetails', 'PrimarySmtpAddress', 'EmailAddresses')
    foreach ($pair in @(@('mailbox', $MailboxAddress), @('onedrive-user', $OneDriveUser), @('admin', $upn))) {
        $found = @(Get-Recipient -Identity $pair[1] -ErrorAction SilentlyContinue)
        Save-Answer "exo-recipient-$($pair[0])" "Get-Recipient -Identity $($pair[1])" ($found.Count -gt 0 ? 200 : 404) (ConvertTo-Plain $found $recipientProperties)
    }
    $missing = @(Get-Recipient -Identity "restoreproof-no-such-recipient@$initial" -ErrorAction SilentlyContinue)
    Save-Answer 'exo-recipient-missing' "Get-Recipient -Identity restoreproof-no-such-recipient@$initial" ($missing.Count -gt 0 ? 200 : 404) (ConvertTo-Plain $missing $recipientProperties)
    Save-Answer 'exo-organization-config' 'Get-OrganizationConfig' 200 (ConvertTo-Plain (Get-OrganizationConfig -ErrorAction Stop) @('IsDehydrated'))
    if ($app) {
        $appId = "$(Get-Field $app 'appId')"
        $pointer = @(Get-ServicePrincipal -Identity $appId -ErrorAction SilentlyContinue)
        Save-Answer 'exo-service-principal' "Get-ServicePrincipal -Identity $appId" ($pointer.Count -gt 0 ? 200 : 404) (ConvertTo-Plain $pointer @('AppId', 'ObjectId', 'DisplayName', 'Identity'))
        $scope = @(Get-ManagementScope -Identity $MailScopeName -ErrorAction SilentlyContinue)
        Save-Answer 'exo-management-scope' "Get-ManagementScope -Identity '$MailScopeName'" ($scope.Count -gt 0 ? 200 : 404) (ConvertTo-Plain $scope @('Name', 'RecipientFilter', 'ScopeRestrictionType', 'Identity'))
        $assignments = @(Get-ManagementRoleAssignment -ErrorAction Stop | Where-Object { "$($_.RoleAssigneeType)" -eq 'ServicePrincipal' })
        Save-Answer 'exo-role-assignments-service-principals' 'Get-ManagementRoleAssignment (RoleAssigneeType ServicePrincipal)' 200 `
            (ConvertTo-Plain $assignments @('Name', 'Role', 'RoleAssigneeType', 'RoleAssigneeName', 'App', 'CustomResourceScope', 'RecipientWriteScope', 'Identity'))
        foreach ($pair in @(@('mailbox', $MailboxAddress), @('onedrive-user', $OneDriveUser), @('admin', $upn))) {
            $test = @(Test-ServicePrincipalAuthorization -Identity $appId -Resource $pair[1] -ErrorAction Stop)
            Save-Answer "exo-authorization-$($pair[0])" "Test-ServicePrincipalAuthorization -Identity $appId -Resource $($pair[1])" 200 `
                (ConvertTo-Plain $test @('RoleName', 'GrantedPermissions', 'AllowedResourceScope', 'ScopeType', 'InScope'))
        }
    }
}
finally {
    Disconnect-ExchangeOnline -Confirm:$false | Out-Null
}

Write-Host "$script:Count answer(s) recorded in $Out"

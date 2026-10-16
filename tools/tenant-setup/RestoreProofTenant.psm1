<#
    RestoreProofTenant.psm1 (W7.0, docs/decisions.md 2026-10-16): every rule of the client tenant
    setup that decides something, as pure functions over the answers Graph and Exchange Online
    gave. Nothing here sends a request or touches a file: Initialize-RestoreProofTenant.ps1 reads,
    passes the answers in, and sends what the plans say. tests/ holds each rule row by row.

    The words. A check returns '' when it holds and one line saying why not otherwise. A plan is a
    list of changes, each @{ Action; Text; Data }, empty when nothing differs, so a second run on
    the state the first left is an empty plan.
#>

Set-StrictMode -Version Latest

# ---- what RestoreProof asks for ---------------------------------------------------------------
$script:RestoreTargetName = 'RestoreTarget'
$script:AppName = 'RestoreProof Worker'
$script:GraphAppId = '00000003-0000-0000-c000-000000000000'
# docs/security/graph-permissions.md #1, #2 and #4: the only application permissions consented.
$script:GraphRoles = @('Sites.Selected', 'Files.SelectedOperations.Selected', 'Lists.SelectedOperations.Selected')
# #3: Exchange RBAC for Applications, scoped to the restoretest mailbox.
$script:MailRoleName = 'Application Mail.ReadWrite'
$script:MailScopeName = 'RestoreProof Worker - restoretest mailbox'
$script:MailAssignmentName = 'RestoreProof Worker - Application Mail.ReadWrite - restoretest'
$script:SharedMailboxName = 'RestoreTest'
$script:ProfileFormat = 'restoreproof.client-profile.v1'
$script:MinKeyBits = 2048
$script:MinValidDays = 30
$script:MailboxKinds = @('UserMailbox', 'SharedMailbox')
# Exchange sees a new Entra service principal minutes after Graph made it (the second live run):
# its pointer is asked again this often, this many seconds apart, about ten minutes in all.
$script:ExchangeAttempts = 20
$script:ExchangeWaitSeconds = 30
$script:GuidPattern = '[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}'

function Get-TenantSetupConstant([string]$Name) { Get-Variable -Scope Script -Name $Name -ValueOnly }

# ---- reading answers --------------------------------------------------------------------------

# A field of a hashtable (Invoke-MgGraphRequest -OutputType HashTable) or of an object, or $null.
function Get-Field($Object, [string]$Name) {
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $null
    }
    $property = $Object.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $null
}

# The 'value' list of a Graph collection reply; throws on a reply of another shape, so an odd
# answer is never read as an empty list.
function Get-GraphList($Reply) {
    # Read directly: a function's return unrolls a list of one into its item.
    $value = $null
    if ($Reply -is [System.Collections.IDictionary]) { if ($Reply.Contains('value')) { $value = $Reply['value'] } }
    elseif ($null -ne $Reply -and $Reply.PSObject.Properties['value']) { $value = $Reply.PSObject.Properties['value'].Value }
    if ($value -isnot [System.Collections.IList]) { throw "a reply without a 'value' list" }
    @($value | Where-Object { $null -ne $_ })
}

function New-Change([string]$Action, [string]$Text, $Data = $null) {
    [pscustomobject]@{ Action = $Action; Text = $Text; Data = $Data }
}

# ---- the parameters ---------------------------------------------------------------------------

# A SharePoint site address the RestoreTarget library may live in: https, a *.sharepoint.com host
# that isn't a OneDrive host, and /sites/<name> or /teams/<name>, nothing else. The tenant's root
# site and a OneDrive are refused: the Worker app gets read on the whole site.
function Test-SiteUrl([string]$SiteUrl) {
    $uri = $null
    if (-not [Uri]::TryCreate($SiteUrl, [UriKind]::Absolute, [ref]$uri)) { return 'is not an absolute address' }
    if ($uri.Scheme -cne 'https') { return 'is not https' }
    if ($uri.Query -or $uri.Fragment -or $uri.UserInfo -or -not $uri.IsDefaultPort) { return 'has a query, a fragment, a user or a port' }
    $hostName = $uri.Host.ToLowerInvariant()
    if ($hostName -notmatch '^[a-z0-9-]+\.sharepoint\.com$') { return 'is not on a *.sharepoint.com host' }
    if ($hostName -match '-my\.sharepoint\.com$') { return "is a OneDrive host, not a SharePoint site" }
    $path = $uri.AbsolutePath.TrimEnd('/')
    if (-not $path) { return "is the tenant's root site: name a site made for RestoreProof" }
    if ($path -notmatch '^/(sites|teams)/[^/]+$') { return 'is not a site address (/sites/<name> or /teams/<name>)' }
    ''
}

# Graph's form of a site address: '<host>:/sites/<name>'.
function Get-SitePath([string]$SiteUrl) {
    $uri = [Uri]$SiteUrl
    "$($uri.Host):$($uri.AbsolutePath.TrimEnd('/'))"
}

# The restoretest mailbox's address, as the profile's schema takes it.
function Test-MailboxAddress([string]$Address) {
    if ($Address.Length -gt 1024 -or $Address -match '[\r\n]') { return 'is too long or holds a line break' }
    if ($Address -cnotmatch '^[Rr][Ee][Ss][Tt][Oo][Rr][Ee][Tt][Ee][Ss][Tt]@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$') {
        return "is not restoretest@<domain>: the Worker restores mail only into a mailbox of that name"
    }
    ''
}

function Test-Guid([string]$Text) { $Text -match "^$script:GuidPattern$" }

# The tenant's initial *.onmicrosoft.com domain from GET /organization, or ''.
function Get-InitialDomain($Organization) {
    foreach ($domain in @(Get-Field $Organization 'verifiedDomains')) {
        if ((Get-Field $domain 'isInitial') -eq $true) { return "$(Get-Field $domain 'name')" }
    }
    ''
}

# ---- the certificate --------------------------------------------------------------------------

# The Worker's public certificate from PEM text: exactly one CERTIFICATE block and no private
# key. Returns @{ Problem; Thumbprint; Base64; NotAfter; Subject }: Problem '' when usable.
function Read-WorkerCertificate([string]$Pem, [datetime]$Now) {
    $result = [ordered]@{ Problem = ''; Thumbprint = ''; Base64 = ''; NotAfter = $null; Subject = '' }
    if ($Pem -match 'PRIVATE KEY') {
        $result.Problem = 'holds a private key: give the public certificate only (rpworker graph certificate)'
        return [pscustomobject]$result
    }
    $blocks = [regex]::Matches($Pem, '-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END CERTIFICATE-----')
    if ($blocks.Count -ne 1) {
        $result.Problem = "holds $($blocks.Count) certificates, not one"
        return [pscustomobject]$result
    }
    try {
        $der = [Convert]::FromBase64String(($blocks[0].Groups[1].Value -replace '\s', ''))
        $cert = [Security.Cryptography.X509Certificates.X509Certificate2]::new($der)
    }
    catch {
        $result.Problem = 'is not a certificate'
        return [pscustomobject]$result
    }
    try {
        $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($cert)
        if ($null -eq $rsa) { $result.Problem = 'has no RSA key: the Worker signs in with RSA' }
        elseif ($rsa.KeySize -lt $script:MinKeyBits) { $result.Problem = "has an RSA key of $($rsa.KeySize) bits, under $script:MinKeyBits" }
        elseif ($cert.NotAfter.ToUniversalTime() -lt $Now.ToUniversalTime().AddDays($script:MinValidDays)) {
            $result.Problem = "expires on $($cert.NotAfter.ToUniversalTime().ToString('yyyy-MM-dd')), within $script:MinValidDays days: renew it first"
        }
        $result.Thumbprint = $cert.Thumbprint.ToUpperInvariant()
        $result.Base64 = [Convert]::ToBase64String($cert.RawData)
        $result.NotAfter = $cert.NotAfter.ToUniversalTime()
        $result.Subject = $cert.Subject
    }
    finally { $cert.Dispose() }
    [pscustomobject]$result
}

# The SHA-1 thumbprint a keyCredential stands for: its customKeyIdentifier (Graph fills it with the
# thumbprint's bytes), else the end of its displayName (the lab's form), else ''.
function Get-KeyThumbprint($KeyCredential) {
    $custom = "$(Get-Field $KeyCredential 'customKeyIdentifier')"
    if ($custom) {
        # 40 hex digits first: they are valid Base64 too.
        if ($custom -match '^[0-9A-Fa-f]{40}$') { return $custom.ToUpperInvariant() }
        try { return ([Convert]::ToHexString([Convert]::FromBase64String($custom))) } catch { }
    }
    $name = "$(Get-Field $KeyCredential 'displayName')"
    if ($name -match '([0-9A-Fa-f]{40})$') { return $Matches[1].ToUpperInvariant() }
    ''
}

# ---- the targets ------------------------------------------------------------------------------

# Whether a recipient found by the address can be the restoretest mailbox: a user or shared
# mailbox whose primary address is that address (Get-Recipient also finds a secondary address).
function Test-MailRecipient($Recipient, [string]$Address) {
    $kind = "$(Get-Field $Recipient 'RecipientTypeDetails')"
    $primary = "$(Get-Field $Recipient 'PrimarySmtpAddress')"
    if ($script:MailboxKinds -cnotcontains $kind) { return "is a $kind, not a user or shared mailbox" }
    if ($primary -ine $Address) { return "is another mailbox's secondary address (its primary address is $primary)" }
    ''
}

# The mailbox step: none found, make a shared mailbox; one usable, nothing; else stop.
function Get-MailboxPlan([object[]]$Recipients, [string]$Address) {
    $found = @($Recipients | Where-Object { $null -ne $_ })
    if ($found.Count -eq 0) {
        return @(New-Change 'mailbox.create' "make the shared mailbox $Address" @{ Address = $Address; Name = $script:SharedMailboxName })
    }
    if ($found.Count -gt 1) { throw "$Address names $($found.Count) recipients: nothing was changed" }
    $why = Test-MailRecipient $found[0] $Address
    if ($why) { throw "$Address $why. Nothing was changed: name a free address or that mailbox's own (-MailboxAddress)." }
    @()
}

# The last segment of a list's address, unescaped.
function Get-UrlLastSegment([string]$Url) {
    $url = $Url.TrimEnd('/')
    [Uri]::UnescapeDataString($url.Substring($url.LastIndexOf('/') + 1))
}

# What is about to hold a write grant must be the RestoreTarget library: the list read by its ID,
# its displayName exactly RestoreTarget, its address's last segment RestoreTarget (any case), a
# document library. Mirrors the Worker's check_restore_library and the lab's Assert-RestoreTargetList.
function Test-RestoreTargetList($List, [string]$ListId) {
    $name = "$(Get-Field $List 'displayName')"
    $url = "$(Get-Field $List 'webUrl')"
    if ("$(Get-Field $List 'id')" -cne $ListId) { return "is not the list $ListId" }
    if ($name -cne $script:RestoreTargetName) { return "is named '$name', not $script:RestoreTargetName" }
    if (-not $url -or (Get-UrlLastSegment $url) -ne $script:RestoreTargetName) { return "is at '$url', not an address ending in /$script:RestoreTargetName" }
    $template = "$(Get-Field (Get-Field $List 'list') 'template')"
    if ($template -cne 'documentLibrary') { return "is a '$template' list, not a document library" }
    ''
}

# The library step, from the site's lists: one RestoreTarget library, nothing; none, make it; a
# list that takes the name or the address but isn't the library, or two, stop.
function Get-LibraryPlan([object[]]$Lists) {
    $named = @($Lists | Where-Object {
            "$(Get-Field $_ 'displayName')" -ieq $script:RestoreTargetName -or
            ("$(Get-Field $_ 'webUrl')" -and (Get-UrlLastSegment "$(Get-Field $_ 'webUrl')") -ieq $script:RestoreTargetName)
        })
    if ($named.Count -eq 0) { return @(New-Change 'library.create' "make the $script:RestoreTargetName library") }
    if ($named.Count -gt 1) { throw "the site has $($named.Count) lists named or addressed ${script:RestoreTargetName}: nothing was changed" }
    $why = Test-RestoreTargetList $named[0] "$(Get-Field $named[0] 'id')"
    if ($why) { throw "the site's list $why. Nothing was changed: rename or remove that list, or name another site." }
    @()
}

# The list the library step found, or $null.
function Find-RestoreTargetList([object[]]$Lists) {
    ($Lists | Where-Object { "$(Get-Field $_ 'displayName')" -ceq $script:RestoreTargetName } | Select-Object -First 1)
}

# What is about to hold a write grant must be the RestoreTarget folder: the item read by its ID,
# named exactly RestoreTarget, a folder, directly under the root of the user's drive. Mirrors the
# Worker's check_restore_onedrive_folder and the lab's Assert-RestoreTargetFolder.
function Test-RestoreTargetFolder($Item, [string]$DriveId, [string]$FolderId) {
    $parent = Get-Field $Item 'parentReference'
    $path = "$(Get-Field $parent 'path')"
    $drive = "$(Get-Field $parent 'driveId')"
    if ("$(Get-Field $Item 'id')" -cne $FolderId) { return "is not the item $FolderId" }
    if ("$(Get-Field $Item 'name')" -cne $script:RestoreTargetName) { return "is named '$(Get-Field $Item 'name')', not $script:RestoreTargetName" }
    if (-not (Get-Field $Item 'folder') -or (Get-Field $Item 'file')) { return 'is not a folder' }
    if ($drive -cne $DriveId) { return "is in another drive" }
    if (@('/drive/root:', "/drives/$DriveId/root:") -cnotcontains $path) { return "is in '$path', not directly under the drive's root" }
    ''
}

# The folder step, from GET <drive>/root:/RestoreTarget ($null for a 404).
function Get-FolderPlan($Item, [string]$DriveId) {
    if ($null -eq $Item) { return @(New-Change 'folder.create' "make the /$script:RestoreTargetName folder") }
    $why = Test-RestoreTargetFolder $Item $DriveId "$(Get-Field $Item 'id')"
    if ($why) { throw "/$script:RestoreTargetName in the user's OneDrive $why. Nothing was changed." }
    @()
}

# ---- the app registration ---------------------------------------------------------------------

# The role IDs of the Worker's three permissions in Graph's service principal, in order.
function Get-GraphRoleIds($GraphServicePrincipal) {
    $ids = [ordered]@{}
    foreach ($name in $script:GraphRoles) {
        $role = @(@(Get-Field $GraphServicePrincipal 'appRoles') | Where-Object {
                "$(Get-Field $_ 'value')" -ceq $name -and @(Get-Field $_ 'allowedMemberTypes') -ccontains 'Application'
            })
        if ($role.Count -ne 1) { throw "Microsoft Graph has no application permission '$name'" }
        $ids[$name] = "$(Get-Field $role[0] 'id')"
    }
    $ids
}

# The app's requiredResourceAccess: Graph, the three roles, nothing else.
function Get-RequiredAccess($RoleIds) {
    @(@{ resourceAppId = $script:GraphAppId; resourceAccess = @($RoleIds.Values | ForEach-Object { @{ id = $_; type = 'Role' } }) })
}

function Test-RequiredAccess($App, $RoleIds) {
    $access = @(Get-Field $App 'requiredResourceAccess')
    if ($access.Count -ne 1 -or "$(Get-Field $access[0] 'resourceAppId')" -ne $script:GraphAppId) { return $false }
    $asked = @(@(Get-Field $access[0] 'resourceAccess') | ForEach-Object { "$(Get-Field $_ 'type')|$(Get-Field $_ 'id')" } | Sort-Object)
    $wanted = @($RoleIds.Values | ForEach-Object { "Role|$_" } | Sort-Object)
    ($asked -join ',') -ceq ($wanted -join ',')
}

function Get-KeyCredential($Certificate) {
    @{ type = 'AsymmetricX509Cert'; usage = 'Verify'; key = $Certificate.Base64; displayName = "CN=RestoreProof Worker $($Certificate.Thumbprint)" }
}

# The app step: make it, or set what differs. $Apps is every app registration of that name.
function Get-AppPlan([object[]]$Apps, $Certificate, $RoleIds) {
    $found = @($Apps | Where-Object { $null -ne $_ })
    if ($found.Count -gt 1) { throw "there are $($found.Count) app registrations named '$script:AppName': delete the extra ones first; nothing was changed" }
    if ($found.Count -eq 0) { return @(New-Change 'app.create' "make the app registration '$script:AppName'") }
    $app = $found[0]
    $plan = @()
    if ("$(Get-Field $app 'signInAudience')" -cne 'AzureADMyOrg' -or -not (Test-RequiredAccess $app $RoleIds)) {
        $plan += New-Change 'app.update' 'set the app to single tenant with exactly the three Graph permissions'
    }
    $keys = @(@(Get-Field $app 'keyCredentials') | Where-Object { $null -ne $_ })
    if ($keys.Count -ne 1 -or (Get-KeyThumbprint $keys[0]) -ne $Certificate.Thumbprint) {
        $plan += New-Change 'app.certificate' "make the Worker's certificate $($Certificate.Thumbprint) the app's only certificate (replaces $($keys.Count))"
    }
    foreach ($secret in @(@(Get-Field $app 'passwordCredentials') | Where-Object { $null -ne $_ })) {
        $plan += New-Change 'app.remove-secret' "remove the client secret '$(Get-Field $secret 'displayName')'" @{ KeyId = "$(Get-Field $secret 'keyId')" }
    }
    $plan
}

# The consent step: the three application consents on Graph, every other one removed (on Graph or
# any other API), every delegated grant on the app removed.
function Get-ConsentPlan([object[]]$Assignments, [object[]]$DelegatedGrants, [string]$GraphSpId, $RoleIds) {
    $plan = @()
    $held = @($Assignments | Where-Object { $null -ne $_ })
    foreach ($name in $RoleIds.Keys) {
        if (-not ($held | Where-Object { "$(Get-Field $_ 'resourceId')" -eq $GraphSpId -and "$(Get-Field $_ 'appRoleId')" -eq $RoleIds[$name] })) {
            $plan += New-Change 'consent.grant' "consent $name" @{ Role = $name; RoleId = $RoleIds[$name] }
        }
    }
    foreach ($extra in $held | Where-Object { -not ("$(Get-Field $_ 'resourceId')" -eq $GraphSpId -and @($RoleIds.Values) -contains "$(Get-Field $_ 'appRoleId')") }) {
        $plan += New-Change 'consent.remove' "remove the consent $(Get-Field $extra 'resourceDisplayName') role $(Get-Field $extra 'appRoleId'): not RestoreProof's" @{ Id = "$(Get-Field $extra 'id')" }
    }
    foreach ($grant in @($DelegatedGrants | Where-Object { $null -ne $_ })) {
        $plan += New-Change 'delegated.remove' "remove the delegated grant '$(Get-Field $grant 'scope')': the Worker runs with no user" @{ Id = "$(Get-Field $grant 'id')" }
    }
    $plan
}

# ---- the SharePoint grants --------------------------------------------------------------------

# Every application a permission names, as @{ Id; Name }, from any of the four ways Graph shows one.
function Get-GrantedApps($Permission) {
    $identities = @(Get-Field $Permission 'grantedToV2') + @(Get-Field $Permission 'grantedTo') +
        @(Get-Field $Permission 'grantedToIdentitiesV2') + @(Get-Field $Permission 'grantedToIdentities')
    foreach ($identity in $identities) {
        $application = Get-Field $identity 'application'
        $id = "$(Get-Field $application 'id')"
        if ($id) { [pscustomobject]@{ Id = $id; Name = "$(Get-Field $application 'displayName')" } }
    }
}

# Whether a permission is AppId's: an application facet with that ID, or, failing closed, the ID
# anywhere in it (SharePoint can show an app principal as a siteUser whose login name holds it).
function Test-NamesApp($Permission, [string]$AppId) {
    # No app yet: no permission is its own (an empty ID is in every text).
    if (-not $AppId) { return $false }
    if (@(Get-GrantedApps $Permission | Where-Object { $_.Id -eq $AppId }).Count -gt 0) { return $true }
    $json = ConvertTo-Json -InputObject $Permission -Depth 20 -Compress -WarningAction SilentlyContinue
    return "$json".IndexOf($AppId, [StringComparison]::OrdinalIgnoreCase) -ge 0
}

# Other applications a permission names only in SharePoint's form (a claim login name).
function Get-SharePointFormApps($Permission) {
    $json = ConvertTo-Json -InputObject $Permission -Depth 20 -Compress -WarningAction SilentlyContinue
    foreach ($match in [regex]::Matches("$json", "\|ms\.sp\.ext\|($script:GuidPattern)@")) { $match.Groups[1].Value }
}

function Get-RoleText($Permission) { (@(Get-Field $Permission 'roles' | Where-Object { $_ }) | Sort-Object) -join ',' }

function Test-Inherited($Permission) { $null -ne (Get-Field $Permission 'inheritedFrom') }

# What one location's permissions mean for the Worker app (lab/entra/check-worker-grants.ps1's
# rules, W3.4). Rule:
#   site-read            exactly one Worker app grant, roles exactly 'read'
#   inherited-read-only  a Worker app grant only if inherited, and then roles exactly 'read'
#   none                 no Worker app grant at all, inherited or not
#   target-write         exactly one non-inherited Worker app grant, roles exactly 'write'
#                        (an inherited one besides it only with roles 'read')
# Returns Problems, Notes (other applications' grants) and the counts. Never throws on odd data.
function Test-PermissionRule {
    param([object[]]$Permissions, [string]$AppId, [string]$Rule)
    if (@('site-read', 'inherited-read-only', 'none', 'target-write') -cnotcontains $Rule) {
        throw "unknown rule '$Rule'"
    }
    $problems = [System.Collections.Generic.List[string]]::new()
    $notes = [System.Collections.Generic.List[string]]::new()
    $worker = [System.Collections.Generic.List[object]]::new()
    $others = 0
    foreach ($permission in @($Permissions | Where-Object { $null -ne $_ })) {
        $apps = @(Get-GrantedApps $permission)
        $roles = Get-RoleText $permission
        $inherited = if (Test-Inherited $permission) { ', inherited' } else { '' }
        $isWorker = Test-NamesApp $permission $AppId
        if ($isWorker) { $worker.Add($permission) }
        foreach ($app in $apps | Where-Object { $_.Id -ne $AppId }) {
            $others++
            $notes.Add("another application's grant: $($app.Id) '$($app.Name)', roles '$roles'$inherited")
        }
        if (-not $isWorker -and $apps.Count -eq 0) {
            foreach ($id in Get-SharePointFormApps $permission) {
                $others++
                $notes.Add("another application's grant (SharePoint's form): $id, roles '$roles'$inherited")
            }
        }
    }
    $own = @($worker | Where-Object { -not (Test-Inherited $_) })
    $inheritedGrants = @($worker | Where-Object { Test-Inherited $_ })
    switch ($Rule) {
        'site-read' {
            if ($worker.Count -eq 0) { $problems.Add('the Worker app has no grant here; it needs exactly one, read') }
            elseif ($worker.Count -gt 1) { $problems.Add("the Worker app has $($worker.Count) grants here; it needs exactly one, read") }
            elseif ((Get-RoleText $worker[0]) -cne 'read') { $problems.Add("the Worker app's grant has roles '$(Get-RoleText $worker[0])'; only 'read' is allowed") }
        }
        'inherited-read-only' {
            foreach ($p in $own) { $problems.Add("the Worker app has a grant of its own here, roles '$(Get-RoleText $p)'; none is allowed") }
            foreach ($p in $inheritedGrants | Where-Object { (Get-RoleText $_) -cne 'read' }) {
                $problems.Add("the Worker app inherits roles '$(Get-RoleText $p)' here; only 'read' is allowed")
            }
        }
        'none' {
            foreach ($p in $worker) {
                $how = if (Test-Inherited $p) { 'an inherited grant' } else { 'a grant' }
                $problems.Add("the Worker app has $how here, roles '$(Get-RoleText $p)'; none is allowed")
            }
        }
        'target-write' {
            if ($own.Count -eq 0) { $problems.Add("the Worker app has no grant of its own here; it needs exactly one, write") }
            elseif ($own.Count -gt 1) { $problems.Add("the Worker app has $($own.Count) grants of its own here; it needs exactly one, write") }
            elseif ((Get-RoleText $own[0]) -cne 'write') { $problems.Add("the Worker app's grant has roles '$(Get-RoleText $own[0])'; it needs exactly 'write'") }
            foreach ($p in $inheritedGrants | Where-Object { (Get-RoleText $_) -cne 'read' }) {
                $problems.Add("the Worker app inherits roles '$(Get-RoleText $p)' here; only 'read' is allowed")
            }
        }
    }
    [pscustomobject]@{
        Problems = @($problems)
        Notes    = @($notes)
        Total    = @($Permissions | Where-Object { $null -ne $_ }).Count
        Worker   = $worker.Count
        Others   = $others
    }
}

# The grant step at one location: $Role 'read' (the site) or 'write' (the list, the folder). The
# Worker app's own grants there (not inherited): none, grant; one of another role, set it; more,
# keep the first and remove the rest. $Where is the location's word in the changes.
function Get-GrantPlan([object[]]$Permissions, [string]$AppId, [string]$Role, [string]$Where) {
    if (@('read', 'write') -cnotcontains $Role) { throw "unknown role '$Role'" }
    $own = @($Permissions | Where-Object { $null -ne $_ -and (Test-NamesApp $_ $AppId) -and -not (Test-Inherited $_) })
    if ($own.Count -eq 0) { return @(New-Change "$Where.grant" "grant the Worker app $Role on the $Where") }
    $plan = @()
    if ((Get-RoleText $own[0]) -cne $Role) {
        $plan += New-Change "$Where.set" "set the Worker app's grant on the $Where from '$(Get-RoleText $own[0])' to '$Role'" @{ Id = "$(Get-Field $own[0] 'id')" }
    }
    foreach ($extra in $own | Select-Object -Skip 1) {
        $plan += New-Change "$Where.remove" "remove the Worker app's extra grant on the $Where ('$(Get-RoleText $extra)')" @{ Id = "$(Get-Field $extra 'id')" }
    }
    $plan
}

# ---- Exchange Online --------------------------------------------------------------------------

function Get-MailScopeFilter([string]$Address) { "PrimarySmtpAddress -eq '$Address'" }

# Whether an Exchange refusal is its word for an Entra service principal it doesn't see yet.
function Test-ExchangeNotYetReplicated([string]$Text) { $Text -cmatch 'AADServicePrincipalNotFound' }

# An Exchange true or false (a Boolean, or its text "True"/"False" in any case) as a Boolean;
# anything else throws, since [bool]'False' is $true and an absent value is no answer.
function ConvertFrom-ExchangeBool($Value, [string]$Name) {
    if ($Value -is [bool]) { return $Value }
    if ($Value -is [string] -and @('true', 'false') -contains $Value.ToLowerInvariant()) { return $Value -ieq 'true' }
    throw "Exchange answered $Name with '$Value', not True or False"
}

# The assignments that are the Worker app's: by name, or a service principal assignee that is it.
function Select-AppAssignments([object[]]$Assignments, [string]$SpId, [string]$AppId) {
    @($Assignments | Where-Object {
            $null -ne $_ -and ("$(Get-Field $_ 'Name')" -eq $script:MailAssignmentName -or
                ("$(Get-Field $_ 'RoleAssigneeType')" -eq 'ServicePrincipal' -and
                @($SpId, $AppId, $script:AppName) -contains "$(Get-Field $_ 'RoleAssigneeName')"))
        })
}

function Test-MailAssignment($Assignment) {
    "$(Get-Field $Assignment 'Name')" -eq $script:MailAssignmentName -and
    "$(Get-Field $Assignment 'Role')" -eq $script:MailRoleName -and
    "$(Get-Field $Assignment 'CustomResourceScope')" -eq $script:MailScopeName
}

# A tenant whose Exchange is "dehydrated" holds no management scope until
# Enable-OrganizationCustomization, tenant-wide and one way: allowed only with the switch. The
# script asks this before its first write, so a refusal leaves the tenant as it was.
function Test-CustomizationAllowed($Scope, [bool]$Dehydrated, [bool]$AllowCustomization) {
    if ($null -ne $Scope -or -not $Dehydrated -or $AllowCustomization) { return '' }
    'Exchange Online in this tenant is not yet customised, so it can hold no management scope. ' +
    'Enable-OrganizationCustomization does that, once, for the whole tenant, and it cannot be undone. ' +
    'Run the script again with -AllowOrganizationCustomization to let it run it; nothing was changed.'
}
# The Exchange step. $Pointer, $Scope: $null when absent. $Dehydrated: Get-OrganizationConfig's
# IsDehydrated. A dehydrated tenant needs Enable-OrganizationCustomization (tenant-wide, one way)
# before a management scope: only with $AllowCustomization, else the step stops, writing nothing.
function Get-ExchangePlan($Pointer, $Scope, [object[]]$Assignments, [bool]$Dehydrated, [bool]$AllowCustomization,
    [string]$SpId, [string]$AppId, [string]$Address) {
    $plan = @()
    $filter = Get-MailScopeFilter $Address
    $why = Test-CustomizationAllowed $Scope $Dehydrated $AllowCustomization
    if ($why) { throw $why }
    if ($null -eq $Pointer) { $plan += New-Change 'exchange.pointer' 'make the Exchange service principal pointer' }
    if ($null -eq $Scope) {
        if ($Dehydrated) { $plan += New-Change 'exchange.customize' 'run Enable-OrganizationCustomization (once per tenant)' }
        $plan += New-Change 'exchange.scope' "make the management scope '$script:MailScopeName': $filter" @{ Filter = $filter }
    }
    elseif ("$(Get-Field $Scope 'RecipientFilter')" -cne $filter) {
        $plan += New-Change 'exchange.scope-filter' "set the management scope's filter to: $filter" @{ Filter = $filter }
    }
    $mine = @(Select-AppAssignments $Assignments $SpId $AppId)
    $good = @($mine | Where-Object { Test-MailAssignment $_ })
    foreach ($extra in $mine | Where-Object { -not (Test-MailAssignment $_) }) {
        $plan += New-Change 'exchange.assignment-remove' "remove the role assignment '$(Get-Field $extra 'Name')' ($(Get-Field $extra 'Role')): not RestoreProof's" @{ Identity = "$(Get-Field $extra 'Identity')" }
    }
    if ($good.Count -eq 0) {
        $plan += New-Change 'exchange.assignment' "assign '$script:MailRoleName' in '$script:MailScopeName'"
    }
    $plan
}

# ---- the check, read-only ---------------------------------------------------------------------

# The app registration as it must be after the setup.
function Test-AppState($App, [object[]]$Federated, [string]$Thumbprint, $RoleIds) {
    $problems = @()
    if ($null -eq $App) { return @("there is no app registration '$script:AppName'") }
    if ("$(Get-Field $App 'signInAudience')" -cne 'AzureADMyOrg') { $problems += "the app is not single tenant ('$(Get-Field $App 'signInAudience')')" }
    if (-not (Test-RequiredAccess $App $RoleIds)) { $problems += 'the app asks for other permissions than the three' }
    $keys = @(@(Get-Field $App 'keyCredentials') | Where-Object { $null -ne $_ })
    if ($keys.Count -ne 1) { $problems += "the app has $($keys.Count) certificates; it needs exactly the Worker's" }
    elseif ((Get-KeyThumbprint $keys[0]) -ne $Thumbprint) { $problems += "the app's certificate is not the Worker's ($Thumbprint)" }
    $secrets = @(@(Get-Field $App 'passwordCredentials') | Where-Object { $null -ne $_ }).Count
    if ($secrets -gt 0) { $problems += "the app has $secrets client secret(s); it may have none" }
    $fed = @($Federated | Where-Object { $null -ne $_ }).Count
    if ($fed -gt 0) { $problems += "the app has $fed federated credential(s); it may have none" }
    $problems
}

# The service principal's consents, delegated grants and directory roles.
function Test-ServicePrincipalState($ServicePrincipal, [object[]]$Assignments, [object[]]$DelegatedGrants, [object[]]$MemberOf, [string]$GraphSpId, $RoleIds) {
    if ($null -eq $ServicePrincipal) { return @('the app has no service principal') }
    $problems = @()
    $held = @($Assignments | Where-Object { $null -ne $_ })
    foreach ($name in $RoleIds.Keys) {
        $n = @($held | Where-Object { "$(Get-Field $_ 'resourceId')" -eq $GraphSpId -and "$(Get-Field $_ 'appRoleId')" -eq $RoleIds[$name] }).Count
        if ($n -ne 1) { $problems += "the consent $name is held $n time(s); it needs exactly once" }
    }
    $extra = @($held | Where-Object { -not ("$(Get-Field $_ 'resourceId')" -eq $GraphSpId -and @($RoleIds.Values) -contains "$(Get-Field $_ 'appRoleId')") })
    foreach ($e in $extra) { $problems += "the app holds another consent: $(Get-Field $e 'resourceDisplayName') role $(Get-Field $e 'appRoleId')" }
    $delegated = @($DelegatedGrants | Where-Object { $null -ne $_ }).Count
    if ($delegated -gt 0) { $problems += "the app holds $delegated delegated grant(s); it may hold none" }
    foreach ($m in @($MemberOf | Where-Object { $null -ne $_ })) {
        $problems += "the app is a member of '$(Get-Field $m 'displayName')' ($(Get-Field $m '@odata.type')); it may be in no directory role or group"
    }
    $problems
}

# Exchange: exactly the one assignment, the scope's filter, and Exchange's own answer for the
# restoretest mailbox (in scope) and the other mailboxes tested (not in scope).
# $Authorizations: @{ Mailbox; Answers (Test-ServicePrincipalAuthorization rows); Expected ($true|$false) }.
function Test-ExchangeState($Scope, [object[]]$Assignments, [string]$SpId, [string]$AppId, [string]$Address, [object[]]$Authorizations) {
    $problems = @()
    if ($null -eq $Scope) { $problems += "there is no management scope '$script:MailScopeName'" }
    elseif ("$(Get-Field $Scope 'RecipientFilter')" -cne (Get-MailScopeFilter $Address)) {
        $problems += "the management scope's filter is '$(Get-Field $Scope 'RecipientFilter')', not '$(Get-MailScopeFilter $Address)'"
    }
    $mine = @(Select-AppAssignments $Assignments $SpId $AppId)
    if ($mine.Count -ne 1 -or -not (Test-MailAssignment $mine[0])) {
        $problems += "the app has $($mine.Count) Exchange role assignment(s); it needs exactly '$script:MailAssignmentName' ($script:MailRoleName in '$script:MailScopeName')"
    }
    foreach ($a in @($Authorizations | Where-Object { $null -ne $_ })) {
        $rows = @(@($a.Answers) | Where-Object { "$(Get-Field $_ 'RoleName')" -eq $script:MailRoleName })
        $inScope = @($rows | Where-Object { "$(Get-Field $_ 'InScope')" -eq 'True' }).Count -gt 0
        if ($a.Expected -and -not $inScope) { $problems += "Exchange says the app may not reach $($a.Mailbox) ($script:MailRoleName not in scope)" }
        if (-not $a.Expected) {
            $others = @(@($a.Answers) | Where-Object { "$(Get-Field $_ 'InScope')" -eq 'True' })
            if ($others.Count -gt 0) { $problems += "Exchange says the app may reach $($a.Mailbox) ($(@($others | ForEach-Object { "$(Get-Field $_ 'RoleName')" }) -join ', ')); only the restoretest mailbox is allowed" }
        }
    }
    $problems
}

# ---- the profile ------------------------------------------------------------------------------

# restoreproof.client-profile.v1, from what was read back. Keys sorted.
function New-ClientProfile([string]$VeeamOrgName, [string]$TenantId, [string]$ClientId, [string]$Mailbox,
    [string]$SiteId, [string]$LibraryDriveId, [string]$DriveId, [string]$FolderId) {
    $values = @{
        format                  = $script:ProfileFormat
        veeam_org_name          = $VeeamOrgName
        graph_tenant_id         = $TenantId.ToLowerInvariant()
        graph_client_id         = $ClientId.ToLowerInvariant()
        test_mailbox            = $Mailbox
        test_site_id            = $SiteId
        test_library_id         = $LibraryDriveId
        test_onedrive_drive_id  = $DriveId
        test_onedrive_folder_id = $FolderId
    }
    $keys = [string[]]$values.Keys
    [Array]::Sort($keys, [StringComparer]::Ordinal)
    $sorted = [ordered]@{}
    foreach ($key in $keys) { $sorted[$key] = $values[$key] }
    $sorted
}

# The profile file's text: sorted keys, two-space indent, LF, one trailing LF.
function ConvertTo-ProfileJson($Profile) {
    ((ConvertTo-Json -InputObject $Profile -Depth 3) -replace "`r`n", "`n") + "`n"
}

Export-ModuleMember -Function *

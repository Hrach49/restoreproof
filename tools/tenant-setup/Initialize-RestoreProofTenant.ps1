<#
.SYNOPSIS
    Prepares a client's Microsoft 365 tenant for RestoreProof: the three restore targets, the
    "RestoreProof Worker" app with exactly its grants, a read-only check, and the client's
    restoreproof.client-profile.v1 (W7.0, docs/decisions.md 2026-10-16; docs/tenant-setup.md).

.DESCRIPTION
    Run it as the client tenant's Global Administrator, in PowerShell 7.4 or later, with the
    modules Microsoft.Graph.Authentication and ExchangeOnlineManagement (3.7.2 or later). Every
    step reads what is there, compares, and changes only what differs; each prints "ok: ..." when
    nothing differs and "change: ..." for each write, and the run ends "changes: <n>". A second
    run on the same tenant prints "changes: 0" and the same profile.

      1. The restoretest mailbox: taken if it is a user or shared mailbox with that primary
         address; made as a shared mailbox (no licence) when there is none.
      2. The RestoreTarget document library in -SiteUrl, and the /RestoreTarget folder directly
         under the root of -OneDriveUser's OneDrive: taken, or made.
      3. The app registration "RestoreProof Worker": single tenant, the Worker's certificate as its
         only credential, exactly Sites.Selected, Files.SelectedOperations.Selected and
         Lists.SelectedOperations.Selected with admin consent; every other consent and every
         delegated grant on it removed, every client secret removed.
      4. SharePoint: read on the site; write on the RestoreTarget list and on the /RestoreTarget
         folder, each only after the target is read again and is named RestoreTarget.
      5. Exchange Online RBAC for Applications: "Application Mail.ReadWrite" in a management scope
         holding the restoretest mailbox alone; any other assignment of the app removed.
      6. The check, read-only (alone with -CheckOnly): stops with "grants: <n> problem(s)" and
         exit 1 unless the app holds exactly its own grants.
      7. The profile, from what was read back, validated against the schema, printed and written
         to -ProfileFile.

    It never writes anywhere else, never grants Sites.Selected write or any *.All role, never adds
    a client secret, never deletes a target or anything in one, seeds no canary and never sees
    the Worker's private key: the certificate it uploads is the public half, from
    `rpworker graph certificate` (-Worker) or a PEM file (-WorkerCertificateFile).

.EXAMPLE
    pwsh -NoProfile -File tools\tenant-setup\Initialize-RestoreProofTenant.ps1 `
        -TenantId 00000000-0000-0000-0000-000000000000 `
        -SiteUrl https://contoso.sharepoint.com/sites/RestoreProof `
        -OneDriveUser restoreproof@contoso.com `
        -WorkerCertificateFile .\worker-graph.pem -ProfileFile .\contoso-profile.json
#>
#Requires -Version 7.4
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$SiteUrl,
    [Parameter(Mandatory)][string]$OneDriveUser,
    # Default: restoretest@<the tenant's initial *.onmicrosoft.com domain>.
    [string]$MailboxAddress = '',
    # Default: the tenant's initial domain, the name Veeam gives an organisation it adds.
    [string]$VeeamOrgName = '',
    [string]$ProfileFile = '',
    # The Worker's public certificate (PEM), e.g. from `rpworker graph certificate > worker-graph.pem`.
    [string]$WorkerCertificateFile = '',
    # Or rpworker.exe on this machine: its `graph certificate` is run to read it.
    [string]$Worker = '',
    [string]$VaultPath = '',
    # Lets the script run Enable-OrganizationCustomization in a tenant that needs it (tenant-wide, one way).
    [switch]$AllowOrganizationCustomization,
    # Read everything and print the plan; change nothing.
    [switch]$WhatIf,
    # Run the read-only check alone.
    [switch]$CheckOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'RestoreProofTenant.psm1') -Force
$GraphBase = 'https://graph.microsoft.com/v1.0/'
$SchemaFile = Join-Path $PSScriptRoot 'client-profile.v1.json'
$Target = Get-TenantSetupConstant 'RestoreTargetName'
$AppName = Get-TenantSetupConstant 'AppName'
$GraphAppId = Get-TenantSetupConstant 'GraphAppId'
$MailRoleName = Get-TenantSetupConstant 'MailRoleName'
$MailScopeName = Get-TenantSetupConstant 'MailScopeName'
$MailAssignmentName = Get-TenantSetupConstant 'MailAssignmentName'
$GraphScopes = @('Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All', 'Sites.FullControl.All',
    'Files.ReadWrite.All', 'User.Read.All', 'Organization.Read.All')
$script:Changes = 0

function Say([string]$Text) { Write-Host $Text }
function Ok([string]$Text) { Say "ok: $Text" }

# One change: printed, counted, and sent unless -WhatIf.
function Invoke-Change($Change, [scriptblock]$Action) {
    if ($WhatIf) { Say "plan: $($Change.Text)"; $script:Changes++; return }
    & $Action
    Say "change: $($Change.Text)"
    $script:Changes++
}

# ---- the parameters -----------------------------------------------------------------------------
if (-not (Test-Guid $TenantId)) { throw '-TenantId is not a GUID' }
$why = Test-SiteUrl $SiteUrl
if ($why) { throw "-SiteUrl $why" }
if ($OneDriveUser -notmatch '^[^@\s]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$') { throw '-OneDriveUser is not a user principal name' }
if ([bool]$WorkerCertificateFile -eq [bool]$Worker) { throw 'Give exactly one of -WorkerCertificateFile and -Worker' }
if ($WhatIf -and $CheckOnly) { throw 'Give at most one of -WhatIf and -CheckOnly' }

# ---- the modules --------------------------------------------------------------------------------
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    throw 'The module Microsoft.Graph.Authentication is not installed. Install it: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
}
$exo = @(Get-Module -ListAvailable -Name ExchangeOnlineManagement | Where-Object { $_.Version -ge [version]'3.7.2' })
if ($exo.Count -eq 0) {
    throw 'The module ExchangeOnlineManagement 3.7.2 or later is not installed. Install it: Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber'
}
Import-Module Microsoft.Graph.Authentication
Import-Module ExchangeOnlineManagement -MinimumVersion 3.7.2

# ---- the Worker's certificate -------------------------------------------------------------------
if ($WorkerCertificateFile) {
    if (-not (Test-Path -LiteralPath $WorkerCertificateFile -PathType Leaf)) { throw "-WorkerCertificateFile $WorkerCertificateFile can't be read" }
    $pem = Get-Content -LiteralPath $WorkerCertificateFile -Raw
}
else {
    $vaultArgs = @()
    if ($VaultPath) { $vaultArgs = @('--vault', $VaultPath) }
    # stdout is the PEM; stderr is rpworker's own line (its thumbprint, or why it failed), repeated
    # on a failure: an unelevated shell, an expired certificate and an empty vault each say so.
    $answer = @(& $Worker graph certificate @vaultArgs 2>&1)
    $code = $LASTEXITCODE
    $said = @($answer | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] } | ForEach-Object { "$_" })
    $pem = @($answer | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] } | ForEach-Object { "$_" }) -join "`n"
    if ($code -ne 0) {
        throw ("rpworker graph certificate failed (exit $code): $($said -join ' '). Nothing was read or changed. " +
            'A vault that holds no Graph certificate yet takes one from New-WorkerGraphCertificate.ps1; never -Replace ' +
            "one this Worker has: every client's app holds it.")
    }
}
$certificate = Read-WorkerCertificate $pem ([datetime]::UtcNow)
if ($certificate.Problem) { throw "The Worker's certificate $($certificate.Problem)" }
Ok "the Worker's certificate $($certificate.Thumbprint), expires $($certificate.NotAfter.ToString('yyyy-MM-dd'))"

# ---- Graph and Exchange -------------------------------------------------------------------------
function Invoke-Graph([string]$Method, [string]$Path, $Body = $null) {
    $request = @{ Method = $Method; Uri = $GraphBase + $Path; OutputType = 'HashTable' }
    if ($null -ne $Body) {
        $request.Body = ConvertTo-Json -InputObject $Body -Depth 10 -Compress
        $request.ContentType = 'application/json'
    }
    Invoke-MgGraphRequest @request
}

# The HTTP status of a failed Graph request, or $null when there was no answer.
function Get-GraphStatus($ErrorRecord) {
    $exception = $ErrorRecord.Exception
    $response = $exception.PSObject.Properties['Response']
    if ($response -and $response.Value -and $response.Value.PSObject.Properties['StatusCode']) { return [int]$response.Value.StatusCode }
    $code = $exception.PSObject.Properties['StatusCode']
    if ($code -and $null -ne $code.Value) { return [int]$code.Value }
    if ("$ErrorRecord" -match '\b(BadRequest|Forbidden|NotFound)\b') { return @{ BadRequest = 400; Forbidden = 403; NotFound = 404 }[$Matches[1]] }
    $null
}

# A GET whose 404 is "not there": the reply, or $null.
function Get-GraphOrNull([string]$Path) {
    try { Invoke-Graph GET $Path }
    catch { if ((Get-GraphStatus $_) -eq 404) { return $null }; throw }
}

# Every item of a collection, following @odata.nextLink within Graph v1.0.
function Get-GraphAll([string]$Path) {
    $all = [System.Collections.Generic.List[object]]::new()
    $next = $Path
    for ($page = 1; $next; $page++) {
        if ($page -gt 100) { throw "more than 100 pages at $Path" }
        $reply = Invoke-Graph GET $next
        foreach ($item in Get-GraphList $reply) { $all.Add($item) }
        $next = "$(Get-Field $reply '@odata.nextLink')"
        if ($next) {
            if (-not $next.StartsWith($GraphBase, [StringComparison]::Ordinal)) { throw 'a next page outside Microsoft Graph v1.0' }
            $next = $next.Substring($GraphBase.Length)
        }
    }
    @($all)
}

# A new app or service principal takes seconds to reach every directory replica; until then Graph
# and Exchange answer 400 or 404 about it. Anything else is final.
function Invoke-WithRetry([scriptblock]$Action, [string]$What) {
    for ($attempt = 1; ; $attempt++) {
        try { return & $Action }
        catch {
            if ($attempt -ge 6 -or @(400, 404) -notcontains (Get-GraphStatus $_)) { throw }
            Say "note: $What not ready yet (attempt $attempt): retrying in 10 s"
            Start-Sleep -Seconds 10
        }
    }
}

# An Exchange write that names the new service principal, asked again while Exchange doesn't see it.
function Invoke-ExchangeWithRetry([scriptblock]$Action) {
    $attempts = Get-TenantSetupConstant 'ExchangeAttempts'
    $seconds = Get-TenantSetupConstant 'ExchangeWaitSeconds'
    for ($attempt = 1; ; $attempt++) {
        try { return & $Action }
        catch {
            if ($attempt -ge $attempts -or -not (Test-ExchangeNotYetReplicated "$_")) { throw }
            Say "note: Exchange does not see the app yet (attempt $attempt): retrying in $seconds s"
            Start-Sleep -Seconds $seconds
        }
    }
}

Connect-MgGraph -TenantId $TenantId -Scopes $GraphScopes -NoWelcome -ContextScope Process
$context = Get-MgContext
if ("$($context.TenantId)" -ne $TenantId) {
    Disconnect-MgGraph | Out-Null
    throw "Signed in to tenant '$($context.TenantId)', not $TenantId. Run it again and sign in to the client's tenant."
}
$account = "$($context.Account)"
# -DisableWAM: the Windows sign-in broker fails from a script (no parent window). Every Exchange
# call carries -ErrorAction Stop: its cmdlets are functions in a generated module, which don't see
# this script's $ErrorActionPreference. -CommandName: the module otherwise imports every cmdlet
# the admin may run, as functions that shadow this script's of the same name (its Get-MailboxPlan
# shadowed the setup module's on the first live run); only these come in.
$ExchangeCommands = @(
    'Get-Recipient', 'New-Mailbox', 'Get-OrganizationConfig', 'Enable-OrganizationCustomization',
    'Get-ServicePrincipal', 'New-ServicePrincipal', 'Remove-ServicePrincipal', 'Get-ManagementScope', 'New-ManagementScope', 'Set-ManagementScope',
    'Get-ManagementRoleAssignment', 'New-ManagementRoleAssignment', 'Remove-ManagementRoleAssignment',
    'Test-ServicePrincipalAuthorization'
)

# Inside the try, so a failed or cancelled Exchange sign-in still ends the Graph session.
try {
    Connect-ExchangeOnline -UserPrincipalName $account -ShowBanner:$false -DisableWAM -CommandName $ExchangeCommands -ErrorAction Stop
    # Exchange connects to the account's own organisation, which for a partner's or a guest's
    # account is not the client's: held to the tenant like the Graph session, before any read.
    $exchangeTenant = "$((@(Get-ConnectionInformation) | Select-Object -Last 1).TenantID)"
    if ($exchangeTenant -ne $TenantId) {
        throw ("Exchange Online signed in to tenant '$exchangeTenant', not $TenantId. Run it again with an account of " +
            "the client's tenant (a partner's or a guest's account reaches its own organisation's Exchange). Nothing was changed.")
    }

    # ---- the tenant ----------------------------------------------------------------------------
    $organization = (Get-GraphList (Invoke-Graph GET 'organization?$select=id,displayName,verifiedDomains') | Select-Object -First 1)
    if ("$(Get-Field $organization 'id')" -ne $TenantId) { throw "Graph's organization is '$(Get-Field $organization 'id')', not $TenantId" }
    $initialDomain = Get-InitialDomain $organization
    if (-not $initialDomain) { throw 'the tenant has no initial *.onmicrosoft.com domain' }
    if (-not $MailboxAddress) { $MailboxAddress = "restoretest@$initialDomain" }
    $why = Test-MailboxAddress $MailboxAddress
    if ($why) { throw "-MailboxAddress $why" }
    if (-not $VeeamOrgName) { $VeeamOrgName = $initialDomain }
    Ok "tenant $TenantId, signed in as $account"

    # Asked before the first write: a dehydrated Exchange without the switch changes nothing.
    $why = Test-CustomizationAllowed (Get-ManagementScope -Identity $MailScopeName -ErrorAction SilentlyContinue) `
        ((ConvertFrom-ExchangeBool (Get-OrganizationConfig -ErrorAction Stop).IsDehydrated 'IsDehydrated')) ([bool]$AllowOrganizationCustomization)
    if ($why -and -not $CheckOnly) { throw $why }

    $graphSp = Invoke-Graph GET "servicePrincipals(appId='$GraphAppId')?`$select=id,appId,appRoles"
    $roleIds = Get-GraphRoleIds $graphSp
    $graphSpId = "$(Get-Field $graphSp 'id')"

    # ---- the readers -------------------------------------------------------------------------
    # The recipients an address names: none only for Exchange's "couldn't be found"; an address
    # that names several, or any other failure, stops the caller (never read as "no recipient").
    function Read-Recipients([string]$Identity = $MailboxAddress) {
        try { @(Get-Recipient -Identity $Identity -ErrorAction Stop | Where-Object { $_ }) }
        catch {
            switch (Get-ExchangeLookupFailure "$_") {
                'not-found' { return }
                'ambiguous' { throw "$Identity names more than one recipient: nothing was changed" }
            }
            throw
        }
    }
    function Read-Site { Invoke-Graph GET "sites/$(Get-SitePath $SiteUrl)?`$select=id,webUrl,displayName" }
    function Read-Lists([string]$SiteId) { Get-GraphAll "sites/$SiteId/lists?`$select=id,displayName,webUrl,list" }
    function Read-Drive {
        try { Invoke-Graph GET "users/$OneDriveUser/drive?`$select=id,webUrl" }
        catch {
            if (@(403, 404) -contains (Get-GraphStatus $_)) {
                throw "$OneDriveUser's OneDrive can't be read (HTTP $(Get-GraphStatus $_)): the user needs a licence with OneDrive and to have opened it once, and $account must be a site collection admin of it (docs/tenant-setup.md). Nothing more was changed."
            }
            throw
        }
    }
    function Read-Folder([string]$DriveId) {
        try { Get-GraphOrNull "drives/$DriveId/root:/${Target}?`$select=id,name,folder,file,parentReference" }
        catch {
            if ((Get-GraphStatus $_) -eq 403) {
                throw "$account can't read $OneDriveUser's OneDrive (HTTP 403): make $account a site collection admin of it first (docs/tenant-setup.md, step 2), then run this again. Nothing more was changed."
            }
            throw
        }
    }
    function Read-Apps { @((Get-GraphAll "applications?`$filter=displayName eq '$AppName'&`$select=id,appId,displayName,signInAudience,keyCredentials,passwordCredentials,requiredResourceAccess")) }
    function Read-ServicePrincipal([string]$AppId) { (Get-GraphAll "servicePrincipals?`$filter=appId eq '$AppId'&`$select=id,appId,displayName" | Select-Object -First 1) }
    function Read-SitePermissions([string]$SiteId) {
        # A site's permission list may leave the roles out: read each grant itself.
        @(foreach ($p in Get-GraphAll "sites/$SiteId/permissions") { Invoke-Graph GET "sites/$SiteId/permissions/$([Uri]::EscapeDataString("$(Get-Field $p 'id')"))" })
    }
    function Read-Assignments { @(Get-ManagementRoleAssignment -ErrorAction Stop | Where-Object { $_ }) }

    if (-not $CheckOnly) {
        # ---- 1. the mailbox ----------------------------------------------------------------------
        $plan = @(Get-MailboxPlan (Read-Recipients) $MailboxAddress)
        foreach ($change in $plan) {
            Invoke-Change $change { New-Mailbox -Shared -Name $change.Data.Name -DisplayName $change.Data.Name -Alias 'restoretest' -PrimarySmtpAddress $change.Data.Address -ErrorAction Stop | Out-Null }
        }
        if ($plan.Count -eq 0) { Ok "the mailbox $MailboxAddress" }

        # ---- 2. the library and the folder ------------------------------------------------------
        $site = Read-Site
        $siteId = "$(Get-Field $site 'id')"
        $lists = @(Read-Lists $siteId)
        foreach ($other in $lists | Where-Object { "$(Get-Field $_ 'displayName')" -cne $Target -and "$(Get-Field (Get-Field $_ 'list') 'template')" -eq 'documentLibrary' }) {
            Say "note: the Worker app will read the site's library '$(Get-Field $other 'displayName')' too (read on the whole site)"
        }
        $plan = @(Get-LibraryPlan $lists)
        foreach ($change in $plan) {
            Invoke-Change $change { Invoke-Graph POST "sites/$siteId/lists" @{ displayName = $Target; list = @{ template = 'documentLibrary' } } | Out-Null }
        }
        if ($plan.Count -eq 0) { Ok "the $Target library in $SiteUrl" }

        $drive = Read-Drive
        $driveId = "$(Get-Field $drive 'id')"
        $plan = @(Get-FolderPlan (Read-Folder $driveId) $driveId)
        foreach ($change in $plan) {
            Invoke-Change $change {
                Invoke-Graph POST "drives/$driveId/root/children" @{ name = $Target; folder = @{}; '@microsoft.graph.conflictBehavior' = 'fail' } | Out-Null
            }
        }
        if ($plan.Count -eq 0) { Ok "the /$Target folder in $OneDriveUser's OneDrive" }

        # ---- 3. the app, its service principal, its consents -----------------------------------
        $apps = @(Read-Apps)
        $plan = @(Get-AppPlan $apps $certificate $roleIds)
        $app = ($apps | Select-Object -First 1)
        foreach ($change in $plan) {
            switch ($change.Action) {
                'app.create' {
                    Invoke-Change $change {
                        $script:createdApp = Invoke-Graph POST 'applications' @{
                            displayName = $AppName; signInAudience = 'AzureADMyOrg'
                            requiredResourceAccess = @(Get-RequiredAccess $roleIds); keyCredentials = @(Get-KeyCredential $certificate)
                        }
                    }
                    if (-not $WhatIf) { $app = $script:createdApp }
                }
                'app.update' { Invoke-Change $change { Invoke-Graph PATCH "applications/$(Get-Field $app 'id')" @{ signInAudience = 'AzureADMyOrg'; requiredResourceAccess = @(Get-RequiredAccess $roleIds) } | Out-Null } }
                'app.certificate' { Invoke-Change $change { Invoke-Graph PATCH "applications/$(Get-Field $app 'id')" @{ keyCredentials = @(Get-KeyCredential $certificate) } | Out-Null } }
                'app.remove-secret' { Invoke-Change $change { Invoke-Graph POST "applications/$(Get-Field $app 'id')/removePassword" @{ keyId = $change.Data.KeyId } | Out-Null } }
            }
        }
        if ($plan.Count -eq 0) { Ok "the app registration '$AppName'" }
        $appId = "$(Get-Field $app 'appId')"

        $sp = if ($appId) { Read-ServicePrincipal $appId } else { $null }
        if (-not $sp) {
            Invoke-Change (New-Change 'sp.create' 'make the app''s service principal') {
                $script:createdSp = Invoke-WithRetry -What 'the app' -Action { Invoke-Graph POST 'servicePrincipals' @{ appId = $appId } }
            }
            if (-not $WhatIf) { $sp = $script:createdSp }
        }
        else { Ok "the service principal $(Get-Field $sp 'id')" }
        $spId = "$(Get-Field $sp 'id')"

        # A service principal made a moment ago may not be on the replica that answers: 404 for a while.
        $assignments = if ($spId) { @(Invoke-WithRetry -What 'the service principal' -Action { Get-GraphAll "servicePrincipals/$spId/appRoleAssignments" }) } else { @() }
        $delegated = if ($spId) { @(Invoke-WithRetry -What 'the service principal' -Action { Get-GraphAll "servicePrincipals/$spId/oauth2PermissionGrants" }) } else { @() }
        $plan = @(Get-ConsentPlan $assignments $delegated $graphSpId $roleIds)
        foreach ($change in $plan) {
            switch ($change.Action) {
                'consent.grant' {
                    Invoke-Change $change {
                        Invoke-WithRetry -What 'the service principal' -Action {
                            try { Invoke-Graph POST "servicePrincipals/$spId/appRoleAssignments" @{ principalId = $spId; resourceId = $graphSpId; appRoleId = $change.Data.RoleId } | Out-Null }
                            catch { if ("$_" -notmatch 'Permission being assigned already exists') { throw } }
                        }
                    }
                }
                'consent.remove' { Invoke-Change $change { Invoke-Graph DELETE "servicePrincipals/$spId/appRoleAssignments/$($change.Data.Id)" | Out-Null } }
                'delegated.remove' { Invoke-Change $change { Invoke-Graph DELETE "oauth2PermissionGrants/$($change.Data.Id)" | Out-Null } }
            }
        }
        if ($plan.Count -eq 0) { Ok "the consents: $(@($roleIds.Keys) -join ', ')" }

        # ---- 4. the SharePoint grants ----------------------------------------------------------
        $plan = @(Get-GrantPlan (Read-SitePermissions $siteId) $appId 'read' 'site')
        foreach ($change in $plan) {
            switch ($change.Action) {
                # Each grant names the app, which SharePoint may not see yet when it was made this run.
                'site.grant' { Invoke-Change $change { Invoke-WithRetry -What 'the app' -Action { Invoke-Graph POST "sites/$siteId/permissions" @{ roles = @('read'); grantedToIdentities = @(@{ application = @{ id = $appId; displayName = $AppName } }) } | Out-Null } } }
                'site.set' { Invoke-Change $change { Invoke-Graph PATCH "sites/$siteId/permissions/$($change.Data.Id)" @{ roles = @('read') } | Out-Null } }
                'site.remove' { Invoke-Change $change { Invoke-Graph DELETE "sites/$siteId/permissions/$($change.Data.Id)" | Out-Null } }
            }
        }
        if ($plan.Count -eq 0) { Ok 'read on the site' }

        $list = Find-RestoreTargetList (Read-Lists $siteId)
        $listId = "$(Get-Field $list 'id')"
        $listPermissions = if ($listId) { @(Get-GraphAll "sites/$siteId/lists/$listId/permissions") } else { @() }
        $plan = @(Get-GrantPlan $listPermissions $appId 'write' 'list')
        foreach ($change in $plan) {
            Invoke-Change $change {
                # The list read again by its ID just before the write: it must be RestoreTarget.
                $why = Test-RestoreTargetList (Invoke-Graph GET "sites/$siteId/lists/${listId}?`$select=id,displayName,webUrl,list") $listId
                if ($why) { throw "the list about to be made writable ${why}: no write grant was made" }
                switch ($change.Action) {
                    'list.grant' { Invoke-WithRetry -What 'the app' -Action { Invoke-Graph POST "sites/$siteId/lists/$listId/permissions" @{ roles = @('write'); grantedToV2 = @{ application = @{ id = $appId } } } | Out-Null } }
                    'list.set' { Invoke-Graph PATCH "sites/$siteId/lists/$listId/permissions/$($change.Data.Id)" @{ roles = @('write') } | Out-Null }
                    'list.remove' { Invoke-Graph DELETE "sites/$siteId/lists/$listId/permissions/$($change.Data.Id)" | Out-Null }
                }
            }
        }
        if ($plan.Count -eq 0) { Ok "write on the $Target list" }

        $folder = Read-Folder $driveId
        $folderId = "$(Get-Field $folder 'id')"
        $folderPermissions = if ($folderId) { @(Get-GraphAll "drives/$driveId/items/$folderId/permissions") } else { @() }
        $plan = @(Get-GrantPlan $folderPermissions $appId 'write' 'folder')
        foreach ($change in $plan) {
            Invoke-Change $change {
                # The folder read again by its ID just before the write: it must be /RestoreTarget.
                $why = Test-RestoreTargetFolder (Invoke-Graph GET "drives/$driveId/items/${folderId}?`$select=id,name,folder,file,parentReference") $driveId $folderId
                if ($why) { throw "the folder about to be made writable ${why}: no write grant was made" }
                switch ($change.Action) {
                    'folder.grant' { Invoke-WithRetry -What 'the app' -Action { Invoke-Graph POST "drives/$driveId/items/$folderId/permissions" @{ roles = @('write'); grantedToV2 = @{ application = @{ id = $appId } } } | Out-Null } }
                    'folder.set' { Invoke-Graph PATCH "drives/$driveId/items/$folderId/permissions/$($change.Data.Id)" @{ roles = @('write') } | Out-Null }
                    'folder.remove' { Invoke-Graph DELETE "drives/$driveId/items/$folderId/permissions/$($change.Data.Id)" | Out-Null }
                }
            }
        }
        if ($plan.Count -eq 0) { Ok "write on the /$Target folder" }

        # ---- 5. Exchange Online ----------------------------------------------------------------
        $pointer = if ($appId) { Get-ServicePrincipal -Identity $appId -ErrorAction SilentlyContinue } else { $null }
        $scope = Get-ManagementScope -Identity $MailScopeName -ErrorAction SilentlyContinue
        $dehydrated = (ConvertFrom-ExchangeBool (Get-OrganizationConfig -ErrorAction Stop).IsDehydrated 'IsDehydrated')
        $plan = @(Get-ExchangePlan $pointer $scope (Read-Assignments) $dehydrated ([bool]$AllowOrganizationCustomization) $spId $appId $MailboxAddress)
        foreach ($change in $plan) {
            switch ($change.Action) {
                'exchange.pointer-remove' { Invoke-Change $change { Remove-ServicePrincipal -Identity $change.Data.Identity -Confirm:$false -ErrorAction Stop | Out-Null } }
                'exchange.pointer' { Invoke-Change $change { Invoke-ExchangeWithRetry { New-ServicePrincipal -AppId $appId -ObjectId $spId -DisplayName $AppName -ErrorAction Stop | Out-Null } } }
                'exchange.customize' { Invoke-Change $change { Enable-OrganizationCustomization -ErrorAction Stop | Out-Null } }
                'exchange.scope' {
                    Invoke-Change $change {
                        try { New-ManagementScope -Name $MailScopeName -RecipientRestrictionFilter $change.Data.Filter -ErrorAction Stop | Out-Null }
                        catch {
                            if ("$_" -notmatch 'Enable-OrganizationCustomization') { throw }
                            throw 'Exchange has not finished Enable-OrganizationCustomization yet. Wait 15 to 60 minutes, then run this again.'
                        }
                    }
                }
                'exchange.scope-filter' { Invoke-Change $change { Set-ManagementScope -Identity $MailScopeName -RecipientRestrictionFilter $change.Data.Filter -ErrorAction Stop | Out-Null } }
                'exchange.assignment-remove' { Invoke-Change $change { Remove-ManagementRoleAssignment -Identity $change.Data.Identity -Confirm:$false -ErrorAction Stop | Out-Null } }
                'exchange.assignment' { Invoke-Change $change { New-ManagementRoleAssignment -Name $MailAssignmentName -App $spId -Role $MailRoleName -CustomResourceScope $MailScopeName -ErrorAction Stop | Out-Null } }
            }
        }
        if ($plan.Count -eq 0) { Ok "'$MailRoleName' on $MailboxAddress alone" }
    }

    if ($WhatIf) {
        Say "changes: $script:Changes (planned; nothing was changed)"
        return
    }

    # ---- 6. the check, read-only ---------------------------------------------------------------
    $problems = [System.Collections.Generic.List[string]]::new()
    $notes = [System.Collections.Generic.List[string]]::new()
    $apps = @(Read-Apps)
    $app = if ($apps.Count -eq 1) { $apps[0] } else { $null }
    if ($apps.Count -gt 1) { $problems.Add("there are $($apps.Count) app registrations named '$AppName'") }
    $appId = "$(Get-Field $app 'appId')"
    $federated = if ($app) { @(Get-GraphAll "applications/$(Get-Field $app 'id')/federatedIdentityCredentials") } else { @() }
    foreach ($p in Test-AppState $app $federated $certificate.Thumbprint $roleIds) { $problems.Add($p) }
    $sp = if ($appId) { Read-ServicePrincipal $appId } else { $null }
    $spId = "$(Get-Field $sp 'id')"
    $assignments = if ($spId) { @(Get-GraphAll "servicePrincipals/$spId/appRoleAssignments") } else { @() }
    $delegated = if ($spId) { @(Get-GraphAll "servicePrincipals/$spId/oauth2PermissionGrants") } else { @() }
    $memberOf = if ($spId) { @(Get-GraphAll "servicePrincipals/$spId/memberOf") } else { @() }
    foreach ($p in Test-ServicePrincipalState $sp $assignments $delegated $memberOf $graphSpId $roleIds) { $problems.Add($p) }

    $site = Read-Site
    $siteId = "$(Get-Field $site 'id')"
    $lists = @(Read-Lists $siteId)
    $list = Find-RestoreTargetList $lists
    $listId = "$(Get-Field $list 'id')"
    $drive = Read-Drive
    $driveId = "$(Get-Field $drive 'id')"
    $folder = Read-Folder $driveId
    $folderId = "$(Get-Field $folder 'id')"
    $root = Invoke-Graph GET "drives/$driveId/root?`$select=id,sharepointIds"
    $oneDriveSiteUrl = "$(Get-Field (Get-Field $root 'sharepointIds') 'siteUrl')"
    # Each location: its label, its rule, and the permissions path read (a site's: each grant read itself).
    $locations = [System.Collections.Generic.List[object]]::new()
    $locations.Add(@('the site', 'site-read', "site:$siteId"))
    if ($listId) {
        $why = Test-RestoreTargetList $list $listId
        if ($why) { $problems.Add("the $Target list $why") }
        $locations.Add(@("the $Target list", 'target-write', "sites/$siteId/lists/$listId/permissions"))
    }
    else { $problems.Add("the site has no $Target library") }
    foreach ($other in $lists | Where-Object { "$(Get-Field $_ 'id')" -ne $listId }) {
        $locations.Add(@("the site's list '$(Get-Field $other 'displayName')'", 'inherited-read-only', "sites/$siteId/lists/$(Get-Field $other 'id')/permissions"))
    }
    if ($folderId) {
        $why = Test-RestoreTargetFolder $folder $driveId $folderId
        if ($why) { $problems.Add("the /$Target folder $why") }
        $locations.Add(@("the /$Target folder", 'target-write', "drives/$driveId/items/$folderId/permissions"))
    }
    else { $problems.Add("$OneDriveUser's OneDrive has no /$Target folder") }
    $locations.Add(@("$OneDriveUser's OneDrive root", 'none', "drives/$driveId/root/permissions"))
    if ($oneDriveSiteUrl) {
        $u = [Uri]$oneDriveSiteUrl
        $locations.Add(@("$OneDriveUser's OneDrive site", 'none', "onedrive-site:$($u.Host):$($u.AbsolutePath.TrimEnd('/'))"))
    }
    else { $problems.Add("$OneDriveUser's OneDrive site can't be found") }
    foreach ($location in $locations) {
        try {
            $path = $location[2]
            $permissions = if ($path.StartsWith('site:')) { Read-SitePermissions $path.Substring(5) }
            elseif ($path.StartsWith('onedrive-site:')) { Read-SitePermissions "$(Get-Field (Invoke-Graph GET "sites/$($path.Substring(14))?`$select=id") 'id')" }
            else { Get-GraphAll $path }
            $result = Test-PermissionRule -Permissions @($permissions) -AppId $appId -Rule $location[1]
        }
        catch {
            $status = Get-GraphStatus $_
            $problems.Add("$($location[0]): the permissions can't be read ($(if ($null -ne $status) { "HTTP $status" } else { $_.Exception.Message }))")
            continue
        }
        foreach ($p in $result.Problems) { $problems.Add("$($location[0]): $p") }
        foreach ($n in $result.Notes) { $notes.Add("$($location[0]): $n") }
    }

    # Every Exchange read below that fails is a problem, never the end of the check.
    $recipients = @()
    try {
        $recipients = @(Read-Recipients)
        if ($recipients.Count -ne 1 -or (Test-MailRecipient $recipients[0] $MailboxAddress)) { $problems.Add("$MailboxAddress is not one user or shared mailbox") }
    }
    catch { $problems.Add("$MailboxAddress can't be read in Exchange: $($_.Exception.Message)") }
    $scope = Get-ManagementScope -Identity $MailScopeName -ErrorAction SilentlyContinue
    $pointer = if ($appId) { Get-ServicePrincipal -Identity $appId -ErrorAction SilentlyContinue } else { $null }
    # Exchange's answer for one mailbox, or why it gave none.
    function Read-Authorization([string]$Mailbox, [bool]$Expected) {
        try { @{ Mailbox = $Mailbox; Expected = $Expected; Answers = @(Test-ServicePrincipalAuthorization -Identity $appId -Resource $Mailbox -ErrorAction Stop) } }
        catch { @{ Mailbox = $Mailbox; Failed = $_.Exception.Message } }
    }
    $authorizations = @()
    # Without a pointer Exchange can answer nothing for the app: Test-ExchangeState names that.
    if ($pointer) {
        $authorizations += Read-Authorization $MailboxAddress $true
        foreach ($other in @($account, $OneDriveUser) | Select-Object -Unique) {
            try { $found = @(Read-Recipients $other | Where-Object { @('UserMailbox', 'SharedMailbox') -contains "$($_.RecipientTypeDetails)" }) }
            catch { $problems.Add("$other can't be read in Exchange: $($_.Exception.Message)"); continue }
            if ($found.Count -eq 0) { $notes.Add("$other has no mailbox to test the scope against"); continue }
            # The OneDrive user may be the restoretest mailbox's own user: in scope by design.
            if (@($found | Where-Object { "$($_.PrimarySmtpAddress)" -ieq $MailboxAddress }).Count -gt 0) {
                $notes.Add("$other is the $MailboxAddress mailbox itself"); continue
            }
            $authorizations += Read-Authorization $other $false
        }
    }
    foreach ($p in Test-ExchangeState $pointer $scope (Read-Assignments) $spId $appId $MailboxAddress $authorizations) { $problems.Add($p) }

    foreach ($n in $notes) { Say "note: $n" }
    foreach ($p in $problems) { Say "problem: $p" }
    if ($problems.Count -gt 0) {
        Say "grants: $($problems.Count) problem(s)"
        Say "changes: $script:Changes"
        exit 1
    }
    Say 'grants: ok'

    # ---- 7. the profile --------------------------------------------------------------------
    $libraryDrive = Invoke-Graph GET "sites/$siteId/lists/$listId/drive?`$select=id"
    $profile = New-ClientProfile -VeeamOrgName $VeeamOrgName -TenantId $TenantId -ClientId $appId `
        -Mailbox "$($recipients[0].PrimarySmtpAddress)" -SiteId $siteId -LibraryDriveId "$(Get-Field $libraryDrive 'id')" `
        -DriveId $driveId -FolderId $folderId
    $text = ConvertTo-ProfileJson $profile
    if (-not (Test-Json -Json $text -SchemaFile $SchemaFile -ErrorAction SilentlyContinue)) {
        throw 'the profile read back is not a valid restoreproof.client-profile.v1 (an ID of an unexpected shape); nothing was written'
    }
    Say 'profile:'
    Say $text.TrimEnd("`n")
    if ($ProfileFile) {
        [IO.File]::WriteAllText([IO.Path]::GetFullPath($ProfileFile, (Get-Location).ProviderPath), $text, [Text.UTF8Encoding]::new($false))
        Say "profile written to $ProfileFile"
    }
    Say "changes: $script:Changes"
    if ($script:Changes -gt 0) {
        Say 'Exchange can take 30 minutes to 2 hours to apply the mail role everywhere; Test-ServicePrincipalAuthorization above reads it at once.'
    }
}
finally {
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}

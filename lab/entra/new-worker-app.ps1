<#
.SYNOPSIS
    Creates or updates the "RestoreProof Worker" app registration in the lab tenant (L1.5).

.DESCRIPTION
    Safe to run again: each step checks what is already there and changes only what differs.
    Run it as the lab's global admin, in PowerShell 7. It never prints or writes a secret:

    1. Certificate. A self-signed RSA 2048 certificate, valid for one year. Its private key
       exists only in a PFX file outside the repo (%LOCALAPPDATA%\RestoreProof\lab\worker-graph.pfx);
       the PFX password is random and goes straight into Windows Credential Manager (generic
       credential "RestoreProof Lab - Worker Graph app PFX"). The copy in the certificate store is
       deleted once the PFX is written. An existing PFX and password are reused.
    2. App registration "RestoreProof Worker": single tenant, the certificate as its only
       credential (any other certificate or client secret is removed), and exactly three Microsoft
       Graph application permissions: Sites.Selected, Files.SelectedOperations.Selected and
       Lists.SelectedOperations.Selected (W3.4). Admin consent is granted for those three; any
       other consented application permission, on Graph (e.g. Mail.Read) or another API (e.g.
       Exchange's full_access_as_app), is removed.
    3. SharePoint: read on the RestoreTest site (Sites.Selected); write on the RestoreTarget list
       only (Lists.SelectedOperations.Selected) and on alice's OneDrive RestoreTarget folder
       (Files.SelectedOperations.Selected), so the Worker's Cleaner can delete restored copies
       (W3.4). Nothing else. Before each write grant the script reads the list or folder and
       refuses unless it is named RestoreTarget (the list's address too; the folder directly
       under the drive's root).
    4. Exchange Online RBAC for Applications: "Application Mail.ReadWrite" on the restoretest
       mailbox only (a management scope; until W3.4 "Application Mail.Read", whose assignment the
       script removes), then Test-ServicePrincipalAuthorization for restoretest and alice.

    It ends by printing the client ID and the certificate thumbprint. The permissions and the
    reasons for them are in docs/security/graph-permissions.md; the steps around it (becoming site
    collection admin of alice's OneDrive first) in lab/README.md.

.EXAMPLE
    pwsh -NoProfile -File lab\entra\new-worker-app.ps1
#>
#Requires -Version 7.2
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---- the lab (lab/tenant.md; lab/tests/test_entra_script.py keeps these in step) ---------------
$TenantId = 'bcd6bd1a-ea42-489d-aa28-2c19a44ad146'
$AdminUpn = 'HrachyaHarutyunyan@RestoreProofLab.onmicrosoft.com'
$RestoreTestUpn = 'restoretest@RestoreProofLab.onmicrosoft.com'
$AliceUpn = 'alice@RestoreProofLab.onmicrosoft.com'
$SiteId = 'restoreprooflab.sharepoint.com,fe08085d-eb70-42e8-95a6-470189bd98eb,4ecaf399-cc0e-4d95-b3fe-cd091a09e689'
$OneDriveDriveId = 'b!wA9gbfhlEUitGAluxbfoNBr_z5gEtDhErm5pJ6bMwyXfZJ8a_dkCQ696RX0r7_U3'
$OneDriveTargetFolderId = '01ZK75LGDGB6QOO3MGNFGYOY6C6VBDG5OH'
$RestoreTargetListId = 'ffec069d-65e4-4c3a-9da2-ac086cf9dafa'
$RestoreTargetName = 'RestoreTarget'

# ---- the app ------------------------------------------------------------------------------------
$AppName = 'RestoreProof Worker'
$GraphAppId = '00000003-0000-0000-c000-000000000000'
$GraphRoles = @('Sites.Selected', 'Files.SelectedOperations.Selected', 'Lists.SelectedOperations.Selected')
$CertSubject = 'CN=RestoreProof Worker (lab)'
$CredTarget = 'RestoreProof Lab - Worker Graph app PFX'
$CredUser = 'rp-worker-pfx'
$PfxName = 'worker-graph.pfx'
$PfxPath = Join-Path $env:LOCALAPPDATA "RestoreProof\lab\$PfxName"
$MailScopeName = 'RestoreProof Worker - restoretest mailbox'
$MailRoleName = 'Application Mail.ReadWrite'
$MailAssignmentName = 'RestoreProof Worker - Application Mail.ReadWrite - restoretest'

function Step([string]$Text) { Write-Host "`n==> $Text" -ForegroundColor Cyan }
function Done([string]$Text) { Write-Host "    $Text" }

# Credential Manager, generic credentials; the password is stored as UTF-16, like cmdkey does.
if (-not ('RpWorkerCredential' -as [type])) {
    Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices;
public static class RpWorkerCredential {
  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  struct CREDENTIAL { public int Flags; public int Type; public string TargetName; public string Comment;
    public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten; public int CredentialBlobSize; public IntPtr CredentialBlob;
    public int Persist; public int AttributeCount; public IntPtr Attributes; public string TargetAlias; public string UserName; }
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool CredReadW(string t, int type, int f, out IntPtr c);
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool CredWriteW(ref CREDENTIAL c, int f);
  [DllImport("advapi32.dll")] static extern void CredFree(IntPtr p);
  // null only when there is no such credential (ERROR_NOT_FOUND); any other failure throws, so a
  // session that can't reach Credential Manager is never told the password is gone.
  public static string Read(string t) {
    IntPtr p;
    if (!CredReadW(t, 1, 0, out p)) {
      int error = Marshal.GetLastWin32Error();
      if (error == 1168) return null;
      throw new System.ComponentModel.Win32Exception(error);
    }
    try { var c = (CREDENTIAL)Marshal.PtrToStructure(p, typeof(CREDENTIAL));
          if (c.CredentialBlobSize == 0) return "";
          return Marshal.PtrToStringUni(c.CredentialBlob, c.CredentialBlobSize / 2); } finally { CredFree(p); } }
  public static void Write(string t, string user, string secret) {
    var c = new CREDENTIAL(); c.Type = 1; c.TargetName = t; c.UserName = user; c.Persist = 2;
    c.CredentialBlobSize = secret.Length * 2; c.CredentialBlob = Marshal.StringToCoTaskMemUni(secret);
    try { if (!CredWriteW(ref c, 0)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()); }
    finally { Marshal.ZeroFreeCoTaskMemUnicode(c.CredentialBlob); } }
}
"@
}

function Invoke-Graph([string]$Method, [string]$Uri, $Body = $null) {
    $request = @{ Method = $Method; Uri = "https://graph.microsoft.com/v1.0/$Uri"; OutputType = 'HashTable' }
    if ($null -ne $Body) {
        $request.Body = $Body | ConvertTo-Json -Depth 10 -Compress
        $request.ContentType = 'application/json'
    }
    Invoke-MgGraphRequest @request
}

# The HTTP status of a failed Invoke-MgGraphRequest, or $null when there was no answer.
function Get-GraphStatus($ErrorRecord) {
    $response = $ErrorRecord.Exception.PSObject.Properties['Response']
    if ($response -and $response.Value) { return [int]$response.Value.StatusCode }
    if ("$ErrorRecord" -match '\b(BadRequest|NotFound)\b') { return @{ BadRequest = 400; NotFound = 404 }[$Matches[1]] }
    return $null
}

# A new app or service principal takes a few seconds to reach every directory replica; until then
# Graph answers 400 or 404 about it. Anything else (403, or a 5xx the SDK already retried) is final.
function Invoke-WithRetry([scriptblock]$Action, [string]$What) {
    for ($attempt = 1; ; $attempt++) {
        try { return & $Action }
        catch {
            if ($attempt -ge 6 -or @(400, 404) -notcontains (Get-GraphStatus $_)) { throw }
            Done "$What not ready yet (attempt $attempt): retrying in 10 s"
            Start-Sleep -Seconds 10
        }
    }
}

# The certificate as the app's only credential: any other certificate and every client secret go
# (an app first made by hand may have a secret). A GET never returns a certificate's key, so the
# list is replaced with just this one; a secret can only be removed by its keyId.
function Set-OnlyCredential($App, $KeyCredential, [string]$Thumbprint) {
    $keys = @($App.keyCredentials | Where-Object { $_ })
    $current = @($keys | Where-Object { $_.displayName -like "*$Thumbprint" })
    if ($current.Count -eq 1 -and $keys.Count -eq 1) {
        Done "exists, client ID $($App.appId); certificate already uploaded"
    }
    else {
        Invoke-Graph PATCH "applications/$($App.id)" @{ keyCredentials = @($KeyCredential) } | Out-Null
        Done "exists, client ID $($App.appId); uploaded the certificate (replaces $($keys.Count) certificate(s))"
    }
    foreach ($secret in @($App.passwordCredentials | Where-Object { $_ })) {
        Invoke-Graph POST "applications/$($App.id)/removePassword" @{ keyId = $secret.keyId } | Out-Null
        Done "removed client secret '$($secret.displayName)': the certificate is the only credential"
    }
}

# W3.4: what is about to become writable must be the RestoreTarget list, by its name and by its
# address. A wrong ID would give the Worker write on another list (the canary library is in the
# same site), so nothing is granted unless both say RestoreTarget. Mirrors the Worker's
# check_restore_library (worker/src/target_guard_graph.cpp): the name exact, the address's last
# segment in any ASCII case.
function Assert-RestoreTargetList {
    $reply = Invoke-Graph GET "sites/$SiteId/lists/${RestoreTargetListId}?`$select=id,displayName,webUrl"
    $name = "$($reply['displayName'])"
    $url = "$($reply['webUrl'])".TrimEnd('/')
    $segment = [Uri]::UnescapeDataString($url.Substring($url.LastIndexOf('/') + 1))
    if ($name -cne $RestoreTargetName -or $segment -ne $RestoreTargetName) {
        throw "The list `$RestoreTargetListId names is '$name' at '$url', not the $RestoreTargetName library: " +
              'no write grant was made. Check the list ID in lab/tenant.md.'
    }
    Done "the list is '$name' ($url)"
}

# W3.4: the folder about to become writable must be RestoreTarget, directly under the root of
# alice's drive (Graph writes the root either way). Mirrors check_restore_onedrive_folder.
function Assert-RestoreTargetFolder {
    $item = Invoke-Graph GET "drives/$OneDriveDriveId/items/${OneDriveTargetFolderId}?`$select=id,name,folder,parentReference"
    $parent = $item['parentReference']
    $path = if ($parent) { "$($parent['path'])" } else { '' }
    $drive = if ($parent) { "$($parent['driveId'])" } else { '' }
    $atRoot = @('/drive/root:', "/drives/$OneDriveDriveId/root:") -ccontains $path
    if ("$($item['name'])" -cne $RestoreTargetName -or -not $item['folder'] -or $drive -cne $OneDriveDriveId -or -not $atRoot) {
        throw "The item `$OneDriveTargetFolderId names is '$($item['name'])' in '$path', not the $RestoreTargetName folder " +
              "directly under the root of alice's OneDrive: no write grant was made. Check the folder ID in lab/tenant.md."
    }
    Done "the folder is '$($item['name'])', directly under the drive's root"
}

# ---- 1. certificate -------------------------------------------------------------------------------
Step "Certificate ($PfxPath)"
$password = [RpWorkerCredential]::Read($CredTarget)
$haveFile = Test-Path -LiteralPath $PfxPath
if ($haveFile -and -not $password) {
    throw "$PfxPath exists but Credential Manager has no '$CredTarget' (or an empty one), so the PFX can't be opened. " +
          "Delete the PFX and run this script again: it makes a new certificate and replaces the app's old one."
}
if (-not $haveFile) {
    $bytes = [byte[]]::new(32)
    [Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    $password = [Convert]::ToBase64String($bytes)
    $new = New-SelfSignedCertificate -Subject $CertSubject -CertStoreLocation 'Cert:\CurrentUser\My' `
        -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 -KeyExportPolicy Exportable `
        -KeyUsage DigitalSignature -NotAfter (Get-Date).AddYears(1)
    try {
        # Password first: a PFX without its password would be useless.
        [RpWorkerCredential]::Write($CredTarget, $CredUser, $password)
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $PfxPath) | Out-Null
        $secure = ConvertTo-SecureString $password -AsPlainText -Force
        Export-PfxCertificate -Cert $new -FilePath $PfxPath -Password $secure -CryptoAlgorithmOption AES256_SHA256 | Out-Null
    }
    finally {
        # The PFX is the only copy of the private key.
        Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($new.Thumbprint)" -DeleteKey
    }
    Done "created a new certificate; its password is in Credential Manager ('$CredTarget')"
}
else {
    Done "reusing the existing PFX and its password in Credential Manager"
}
# EphemeralKeySet: the key is never written to a key store while the public part is read.
$x509 = [Security.Cryptography.X509Certificates.X509Certificate2]::new($PfxPath, $password, [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
$thumbprint = $x509.Thumbprint
$notAfter = $x509.NotAfter.ToUniversalTime()
$certKey = [Convert]::ToBase64String($x509.RawData)  # the public certificate only
$x509.Dispose()
Remove-Variable password, secure -ErrorAction SilentlyContinue
Done "thumbprint (SHA-1) $thumbprint, expires $($notAfter.ToString('yyyy-MM-dd')) UTC"

# ---- 2. app registration, service principal, admin consent ------------------------------------------
Step "Sign in to Microsoft Graph as $AdminUpn"
Connect-MgGraph -TenantId $TenantId -NoWelcome -ContextScope Process `
    -Scopes 'Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All', 'Sites.FullControl.All'
$account = (Get-MgContext).Account
if ($account -ne $AdminUpn) {
    Disconnect-MgGraph | Out-Null
    throw "Signed in as '$account', but this script must run as $AdminUpn. Run it again and pick that account."
}

try {
    Step "App registration '$AppName'"
    $graphSp = Invoke-Graph GET "servicePrincipals(appId='$GraphAppId')?`$select=id,appRoles"
    $roleIds = [ordered]@{}
    foreach ($name in $GraphRoles) {
        $role = @($graphSp.appRoles | Where-Object { $_.value -eq $name -and $_.allowedMemberTypes -contains 'Application' })
        if ($role.Count -ne 1) { throw "Microsoft Graph has no application permission '$name'" }
        $roleIds[$name] = $role[0].id
    }
    $required = @(@{
            resourceAppId  = $GraphAppId
            resourceAccess = @($roleIds.Values | ForEach-Object { @{ id = $_; type = 'Role' } })
        })
    $keyCredential = @{
        type        = 'AsymmetricX509Cert'
        usage       = 'Verify'
        key         = $certKey
        displayName = "$CertSubject $thumbprint"
    }

    $found = @((Invoke-Graph GET "applications?`$filter=displayName eq '$AppName'&`$select=id,appId,keyCredentials,passwordCredentials").value)
    if ($found.Count -gt 1) { throw "There are $($found.Count) app registrations named '$AppName'; delete the extra ones first." }
    if ($found.Count -eq 0) {
        $app = Invoke-Graph POST 'applications' @{
            displayName            = $AppName
            signInAudience         = 'AzureADMyOrg'
            requiredResourceAccess = $required
            keyCredentials         = @($keyCredential)
        }
        Done "created, client ID $($app.appId)"
    }
    else {
        $app = $found[0]
        # Exactly these two permissions: anything else once added is dropped here.
        Invoke-Graph PATCH "applications/$($app.id)" @{ signInAudience = 'AzureADMyOrg'; requiredResourceAccess = $required } | Out-Null
        Set-OnlyCredential -App $app -KeyCredential $keyCredential -Thumbprint $thumbprint
    }
    $appId = $app.appId

    Step "Service principal"
    $sp = Invoke-WithRetry -What 'service principal' -Action {
        $existing = @((Invoke-Graph GET "servicePrincipals?`$filter=appId eq '$appId'&`$select=id,appId").value)
        if ($existing.Count -gt 0) { $existing[0] } else { Invoke-Graph POST 'servicePrincipals' @{ appId = $appId } }
    }
    $spId = $sp.id
    Done "object ID $spId"

    Step "Admin consent: $($GraphRoles -join ', ')"
    $assigned = @((Invoke-Graph GET "servicePrincipals/$spId/appRoleAssignments").value)
    foreach ($name in $GraphRoles) {
        if ($assigned | Where-Object { $_.resourceId -eq $graphSp.id -and $_.appRoleId -eq $roleIds[$name] }) {
            Done "$name already granted"
            continue
        }
        Invoke-WithRetry -What 'consent' -Action {
            try {
                Invoke-Graph POST "servicePrincipals/$spId/appRoleAssignments" @{
                    principalId = $spId; resourceId = $graphSp.id; appRoleId = $roleIds[$name]
                }
            }
            catch {
                # An earlier attempt got through but its answer was lost: the grant is in place.
                if ("$_" -notmatch 'Permission being assigned already exists') { throw }
            }
        } | Out-Null
        Done "$name granted"
    }
    foreach ($extra in $assigned | Where-Object { -not ($_.resourceId -eq $graphSp.id -and @($roleIds.Values) -contains $_.appRoleId) }) {
        # A consent on another API (Exchange's full_access_as_app, SharePoint's Sites.FullControl.All)
        # has no Graph role: reading .value off $null throws under strict mode, so test first.
        $graphRole = $graphSp.appRoles | Where-Object { $_.id -eq $extra.appRoleId } | Select-Object -First 1
        $label = if ($graphRole) { $graphRole.value } else { "$($extra.resourceDisplayName) role $($extra.appRoleId)" }
        Invoke-Graph DELETE "servicePrincipals/$spId/appRoleAssignments/$($extra.id)" | Out-Null
        Done "removed consent for $($label): not needed (docs/security/graph-permissions.md)"
    }

    # ---- 3. SharePoint and OneDrive grants --------------------------------------------------------
    Step 'Sites.Selected: read on the RestoreTest site'
    $sitePerms = @((Invoke-Graph GET "sites/$SiteId/permissions").value)
    $mine = @($sitePerms | Where-Object {
            @($_.grantedToIdentitiesV2) + @($_.grantedToIdentities) | Where-Object { $_ -and $_.application -and $_.application.id -eq $appId }
        })
    if ($mine.Count -eq 0) {
        Invoke-Graph POST "sites/$SiteId/permissions" @{
            roles               = @('read')
            grantedToIdentities = @(@{ application = @{ id = $appId; displayName = $AppName } })
        } | Out-Null
        Done 'granted'
    }
    else {
        # The list may omit roles; read the grant itself.
        $grant = Invoke-Graph GET "sites/$SiteId/permissions/$($mine[0].id)"
        if ((@($grant.roles) -join ',') -ne 'read') {
            Invoke-Graph PATCH "sites/$SiteId/permissions/$($mine[0].id)" @{ roles = @('read') } | Out-Null
            Done "changed roles from '$(@($grant.roles) -join ',')' to 'read'"
        }
        else { Done 'already granted' }
    }

    Step 'Lists.SelectedOperations.Selected: write on the RestoreTarget list only (W3.4)'
    Assert-RestoreTargetList
    $list = "sites/$SiteId/lists/$RestoreTargetListId"
    $listPerms = @((Invoke-Graph GET "$list/permissions").value)
    # A list's grant may come back in the folder's form or the site's (grantedToIdentities): either counts.
    $mine = @($listPerms | Where-Object {
            @($_['grantedToV2'], $_['grantedTo']) + @($_['grantedToIdentitiesV2']) + @($_['grantedToIdentities']) |
                Where-Object { $_ -and $_['application'] -and $_['application'].id -eq $appId }
        })
    if ($mine.Count -eq 0) {
        Invoke-Graph POST "$list/permissions" @{
            roles       = @('write')
            grantedToV2 = @{ application = @{ id = $appId } }
        } | Out-Null
        Done 'granted'
    }
    elseif ((@($mine[0].roles) -join ',') -ne 'write') {
        Invoke-Graph PATCH "$list/permissions/$($mine[0].id)" @{ roles = @('write') } | Out-Null
        Done "changed roles from '$(@($mine[0].roles) -join ',')' to 'write'"
    }
    else { Done 'already granted' }

    Step "Files.SelectedOperations.Selected: write on alice's OneDrive RestoreTarget folder (W3.4)"
    $folder = "drives/$OneDriveDriveId/items/$OneDriveTargetFolderId"
    try { $folderPerms = @((Invoke-Graph GET "$folder/permissions").value) }
    catch {
        throw "Can't read the permissions of alice's RestoreTarget folder as $AdminUpn ($($_.Exception.Message)). " +
              "Make $AdminUpn a site collection admin of alice's OneDrive first (lab/README.md, 'RestoreProof Worker app'), then run this script again."
    }
    Assert-RestoreTargetFolder
    $mine = @($folderPerms | Where-Object {
            @($_['grantedToV2'], $_['grantedTo']) | Where-Object { $_ -and $_['application'] -and $_['application'].id -eq $appId }
        })
    if ($mine.Count -eq 0) {
        Invoke-Graph POST "$folder/permissions" @{
            roles       = @('write')
            grantedToV2 = @{ application = @{ id = $appId } }
        } | Out-Null
        Done 'granted'
    }
    elseif ((@($mine[0].roles) -join ',') -ne 'write') {
        Invoke-Graph PATCH "$folder/permissions/$($mine[0].id)" @{ roles = @('write') } | Out-Null
        Done "changed roles from '$(@($mine[0].roles) -join ',')' to 'write'"
    }
    else { Done 'already granted' }
}
finally {
    Disconnect-MgGraph | Out-Null
}

# ---- 4. Exchange Online RBAC for Applications -------------------------------------------------------
Step "Exchange Online: '$MailRoleName' on $RestoreTestUpn only (sign in as $AdminUpn)"
# Import-Module takes the highest version. Veeam Backup for Microsoft 365 ships its own copy,
# which Install-Module counts as installed but PowerShell 7 can't load. 3.7.2 is the first
# version with Connect-ExchangeOnline -DisableWAM.
try { Import-Module ExchangeOnlineManagement -MinimumVersion 3.7.2 }
catch {
    throw "Can't load the ExchangeOnlineManagement module ($($_.Exception.Message)). Install your own copy: " +
          "Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber (installs it next to Veeam's bundled one, or upgrades an older copy), then run this script again."
}
# -DisableWAM: the Windows sign-in broker fails with a NullReferenceException when the module
# runs from a script (no parent window); a browser sign-in works.
# Every Exchange call below carries -ErrorAction Stop: its cmdlets are functions in a generated
# module, which don't see this script's $ErrorActionPreference when it is started as
# .
ew-worker-app.ps1 from an open window, so their errors would print and the run carry on.
Connect-ExchangeOnline -UserPrincipalName $AdminUpn -ShowBanner:$false -DisableWAM -ErrorAction Stop
try {
    if (-not (Get-ServicePrincipal -Identity $appId -ErrorAction SilentlyContinue)) {
        New-ServicePrincipal -AppId $appId -ObjectId $spId -DisplayName $AppName -ErrorAction Stop | Out-Null
        Done 'service principal pointer created'
    }
    else { Done 'service principal pointer exists' }

    $filter = "PrimarySmtpAddress -eq '$RestoreTestUpn'"
    $scope = Get-ManagementScope -Identity $MailScopeName -ErrorAction SilentlyContinue
    if (-not $scope) {
        # A new tenant is "dehydrated": it can't hold custom RBAC objects such as a management
        # scope until this one-time, tenant-wide and irreversible step (docs/decisions.md 2026-09-27).
        if ((Get-OrganizationConfig -ErrorAction Stop).IsDehydrated) {
            Enable-OrganizationCustomization -ErrorAction Stop
            Done 'Enable-OrganizationCustomization run (once per tenant)'
        }
        try { New-ManagementScope -Name $MailScopeName -RecipientRestrictionFilter $filter -ErrorAction Stop | Out-Null }
        catch {
            if ("$_" -notmatch 'Enable-OrganizationCustomization') { throw }
            throw 'Exchange has not finished Enable-OrganizationCustomization yet. Wait 15 to 60 minutes, then run this script again.'
        }
        Done "management scope '$MailScopeName' created"
    }
    elseif ($scope.RecipientFilter -ne $filter) {
        Set-ManagementScope -Identity $MailScopeName -RecipientRestrictionFilter $filter -ErrorAction Stop
        Done "management scope filter reset to: $filter"
    }
    else { Done "management scope '$MailScopeName' exists" }

    # Every assignment held by this app (the lab has few, so list them all).
    $mineRoles = @(Get-ManagementRoleAssignment -ErrorAction Stop |
            Where-Object { $_.Name -eq $MailAssignmentName -or ("$($_.RoleAssigneeType)" -eq 'ServicePrincipal' -and @($spId, $appId, $AppName) -contains "$($_.RoleAssigneeName)") })
    if (-not ($mineRoles | Where-Object Name -eq $MailAssignmentName)) {
        New-ManagementRoleAssignment -Name $MailAssignmentName -App $spId -Role $MailRoleName -CustomResourceScope $MailScopeName -ErrorAction Stop | Out-Null
        Done "role assignment '$MailAssignmentName' created"
    }
    else { Done "role assignment '$MailAssignmentName' exists" }
    foreach ($extra in $mineRoles | Where-Object Name -ne $MailAssignmentName) {
        Remove-ManagementRoleAssignment -Identity $extra.Identity -Confirm:$false -ErrorAction Stop
        Done "removed role assignment '$($extra.Name)' ($($extra.Role)): not needed"
    }

    Done 'Test-ServicePrincipalAuthorization (bypasses the 30 min to 2 h permission cache):'
    foreach ($mailbox in @($RestoreTestUpn, $AliceUpn)) {
        Test-ServicePrincipalAuthorization -Identity $appId -Resource $mailbox -ErrorAction Stop |
            Select-Object @{ n = 'Mailbox'; e = { $mailbox } }, RoleName, AllowedResourceScope, InScope |
            Format-Table -AutoSize | Out-String -Stream | Where-Object { $_ } | ForEach-Object { Done $_ }
    }
}
finally {
    Disconnect-ExchangeOnline -Confirm:$false | Out-Null
}

Step 'RestoreProof Worker app is set up'
Done "Tenant ID                  $TenantId"
Done "Application (client) ID    $appId"
Done "Service principal ID       $spId"
Done "Certificate thumbprint     $thumbprint (SHA-1), expires $($notAfter.ToString('yyyy-MM-dd')) UTC"
Done "Certificate file           $PfxPath (password: Credential Manager, '$CredTarget')"
Done ''
Done 'Mail access can take 30 minutes to 2 hours to apply (until then a mail delete may get 403). Then, from lab\:'
Done "  uv run python -m seeder check-worker-app --client-id $appId"

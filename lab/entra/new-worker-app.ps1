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
       credential, and exactly two Microsoft Graph application permissions: Sites.Selected and
       Files.SelectedOperations.Selected. Admin consent is granted for those two; any other
       consented application permission (e.g. Mail.Read) is removed.
    3. SharePoint: read on the RestoreTest site (Sites.Selected), read on alice's OneDrive
       RestoreTarget folder (Files.SelectedOperations.Selected). Nothing else.
    4. Exchange Online RBAC for Applications: "Application Mail.Read" on the restoretest mailbox
       only (a management scope), then Test-ServicePrincipalAuthorization for restoretest and alice.

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

# ---- the app ------------------------------------------------------------------------------------
$AppName = 'RestoreProof Worker'
$GraphAppId = '00000003-0000-0000-c000-000000000000'
$GraphRoles = @('Sites.Selected', 'Files.SelectedOperations.Selected')
$CertSubject = 'CN=RestoreProof Worker (lab)'
$CredTarget = 'RestoreProof Lab - Worker Graph app PFX'
$CredUser = 'rp-worker-pfx'
$PfxName = 'worker-graph.pfx'
$PfxPath = Join-Path $env:LOCALAPPDATA "RestoreProof\lab\$PfxName"
$MailScopeName = 'RestoreProof Worker - restoretest mailbox'
$MailRoleName = 'Application Mail.Read'
$MailAssignmentName = 'RestoreProof Worker - Application Mail.Read - restoretest'

function Step([string]$Text) { Write-Host "`n==> $Text" -ForegroundColor Cyan }
function Done([string]$Text) { Write-Host "    $Text" }

# Credential Manager, generic credentials; the password is stored as UTF-16, like cmdkey does.
if (-not ('RpWorkerCred' -as [type])) {
    Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices;
public static class RpWorkerCred {
  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  struct CREDENTIAL { public int Flags; public int Type; public string TargetName; public string Comment;
    public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten; public int CredentialBlobSize; public IntPtr CredentialBlob;
    public int Persist; public int AttributeCount; public IntPtr Attributes; public string TargetAlias; public string UserName; }
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool CredReadW(string t, int type, int f, out IntPtr c);
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool CredWriteW(ref CREDENTIAL c, int f);
  [DllImport("advapi32.dll")] static extern void CredFree(IntPtr p);
  public static string Read(string t) {
    IntPtr p; if (!CredReadW(t, 1, 0, out p)) return null;
    try { var c = (CREDENTIAL)Marshal.PtrToStructure(p, typeof(CREDENTIAL));
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

# A new app or service principal takes a few seconds to reach every directory replica.
function Invoke-WithRetry([scriptblock]$Action, [string]$What) {
    for ($attempt = 1; ; $attempt++) {
        try { return & $Action }
        catch {
            if ($attempt -ge 6) { throw }
            Done "$What not ready yet (attempt $attempt): retrying in 10 s"
            Start-Sleep -Seconds 10
        }
    }
}

# ---- 1. certificate -------------------------------------------------------------------------------
Step "Certificate ($PfxPath)"
$password = [RpWorkerCred]::Read($CredTarget)
$haveFile = Test-Path -LiteralPath $PfxPath
if ($haveFile -and -not $password) {
    throw "$PfxPath exists but Credential Manager has no '$CredTarget', so the PFX can't be opened. " +
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
        [RpWorkerCred]::Write($CredTarget, $CredUser, $password)
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

    $found = @((Invoke-Graph GET "applications?`$filter=displayName eq '$AppName'&`$select=id,appId,keyCredentials").value)
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
        $current = @($app.keyCredentials | Where-Object { $_.displayName -like "*$thumbprint" })
        if ($current.Count -eq 0) {
            $old = @($app.keyCredentials).Count
            Invoke-Graph PATCH "applications/$($app.id)" @{ keyCredentials = @($keyCredential) } | Out-Null
            Done "uploaded the certificate (replaces $old old one(s))"
        }
        else {
            Done "exists, client ID $($app.appId); certificate already uploaded"
        }
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
            Invoke-Graph POST "servicePrincipals/$spId/appRoleAssignments" @{
                principalId = $spId; resourceId = $graphSp.id; appRoleId = $roleIds[$name]
            }
        } | Out-Null
        Done "$name granted"
    }
    foreach ($extra in $assigned | Where-Object { -not ($_.resourceId -eq $graphSp.id -and @($roleIds.Values) -contains $_.appRoleId) }) {
        $label = ($graphSp.appRoles | Where-Object { $_.id -eq $extra.appRoleId } | Select-Object -First 1).value
        if (-not $label) { $label = "$($extra.resourceDisplayName) role $($extra.appRoleId)" }
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

    Step "Files.SelectedOperations.Selected: read on alice's OneDrive RestoreTarget folder"
    $folder = "drives/$OneDriveDriveId/items/$OneDriveTargetFolderId"
    try { $folderPerms = @((Invoke-Graph GET "$folder/permissions").value) }
    catch {
        throw "Can't read the permissions of alice's RestoreTarget folder as $AdminUpn ($($_.Exception.Message)). " +
              "Make $AdminUpn a site collection admin of alice's OneDrive first (lab/README.md, 'RestoreProof Worker app'), then run this script again."
    }
    $mine = @($folderPerms | Where-Object {
            @($_['grantedToV2'], $_['grantedTo']) | Where-Object { $_ -and $_['application'] -and $_['application'].id -eq $appId }
        })
    if ($mine.Count -eq 0) {
        Invoke-Graph POST "$folder/permissions" @{
            roles       = @('read')
            grantedToV2 = @{ application = @{ id = $appId } }
        } | Out-Null
        Done 'granted'
    }
    elseif ((@($mine[0].roles) -join ',') -ne 'read') {
        Invoke-Graph PATCH "$folder/permissions/$($mine[0].id)" @{ roles = @('read') } | Out-Null
        Done "changed roles from '$(@($mine[0].roles) -join ',')' to 'read'"
    }
    else { Done 'already granted' }
}
finally {
    Disconnect-MgGraph | Out-Null
}

# ---- 4. Exchange Online RBAC for Applications -------------------------------------------------------
Step "Exchange Online: '$MailRoleName' on $RestoreTestUpn only (sign in as $AdminUpn)"
# Import-Module takes the highest version. Veeam Backup for Microsoft 365 ships its own copy,
# which Install-Module counts as installed but PowerShell 7 can't load.
try { Import-Module ExchangeOnlineManagement -MinimumVersion 3.2.0 }
catch {
    throw "Can't load the ExchangeOnlineManagement module ($($_.Exception.Message)). Install your own copy: " +
          "Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force (-Force installs it next to Veeam's bundled one), then run this script again."
}
Connect-ExchangeOnline -UserPrincipalName $AdminUpn -ShowBanner:$false
try {
    if (-not (Get-ServicePrincipal -Identity $appId -ErrorAction SilentlyContinue)) {
        New-ServicePrincipal -AppId $appId -ObjectId $spId -DisplayName $AppName | Out-Null
        Done 'service principal pointer created'
    }
    else { Done 'service principal pointer exists' }

    $filter = "PrimarySmtpAddress -eq '$RestoreTestUpn'"
    $scope = Get-ManagementScope -Identity $MailScopeName -ErrorAction SilentlyContinue
    if (-not $scope) {
        New-ManagementScope -Name $MailScopeName -RecipientRestrictionFilter $filter | Out-Null
        Done "management scope '$MailScopeName' created"
    }
    elseif ($scope.RecipientFilter -ne $filter) {
        Set-ManagementScope -Identity $MailScopeName -RecipientRestrictionFilter $filter
        Done "management scope filter reset to: $filter"
    }
    else { Done "management scope '$MailScopeName' exists" }

    # Every assignment held by this app (the lab has few, so list them all).
    $mineRoles = @(Get-ManagementRoleAssignment -ResultSize Unlimited |
            Where-Object { $_.Name -eq $MailAssignmentName -or ("$($_.RoleAssigneeType)" -eq 'ServicePrincipal' -and @($spId, $appId, $AppName) -contains "$($_.RoleAssigneeName)") })
    if (-not ($mineRoles | Where-Object Name -eq $MailAssignmentName)) {
        New-ManagementRoleAssignment -Name $MailAssignmentName -App $spId -Role $MailRoleName -CustomResourceScope $MailScopeName | Out-Null
        Done "role assignment '$MailAssignmentName' created"
    }
    else { Done "role assignment '$MailAssignmentName' exists" }
    foreach ($extra in $mineRoles | Where-Object Name -ne $MailAssignmentName) {
        Remove-ManagementRoleAssignment -Identity $extra.Identity -Confirm:$false
        Done "removed role assignment '$($extra.Name)' ($($extra.Role)): not needed"
    }

    Done 'Test-ServicePrincipalAuthorization (bypasses the 30 min to 2 h permission cache):'
    foreach ($mailbox in @($RestoreTestUpn, $AliceUpn)) {
        Test-ServicePrincipalAuthorization -Identity $appId -Resource $mailbox |
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
Done 'Mail access can take 30 minutes to 2 hours to apply. Then, from lab\:'
Done "  uv run python -m seeder check-worker-app --client-id $appId"

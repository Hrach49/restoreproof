# W7.0 (#189): makes the lab tenant one that "has never seen RestoreProof" for the live Done-when
# (docs/decisions.md 2026-10-16, "W7.0 (#189)", point 11 (A)). LAB ONLY, run by the owner, once,
# from PowerShell 7 as the lab's global admin, after tools\tenant-setup\tests\record\
# Record-TenantAnswers.ps1 has recorded the tenant as it is. It deletes, so it shows what it will
# remove and asks for "remove" typed at the console first (-WhatIf: show and stop).
#
#   pwsh -File docs\api\veeam-lab\w7.0-harness\w70-teardown.ps1 -WhatIf
#   pwsh -File docs\api\veeam-lab\w7.0-harness\w70-teardown.ps1 | Tee-Object $env:LOCALAPPDATA\RestoreProof\lab\w7.0-teardown.txt
#
# The IDs are the lab profile's (%LOCALAPPDATA%\RestoreProof\lab\lab-profile.json, which
# w70-live.ps1 writes from the setup script's profile; -ProfileFile another), since every setup run
# on a torn-down lab makes new ones. It removes, each found by those IDs and checked by name first:
#   - the Exchange role assignment and management scope of the Worker app (by their names), and
#     its Exchange service principal pointer;
#   - the Worker app's grants on the RestoreTest site (by the app's ID);
#   - the RestoreTarget library (the list of the profile's library drive, named RestoreTarget,
#     empty) and alice's /RestoreTarget folder (the profile's item, named RestoreTarget, directly
#     under her root, empty): their own grants go with them;
#   - the app registration "RestoreProof Worker" (the profile's client ID), then permanently
#     from the directory's deleted items, with its service principal and its consents.
# It never touches the canary library, alice's /RestoreTest folder, the restoretest user, any
# other app, user, site or list, and it stops at the first item that isn't what its ID says.
# The Worker's certificate stays in the vault: the setup script uploads it again.
#Requires -Version 7.4
[CmdletBinding()]
param([switch]$WhatIf, [string]$ProfileFile = (Join-Path $env:LOCALAPPDATA 'RestoreProof\lab\lab-profile.json'))

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---- the lab (lab/tenant.md), and the IDs of its current setup (the lab profile) -----------------
$TenantId = 'bcd6bd1a-ea42-489d-aa28-2c19a44ad146'
$AdminUpn = 'HrachyaHarutyunyan@RestoreProofLab.onmicrosoft.com'
$SiteId = 'restoreprooflab.sharepoint.com,fe08085d-eb70-42e8-95a6-470189bd98eb,4ecaf399-cc0e-4d95-b3fe-cd091a09e689'
$OneDriveDriveId = 'b!wA9gbfhlEUitGAluxbfoNBr_z5gEtDhErm5pJ6bMwyXfZJ8a_dkCQ696RX0r7_U3'
$labProfile = Get-Content -LiteralPath $ProfileFile -Raw | ConvertFrom-Json -AsHashtable
if ($labProfile['graph_tenant_id'] -ne $TenantId -or $labProfile['test_site_id'] -ne $SiteId -or $labProfile['test_onedrive_drive_id'] -ne $OneDriveDriveId) {
    throw "$ProfileFile is not a profile of the lab's tenant, site and OneDrive"
}
$WorkerAppId = "$($labProfile['graph_client_id'])"
$LibraryDriveId = "$($labProfile['test_library_id'])"
$OneDriveTargetFolderId = "$($labProfile['test_onedrive_folder_id'])"
$MailScopeName = 'RestoreProof Worker - restoretest mailbox'
$MailAssignmentName = 'RestoreProof Worker - Application Mail.ReadWrite - restoretest'
$Name = 'RestoreTarget'
$GraphBase = 'https://graph.microsoft.com/v1.0/'

function Say([string]$Text) { Write-Host $Text }
function Get-Graph([string]$Path) { Invoke-MgGraphRequest -Method GET -Uri ($GraphBase + $Path) -OutputType HashTable }
function Remove-Graph([string]$Path) { Invoke-MgGraphRequest -Method DELETE -Uri ($GraphBase + $Path) -OutputType HashTable | Out-Null }

Say "W7.0 teardown of the lab tenant, $([DateTime]::UtcNow.ToString('s'))Z"
Connect-MgGraph -TenantId $TenantId -NoWelcome -ContextScope Process -Scopes 'Application.ReadWrite.All', 'Sites.FullControl.All', 'Files.ReadWrite.All'
if ("$((Get-MgContext).Account)" -ne $AdminUpn) { Disconnect-MgGraph | Out-Null; throw "sign in as $AdminUpn" }
Import-Module ExchangeOnlineManagement -MinimumVersion 3.7.2
Connect-ExchangeOnline -UserPrincipalName $AdminUpn -ShowBanner:$false -DisableWAM -ErrorAction Stop
try {
    # ---- what is there, each checked by name before anything goes ---------------------------------
    $apps = @((Get-Graph "applications?`$filter=appId eq '$WorkerAppId'&`$select=id,appId,displayName").value)
    if ($apps.Count -ne 1 -or "$($apps[0].displayName)" -cne 'RestoreProof Worker') { throw "the app $WorkerAppId is not the one RestoreProof Worker app" }
    $app = $apps[0]
    $sp = @((Get-Graph "servicePrincipals?`$filter=appId eq '$WorkerAppId'&`$select=id").value)[0]

    $RestoreTargetListId = "$((Get-Graph "drives/$LibraryDriveId/list?`$select=id").id)"
    $list = Get-Graph "sites/$SiteId/lists/${RestoreTargetListId}?`$select=id,displayName,webUrl"
    if ("$($list.displayName)" -cne $Name -or "$($list.webUrl)".TrimEnd('/') -notmatch '/RestoreTarget$') { throw "the list $RestoreTargetListId is not the $Name library" }
    $libraryRoot = Get-Graph "sites/$SiteId/lists/$RestoreTargetListId/drive/root?`$select=folder"
    if ([int]$libraryRoot.folder.childCount -ne 0) { throw "the $Name library is not empty: empty it first (rpworker graph list)" }

    $folder = Get-Graph "drives/$OneDriveDriveId/items/${OneDriveTargetFolderId}?`$select=id,name,folder,parentReference"
    if ("$($folder.name)" -cne $Name -or -not $folder.folder -or @('/drive/root:', "/drives/$OneDriveDriveId/root:") -cnotcontains "$($folder.parentReference.path)") {
        throw "the item $OneDriveTargetFolderId is not alice's /$Name folder"
    }
    if ([int]$folder.folder.childCount -ne 0) { throw "alice's /$Name folder is not empty: empty it first (rpworker graph list)" }

    $siteGrants = @((Get-Graph "sites/$SiteId/permissions").value | Where-Object {
            (ConvertTo-Json $_ -Depth 10 -Compress).IndexOf($WorkerAppId, [StringComparison]::OrdinalIgnoreCase) -ge 0 })
    $assignment = Get-ManagementRoleAssignment -Identity $MailAssignmentName -ErrorAction SilentlyContinue
    $scope = Get-ManagementScope -Identity $MailScopeName -ErrorAction SilentlyContinue
    $pointer = Get-ServicePrincipal -Identity $WorkerAppId -ErrorAction SilentlyContinue

    Say 'to remove:'
    Say "  Exchange role assignment '$MailAssignmentName': $([bool]$assignment)"
    Say "  Exchange management scope '$MailScopeName': $([bool]$scope)"
    Say "  Exchange service principal pointer of $WorkerAppId`: $([bool]$pointer)"
    Say "  the Worker app's grants on the RestoreTest site: $($siteGrants.Count)"
    Say "  the $Name library (list $RestoreTargetListId), empty"
    Say "  alice's /$Name folder (item $OneDriveTargetFolderId), empty"
    Say "  the app registration RestoreProof Worker ($WorkerAppId), its service principal $($sp.id), permanently"
    if ($WhatIf) { Say 'WhatIf: nothing was removed'; return }
    if ((Read-Host 'type remove to remove them') -cne 'remove') { Say 'nothing was removed'; return }

    # ---- removed, Exchange first (its pointer names the app) ------------------------------------
    if ($assignment) { Remove-ManagementRoleAssignment -Identity $MailAssignmentName -Confirm:$false -ErrorAction Stop; Say "removed the role assignment" }
    if ($scope) { Remove-ManagementScope -Identity $MailScopeName -Confirm:$false -ErrorAction Stop; Say 'removed the management scope' }
    if ($pointer) { Remove-ServicePrincipal -Identity $WorkerAppId -Confirm:$false -ErrorAction Stop; Say 'removed the Exchange service principal pointer' }
    foreach ($grant in $siteGrants) { Remove-Graph "sites/$SiteId/permissions/$([Uri]::EscapeDataString("$($grant.id)"))"; Say "removed the site grant $($grant.id)" }
    Remove-Graph "sites/$SiteId/lists/$RestoreTargetListId"; Say "removed the $Name library"
    Remove-Graph "drives/$OneDriveDriveId/items/$OneDriveTargetFolderId"; Say "removed alice's /$Name folder"
    Remove-Graph "applications/$($app.id)"; Say 'removed the app registration'
    Remove-Graph "directory/deletedItems/$($app.id)"; Say 'removed it from the deleted items'
    Say 'teardown: done. Before the setup script: delete the RestoreTarget library from the RestoreTest site''s recycle bin, both stages,'
    Say 'so its address /RestoreTarget is free again (a library in the recycle bin keeps it).'
}
finally {
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}

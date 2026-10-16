<#
.SYNOPSIS
    Read-only: proves from the grants themselves that the RestoreProof Worker app can't write at a
    canary (W3.4), and that it holds its write grants on the two file restore targets.

.DESCRIPTION
    No write probe can prove a refusal at a canary without risking a real write: live on
    2026-10-02, a PATCH with a made-up If-Match got 412 (the ETag is checked before write
    permission) and a folder create with an invalid name got 400 at both canary locations, alice's
    RestoreTest folder included, which the app can't even read (Graph checks the name before any
    permission). So the proof is the grant listing: in Microsoft's selected-permissions model an
    app reaches a site, list, folder or file only through an application grant on it or on a
    parent it inherits from (https://learn.microsoft.com/graph/permissions-selected-overview, "How
    access is calculated"). docs/decisions.md 2026-10-02, W3.4 build notes, points 13 and 14.

    That is half the proof. The other half is the app's tenant-wide roles: an application role
    such as Sites.ReadWrite.All or Files.ReadWrite.All would reach every canary without any grant
    listed here. check-worker-app checks those (its token-roles row: only the three *.Selected
    roles, no SharePoint or Exchange role); this script doesn't, and says so on its second line.

    It sends GETs only, as the lab's global admin with the one delegated scope that can read
    grants, Sites.FullControl.All, and signs out again. The Worker app is matched by its client
    ID ($WorkerAppId), never by its name (Graph printed an empty name on a list grant), and fail
    closed: a permission that names that ID anywhere (a SharePoint-side grant can show the app as
    a siteUser with the ID in its login name, and no application facet) is the Worker app's.
    Every parent of each canary is read, up to the site. Checked:

      RestoreTest site                the Worker app has exactly one grant, roles exactly 'read'
      canary library (list)           no Worker app grant; an inherited one only with roles 'read'
      canary library root folder      the same (the library canaries sit in the library's root)
      the 10 library canary files     the same
      alice's OneDrive site           no Worker app grant at all
      alice's OneDrive Documents list no Worker app grant at all
      alice's OneDrive root           no Worker app grant at all
      alice's RestoreTest folder      no Worker app grant at all
      the 10 OneDrive canary files    no Worker app grant at all
      RestoreTarget list              exactly one non-inherited Worker app grant, roles exactly 'write'
      alice's RestoreTarget folder    the same

    alice's OneDrive site is found by its URL and her Documents list through her drive, read-only;
    the site's drive must be her OneDrive drive, or neither is checked and that is a problem.

    The canary files come from lab/seed-manifest.json; fewer than 20, a manifest that can't be read,
    or a canary file outside its canary drive, list or folder, and it refuses to run. Any other
    application's grant is printed as a note. A failed GET, or a reply without a permission list,
    is a problem, never a pass. It prints one line per location and then "canary grants: ok" (exit 0)
    or "canary grants: N problem(s)" (exit 1). Nothing it prints is secret.

    new-worker-app.ps1 runs it at its end with -UseCurrentSession, in its own Graph session.
    Reading alice's OneDrive needs the admin to be a site collection admin of it (lab/README.md,
    "RestoreProof Worker app", step 2).

.EXAMPLE
    pwsh -NoProfile -File lab\entra\check-worker-grants.ps1 | Tee-Object docs\security\w3.4-worker-grants-check.txt
#>
#Requires -Version 7.2
[CmdletBinding()]
param(
    # new-worker-app.ps1: use its Graph session (signed in as the admin) and leave it open.
    [switch]$UseCurrentSession,
    # The Worker app's client ID, if not $WorkerAppId (new-worker-app.ps1 passes the one it set up).
    [string]$AppId = '',
    [string]$ManifestPath = (Join-Path $PSScriptRoot '..\seed-manifest.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---- the lab (lab/tenant.md; lab/tests/test_entra_script.py pins these to seeder/tenant.py) ------
$TenantId = 'bcd6bd1a-ea42-489d-aa28-2c19a44ad146'
$AdminUpn = 'HrachyaHarutyunyan@RestoreProofLab.onmicrosoft.com'
$WorkerAppId = 'de8d4348-08a9-48ee-a04a-47c7189c5006'
$SiteId = 'restoreprooflab.sharepoint.com,fe08085d-eb70-42e8-95a6-470189bd98eb,4ecaf399-cc0e-4d95-b3fe-cd091a09e689'
$CanaryListId = '7eb0f08a-f57b-418c-8ca6-f2ab81297666'
$CanaryLibraryDriveId = 'b!XQgI_nDr6EKVpkcBib2Y65nzyk4OzJVNs_7NCRoJ5omK8LB-e_WMQYym8quBKXZm'
$OneDriveDriveId = 'b!wA9gbfhlEUitGAluxbfoNBr_z5gEtDhErm5pJ6bMwyXfZJ8a_dkCQ696RX0r7_U3'
$CanaryFolderId = '01ZK75LGF7FPAIWTU5MFGIMX6YUFEV7ZC4'
$OneDriveTargetFolderId = '01ZK75LGEIWSMV5NCPERHJYGWANJI7YUFB'
$RestoreTargetListId = '29dfd30b-9223-49fc-ab87-a205a757f896'
$OneDriveHost = 'restoreprooflab-my.sharepoint.com'
$AliceSitePath = '/personal/alice_restoreprooflab_onmicrosoft_com'
$CanaryLibraryFolderPath = '/'

$GraphBase = 'https://graph.microsoft.com/v1.0/'
$MinCanaryFiles = 20
$MaxPages = 100
$GuidPattern = '[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}'

# ---- the pure part: what a permission list means (lab/tests/test_entra_script.py) ----------------

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
    if (@(Get-GrantedApps $Permission | Where-Object { $_.Id -eq $AppId }).Count -gt 0) { return $true }
    $json = ConvertTo-Json -InputObject $Permission -Depth 20 -Compress -WarningAction SilentlyContinue
    return "$json".IndexOf($AppId, [StringComparison]::OrdinalIgnoreCase) -ge 0
}

# Other applications a permission names only in SharePoint's form (a claim login name).
function Get-SharePointFormApps($Permission) {
    $json = ConvertTo-Json -InputObject $Permission -Depth 20 -Compress -WarningAction SilentlyContinue
    foreach ($match in [regex]::Matches("$json", "\|ms\.sp\.ext\|($GuidPattern)@")) { $match.Groups[1].Value }
}

function Get-RoleText($Permission) { (@(Get-Field $Permission 'roles' | Where-Object { $_ }) | Sort-Object) -join ',' }

function Test-Inherited($Permission) { $null -ne (Get-Field $Permission 'inheritedFrom') }

# What one location's permissions mean for the Worker app. Rule:
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

# The 20 canary files of lab/seed-manifest.json, each @{ Kind; Name; DriveId; ItemId }. Throws,
# naming what is wrong, unless there are at least 20 and each sits where this script reads its
# parents: a library file in the canary list's root folder, a OneDrive file in alice's canary folder.
function Read-CanaryFiles([string]$Path) {
    try { $manifest = Get-Content -LiteralPath $Path -Raw -Encoding utf8 | ConvertFrom-Json -AsHashtable }
    catch { throw "the canary manifest $Path can't be read: $($_.Exception.Message)" }
    $entries = Get-Field $manifest 'entries'
    if ($entries -isnot [System.Collections.IList]) { throw "the canary manifest $Path has no entries list" }
    $drives = @{ sharepoint_file = $CanaryLibraryDriveId; onedrive_file = $OneDriveDriveId }
    $files = foreach ($entry in $entries) {
        $kind = "$(Get-Field $entry 'kind')"
        if (@('sharepoint_file', 'onedrive_file') -cnotcontains $kind) { continue }
        $name = "$(Get-Field $entry 'name')"
        $driveId = "$(Get-Field (Get-Field $entry 'location') 'drive_id')"
        $itemId = "$(Get-Field $entry 'drive_item_id')"
        $location = Get-Field $entry 'location'
        if ($driveId -cne $drives[$kind]) { throw "the canary manifest's $kind '$name' is not in its canary drive" }
        if ($kind -ceq 'sharepoint_file' -and ("$(Get-Field $location 'list_id')" -cne $CanaryListId -or
                "$(Get-Field $location 'folder_path')" -cne $CanaryLibraryFolderPath)) {
            throw "the canary manifest's $kind '$name' is not in the canary library's root folder"
        }
        if ($kind -ceq 'onedrive_file' -and "$(Get-Field $location 'folder_id')" -cne $CanaryFolderId) {
            throw "the canary manifest's $kind '$name' is not in alice's canary folder"
        }
        if ($itemId -cnotmatch '^[A-Za-z0-9!_=-]{1,512}$') { throw "the canary manifest's $kind '$name' has no usable drive_item_id" }
        [pscustomobject]@{ Kind = $kind; Name = $name; DriveId = $driveId; ItemId = $itemId }
    }
    $files = @($files)
    if ($files.Count -lt $MinCanaryFiles) {
        throw "the canary manifest $Path lists $($files.Count) canary file(s), not $MinCanaryFiles"
    }
    $files
}

# Every location checked, in order: Label, the permissions Path (relative to Graph v1.0), Rule.
# alice's site and list are left out when they couldn't be resolved (that is a problem of its own).
function Get-GrantLocations([object[]]$CanaryFiles, [string]$AliceSiteId, [string]$AliceListId) {
    $location = { param($Label, $Path, $Rule) [pscustomobject]@{ Label = $Label; Path = $Path; Rule = $Rule } }
    & $location 'RestoreTest site' "sites/$SiteId/permissions" 'site-read'
    & $location 'canary library RestoreTest (list)' "sites/$SiteId/lists/$CanaryListId/permissions" 'inherited-read-only'
    & $location 'canary library root folder' "drives/$CanaryLibraryDriveId/root/permissions" 'inherited-read-only'
    if ($AliceSiteId -and $AliceListId) {
        & $location "alice's OneDrive site" "sites/$AliceSiteId/permissions" 'none'
        & $location "alice's OneDrive Documents list" "sites/$AliceSiteId/lists/$AliceListId/permissions" 'none'
    }
    & $location "alice's OneDrive root" "drives/$OneDriveDriveId/root/permissions" 'none'
    & $location "alice's RestoreTest canary folder" "drives/$OneDriveDriveId/items/$CanaryFolderId/permissions" 'none'
    foreach ($file in $CanaryFiles) {
        $library = $file.Kind -ceq 'sharepoint_file'
        $where = if ($library) { 'library' } else { 'OneDrive' }
        $rule = if ($library) { 'inherited-read-only' } else { 'none' }
        & $location "canary file $($file.Name) ($where)" "drives/$($file.DriveId)/items/$($file.ItemId)/permissions" $rule
    }
    & $location 'RestoreTarget list' "sites/$SiteId/lists/$RestoreTargetListId/permissions" 'target-write'
    & $location "alice's RestoreTarget folder" "drives/$OneDriveDriveId/items/$OneDriveTargetFolderId/permissions" 'target-write'
}

# ---- reading (GET only) ---------------------------------------------------------------------------

function Invoke-GraphGet([string]$Uri) {
    if (-not $Uri.StartsWith($GraphBase, [StringComparison]::Ordinal)) { $Uri = $GraphBase + $Uri }
    Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType HashTable
}

# Every permission at Path, following @odata.nextLink (only ever within Graph v1.0).
function Get-AllPermissions([string]$Path) {
    $all = [System.Collections.Generic.List[object]]::new()
    $next = $Path
    for ($page = 1; $next; $page++) {
        if ($page -gt $MaxPages) { throw "more than $MaxPages pages of permissions" }
        $reply = Invoke-GraphGet $next
        # Never pass on a reply of an unexpected shape: it must hold a 'value' list (empty is fine).
        $value = $null
        if ($reply -is [System.Collections.IDictionary]) { if ($reply.Contains('value')) { $value = $reply['value'] } }
        elseif ($null -ne $reply -and $reply.PSObject.Properties['value']) { $value = $reply.PSObject.Properties['value'].Value }
        if ($value -isnot [System.Collections.IList]) { throw "a reply without a permission list ('value')" }
        foreach ($permission in $value) { if ($null -ne $permission) { $all.Add($permission) } }
        $next = "$(Get-Field $reply '@odata.nextLink')"
        if ($next -and -not $next.StartsWith($GraphBase, [StringComparison]::Ordinal)) {
            throw 'a next page outside Microsoft Graph v1.0'
        }
    }
    @($all)
}

# alice's OneDrive site ID and her Documents list's ID, read-only: the site by its URL, checked to
# hold her OneDrive drive, and the list through that drive. Throws, naming what is wrong.
function Resolve-AliceSiteAndList {
    $site = Invoke-GraphGet "sites/${OneDriveHost}:${AliceSitePath}?`$select=id"
    $siteId = "$(Get-Field $site 'id')"
    if ($siteId -cnotmatch "^$([regex]::Escape($OneDriveHost)),$GuidPattern,$GuidPattern$") {
        throw "alice's OneDrive site has no usable ID"
    }
    $drive = Invoke-GraphGet "sites/$siteId/drive?`$select=id"
    if ("$(Get-Field $drive 'id')" -cne $OneDriveDriveId) { throw "alice's OneDrive site doesn't hold her OneDrive drive" }
    $list = Invoke-GraphGet "drives/$OneDriveDriveId/list?`$select=id"
    $listId = "$(Get-Field $list 'id')"
    if ($listId -cnotmatch "^$GuidPattern$") { throw "alice's OneDrive Documents list has no usable ID" }
    [pscustomobject]@{ SiteId = $siteId; ListId = $listId }
}

# The HTTP status of a failed request, or $null when there was no answer.
function Get-HttpStatus($ErrorRecord) {
    $response = $ErrorRecord.Exception.PSObject.Properties['Response']
    if ($response -and $response.Value) { return [int]$response.Value.StatusCode }
    return $null
}

# Checks every location and prints one line each (then its problems and notes), and the final
# line, to the host (a redirected `pwsh -File` writes it to stdout). Returns only the number of
# problems; never throws for a failed GET or a bad manifest.
function Invoke-GrantCheck([string]$AppId, [string]$ManifestPath) {
    Write-Host "RestoreProof Worker grant check (W3.4): read-only, Worker app $AppId"
    Write-Host ('scope: the app''s grants on the canaries and every parent; its tenant-wide roles are ' +
        'check-worker-app''s token-roles row (only the three *.Selected roles)')
    try { $files = @(Read-CanaryFiles $ManifestPath) }
    catch {
        Write-Host ('{0,-56} {1,-8} {2}' -f 'canary manifest', 'PROBLEM', "$($_.Exception.Message); nothing was read")
        Write-Host 'canary grants: 1 problem(s)'
        return 1
    }
    $problems = 0
    $alice = $null
    try { $alice = Resolve-AliceSiteAndList }
    catch {
        $status = Get-HttpStatus $_
        $why = if ($null -ne $status) { "HTTP $status" } else { $_.Exception.Message }
        $problems++
        Write-Host ('{0,-56} {1,-8} {2}' -f "alice's OneDrive site and list", 'PROBLEM', "can't be resolved ($why); their grants were not read")
    }
    $aliceSiteId = if ($alice) { $alice.SiteId } else { '' }
    $aliceListId = if ($alice) { $alice.ListId } else { '' }
    foreach ($location in Get-GrantLocations $files $aliceSiteId $aliceListId) {
        try {
            $permissions = @(Get-AllPermissions $location.Path)
            if ($location.Rule -ceq 'site-read') {
                # A site's permission list may leave roles out: read each of the Worker app's grants itself.
                $permissions = @(foreach ($p in $permissions) {
                        if ((Test-NamesApp $p $AppId) -and "$(Get-Field $p 'id')") {
                            Invoke-GraphGet "$($location.Path)/$([Uri]::EscapeDataString("$(Get-Field $p 'id')"))"
                        }
                        else { $p }
                    })
            }
            $result = Test-PermissionRule -Permissions $permissions -AppId $AppId -Rule $location.Rule
        }
        catch {
            $status = Get-HttpStatus $_
            $why = if ($null -ne $status) { "HTTP $status" } else { $_.Exception.Message }
            $problems++
            Write-Host ('{0,-56} {1,-8} {2}' -f $location.Label, 'PROBLEM', "the permissions can't be read ($why)")
            continue
        }
        $verdict = if ($result.Problems.Count -eq 0) { 'ok' } else { 'PROBLEM' }
        $counts = "$($result.Total) permission(s), $($result.Worker) Worker app, $($result.Others) other app(s)"
        Write-Host ('{0,-56} {1,-8} {2}' -f $location.Label, $verdict, $counts)
        foreach ($problem in $result.Problems) { Write-Host "    problem: $problem" }
        foreach ($note in $result.Notes) { Write-Host "    note: $note" }
        $problems += $result.Problems.Count
    }
    Write-Host ($problems -eq 0 ? 'canary grants: ok' : "canary grants: $problems problem(s)")
    return $problems
}

# ---- run ------------------------------------------------------------------------------------------
if (-not $AppId) { $AppId = $WorkerAppId }
if (-not $UseCurrentSession) {
    Connect-MgGraph -TenantId $TenantId -NoWelcome -ContextScope Process -Scopes 'Sites.FullControl.All'
}
try {
    $account = (Get-MgContext).Account
    if ($account -ne $AdminUpn) {
        throw "Signed in as '$account', but the grants are read as $AdminUpn. Run it again and pick that account."
    }
    $count = Invoke-GrantCheck -AppId $AppId -ManifestPath $ManifestPath
}
finally {
    if (-not $UseCurrentSession) { Disconnect-MgGraph | Out-Null }
}
exit ($count -eq 0 ? 0 : 1)

# Step 10 (W2.4): restore canary items through the REST API into the restore targets
# (docs/api/veeam-restore-flow.md).
#   pwsh -File 10-restore.ps1 -Type mail|sp|od -Item <manifest id>[,<id>...] [-Tag x1] [-WhatIf] [-SaveEvidence]
# This script WRITES to the test tenant; it is the only one in this collection that does. The targets
# are fixed below and a hand-written guard (until W2.7's TargetGuard) asserts them on the exact body
# before the POST: restoretest's Inbox, the RestoreTarget library, alice's OneDrive /RestoreTarget.
# Never the canary library or folder, never the original location, never overwrite.
# The restore credential is Veeam's own organisation app (docs/decisions.md, W2.4): its certificate is
# exported from Cert:\LocalMachine\My in memory (X509Certificate2.Export) under a random one-time
# password; no file is written (W4.12; before it, a temporary PFX in %TEMP%, deleted at once). The
# private key must be readable by the account running the script: an administrator, LocalSystem, or
# an account with read access to the key file (W4.12, docs/decisions.md 2026-10-07).
# -WhatIf sends no restore POST and exports nothing: it still signs in, opens (and stops) an explore
# session, browses, builds the body and runs the guard. It saves no evidence and exits 0 if the guard passed.
# Exit codes: 0 Veeam says restored (or -WhatIf: guard passed); 1 restore finished, not a success;
# 2 refused before any POST (guard, preflight, resolve, or a 4xx on the POST: nothing started);
# 3 no verdict (timeout, POST without an answer, a duplicate check that doesn't confirm exactly the
# returned session, statistics or events unreadable or of an unexpected shape); 64 usage (also: the
# certificate's private key can't be opened, without -WhatIf). PowerShell's own parameter-binding
# errors exit 1 before the script runs.
# A restore that may still be running when the script gives up (exit 3 after the POST) is left alone,
# and so is the explore session it came from: see the message it prints.
[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Mandatory)][ValidateSet('mail', 'sp', 'od')][string]$Type,
    [Parameter(Mandatory)][string[]]$Item,
    [string]$Tag,
    [ValidateRange(1, 45)][int]$TimeoutMinutes = 20,   # below the access token's 3600 s: nothing refreshes it
    [switch]$WhatIf,
    [switch]$SaveEvidence
)
. "$PSScriptRoot\VeeamLab.ps1"
if ($WhatIf) { $SaveEvidence = $false }

# The restore targets (lab/tenant.md, "Restore targets"). The ONLY places this script restores to.
$TargetMailbox        = 'restoretest@RestoreProofLab.onmicrosoft.com'
$TargetMailFolder     = 'Inbox'
$TargetSiteUrl        = 'https://restoreprooflab.sharepoint.com/sites/RestoreTest'
$TargetLibrary        = 'RestoreTarget'   # display name of list ffec069d-65e4-4c3a-9da2-ac086cf9dafa
$TargetOneDriveUrl    = 'https://restoreprooflab-my.sharepoint.com/personal/alice_restoreprooflab_onmicrosoft_com'
$TargetOneDriveFolder = 'RestoreTarget'   # alice's /RestoreTarget, item 01ZK75LGDGB6QOO3MGNFGYOY6C6VBDG5OH
# The canary SOURCES (never a target) and names a target must never take.
$CanaryListId   = '7eb0f08a-f57b-418c-8ca6-f2ab81297666'   # RestoreTest library
$TargetListId   = 'ffec069d-65e4-4c3a-9da2-ac086cf9dafa'   # RestoreTarget library: never a source (it is in the backup too)
$CanaryOdFolder = 'RestoreTest'                            # alice's /RestoreTest
$Forbidden      = @('RestoreTest', 'Documents', 'Shared Documents')
# Veeam's organisation app (docs/environment.md), cross-checked against GET /v8/Organizations.
$VeeamAppId    = '1fd2609d-1242-43fe-94b5-d58688a90bd6'
$VeeamAppThumb = 'AC3220B58A2B4C438DA13816C2DD1E25D1F783A7'
$Manifest      = Join-Path $PSScriptRoot '..\..\..\lab\seed-manifest.json'
$RestoreLogDir = 'C:\ProgramData\Veeam\Backup365\Logs\RestoreREST'

# Exact top-level key sets of the three bodies (docs/api/veeam-feasibility.md §2c). Nothing else may be sent.
$ExpectedKeys = @{
    mail = 'mailbox', 'folder', 'items', 'changedItems', 'deletedItems', 'markRestoredAsUnread', 'excludeDrafts',
           'excludeDeletedItems', 'excludeInPlaceHoldItems', 'excludeLitigationHoldItems', 'officeRegion',
           'officeOrganizationName', 'applicationId', 'applicationCertificate', 'applicationCertificatePassword',
           'impersonationAccountName'
    sp   = 'documents', 'siteURL', 'list', 'sendSharedLinksNotification', 'documentVersion', 'documentLastVersionAction',
           'officeRegion', 'organizationName', 'applicationId', 'applicationCertificate', 'applicationCertificatePassword'
    od   = 'documents', 'onedrive', 'folder', 'changedItems', 'deletedItems', 'documentVersion', 'documentLastVersionAction',
           'officeRegion', 'organizationName', 'applicationId', 'applicationCertificate', 'applicationCertificatePassword'
}
$SessionType = @{ mail = 'Vex'; sp = 'Vesp'; od = 'Veod' }[$Type]

$JsonOpts = [System.Text.Json.JsonSerializerOptions]::new()
$JsonOpts.Encoder = [System.Text.Encodings.Web.JavaScriptEncoder]::UnsafeRelaxedJsonEscaping

function Refuse([string]$Why) { throw [System.InvalidOperationException]::new("REFUSED: $Why") }
function Get-Node($r) { , [System.Text.Json.Nodes.JsonNode]::Parse($r.Body) }
function Get-Results($r) { @((Get-Node $r)['results'].AsArray()) }
function Esc([string]$s) { [uri]::EscapeDataString($s) }
function Get-Keys($obj) { @($obj.AsObject() | ForEach-Object Key) }
function Step($r, [string]$What, [string]$Note) {
    Show-Call $r | Out-Host
    if ($What) { Save-Evidence "w2.4-$Type-$Tag-$What" $r $Note | Out-Host }
    if ($r.Status -ge 400) { Refuse "$What answered $($r.Status)" }
}
# A field the verdict reads must be there and of the expected JSON kind (String, Number or Array);
# anything else is no verdict (exit 3), never "NOT restored". An Array is returned unrolled: wrap in @().
function Field($Node, [string]$Key, [string]$Kind, [string]$What) {
    $v = $null   # not "$v = if ...": an if statement's output would unroll a JsonArray
    if ($Node -is [System.Text.Json.Nodes.JsonObject]) { $v = $Node[$Key] }
    if ($Kind -eq 'Array') {
        if ($v -isnot [System.Text.Json.Nodes.JsonArray]) { throw "$What has no '$Key' array: no verdict" }
        return $v
    }
    if ($v -isnot [System.Text.Json.Nodes.JsonValue] -or $v.GetValueKind() -ne $Kind) { throw "$What has no '$Key' ($Kind): no verdict" }
    if ($Kind -eq 'Number') { $v.GetValue[long]() } else { $v.GetValue[string]() }
}
function Format-Utc([datetime]$t) { $t.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) }

# ---- The hand-written target guard (W2.7 replaces it). Parses the exact text that will be sent. ----
# Every comparison is ordinal: PowerShell's -ceq/-cne/-in compare by culture, which ignores characters
# such as U+00AD, so 'Restore<soft hyphen>Target' -ceq 'RestoreTarget' is true.
$GuidRx = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
function Same([string]$a, [string]$b) { [string]::Equals($a, $b, [StringComparison]::Ordinal) }
function In([string]$s, $list) { [Array]::IndexOf([string[]]@($list), $s) -ge 0 }   # Array.IndexOf: ordinal
function InIgnoreCase([string]$s, $list) { @($list | Where-Object { [string]::Equals($_, $s, [StringComparison]::OrdinalIgnoreCase) }).Count -gt 0 }
# JsonNode.Parse accepts a duplicate key and throws only when that object is first read, so every
# object of the body is enumerated here, once, and a duplicate becomes a guard refusal.
function Assert-NoDuplicateKeys($n) {
    if ($n -is [System.Text.Json.Nodes.JsonObject]) {
        try { $kids = @($n | ForEach-Object Value) } catch { throw 'GUARD: the body has a duplicate key' }
        foreach ($k in $kids) { Assert-NoDuplicateKeys $k }
    } elseif ($n -is [System.Text.Json.Nodes.JsonArray]) { foreach ($k in $n) { Assert-NoDuplicateKeys $k } }
}
function Join-Sorted($list) { [string[]]$a = @($list); [Array]::Sort($a, [StringComparer]::Ordinal); $a -join "`n" }
# A value the guard checks must be a JSON string of printable ASCII (a [string] cast would join an array).
function Str($n, [string]$What) {
    if ($n -isnot [System.Text.Json.Nodes.JsonValue] -or $n.GetValueKind() -ne [System.Text.Json.JsonValueKind]::String) { throw "GUARD: $What is not a JSON string" }
    $s = $n.GetValue[string]()
    if ($s -cnotmatch '^[\x20-\x7E]*\z') { throw "GUARD: $What has a character outside printable ASCII" }
    $s
}
function Bool($n, [string]$What) {
    if ($n -isnot [System.Text.Json.Nodes.JsonValue] -or $n.GetValueKind() -notin 'True', 'False') { throw "GUARD: $What is not a JSON boolean" }
    $n.GetValue[bool]()
}
function Assert-RestoreTarget([string]$Path, [string]$Text, $Ctx) {
    $b = [System.Text.Json.Nodes.JsonNode]::Parse($Text).AsObject()
    Assert-NoDuplicateKeys $b
    if ($Ctx.ExploreId -cnotmatch "^$GuidRx\z" -or -not (In $Ctx.ExploreId $script:Opened)) { throw 'GUARD: the explore session is not one this run opened' }
    if ($Ctx.ContainerId -cnotmatch "^(?:$GuidRx)+\z") { throw 'GUARD: the container id is not GUIDs' }
    $u = [uri]"https://veeam.invalid$Path"
    if ($u.Query -or $u.Fragment -or -not (Same $u.AbsolutePath $Path)) { throw 'GUARD: the path has a query, fragment or dot segment' }
    $want = switch ($Type) {
        'mail' { "/v8/RestoreSessions/$($Ctx.ExploreId)/organization/mailboxes/$($Ctx.ContainerId)/items/restoreTo" }
        'sp'   { "/v8/RestoreSessions/$($Ctx.ExploreId)/Organization/Sites/$($Ctx.ContainerId)/Documents/restoreTo" }
        'od'   { "/v8/RestoreSessions/$($Ctx.ExploreId)/Organization/OneDrives/$($Ctx.ContainerId)/Documents/copyTo" }
    }
    if (-not (Same $Path $want)) { throw "GUARD: path $(Format-PathTemplate $Path) is not the $Type restore-to-another-location call" }
    if (-not (Same (Join-Sorted (Get-Keys $b)) (Join-Sorted $ExpectedKeys[$Type]))) { throw "GUARD: body keys [$((Get-Keys $b) -join ',')] are not the $Type set" }
    if (-not (Same (Str $b['officeRegion'] 'officeRegion') 'Worldwide')) { throw 'GUARD: officeRegion' }
    if (-not (Same (Str $b['applicationId'] 'applicationId') $VeeamAppId)) { throw "GUARD: applicationId is not Veeam's organisation app" }
    [void](Str $b['applicationCertificate'] 'applicationCertificate'); [void](Str $b['applicationCertificatePassword'] 'applicationCertificatePassword')
    switch ($Type) {
        'mail' {
            if (-not (Same (Str $b['mailbox'] 'mailbox') $TargetMailbox)) { throw "GUARD: mailbox is not $TargetMailbox" }
            if (-not (Same (Str $b['impersonationAccountName'] 'impersonationAccountName') $TargetMailbox)) { throw 'GUARD: impersonationAccountName is not the target mailbox' }
            if (-not (Same (Str $b['folder'] 'folder') $TargetMailFolder)) { throw "GUARD: folder is not $TargetMailFolder" }
            if (-not (Same (Str $b['officeOrganizationName'] 'officeOrganizationName') $LabOrgName)) { throw 'GUARD: officeOrganizationName' }
            foreach ($k in 'changedItems', 'deletedItems', 'markRestoredAsUnread', 'excludeDrafts', 'excludeDeletedItems', 'excludeInPlaceHoldItems', 'excludeLitigationHoldItems') { [void](Bool $b[$k] $k) }
            $list = @($b['items'].AsArray())
            $ids = foreach ($i in $list) {   # per item
                if (-not (Same ((Get-Keys $i) -join ',') 'id')) { throw 'GUARD: a mail item carries more than its id' }
                $id = Str $i['id'] 'items[].id'
                if (-not (In $id $Ctx.ItemIds)) { throw 'GUARD: a mail item is not one of the resolved canaries' }
                $id
            }
        }
        'sp' {
            if (-not (Same (Str $b['siteURL'] 'siteURL') $TargetSiteUrl)) { throw "GUARD: siteURL is not $TargetSiteUrl" }
            $l = Str $b['list'] 'list'
            if (-not (Same $l $TargetLibrary) -or (In $l $Forbidden)) { throw "GUARD: list is not $TargetLibrary" }
            if (-not (Same (Str $b['organizationName'] 'organizationName') $LabOrgName)) { throw 'GUARD: organizationName' }
            if (-not (Same (Str $b['documentLastVersionAction'] 'documentLastVersionAction') 'Merge') -or -not (Same (Str $b['documentVersion'] 'documentVersion') 'Last')) { throw 'GUARD: version options' }
            if (Bool $b['sendSharedLinksNotification'] 'sendSharedLinksNotification') { throw 'GUARD: sendSharedLinksNotification' }
            $list = @($b['documents'].AsArray())
            $ids = foreach ($d in $list) {   # per item
                $id = Str $d['id'] 'documents[].id'; $name = Str $d['name'] 'documents[].name'
                if (-not $id.StartsWith($Ctx.ContainerId + $CanaryListId, [StringComparison]::Ordinal)) { throw "GUARD: $name is not from the canary library" }
                if (-not (Same (Str $d['siteId'] 'documents[].siteId') $Ctx.ContainerId)) { throw 'GUARD: a document of another site' }
                if (-not (In $id $Ctx.ItemIds) -or -not (In $name $Ctx.Names) -or (Bool $d['isFolder'] 'isFolder')) { throw "GUARD: $name is not a resolved canary file" }
                $id
            }
        }
        'od' {
            $od = $b['onedrive'].AsObject()
            if (-not (Same (Join-Sorted (Get-Keys $od)) (Join-Sorted 'id', 'name', 'url'))) { throw 'GUARD: onedrive object keys' }
            if (-not (Same (Str $od['url'] 'onedrive.url') $TargetOneDriveUrl)) { throw "GUARD: onedrive.url is not alice's" }
            if (-not (Same (Str $od['id'] 'onedrive.id') $Ctx.ContainerId)) { throw "GUARD: onedrive.id is not alice's OneDrive in this session" }
            [void](Str $od['name'] 'onedrive.name')
            $f = Str $b['folder'] 'folder'
            if (-not (Same $f $TargetOneDriveFolder) -or (In $f $Forbidden)) { throw "GUARD: folder is not $TargetOneDriveFolder" }
            if (-not (Same (Str $b['organizationName'] 'organizationName') $LabOrgName)) { throw 'GUARD: organizationName' }
            if (-not (Same (Str $b['documentLastVersionAction'] 'documentLastVersionAction') 'Merge') -or -not (Same (Str $b['documentVersion'] 'documentVersion') 'Last')) { throw 'GUARD: version options' }
            foreach ($k in 'changedItems', 'deletedItems') { [void](Bool $b[$k] $k) }
            $list = @($b['documents'].AsArray())
            $ids = foreach ($d in $list) {   # per item
                $id = Str $d['id'] 'documents[].id'; $name = Str $d['name'] 'documents[].name'
                if (-not (Same (Str $d['oneDriveId'] 'documents[].oneDriveId') $Ctx.ContainerId)) { throw 'GUARD: a document of another OneDrive' }
                if (-not (In $id $Ctx.ItemIds) -or -not (In $name $Ctx.Names) -or (Bool $d['isFolder'] 'isFolder')) { throw "GUARD: $name is not a resolved canary file" }
                $id
            }
        }
    }
    # Exactly the resolved set: no duplicate, none missing, none added.
    if (-not (Same (Join-Sorted $ids) (Join-Sorted $Ctx.ItemIds))) { throw "GUARD: the $($list.Count) item(s) in the body are not exactly the $($Ctx.ItemIds.Count) resolved" }
}

# Mutates the real body and path; the guard must refuse every mutation, or the run stops.
function Test-GuardRefuses([string]$Path, [string]$Text, $Ctx) {
    $cases = [ordered]@{
        'wrong site/mailbox/OneDrive' = { param($b) switch ($Type) { 'mail' { $b['mailbox'] = 'alice@RestoreProofLab.onmicrosoft.com' } 'sp' { $b['siteURL'] = 'https://restoreprooflab.sharepoint.com/sites/Other' } 'od' { $b['onedrive']['url'] = 'https://restoreprooflab-my.sharepoint.com/personal/bob_restoreprooflab_onmicrosoft_com' } } }
        'canary library/folder'       = { param($b) switch ($Type) { 'mail' { $b['folder'] = 'Sent Items' } 'sp' { $b['list'] = 'RestoreTest' } 'od' { $b['folder'] = 'RestoreTest' } } }
        'impersonation/case'          = { param($b) switch ($Type) { 'mail' { $b['impersonationAccountName'] = 'alice@RestoreProofLab.onmicrosoft.com' } 'sp' { $b['list'] = 'restoretarget' } 'od' { $b['folder'] = 'restoretarget' } } }
        'extra key'                   = { param($b) $b['restoreToOriginalLocation'] = $true }
        'other app'                   = { param($b) $b['applicationId'] = '00000000-0000-0000-0000-000000000000' }
        'look-alike target'           = { param($b) switch ($Type) { 'mail' { $b['folder'] = "In$([char]0xAD)box" } 'sp' { $b['list'] = "Restore$([char]0xAD)Target" } 'od' { $b['folder'] = "Restore$([char]0xAD)Target" } } }
        # JsonValue.Create: a bare $a.Add($v) binds to the generic Add<T>, whose node can't be serialised
        'array value'                 = { param($b) $k = @{ mail = 'mailbox'; sp = 'siteURL'; od = 'folder' }[$Type]; $v = $b[$k].GetValue[string](); $a = [System.Text.Json.Nodes.JsonArray]::new(); $a.Add([System.Text.Json.Nodes.JsonValue]::Create([string]$v)); $b[$k] = $a }
        'duplicated item'             = { param($b) $a = $b[$(if ($Type -eq 'mail') { 'items' } else { 'documents' })].AsArray(); $c = $a[0].DeepClone(); if ($a.Count -gt 1) { $a.RemoveAt($a.Count - 1) }; $a.Add($c) }
        'extra item'                  = { param($b) $a = $b[$(if ($Type -eq 'mail') { 'items' } else { 'documents' })].AsArray(); $a.Add($a[0].DeepClone()) }
    }
    # A mutation counts as refused only if the guard itself refused it ("GUARD: ..."). Any other
    # exception means the case never reached the guard, and the self-test fails.
    function Test-One([string]$Name, [string]$P, [scriptblock]$MakeText) {
        try { $t = & $MakeText } catch { Refuse "guard self-test: '$Name' could not be built: $($_.Exception.Message)" }
        try { Assert-RestoreTarget $P $t $Ctx } catch {
            if ($_.Exception.Message.StartsWith('GUARD:', [StringComparison]::Ordinal)) { return }
            Refuse "guard self-test: '$Name' failed outside the guard: $($_.Exception.Message)"
        }
        Refuse "guard self-test: '$Name' was accepted"
    }
    foreach ($k in $cases.Keys) {
        Test-One $k $Path { $b = [System.Text.Json.Nodes.JsonNode]::Parse($Text).AsObject(); & $cases[$k] $b; $b.ToJsonString($JsonOpts) }
    }
    $first = @(Get-Keys ([System.Text.Json.Nodes.JsonNode]::Parse($Text)))[0]
    Test-One 'duplicate key' $Path { '{"' + $first + '":"x",' + $Text.Substring(1) }
    Test-One 'original-location path' ($Path -replace '/(restoreTo|copyTo)$', '/restore') { $Text }
    Test-One 'dot-segment path' "$Path/../../restore" { $Text }
    "  guard self-test: $($cases.Count + 3) mutations refused by the guard" | Out-Host
}

# ---- Resolving canaries in the explore session (docs/api/veeam-notes.md §5): list, match exactly, re-read. ----
function Resolve-Mail($base, $entries) {
    $src = @($entries | ForEach-Object { $_.location.mailbox } | Sort-Object -Unique)
    if ($src.Count -ne 1) { Refuse 'mail items of one call must share one source mailbox' }
    if ([string]::Equals([string]$src[0], $TargetMailbox, [StringComparison]::OrdinalIgnoreCase)) { Refuse 'the source mailbox is the target mailbox' }
    $r = Invoke-Veeam -Path "$base/mailboxes?limit=1000"
    Step $r 'mailboxes' 'GET .../organization/mailboxes?limit=1000'
    $mb = @(Get-Results $r | Where-Object { [string]::Equals([string]$_['email'], $src[0], [StringComparison]::OrdinalIgnoreCase) })
    if ($mb.Count -ne 1) { Refuse "source mailbox $($src[0]): $($mb.Count) match(es)" }
    $mbId = [string]$mb[0]['id']
    $r = Invoke-Veeam -Path "$base/mailboxes/$(Esc $mbId)/folders?name=Inbox"
    Step $r 'folder-inbox' 'GET .../organization/mailboxes/{mailboxId}/folders?name=Inbox (the source folder)'
    $f = @(Get-Results $r | Where-Object { (Same ([string]$_['name']) 'Inbox') })
    if ($f.Count -ne 1) { Refuse "source Inbox: $($f.Count) match(es)" }
    $r = Invoke-Veeam -Path "$base/mailboxes/$(Esc $mbId)/items?parentId=$(Esc ([string]$f[0]['id']))&limit=1000"
    Step $r 'items' 'GET .../organization/mailboxes/{mailboxId}/items?parentId={folderId}&limit=1000'
    $all = @(Get-Results $r)
    $ids = foreach ($e in $entries) {
        $hit = @($all | Where-Object { (Same ([string]$_['subject']) $e.subject) })
        if ($hit.Count -ne 1) { Refuse "$($e.id): $($hit.Count) item(s) with that subject" }
        $received = ([DateTimeOffset]::Parse([string]$hit[0]['received'], [Globalization.CultureInfo]::InvariantCulture)).ToString('yyyy-MM-ddTHH:mm:ssZ')
        # ConvertFrom-Json turned the manifest's received_at into a DateTime; compare as UTC text.
        $want = $e.received_at
        if ($want -is [datetime]) { $want = $(if ($want.Kind -eq 'Unspecified') { [datetime]::SpecifyKind($want, 'Utc') } else { $want.ToUniversalTime() }).ToString('yyyy-MM-ddTHH:mm:ssZ') }
        if (-not (Same $received $want)) { Refuse "$($e.id): received $received, manifest $want" }
        $id = [string]$hit[0]['id']
        $r = Invoke-Veeam -Path "$base/mailboxes/$(Esc $mbId)/items/$(Esc $id)"
        Step $r $(if ($e -eq $entries[0]) { 'item' }) 'GET .../organization/mailboxes/{mailboxId}/items/{itemId} (the re-read)'
        if (-not (Same ([string](Get-Node $r)['subject']) $e.subject)) { Refuse "$($e.id): the re-read differs" }
        "  $($e.id): item found, received $received" | Out-Host
        $id
    }
    $items = [System.Text.Json.Nodes.JsonArray]::new()
    foreach ($id in $ids) { $o = [System.Text.Json.Nodes.JsonObject]::new(); $o['id'] = $id; $items.Add($o) }
    [pscustomobject]@{ ContainerId = $mbId; ItemIds = @($ids); Names = @($entries.subject); Array = $items
                       Path = "$base/mailboxes/$mbId/items/restoreTo" }
}

function Resolve-Documents($base, $entries, $containerPath, $parentId, $what) {
    $r = Invoke-Veeam -Path "$containerPath/Documents?parentId=$(Esc $parentId)&limit=1000"
    Step $r 'documents' "GET .../$what/Documents?parentId={parentId}&limit=1000 (the canary source)"
    $all = @(Get-Results $r)
    $docs = [System.Text.Json.Nodes.JsonArray]::new(); $ids = @()
    foreach ($e in $entries) {
        $hit = @($all | Where-Object { (Same ([string]$_['name']) $e.name) -and -not $_['isFolder'].GetValue[bool]() })
        if ($hit.Count -ne 1) { Refuse "$($e.id): $($hit.Count) document(s) with that name" }
        $r = Invoke-Veeam -Path "$containerPath/Documents/$(Esc ([string]$hit[0]['id']))"
        Step $r $(if ($e -eq $entries[0]) { 'document' }) "GET .../$what/Documents/{documentId} (the re-read, sent in the body)"
        $d = (Get-Node $r).AsObject()
        foreach ($k in '_links', '_actions') { [void]$d.Remove($k) }
        if (-not (Same ([string]$d['name']) $e.name) -or [long]([string]$d['sizeBytes']) -ne $e.stored_size) { Refuse "$($e.id): the re-read differs from the manifest" }
        "  $($e.id): document found, $([string]$d['sizeBytes']) bytes" | Out-Host
        $ids += [string]$d['id']; $docs.Add($d)
    }
    [pscustomobject]@{ ItemIds = $ids; Names = @($entries.name); Array = $docs }
}

function Resolve-Sp($base, $entries) {
    $r = Invoke-Veeam -Path "$base/Sites?parentId=root&limit=1000"
    Step $r 'sites' 'GET .../Organization/Sites?parentId=root&limit=1000'
    $site = @(Get-Results $r | Where-Object { (Same ([string]$_['url']) $TargetSiteUrl) })
    if ($site.Count -ne 1) { Refuse "RestoreTest site: $($site.Count) match(es)" }
    $siteId = [string]$site[0]['id']
    $r = Invoke-Veeam -Path "$base/Sites/$siteId/Libraries"
    Step $r 'libraries' 'GET .../Organization/Sites/{siteId}/Libraries'
    $libs = @(Get-Results $r)
    $src = @($libs | Where-Object { ([string]$_['id']).EndsWith($CanaryListId, 'Ordinal') })
    if ($src.Count -ne 1) { Refuse "canary library: $($src.Count) match(es)" }
    # Backups since 2026-09-27 include the RestoreTarget library too: never a source, only named as the target.
    if (@($libs | Where-Object { ([string]$_['id']).EndsWith($TargetListId, 'Ordinal') }).Count) { "  note: the RestoreTarget library is in this restore point (not used as a source)" | Out-Host }
    $d = Resolve-Documents $base $entries "$base/Sites/$siteId" ([string]$src[0]['id']) 'Sites/{siteId}'
    $d | Add-Member ContainerId $siteId -PassThru | Add-Member Path "$base/Sites/$siteId/Documents/restoreTo" -PassThru
}

function Resolve-Od($base, $entries) {
    $r = Invoke-Veeam -Path "$base/OneDrives?limit=1000"
    Step $r 'onedrives' 'GET .../Organization/OneDrives?limit=1000'
    $od = @(Get-Results $r | Where-Object { (Same ([string]$_['url']) $TargetOneDriveUrl) })
    if ($od.Count -ne 1) { Refuse "alice's OneDrive: $($od.Count) match(es)" }
    $odId = [string]$od[0]['id']
    $r = Invoke-Veeam -Path "$base/OneDrives/$(Esc $odId)/Folders?parentId=root"
    Step $r 'folders-root' 'GET .../Organization/OneDrives/{oneDriveId}/Folders?parentId=root'
    $folders = @(Get-Results $r)
    $src = @($folders | Where-Object { (Same ([string]$_['name']) $CanaryOdFolder) })
    if ($src.Count -ne 1) { Refuse "/${CanaryOdFolder}: $($src.Count) match(es)" }
    if (@($folders | Where-Object { (Same ([string]$_['name']) $TargetOneDriveFolder) }).Count) { "  note: /$TargetOneDriveFolder is in this restore point (not used as a source)" | Out-Host }
    $d = Resolve-Documents $base $entries "$base/OneDrives/$(Esc $odId)" ([string]$src[0]['id']) 'OneDrives/{oneDriveId}'
    $target = [System.Text.Json.Nodes.JsonObject]::new()
    $target['id'] = $odId; $target['name'] = [string]$od[0]['name']; $target['url'] = [string]$od[0]['url']
    $d | Add-Member ContainerId $odId -PassThru | Add-Member Target $target -PassThru |
        Add-Member Path "$base/OneDrives/$odId/Documents/copyTo" -PassThru
}

# The body, in the key order of the W1.0 recordings. Credential values are placeholders until the guard passed.
function New-RestoreBody($res) {
    $b = [System.Text.Json.Nodes.JsonObject]::new()
    switch ($Type) {
        'mail' {
            $b['mailbox'] = $TargetMailbox; $b['folder'] = $TargetMailFolder; $b['items'] = $res.Array
            $b['changedItems'] = $true; $b['deletedItems'] = $true; $b['markRestoredAsUnread'] = $false
            $b['excludeDrafts'] = $false; $b['excludeDeletedItems'] = $false
            $b['excludeInPlaceHoldItems'] = $true; $b['excludeLitigationHoldItems'] = $true
            $b['officeRegion'] = 'Worldwide'; $b['officeOrganizationName'] = $LabOrgName
        }
        'sp' {
            $b['documents'] = $res.Array; $b['siteURL'] = $TargetSiteUrl; $b['list'] = $TargetLibrary
            $b['sendSharedLinksNotification'] = $false; $b['documentVersion'] = 'Last'; $b['documentLastVersionAction'] = 'Merge'
            $b['officeRegion'] = 'Worldwide'; $b['organizationName'] = $LabOrgName
        }
        'od' {
            $b['documents'] = $res.Array; $b['onedrive'] = $res.Target; $b['folder'] = $TargetOneDriveFolder
            $b['changedItems'] = $true; $b['deletedItems'] = $true; $b['documentVersion'] = 'Last'; $b['documentLastVersionAction'] = 'Merge'
            $b['officeRegion'] = 'Worldwide'; $b['organizationName'] = $LabOrgName
        }
    }
    $b['applicationId'] = $VeeamAppId
    $b['applicationCertificate'] = '[not exported yet]'
    $b['applicationCertificatePassword'] = '[not exported yet]'
    if ($Type -eq 'mail') { $b['impersonationAccountName'] = $TargetMailbox }
    , $b
}

# Veeam's organisation app certificate as Base64 PFX, exported in memory (W4.12): no temporary file.
function Get-RestoreCredential {
    $cert = Get-Item "Cert:\LocalMachine\My\$VeeamAppThumb"
    if (-not $cert.HasPrivateKey -or $cert.NotAfter -le (Get-Date)) { Refuse 'Veeam app certificate: no private key or expired' }
    $bytes = [byte[]]::new(32); [Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    $pw = [Convert]::ToBase64String($bytes); Register-Secret $pw
    try { $pfx = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $pw) }
    catch { Refuse "Veeam app certificate: the in-memory export failed ($($_.Exception.Message.Trim())): its private key must be readable by this account and exportable" }
    $b64 = [Convert]::ToBase64String($pfx); [Array]::Clear($pfx, 0, $pfx.Length)
    $script:Known.Add($b64)   # scrubbed like any secret; no DPAPI copy of the key material
    "  certificate exported in memory ($($b64.Length) Base64 chars); nothing written to disk" | Out-Host
    [pscustomobject]@{ Pfx = $b64; Password = $pw }
}

# Our restore sessions created since $Since, other than every session this run already knows (the
# explore sessions it opened and any restore session a POST returned or the check adopted).
$script:Restores = [System.Collections.Generic.List[string]]::new()
function Find-NewRestoreSessions([datetime]$Since, [string]$What) {
    $from = Format-Utc $Since.AddSeconds(-60)
    $r = Invoke-Veeam -Path "/v8/RestoreSessions?startTimeFrom=$from&orderBy=CreationTime&orderAsc=false&limit=50"
    Show-Call $r | Out-Host
    Save-Evidence "w2.4-$Type-$Tag-$What" $r 'GET /v8/RestoreSessions?startTimeFrom={post time - 60 s}&orderBy=CreationTime&orderAsc=false&limit=50 (the duplicate check)' | Out-Host
    if ($r.Status -ne 200) { throw "the duplicate check answered $($r.Status): no verdict" }
    $me = @($script:VeeamUser, ($script:VeeamUser -split '\\')[-1])
    @(Get-Results $r | Where-Object {
        (InIgnoreCase ([string]$_['initiatedBy']) $me) -and (Same ([string]$_['type']) $SessionType) -and
        -not (In ([string]$_['id']) $script:Opened) -and -not (In ([string]$_['id']) $script:Restores) -and ([string]$_['id']) -cmatch "^$GuidRx\z" -and
        [DateTimeOffset]::Parse([string]$_['creationTime'], [Globalization.CultureInfo]::InvariantCulture) -ge [DateTimeOffset]$Since.AddSeconds(-5)
    } | ForEach-Object { [string]$_['id'] })
}

# ---- Main ----
$script:Exit = 0
$Item = @($Item | ForEach-Object { $_ -split ',' } | ForEach-Object Trim | Where-Object { $_ })
if ($Item.Count -lt 1 -or $Item.Count -gt 5 -or @($Item | Sort-Object -Unique).Count -ne $Item.Count) {
    "usage: 1 to 5 distinct manifest ids"; exit 64
}
if (-not $Tag) { $Tag = "x$($Item.Count)" }
if ($SaveEvidence -and @(Get-ChildItem $script:EvidenceDir -Filter "w2.4-$Type-$Tag-*.json").Count) {
    "usage: evidence of an earlier $Type $Tag run exists (w2.4-$Type-$Tag-*.json): delete it or pass another -Tag"; exit 64
}
$kind = @{ mail = 'mail'; sp = 'sharepoint_file'; od = 'onedrive_file' }[$Type]
try { $all = @((Get-Content -Raw $Manifest | ConvertFrom-Json).entries) } catch { "usage: cannot read lab/seed-manifest.json: $($_.Exception.Message)"; exit 64 }
$entries = @(foreach ($id in $Item) {
    $e = @($all | Where-Object { Same $_.id $id })
    if ($e.Count -ne 1) { "usage: $id is not a canary in lab/seed-manifest.json" | Out-Host; exit 64 }
    if (-not (Same $e[0].kind $kind)) { "usage: $id is a $($e[0].kind), not $kind" | Out-Host; exit 64 }
    $e[0]
})
if (-not $WhatIf) {
    # The export needs the private key readable by this account (W4.12: an administrator, LocalSystem, or
    # an account granted read on the key file) and exportable. Checked before any session is opened.
    try { $null = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey((Get-Item "Cert:\LocalMachine\My\$VeeamAppThumb")).KeySize }
    catch { "the Veeam app certificate's private key can't be opened as $([Security.Principal.WindowsIdentity]::GetCurrent().Name): $($_.Exception.Message.Trim()). Run elevated, or grant this account read access to the key file (or use -WhatIf)"; exit 64 }
}
"W2.4 restore: $Type, $($Item -join ', ')$(if ($WhatIf) { ' (WhatIf: nothing is exported or posted)' })"

$script:Posted = $false; $script:RestoreOpen = $false
function Invoke-Restore {
    # 1. Preflight: no session of ours still Working (the duplicate check relies on it), and the org's app.
    $r = Invoke-Veeam -Path '/v8/RestoreSessions?limit=200'
    Step $r 'sweep-before' 'GET /v8/RestoreSessions?limit=200 (preflight: none of ours Working)'
    $me = @($script:VeeamUser, ($script:VeeamUser -split '\\')[-1])
    $busy = @(Get-Results $r | Where-Object { (Same ([string]$_['state']) 'Working') -and (InIgnoreCase ([string]$_['initiatedBy']) $me) })
    if ($busy.Count) { Refuse "$($busy.Count) rp-veeam session(s) still Working: if a restore is among them, wait until it stops; then run 08-sweep-sessions.ps1" }
    $r = Invoke-Veeam -Path '/v8/Organizations'
    Step $r 'org' 'GET /v8/Organizations (the org app used as restore credential)'
    $org = @(Get-Results $r | Where-Object { (Same ([string]$_['id']) $LabOrgId) -and (Same ([string]$_['name']) $LabOrgName) })
    if ($org.Count -ne 1) { Refuse 'lab organisation not found' }
    foreach ($s in 'exchangeOnlineSettings', 'sharePointOnlineSettings') {
        if (-not (Same ([string]$org[0][$s]['applicationId']) $VeeamAppId) -or -not (Same ([string]$org[0][$s]['applicationCertificateThumbprint']) $VeeamAppThumb)) {
            Refuse "the organisation's $s app is not $VeeamAppId / $VeeamAppThumb" }
    }

    # 2. The latest restore point, and one explore session at its exact backupTime.
    $latest = Get-LatestRestorePoint
    "latest restore point: $($latest.id) backupTime $($latest.backupTime)"
    $x = New-ExploreSession $SessionType $latest.backupTime
    Step $x 'explore' "POST /v8/Organizations/{organizationId}/explore {type: $SessionType} at the latest backupTime"
    $exploreId = [string](Get-Node $x)['id']
    "explore session: $exploreId"
    $base = if ($Type -eq 'mail') { "/v8/RestoreSessions/$exploreId/organization" } else { "/v8/RestoreSessions/$exploreId/Organization" }

    # 3. Resolve the canaries, build the body, guard it (and prove the guard refuses mutations).
    $res = switch ($Type) { 'mail' { Resolve-Mail $base $entries } 'sp' { Resolve-Sp $base $entries } 'od' { Resolve-Od $base $entries } }
    # Results name the items (events by name only), so no two items of one call may share a name.
    if (@($res.Names | Sort-Object -Unique -CaseSensitive).Count -ne @($res.Names).Count) { Refuse 'two items of one call share a name' }
    $ctx = [pscustomobject]@{ ExploreId = $exploreId; ContainerId = $res.ContainerId; ItemIds = $res.ItemIds; Names = $res.Names }
    $body = New-RestoreBody $res
    $draft = $body.ToJsonString($JsonOpts)
    Assert-RestoreTarget $res.Path $draft $ctx
    Test-GuardRefuses $res.Path $draft $ctx
    $shown = [System.Text.Json.Nodes.JsonNode]::Parse($draft)
    $shown[$(if ($Type -eq 'mail') { 'items' } else { 'documents' })] = "[$($res.ItemIds.Count) item(s)]"
    "restore call: POST $(Format-PathTemplate $res.Path)"
    "  body: $($shown.ToJsonString($JsonOpts))"
    if ($WhatIf) { "WhatIf: guard passed; nothing exported, nothing posted"; return }

    # 4. The credential, the guard once more on the exact text, and ONE POST. Never resent.
    $cred = Get-RestoreCredential
    $body['applicationCertificate'] = $cred.Pfx
    $body['applicationCertificatePassword'] = $cred.Password
    $bodyText = $body.ToJsonString($JsonOpts)
    Assert-RestoreTarget $res.Path $bodyText $ctx
    $posted = [DateTime]::UtcNow; $script:Posted = $true; $script:RestoreOpen = $true
    $restoreId = $null; $cause = $null; $p = $null
    try { $p = Invoke-Veeam -Method POST -Path $res.Path -Json $bodyText -TimeoutSeconds 60 }
    catch { $cause = "no answer ($($_.Exception.GetType().Name))" }
    finally { $body['applicationCertificate'] = $null; $body['applicationCertificatePassword'] = $null; $bodyText = $null; $cred = $null }
    if ($p) {
        # Not Show-Call: it scrubs only literal secrets, and an echoed error body could hold them JSON-escaped.
        $msg = if ($p.Status -ge 400) { try { ': ' + (Protect-Text ([string](Get-Node $p)['message'])) } catch { ': (body not shown)' } }
        "POST $(Format-PathTemplate $p.Path) -> $($p.Status) ($($p.Ms) ms)$msg"
        # Any 2xx may carry the session; a 4xx started nothing; anything else (1xx, 3xx, 5xx): look for it.
        if ($p.Status -ge 200 -and $p.Status -lt 300) {
            $m = [regex]::Match($p.Body, '"sessionId"\s*:\s*"([0-9a-f-]{36})"')
            if ($m.Success) { $restoreId = $m.Groups[1].Value; "restore session: $restoreId" }
            else { $cause = "a $($p.Status) without a sessionId" }
        } elseif ($p.Status -lt 400 -or $p.Status -ge 500) { $cause = "a $($p.Status)" }
        # The evidence is written only once the session ID is known: a failed write loses nothing.
        $what = if ($p.Status -eq 200) { 'restore' } else { "restore-$($p.Status)" }
        $verb = if ($Type -eq 'od') { 'copyTo' } else { 'restoreTo' }
        $target = @{ mail = "$TargetMailbox $TargetMailFolder"; sp = "$TargetSiteUrl list $TargetLibrary"; od = "alice's OneDrive /$TargetOneDriveFolder" }[$Type]
        try { Save-Evidence "w2.4-$Type-$Tag-$what" $p "POST .../$verb ($($res.ItemIds.Count) item(s) -> $target), Veeam org app certificate" }
        catch { "  the POST's evidence was not saved: $($_.Exception.Message)" }
        if ($p.Status -ge 400 -and $p.Status -lt 500) { $script:RestoreOpen = $false; $script:Exit = 2; Refuse "the restore POST answered $($p.Status): nothing started" }
    }

    # 5. The duplicate check, run on every POST so its query is proven: exactly the one new session.
    $checked = $false
    if ($restoreId) {
        # The returned session is known, so a failing check must not lose it: it is polled either way,
        # but only a check that lists exactly this one new session lets the run end with exit 0.
        try {
            $found = @(Find-NewRestoreSessions $posted 'sessions-after-post')
            $checked = $found.Count -eq 1 -and (Same $found[0] $restoreId)
            "  duplicate check: $($found.Count) new session(s) of ours; exactly this one: $checked$(if (-not $checked) { ' (no verdict at the end)' })"
        } catch { "  duplicate check failed: $($_.Exception.Message); polling the returned session anyway (no verdict at the end)" }
        $script:Restores.Add($restoreId)
    } else {
        "the POST gave no session id ($cause): looking for it instead of resending"
        $found = @(Find-NewRestoreSessions $posted 'sessions-after-post')
        for ($i = 0; $found.Count -eq 0 -and $i -lt 3; $i++) { Start-Sleep -Seconds 10; $found = @(Find-NewRestoreSessions $posted 'sessions-after-timeout') }
        if ($found.Count -ne 1) { "  $($found.Count) candidate session(s): no verdict, not resent"; $script:Exit = 3; return }
        $restoreId = $found[0]; $script:Restores.Add($restoreId); $checked = $true
        "  adopted restore session $restoreId after $cause"
    }

    # 6. Poll every 5 s until Stopped (docs/api/veeam-notes.md §7), then statistics and events.
    $deadline = [DateTime]::UtcNow.AddMinutes($TimeoutMinutes); $fails = 0; $sawWorking = $false; $s = $null
    $leave = "wait until GET /v8/RestoreSessions/$restoreId reads Stopped, then run 08-sweep-sessions.ps1"
    while ($true) {
        try { $r = Invoke-Veeam -Path "/v8/RestoreSessions/$restoreId" }
        catch { $r = [pscustomobject]@{ Status = 0; Method = 'GET'; Path = "/v8/RestoreSessions/$restoreId"; Ms = 0; Body = $_.Exception.Message } }
        if ($r.Status -eq 200) {
            $fails = 0; $s = Get-Node $r
            if ([string]$s['state'] -ceq 'Stopped') { $script:RestoreOpen = $false; break }
            if (-not $sawWorking) { $sawWorking = $true; Save-Evidence "w2.4-$Type-$Tag-session-working" $r 'GET /v8/RestoreSessions/{restoreSessionId} (the restore session, Working)' }
        } elseif ($r.Status -eq 404) { Show-Call $r; "restore session $restoreId not found: no verdict; $leave"; $script:Exit = 3; return }
        elseif (++$fails -ge 6) { Show-Call $r; "6 polls in a row failed: no verdict; $leave"; $script:Exit = 3; return }
        if ([DateTime]::UtcNow -gt $deadline) { "timeout: restore session $restoreId still $(if ($s) { $s['state'] }) after $TimeoutMinutes min: no verdict; $leave"; $script:Exit = 3; return }
        Start-Sleep -Seconds 5
    }
    Save-Evidence "w2.4-$Type-$Tag-session" $r 'GET /v8/RestoreSessions/{restoreSessionId} (the restore session, Stopped)'
    $result = Field $s 'result' 'String' 'the session'
    $took = [DateTimeOffset]::Parse((Field $s 'endTime' 'String' 'the session'), [Globalization.CultureInfo]::InvariantCulture) - [DateTimeOffset]::Parse((Field $s 'creationTime' 'String' 'the session'), [Globalization.CultureInfo]::InvariantCulture)
    "restore session $restoreId : state=$($s['state']) result=$result details=`"$($s['details'])`" ($([int]$took.TotalSeconds) s)"
    for ($i = 0; $i -lt 6; $i++) {
        $r = Invoke-Veeam -Path "/v8/RestoreSessions/$restoreId/Statistics"
        if ($r.Status -ne 409) { break }
        if ($i -eq 0) { Save-Evidence "w2.4-$Type-$Tag-statistics-409" $r 'GET /v8/RestoreSessions/{restoreSessionId}/Statistics (409 just after Stopped)' }
        Start-Sleep -Seconds 5
    }
    Show-Call $r
    Save-Evidence "w2.4-$Type-$Tag-statistics" $r 'GET /v8/RestoreSessions/{restoreSessionId}/Statistics'
    if ($r.Status -ne 200) { "statistics answered $($r.Status): no verdict"; $script:Exit = 3; return }
    $st = Get-Node $r
    $restored = Field $st 'restoredItemsCount' 'Number' 'the statistics'
    $statItems = @(Field $st 'items' 'Array' 'the statistics')
    "  statistics: total=$($st['totalItemsCount']) restored=$restored failed=$($st['failedItemsCount']) skipped=$($st['skippedItemsCount'])"
    foreach ($i in $statItems) { "    $($i['name']) [$($i['id'])]: $($i['status'])" }
    $r = Invoke-Veeam -Path "/v8/RestoreSessions/$restoreId/Events?limit=100"
    Show-Call $r
    Save-Evidence "w2.4-$Type-$Tag-events" $r 'GET /v8/RestoreSessions/{restoreSessionId}/Events?limit=100'
    if ($r.Status -ne 200) { "events answered $($r.Status): no verdict"; $script:Exit = 3; return }
    $events = @(Field (Get-Node $r) 'results' 'Array' 'the events')
    foreach ($e in $events) {
        if ([string]$e['type'] -ceq 'Restore' -or [string]$e['status'] -cne 'Success') { "  event $($e['type'])/$($e['status']): $($e['message'])" }
    }

    # 7. The verdict "Veeam says restored" (docs/api/veeam-restore-flow.md §12): Graph decides after that.
    $n = $res.ItemIds.Count
    $ok = (Same $result 'Success') -and $restored -eq $n
    # Events carry only the item's name; names are unique within the call (checked before the POST).
    $okNames = @($events | Where-Object { (Same ([string]$_['type']) 'Restore') -and (Same ([string]$_['status']) 'Success') } | ForEach-Object { [string]$_['itemName'] })
    foreach ($name in $res.Names) { if (-not (In $name $okNames)) { $ok = $false; "  no successful Restore event for $name" } }
    if ($Type -ne 'mail') {
        # File statistics carry an id: the OneDrive document ID, or the list item GUID that ends the SharePoint document ID.
        $okIds = @($statItems | Where-Object { (Same ([string]$_['status']) 'Success') -and ([string]$_['id']) -cmatch "^$GuidRx\z" } | ForEach-Object { [string]$_['id'] })
        foreach ($id in $res.ItemIds) {
            if (@($okIds | Where-Object { $id.EndsWith($_, [StringComparison]::Ordinal) }).Count -ne 1) { $ok = $false; "  statistics show no success for $id" }
        }
    }
    if ($ok -and -not $checked) {
        "VERDICT: none. Veeam reports the restore, but the duplicate check didn't confirm it as the only new session ($n item(s), restore session $restoreId)"
        $script:Exit = 3
    } else {
        "VERDICT: $(if ($ok) { 'Veeam says restored' } else { 'NOT restored' }) ($n item(s), restore session $restoreId)"
        if (-not $ok) { $script:Exit = 1 }
    }
    $log = Get-ChildItem $RestoreLogDir -Filter "restore_*_$($restoreId -replace '-', '')_*.log" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($log) { "  Veeam's log: $($log.FullName) ($($log.Length) bytes; not committed)" }
}

try { Connect-VeeamAdmin | Out-Null; Invoke-Restore }
catch {
    # A refusal or guard failure before the POST: 2. Anything after it: 3 (no verdict), unless already set.
    "$($_.Exception.Message)"
    if (-not $script:Exit) { $script:Exit = if ($script:Posted) { 3 } else { 2 } }
} finally {
    # A restore that may still be running keeps its explore session: stopping it under the restore is untested.
    if ($script:RestoreOpen) { "explore session(s) left open under a restore that may still be running: $($script:Opened -join ', ')" }
    else { Stop-OpenedSessions }
    Disconnect-VeeamAdmin
}
exit $script:Exit

# Step 9: what an expired access token and its (unused) refresh token answer (docs/api/veeam-notes.md §1.5).
#   pwsh -File 09-token-expiry.ps1 -Start -StateDir <folder>                  # grant, keep the tokens (DPAPI) in <folder>
#   pwsh -File 09-token-expiry.ps1 -Probe -StateDir <folder>                  # any time: is the access token still accepted? (keeps the files)
#   pwsh -File 09-token-expiry.ps1 -Check -StateDir <folder> [-SaveEvidence]  # after .expires: use them, then delete <folder>\*.xml
# The tokens are stored only as DPAPI-protected files (this Windows user) in -StateDir; use a temp folder.
param([switch]$Start, [switch]$Probe, [switch]$Check, [Parameter(Mandatory)][string]$StateDir, [switch]$SaveEvidence)
. "$PSScriptRoot\VeeamLab.ps1"

function Save-State([string]$Name, [string]$Value) {
    ConvertTo-SecureString $Value -AsPlainText -Force | Export-Clixml (Join-Path $StateDir "$Name.xml")
}
function Read-State([string]$Name) {
    $v = [System.Net.NetworkCredential]::new('', (Import-Clixml (Join-Path $StateDir "$Name.xml"))).Password
    Register-Secret $v
    $v
}

New-Item -ItemType Directory -Force $StateDir | Out-Null
if ($Start) {
    $r = Connect-VeeamAdmin
    $b = Get-Body $r
    Save-State 'access' (Get-VeeamAccessToken); Save-State 'refresh' (Get-VeeamRefreshToken)
    [IO.File]::WriteAllText((Join-Path $StateDir 'expires.txt'), [regex]::Match($r.Body, '"\.expires"\s*:\s*"([^"]+)"').Groups[1].Value)
    "granted; the access token expires at $(Get-Content (Join-Path $StateDir 'expires.txt')) (expires_in $($b.expires_in) s). Run -Check after that."
} elseif ($Probe) {
    $a = Read-State 'access'
    $r = Invoke-Veeam -Path '/v8/Organizations?limit=1' -Token $a
    "$([DateTime]::UtcNow.ToString('HH:mm:ss'))Z, .expires $(Get-Content (Join-Path $StateDir 'expires.txt')): $(Show-Call $r)"
} elseif ($Check) {
    $expires = [DateTimeOffset]::Parse((Get-Content (Join-Path $StateDir 'expires.txt')), [Globalization.CultureInfo]::InvariantCulture)
    if ([DateTimeOffset]::UtcNow -lt $expires) { throw "not expired yet: $expires" }
    $a = Read-State 'access'; $rt = Read-State 'refresh'
    try {
        $r = Invoke-Veeam -Path '/v8/Organizations?limit=1' -Token $a
        "expired access token: $(Show-Call $r) WWW-Authenticate: $($r.Headers['WWW-Authenticate'])"
        Save-Evidence 'w1.4-auth-expired-access-401' $r "GET /v8/Organizations with an access token past its .expires ($expires)"
        $r = Invoke-Veeam -Method POST -Path '/v8/token' -NoAuth -Form ([ordered]@{
            grant_type = 'refresh_token'; refresh_token = $rt; disable_antiforgery_token = 'true' })
        "its refresh token, after the access token expired: $(Show-Call $r)"
        Save-Evidence 'w1.4-auth-refresh-after-expiry' $r 'POST /v8/token grant_type=refresh_token with the refresh token of that expired access token'
        if ($r.Status -eq 200) { Set-VeeamTokens $r; Disconnect-VeeamAdmin }
    } finally {
        Remove-Item (Join-Path $StateDir '*.xml'), (Join-Path $StateDir 'expires.txt') -ErrorAction SilentlyContinue
    }
} else { throw 'pass -Start, -Probe or -Check' }

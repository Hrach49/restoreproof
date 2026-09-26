# Step 1: health, login, refresh, logout (docs/api/veeam-notes.md §1).
#   pwsh -File 01-auth.ps1 [-SaveEvidence]
# Makes two password grants (one form-encoded, one JSON) for rp-veeam and logs every token out again. Read-only otherwise.
param([switch]$SaveEvidence)
. "$PSScriptRoot\VeeamLab.ps1"

# /v8/Health needs no token.
$r = Invoke-Veeam -Path '/v8/Health' -NoAuth
Show-Call $r; "  body: $($r.Body)"
Save-Evidence 'w1.4-auth-health' $r 'GET /v8/Health without a token'

# No token, and a token Veeam never issued.
$r = Invoke-Veeam -Path '/v8/Organizations' -NoAuth
Show-Call $r; Save-Evidence 'w1.4-auth-no-token-401' $r 'GET /v8/Organizations without an Authorization header'
$r = Invoke-Veeam -Path '/v8/Organizations' -Token 'not-a-veeam-token'
Show-Call $r; Save-Evidence 'w1.4-auth-bad-token-401' $r 'GET /v8/Organizations with a bearer value Veeam never issued'

# Chain 1: password grant (form-encoded), then refresh.
$r = Connect-VeeamAdmin
Show-Call $r
$b = Get-Body $r
"  token_type=$($b.token_type) expires_in=$($b.expires_in) userName=$($b.userName) .issued=$($b.'.issued') .expires=$($b.'.expires')"
"  access token: $($b.access_token.Length) chars, JWT-shaped: $($b.access_token -match '^eyJ'); refresh token: $($b.refresh_token.Length) chars"
Save-Evidence 'w1.4-auth-token' $r 'POST /v8/token grant_type=password, form-encoded, disable_antiforgery_token=true (rp-veeam)'
try {
    $r = Invoke-Veeam -Path '/v8/Organizations?limit=1'
    Show-Call $r

    $old = Get-VeeamRefreshToken
    $r = Invoke-Veeam -Method POST -Path '/v8/token' -NoAuth -Form ([ordered]@{
        grant_type = 'refresh_token'; refresh_token = $old; disable_antiforgery_token = 'true' })
    Show-Call $r
    Save-Evidence 'w1.4-auth-refresh' $r 'POST /v8/token grant_type=refresh_token with the refresh token of w1.4-auth-token'
    $prevAccess = Get-VeeamAccessToken
    Set-VeeamTokens $r
    "  refresh rotated: $((Get-VeeamRefreshToken) -ne $old); new access token differs: $((Get-VeeamAccessToken) -ne $prevAccess)"

    # The access token from before the refresh: still valid?
    $r = Invoke-Veeam -Path '/v8/Organizations?limit=1' -Token $prevAccess
    "pre-refresh access token after the refresh: $(Show-Call $r)"
    Save-Evidence 'w1.4-auth-pre-refresh-access' $r 'GET /v8/Organizations with the access token issued before the refresh'

    # The used refresh token again: single-use?
    $r = Invoke-Veeam -Method POST -Path '/v8/token' -NoAuth -Form ([ordered]@{
        grant_type = 'refresh_token'; refresh_token = $old; disable_antiforgery_token = 'true' })
    "reuse of the used refresh token: $(Show-Call $r)"
    Save-Evidence 'w1.4-auth-refresh-reuse-401' $r 'POST /v8/token grant_type=refresh_token with the refresh token already used by w1.4-auth-refresh'

    # After that reuse attempt, does the newest refresh token still work (no family revocation)?
    $r = Invoke-Veeam -Method POST -Path '/v8/token' -NoAuth -Form ([ordered]@{
        grant_type = 'refresh_token'; refresh_token = (Get-VeeamRefreshToken); disable_antiforgery_token = 'true' })
    "newest refresh token after the reuse attempt: $(Show-Call $r)"
    Save-Evidence 'w1.4-auth-refresh-after-reuse' $r 'POST /v8/token grant_type=refresh_token with the newest refresh token, after the old one was replayed'
    if ($r.Status -eq 200) { Set-VeeamTokens $r }
} finally {
    $a1 = Get-VeeamAccessToken; $r1 = Get-VeeamRefreshToken
}

# Chain 2: a JSON grant, to show both encodings work. Kept alive while chain 1 logs out.
$r = Invoke-Veeam -Method POST -Path '/v8/token' -NoAuth -Json ([ordered]@{
    grant_type = 'password'; username = $script:VeeamUser; password = (Read-CredManPassword $script:CredTarget); disable_antiforgery_token = $true } | ConvertTo-Json)
"JSON password grant: $(Show-Call $r)"
Save-Evidence 'w1.4-auth-token-json' $r 'POST /v8/token grant_type=password as application/json'
$b2 = Get-Body $r
if ($r.Status -eq 200) { Register-Secret $b2.access_token; Register-Secret $b2.refresh_token }

# Log chain 1 out, then try its access and refresh tokens, and check chain 2 still works.
$r = Invoke-Veeam -Method POST -Path '/v8/token/logout' -Token $a1
"logout chain 1: $(Show-Call $r)"
Save-Evidence 'w1.4-auth-logout' $r 'POST /v8/token/logout with the access token of chain 1'
$r = Invoke-Veeam -Path '/v8/Organizations?limit=1' -Token $a1
"chain 1 access token after logout: $(Show-Call $r)"
Save-Evidence 'w1.4-auth-after-logout-access' $r 'GET /v8/Organizations with the access token that was logged out'
$r = Invoke-Veeam -Method POST -Path '/v8/token' -NoAuth -Form ([ordered]@{
    grant_type = 'refresh_token'; refresh_token = $r1; disable_antiforgery_token = 'true' })
"chain 1 refresh token after logout: $(Show-Call $r)"
Save-Evidence 'w1.4-auth-after-logout-refresh' $r 'POST /v8/token grant_type=refresh_token with the refresh token of the logged-out chain'
if ($r.Status -eq 200) { Set-VeeamTokens $r; Disconnect-VeeamAdmin }   # it survived: log that one out too

if ($b2) {
    $r = Invoke-Veeam -Path '/v8/Organizations?limit=1' -Token $b2.access_token
    "chain 2 (separate grant) after chain 1 logged out: $(Show-Call $r)"
    Save-Evidence 'w1.4-auth-other-token-after-logout' $r 'GET /v8/Organizations with a second, separately granted token after the first was logged out'
    $r = Invoke-Veeam -Method POST -Path '/v8/token/logout' -Token $b2.access_token
    "logout chain 2: $(Show-Call $r)"
}

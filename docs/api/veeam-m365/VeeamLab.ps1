# Shared helper for the W1.4 Veeam REST scripts. Dot-source it:  . "$PSScriptRoot\VeeamLab.ps1"
#
# - TLS: the Veeam REST leaf certificate is trusted by its exact SHA-256 (pinned). Nothing else is
#   accepted, and verification is never switched off. Veeam's default certificate has no SAN, so no
#   host name verifies against it (docs/api/veeam-feasibility.md §5.1).
# - Secrets: rp-veeam's password is read from Windows Credential Manager at run time. It and every
#   token live only in this process's memory. If $env:RP_LAB_SECRET_DIR is set, a DPAPI copy of each
#   is also written there, so audit-evidence.ps1 can check saved evidence against the literal values
#   later; delete that folder when done.
# - Evidence: Save-Evidence writes one scrubbed JSON per call to docs/api/veeam-lab/ (format in its
#   README), and refuses to write a file in which a known secret survived.
Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

$script:VeeamBase  = if ($env:RP_VEEAM_URL) { $env:RP_VEEAM_URL.TrimEnd('/') } else { 'https://localhost:4443' }
$script:VeeamPin   = if ($env:RP_VEEAM_PIN_SHA256) { $env:RP_VEEAM_PIN_SHA256 } else { '9FB19E0E604C9BE49F83D8E508EFA8EA0986A952377C783E5035CEA2D772A213' }
$script:VeeamUser  = if ($env:RP_VEEAM_USER) { $env:RP_VEEAM_USER } else { 'DESKTOP-P55CDUM\rp-veeam' }
$script:CredTarget = 'RestoreProof Lab - rp-veeam (local Veeam REST)'
$script:EvidenceDir = Join-Path $PSScriptRoot '..\veeam-lab' | Resolve-Path | Select-Object -ExpandProperty Path
$script:Known = [System.Collections.Generic.List[string]]::new()   # literal secret values seen in this process
$script:Access = $null                                            # current access token
$script:Refresh = $null                                           # current refresh token

# The lab's fixed IDs (lab/tenant.md, docs/environment.md). Not secret.
$LabOrgId     = 'ff96d072-29e2-4cb4-a155-2590f5473176'
$LabOrgName   = 'RestoreProofLab.onmicrosoft.com'
$LabRepoId    = 'c2f0f2e7-177f-48ac-992b-93a50cf702e3'
$LabFullPoint = '2fb3c7e0-ff6e-4949-8b2d-ae32ecf9e9a7'   # 2026-09-25T19:24:31Z
$LabIncPoint  = '71ac3d9c-eb29-42b6-a391-ae81fcc4681c'   # 2026-09-25T19:37:15Z, the latest

if (-not ('RpPinned' -as [type])) {
    # PowerShell script blocks can't run as TLS callbacks on the handler's thread, so compile one.
    Add-Type -TypeDefinition @'
using System;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public static class RpPinned {
    public static HttpClient Create(string sha256Hex, int timeoutSeconds) {
        var h = new SocketsHttpHandler();
        h.AllowAutoRedirect = false;
        h.UseCookies = false;
        h.SslOptions.RemoteCertificateValidationCallback =
            (object s, X509Certificate c, X509Chain ch, SslPolicyErrors e) => {
                if (c == null) return false;
                var x = new X509Certificate2(c);
                return string.Equals(x.GetCertHashString(System.Security.Cryptography.HashAlgorithmName.SHA256),
                                     sha256Hex, StringComparison.OrdinalIgnoreCase);
            };
        var cl = new HttpClient(h);
        cl.Timeout = TimeSpan.FromSeconds(timeoutSeconds);
        return cl;
    }
}
'@
}

function Register-Secret([string]$Value) {
    if (-not $Value -or $Value.Length -lt 6 -or $script:Known.Contains($Value)) { return }
    $script:Known.Add($Value)
    if ($env:RP_LAB_SECRET_DIR) {
        New-Item -ItemType Directory -Force $env:RP_LAB_SECRET_DIR | Out-Null
        $n = [guid]::NewGuid().ToString('N')
        ConvertTo-SecureString $Value -AsPlainText -Force | Export-Clixml (Join-Path $env:RP_LAB_SECRET_DIR "$n.xml")
    }
}

function Read-CredManPassword([string]$Target) {
    if (-not ('RpCredMan' -as [type])) {
        Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices;
public static class RpCredMan {
  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  struct CREDENTIAL { public int Flags; public int Type; public IntPtr TargetName; public IntPtr Comment;
    public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten; public int CredentialBlobSize; public IntPtr CredentialBlob;
    public int Persist; public int AttributeCount; public IntPtr Attributes; public IntPtr TargetAlias; public IntPtr UserName; }
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool CredReadW(string t, int type, int f, out IntPtr c);
  [DllImport("advapi32.dll")] static extern void CredFree(IntPtr p);
  public static string Read(string t) { IntPtr p; if (!CredReadW(t, 1, 0, out p)) return null;
    try { var c = (CREDENTIAL)Marshal.PtrToStructure(p, typeof(CREDENTIAL)); return Marshal.PtrToStringUni(c.CredentialBlob, c.CredentialBlobSize / 2); } finally { CredFree(p); } }
}
"@
    }
    $v = [RpCredMan]::Read($Target)
    if ($null -eq $v) { throw "Credential Manager has no generic credential '$Target'" }
    Register-Secret $v
    $v
}

# Replaces known secret values, token-like JSON/form values, bearer values and JWTs.
function Protect-Text([string]$Text) {
    if ($null -eq $Text) { return $Text }
    $t = $Text
    foreach ($v in $script:Known) { $t = $t.Replace($v, '[REDACTED]') }
    $t = [regex]::Replace($t, '(?i)("(?:access_token|refresh_token|id_token|password|client_secret|assertion|applicationCertificate|applicationCertificatePassword|userPassword|token|device_code|userCode)"\s*:\s*)("(?:[^"\\]|\\.)*"|[^,}\]]+)', '$1"[REDACTED]"')
    $t = [regex]::Replace($t, '(?i)\b(access_token|refresh_token|id_token|password|client_secret|assertion|device_code)=[^&\s"]*', '$1=[REDACTED]')
    # a bearer value (token-length, so WWW-Authenticate's 'Bearer error="invalid_token"' stays readable)
    $t = [regex]::Replace($t, '(?i)(Bearer\s+)[A-Za-z0-9\-\._~\+/]{16,}=*', '$1[REDACTED]')
    [regex]::Replace($t, 'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*', '[REDACTED-JWT]')
}

# Invoke-Veeam [-Method GET] -Path /v8/... [-Form @{}] [-Json obj|string] [-Token <access token> | -NoAuth]
# Sends with the current access token unless -NoAuth or -Token is given. Returns a record of the exchange.
function Invoke-Veeam {
    param(
        [string]$Method = 'GET',
        [Parameter(Mandatory)][string]$Path,
        [System.Collections.IDictionary]$Form,
        $Json,
        [string]$Token,
        [switch]$NoAuth,
        [int]$TimeoutSeconds = 120
    )
    $cl = [RpPinned]::Create($script:VeeamPin, $TimeoutSeconds)
    try {
        $req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::new($Method), "$script:VeeamBase$Path")
        $req.Headers.Accept.ParseAdd('application/json')
        $bearer = if ($Token) { $Token } elseif (-not $NoAuth) { $script:Access } else { $null }
        if ($bearer) { $req.Headers.Authorization = [System.Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $bearer) }
        $reqBody = $null
        if ($Form) {
            $pairs = [System.Collections.Generic.List[System.Collections.Generic.KeyValuePair[string,string]]]::new()
            foreach ($k in $Form.Keys) { $pairs.Add([System.Collections.Generic.KeyValuePair[string,string]]::new($k, [string]$Form[$k])) }
            $req.Content = [System.Net.Http.FormUrlEncodedContent]::new($pairs)
            $reqBody = ($Form.Keys | ForEach-Object { "$_=" + $Form[$_] }) -join '&'
        } elseif ($null -ne $Json) {
            $reqBody = if ($Json -is [string]) { $Json } else { $Json | ConvertTo-Json -Depth 20 }
            $req.Content = [System.Net.Http.StringContent]::new($reqBody, [System.Text.Encoding]::UTF8, 'application/json')
        }
        $started = [DateTime]::UtcNow
        $resp = $cl.SendAsync($req).GetAwaiter().GetResult()
        $text = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        $ct = if ($resp.Content.Headers.ContentType) { $resp.Content.Headers.ContentType.ToString() } else { '' }
        $hdrs = [ordered]@{}
        foreach ($h in $resp.Headers) { $hdrs[$h.Key] = ($h.Value -join ', ') }
        foreach ($h in $resp.Content.Headers) { $hdrs[$h.Key] = ($h.Value -join ', ') }
        [pscustomobject]@{
            Method = $Method; Path = $Path; Status = [int]$resp.StatusCode; ContentType = $ct
            Headers = $hdrs; RequestBody = $reqBody; Body = $text
            StartedUtc = $started.ToString('yyyy-MM-ddTHH:mm:ss.fffZ'); Ms = [int]([DateTime]::UtcNow - $started).TotalMilliseconds
        }
    } finally { $cl.Dispose() }
}

# The parsed JSON body, or $null.
function Get-Body($r) { if ($r.Body -and $r.ContentType -match 'json') { $r.Body | ConvertFrom-Json -Depth 50 } }

# One line per call, safe to print: "GET /v8/... -> 200 (12 ms)" plus a scrubbed error message.
function Show-Call($r) {
    $line = "$($r.Method) $($r.Path) -> $($r.Status) ($($r.Ms) ms)"
    if ($r.Status -ge 400) { $line += ': ' + (Protect-Text $r.Body) }
    $line
}

function New-JsonValue($v) {
    if ($null -eq $v) { return $null }
    if ($v -is [int]) { return [System.Text.Json.Nodes.JsonValue]::Create([int]$v) }
    [System.Text.Json.Nodes.JsonValue]::Create([string]$v)
}
# Scrubbed body as a JSON node when it parses as JSON, else as a (scrubbed) string.
function ConvertTo-JsonNode([string]$Text) {
    if ([string]::IsNullOrEmpty($Text)) { return $null }
    $t = Protect-Text $Text
    # The comma keeps PowerShell from enumerating a JsonObject/JsonArray into its members.
    try { return , [System.Text.Json.Nodes.JsonNode]::Parse($t) } catch { return New-JsonValue $t }
}

# Writes docs/api/veeam-lab/<Name>.json (scrubbed) when $SaveEvidence is true in the caller.
function Save-Evidence([string]$Name, $r, [string]$Note) {
    if (-not (Get-Variable -Name SaveEvidence -ValueOnly -ErrorAction SilentlyContinue)) { return }
    # System.Text.Json nodes keep every value as sent (ConvertFrom-Json would turn ISO dates into
    # DateTime and write them back in another form).
    $o = [System.Text.Json.Nodes.JsonObject]::new()
    $o['note'] = New-JsonValue $Note
    $o['captured_utc'] = New-JsonValue $r.StartedUtc
    $o['duration_ms'] = New-JsonValue $r.Ms
    $req = [System.Text.Json.Nodes.JsonObject]::new()
    $req['method'] = New-JsonValue $r.Method
    $req['path'] = New-JsonValue $r.Path
    $req['body'] = ConvertTo-JsonNode $r.RequestBody
    $o['request'] = $req
    $resp = [System.Text.Json.Nodes.JsonObject]::new()
    $resp['status'] = New-JsonValue $r.Status
    $resp['content_type'] = New-JsonValue $r.ContentType
    $h = [System.Text.Json.Nodes.JsonObject]::new()
    foreach ($k in $r.Headers.Keys) { if ($k -notmatch '(?i)^(set-cookie|authorization)$') { $h[$k] = New-JsonValue (Protect-Text $r.Headers[$k]) } }
    $resp['headers'] = $h
    $resp['body'] = ConvertTo-JsonNode $r.Body
    $o['response'] = $resp
    $opts = [System.Text.Json.JsonSerializerOptions]::new()
    $opts.WriteIndented = $true
    $opts.Encoder = [System.Text.Encodings.Web.JavaScriptEncoder]::UnsafeRelaxedJsonEscaping
    $out = Protect-Text $o.ToJsonString($opts)
    foreach ($v in $script:Known) { if ($out.Contains($v)) { throw "a secret survived scrubbing in $Name; nothing written" } }
    [IO.File]::WriteAllText((Join-Path $script:EvidenceDir "$Name.json"), $out.Replace("`r`n", "`n") + "`n", [Text.UTF8Encoding]::new($false))
    "  saved $Name.json"
}

# Password grant for rp-veeam. Keeps the tokens in memory and returns the exchange.
function Connect-VeeamAdmin {
    $pw = Read-CredManPassword $script:CredTarget
    $r = Invoke-Veeam -Method POST -Path '/v8/token' -NoAuth -Form ([ordered]@{
        grant_type = 'password'; username = $script:VeeamUser; password = $pw; disable_antiforgery_token = 'true' })
    $pw = $null
    if ($r.Status -ne 200) { throw "login failed: $(Show-Call $r)" }
    Set-VeeamTokens $r
    $r
}

function Set-VeeamTokens($r) {
    $b = $r.Body | ConvertFrom-Json
    Register-Secret $b.access_token; Register-Secret $b.refresh_token
    $script:Access = $b.access_token; $script:Refresh = $b.refresh_token
}
function Get-VeeamAccessToken { $script:Access }
function Get-VeeamRefreshToken { $script:Refresh }

# Logs out the current token; never throws (used in finally blocks).
function Disconnect-VeeamAdmin {
    if (-not $script:Access) { return }
    try { $r = Invoke-Veeam -Method POST -Path '/v8/token/logout'; "logout -> $($r.Status)" } catch { "logout failed: $($_.Exception.Message)" }
    $script:Access = $null; $script:Refresh = $null
}

# Opens an explore session and returns the exchange. -Type Vex|Vesp|Veod. The id of every session
# it opens is remembered at once, so Stop-OpenedSessions (in a finally) can stop it whatever fails later.
$script:Opened = [System.Collections.Generic.List[string]]::new()
function New-ExploreSession([string]$Type, [string]$DateTime, [string]$RawJson) {
    $json = if ($RawJson) { $RawJson } else {
        [ordered]@{ dateTime = $DateTime; type = $Type; showDeleted = $false; showAllVersions = $false } | ConvertTo-Json }
    $r = Invoke-Veeam -Method POST -Path "/v8/Organizations/$LabOrgId/explore" -Json $json
    if ($r.Status -eq 201) { $script:Opened.Add(([regex]::Match($r.Body, '"id"\s*:\s*"([0-9a-f-]{36})"')).Groups[1].Value) }
    $r
}
function Stop-OpenedSessions { foreach ($id in $script:Opened) { Stop-ExploreSession $id } }

# Stops a session if it is still Working; never throws (used in finally blocks).
function Stop-ExploreSession([string]$SessionId) {
    if (-not $SessionId) { return }
    try {
        $s = Get-Body (Invoke-Veeam -Path "/v8/RestoreSessions/$SessionId")
        if ($s -and $s.state -eq 'Working') {
            $r = Invoke-Veeam -Method POST -Path "/v8/RestoreSessions/$SessionId/Stop"
            "stopped session $SessionId -> $($r.Status)"
        } else { "session $SessionId already $($s.state)" }
    } catch { "could not stop session ${SessionId}: $($_.Exception.Message)" }
}

# The latest restore point of the lab organisation: the newest backupTime, compared as instants.
# Returns id and backupTime as the raw strings Veeam sent, so backupTime can go straight into an
# explore body (a dateTime without an offset is refused with a 500).
function Get-LatestRestorePoint {
    $r = Invoke-Veeam -Path "/v8/RestorePoints?organizationId=$LabOrgId&limit=10000"
    if ($r.Status -ne 200) { throw "restore points: $(Show-Call $r)" }
    $doc = [System.Text.Json.JsonDocument]::Parse($r.Body)
    try {
        $doc.RootElement.GetProperty('results').EnumerateArray() | ForEach-Object {
            $t = $_.GetProperty('backupTime').GetString()
            [pscustomobject]@{ id = $_.GetProperty('id').GetString(); backupTime = $t; instant = [DateTimeOffset]::Parse($t, [Globalization.CultureInfo]::InvariantCulture) }
        } | Sort-Object instant -Descending | Select-Object -First 1
    } finally { $doc.Dispose() }
}

# Replaces the session and other volatile IDs in a path with placeholders, for evidence notes.
function Format-PathTemplate([string]$Path) {
    $Path -replace '/RestoreSessions/[0-9a-f-]{36}', '/RestoreSessions/{restoreSessionId}'
}

# Audit scrubbed evidence before a commit: no secret value and nothing secret-shaped may be in it.
#   pwsh -File audit-evidence.ps1 [-Path ..\veeam-lab\w2.4-*.json]
# Without -Path it audits every w1.4-*.json and w2.4-*.json in ..\veeam-lab.
# Checks every file against:
#   - the literal value of rp-veeam's password (read from Credential Manager) and of every token the
#     scripts registered in $env:RP_LAB_SECRET_DIR (DPAPI copies; see VeeamLab.ps1);
#   - JWT-shaped strings, bearer values, PFX/DER Base64 (MII...), PEM blocks;
#   - secret-named JSON keys or form fields whose value is not "[REDACTED]".
# Exits 1 and names the file and the rule on any hit; prints only the rule, never the matched value.
param([string[]]$Path = @("$PSScriptRoot\..\veeam-lab\w1.4-*.json", "$PSScriptRoot\..\veeam-lab\w2.4-*.json"))
. "$PSScriptRoot\VeeamLab.ps1"

$literals = [System.Collections.Generic.List[string]]::new()
$literals.Add((Read-CredManPassword $script:CredTarget))
if ($env:RP_LAB_SECRET_DIR -and (Test-Path $env:RP_LAB_SECRET_DIR)) {
    Get-ChildItem (Join-Path $env:RP_LAB_SECRET_DIR '*.xml') | ForEach-Object {
        $literals.Add([System.Net.NetworkCredential]::new('', (Import-Clixml $_.FullName)).Password)
    }
}
$rules = [ordered]@{
    'JWT'          = 'eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}'
    'bearer value' = '(?i)Bearer\s+(?!\[REDACTED)(?!error=)[A-Za-z0-9\-\._~\+/]{16,}'
    'PFX/DER Base64' = 'MII[A-Za-z0-9+/]{60,}'
    'PEM block'    = '-----BEGIN [A-Z ]+-----'
    'secret JSON key with a value' = '(?i)"(access_token|refresh_token|id_token|password|client_secret|assertion|applicationCertificate|applicationCertificatePassword|userPassword|token|device_code|userCode)"\s*:\s*(?!"\[REDACTED\]")(?!null)[^\s,}]'
    'secret form field with a value' = '(?i)\b(access_token|refresh_token|id_token|password|client_secret|assertion|device_code)=(?!\[REDACTED\])[^&\s"]'
}
$files = @($Path | ForEach-Object { Get-ChildItem $_ })
$bad = 0
foreach ($f in $files) {
    $t = [IO.File]::ReadAllText($f.FullName)
    foreach ($v in $literals) { if ($v -and $t.Contains($v)) { "HIT $($f.Name): a literal secret value"; $bad++ } }
    foreach ($k in $rules.Keys) { if ($t -match $rules[$k]) { "HIT $($f.Name): $k"; $bad++ } }
}
"audited $($files.Count) file(s) against $($literals.Count) literal secret(s) and $($rules.Count) patterns: $bad hit(s)"
if ($bad) { exit 1 }

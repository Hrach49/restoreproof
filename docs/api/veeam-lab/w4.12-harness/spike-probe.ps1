# W4.12 (#135) spike probe. Runs under the candidate service account (through RpSpikeHost).
# Prints the identity, reads GET /v8/Organizations, finds the organisation app's certificate in
# Cert:\LocalMachine\My by the thumbprint Veeam reports, checks the app ID, opens the private key,
# exports the certificate in memory only (and checks the export holds the key), then asks the
# Worker's own exporter (rptests "[spike_cert_export]") the same. Never prints a byte of any
# secret: only lengths and outcomes.
param(
    [string]$ExpectedAppId = '1fd2609d-1242-43fe-94b5-d58688a90bd6',
    [string]$OrgName = 'RestoreProofLab.onmicrosoft.com',
    [string]$Rptests = 'C:\restoreproof\worker\build\dev\rptests.exe'
)
$ErrorActionPreference = 'Stop'
function Say([string]$s) { Write-Output $s }

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = [Security.Principal.WindowsPrincipal]$id
Say "identity: $($id.Name)  (SID $($id.User.Value))"
Say "member of Administrators: $($pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"
Say "session: $((Get-Process -Id $PID).SessionId)  pwsh $($PSVersionTable.PSVersion)"
Say "groups: $((whoami /groups /fo csv | ConvertFrom-Csv | Where-Object { $_.'Group Name' -match 'SERVICE|Users|Administrators|SYSTEM|Everyone|Authenticated' } | ForEach-Object 'Group Name') -join '; ')"
Say "TEMP: $env:TEMP"

. 'C:\restoreproof\docs\api\veeam-m365\VeeamLab.ps1'
Connect-VeeamAdmin | Out-Null
Say "Veeam sign-in: ok as $script:VeeamUser"
$r = Invoke-Veeam -Path '/v8/Organizations'
Say (Show-Call $r)
if ($r.Status -ne 200) { throw "GET /v8/Organizations answered $($r.Status)" }
$org = @((Get-Body $r).results | Where-Object name -ceq $OrgName)
if ($org.Count -ne 1) { throw "organisation $($OrgName): $($org.Count) match(es)" }
$ex = $org[0].exchangeOnlineSettings; $sp = $org[0].sharePointOnlineSettings
Say "exchangeOnlineSettings:   applicationId $($ex.applicationId)  thumbprint $($ex.applicationCertificateThumbprint)"
Say "sharePointOnlineSettings: applicationId $($sp.applicationId)  thumbprint $($sp.applicationCertificateThumbprint)"
if ($ex.applicationId -cne $ExpectedAppId -or $sp.applicationId -cne $ExpectedAppId) { throw "the organisation's app is not $ExpectedAppId" }
if ($ex.applicationCertificateThumbprint -cne $sp.applicationCertificateThumbprint) { throw 'the two settings name different certificates' }
$thumb = [string]$ex.applicationCertificateThumbprint
Say "app ID check: ok ($ExpectedAppId in both settings)"
Disconnect-VeeamAdmin | Out-Null

$cert = @(Get-ChildItem Cert:\LocalMachine\My | Where-Object Thumbprint -ceq $thumb)
if ($cert.Count -ne 1) { throw "certificate ${thumb}: $($cert.Count) in Cert:\LocalMachine\My" }
$cert = $cert[0]
Say "certificate: found in Cert:\LocalMachine\My: $($cert.Subject), valid $($cert.NotBefore.ToUniversalTime().ToString('u')) to $($cert.NotAfter.ToUniversalTime().ToString('u')), HasPrivateKey $($cert.HasPrivateKey)"

# The key: open it (no UI), name its file, sign something with it.
$rsa = $null
try {
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    if ($null -eq $rsa) { throw 'GetRSAPrivateKey returned null' }
    $sig = $rsa.SignData([byte[]](1..16), [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    Say "private key: opened; a test signature of $($sig.Length) bytes succeeded"
    if ($rsa -is [System.Security.Cryptography.RSACng]) {
        $k = $rsa.Key
        Say "private key: provider '$($k.Provider.Provider)', export policy $($k.ExportPolicy), unique name $($k.UniqueName)"
        $f = @(@("C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\$($k.UniqueName)", "C:\ProgramData\Microsoft\Crypto\Keys\$($k.UniqueName)") | Where-Object { Test-Path -LiteralPath $_ })
        if ($f.Count) { Say "key file: $($f[0])"; try { Say "key file ACL: $(((Get-Acl -LiteralPath $f[0]).Access | ForEach-Object { "$($_.IdentityReference)=$($_.FileSystemRights)" }) -join '; ')" } catch { Say "key file ACL: can't be read by this account ($($_.Exception.Message.Trim()))" } }
        else { Say 'key file: not under the two machine key folders' }
    }
} catch {
    Say "private key: can't be opened: $($_.Exception.GetType().Name): $($_.Exception.Message.Trim()) (HResult 0x$($_.Exception.HResult.ToString('X8')))"
}

# In-memory export under a one-time password: bytes only, never a file.
if ($rsa) {
    $pwBytes = [byte[]]::new(32); [Security.Cryptography.RandomNumberGenerator]::Fill($pwBytes)
    $pw = [Convert]::ToBase64String($pwBytes)
    try {
        $pfx = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $pw)
        Say "in-memory export (.NET X509Certificate2.Export): $($pfx.Length) bytes of PFX, $([Convert]::ToBase64String($pfx).Length) Base64 characters; no file"
        $back = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($pfx, $pw, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
        Say "re-import (ephemeral): thumbprint matches $($back.Thumbprint -ceq $thumb), HasPrivateKey $($back.HasPrivateKey)"
        $back.Dispose()
        [Array]::Clear($pfx, 0, $pfx.Length)
    } catch {
        Say "in-memory export: failed: $($_.Exception.GetType().Name): $($_.Exception.Message.Trim()) (HResult 0x$($_.Exception.HResult.ToString('X8')))"
    }
    $pw = $null; [Array]::Clear($pwBytes, 0, 32)
}

# The Worker's own exporter (rp::make_local_machine_cert_exporter), through the hidden test.
Say '--- the Worker exporter (rptests "[spike_cert_export]")'
$env:RP_SPIKE_THUMBPRINT = $thumb
& $Rptests '[spike_cert_export]' 2>&1 | ForEach-Object { Say "  $_" }
Say "  rptests exit code: $LASTEXITCODE"
Remove-Item Env:RP_SPIKE_THUMBPRINT
Say 'probe done'

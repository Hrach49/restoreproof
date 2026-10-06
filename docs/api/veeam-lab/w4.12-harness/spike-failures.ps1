# W4.12 (#135): the three failure cases for `rpworker doctor`, as the Worker's exporter reports
# them (rptests "[spike_cert_export]", the hidden probe test) from the service account:
# a missing certificate (a thumbprint no certificate has), one whose key isn't exportable, and
# one that has expired. Both throwaway certificates were made by the elevated shell in
# Cert:\LocalMachine\My and are deleted at the end of the spike. Veeam's real certificate is
# never touched. Also shows what .NET's X509Certificate2.Export says, for 10-restore.ps1.
param(
    [Parameter(Mandatory)][string]$ExpiredThumb,
    [Parameter(Mandatory)][string]$NonExportableThumb,
    [string]$MissingThumb = '0123456789ABCDEF0123456789ABCDEF01234567',
    [string]$Rptests = 'C:\restoreproof\worker\build\dev\rptests.exe'
)
$ErrorActionPreference = 'Continue'
"identity: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)"
$cases = [ordered]@{ 'missing (no such thumbprint)' = $MissingThumb; 'not exportable' = $NonExportableThumb; 'expired' = $ExpiredThumb }
foreach ($name in $cases.Keys) {
    $t = $cases[$name]
    "--- case: $name  ($t)"
    $c = @(Get-ChildItem Cert:\LocalMachine\My | Where-Object Thumbprint -ceq $t)
    if ($c.Count) { "  store: $($c[0].Subject), valid to $($c[0].NotAfter.ToUniversalTime().ToString('u')), HasPrivateKey $($c[0].HasPrivateKey)" } else { '  store: no such certificate' }
    $env:RP_SPIKE_THUMBPRINT = $t
    $out = & $Rptests '[spike_cert_export]' 2>&1
    Remove-Item Env:RP_SPIKE_THUMBPRINT
    $out | Where-Object { "$_" -match '^spike export|passed|failed' } | ForEach-Object { "  worker: $_" }
    if ($c.Count) {
        try {
            $pfx = $c[0].Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, 'spike-throwaway')
            "  .NET Export: $($pfx.Length) bytes (an expired certificate exports: the Worker refuses it first)"
        } catch { "  .NET Export: $($_.Exception.GetType().Name): $($_.Exception.Message.Trim()) (HResult 0x$($_.Exception.HResult.ToString('X8')))" }
    }
}

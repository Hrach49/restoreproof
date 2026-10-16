# W7.1 (#80): the clean Windows Server 2022 VM for the installer's Done-when (docs/decisions.md
# 2026-10-16, "W7.1 (#80)", point 11 (a)): "the service registers within 2 minutes" on a machine
# that has never seen RestoreProof, against the Compose stack on this laptop. Hyper-V on this
# laptop; the Server 2022 evaluation ISO (free, 180 days) downloaded by hand. Run elevated.
#
#   pwsh -File docs\api\veeam-lab\w7.1-harness\w71-vm.ps1 -Iso <path to the ISO>      # make the VM, the host's port forwards
#   pwsh -File docs\api\veeam-lab\w7.1-harness\w71-vm.ps1 -Teardown                   # the VM and the forwards away
#
# What this script does on the host:
#   - a Generation 2 VM "rp-w71-server2022", 2 vCPU, 4 GB dynamic memory, a 40 GB dynamic VHDX
#     under -VmDir, the Default Switch, the ISO attached, Secure Boot on (Windows template);
#   - netsh portproxy: the host's Default Switch address, port 8443, to 127.0.0.1:8443 (Caddy),
#     and a firewall rule for it, so the VM reaches the stack as https://localhost:8443 through its
#     own forward below and Caddy's `localhost` certificate holds; the same for 4443 (Veeam's REST
#     on this laptop), which the installer pins by its certificate (-AllowRemoteVeeam, confirmed
#     with -VeeamThumbprint);
#   - prints what to do inside the VM once Windows is installed: the VM's own portproxy
#     127.0.0.1:8443 -> <host>:8443, the package copied in (a VM share or \\tsclient), Caddy's root
#     beside it, then the installer with -AllowRemoteVeeam -VeeamUrl https://<host>:4443
#     -VeeamThumbprint <the REST certificate's SHA-1> -CloudUrl https://localhost:8443
#     -CloudCaFile <root>, and "installed in <s> s" plus the Cloud's worker row as the evidence.
# Installing Windows itself, copying the package and running the installer in the VM are by hand:
# the evidence is the installer's text and the Cloud's rows, saved as
# docs\api\veeam-lab\w7.1-vm-done-when.txt by the person who ran it.
#Requires -Version 7.4
#Requires -RunAsAdministrator
param(
    [string]$Iso = '',
    [string]$VmDir = (Join-Path $env:LOCALAPPDATA 'RestoreProof\lab\w7.1-vm'),
    [string]$VmName = 'rp-w71-server2022',
    [switch]$Teardown
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ports = @(8443, 4443)
$hostAddress = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -like '*Default Switch*' } | Select-Object -First 1).IPAddress

if ($Teardown) {
    if (Get-VM -Name $VmName -ErrorAction SilentlyContinue) {
        if ((Get-VM -Name $VmName).State -ne 'Off') { Stop-VM -Name $VmName -Force }
        Remove-VM -Name $VmName -Force
        "VM $VmName removed (its VHDX under $VmDir is left for you to delete)"
    }
    foreach ($port in $ports) {
        & netsh interface portproxy delete v4tov4 listenaddress=$hostAddress listenport=$port | Out-Null
        Get-NetFirewallRule -DisplayName "RestoreProof W7.1 VM $port" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    }
    'port forwards and firewall rules removed'
    exit 0
}

if (-not $Iso -or -not (Test-Path -LiteralPath $Iso -PathType Leaf)) { throw 'give -Iso <the Windows Server 2022 evaluation ISO>' }
if (-not $hostAddress) { throw 'no Default Switch address: is Hyper-V on?' }
New-Item -ItemType Directory -Force $VmDir | Out-Null
$vhd = Join-Path $VmDir "$VmName.vhdx"
if (-not (Get-VM -Name $VmName -ErrorAction SilentlyContinue)) {
    New-VM -Name $VmName -Generation 2 -MemoryStartupBytes 4GB -NewVHDPath $vhd -NewVHDSizeBytes 40GB -SwitchName 'Default Switch' | Out-Null
    Set-VM -Name $VmName -ProcessorCount 2 -DynamicMemory -MemoryMinimumBytes 2GB -MemoryMaximumBytes 4GB -AutomaticCheckpointsEnabled $false
    Set-VMFirmware -VMName $VmName -EnableSecureBoot On -SecureBootTemplate 'MicrosoftWindows'
    Add-VMDvdDrive -VMName $VmName -Path $Iso
    $dvd = Get-VMDvdDrive -VMName $VmName
    Set-VMFirmware -VMName $VmName -FirstBootDevice $dvd
    "VM $VmName made: 2 vCPU, 2-4 GB, $vhd (40 GB dynamic), $Iso attached"
} else { "VM $VmName is there already" }
foreach ($port in $ports) {
    & netsh interface portproxy add v4tov4 listenaddress=$hostAddress listenport=$port connectaddress=127.0.0.1 connectport=$port | Out-Null
    if (-not (Get-NetFirewallRule -DisplayName "RestoreProof W7.1 VM $port" -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName "RestoreProof W7.1 VM $port" -Direction Inbound -Protocol TCP -LocalPort $port -Action Allow -Profile Any | Out-Null
    }
}
$rest = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq 'CN=Veeam Software' } | Select-Object -First 1
@"
host forwards: ${hostAddress}:8443 -> 127.0.0.1:8443 (Caddy), ${hostAddress}:4443 -> 127.0.0.1:4443 (Veeam REST); firewall rules added
Veeam's REST certificate on this laptop: $(if ($rest) { "thumbprint $($rest.Thumbprint)" } else { 'not found by subject; read it from the Veeam console' })

Next, by hand:
  1. Start-VM $VmName; vmconnect; install Windows Server 2022 (Standard, Desktop Experience), set the administrator password.
  2. In the VM, elevated PowerShell:
       netsh interface portproxy add v4tov4 listenaddress=127.0.0.1 listenport=8443 connectaddress=$hostAddress connectport=8443
     Install PowerShell 7.4 (winget install Microsoft.PowerShell, or the MSI).
  3. Copy the unpacked package and Caddy's root (docker compose cp proxy:/data/caddy/pki/authorities/local/root.crt cloud-ca.pem) into the VM.
  4. On the laptop: manage.py create-worker-token; in the VM, from pwsh (elevated), in the package folder:
       Unblock-File -Recurse .
       .\Install-RestoreProofWorker.ps1 -CloudUrl https://localhost:8443 -CloudCaFile .\cloud-ca.pem -AllowRemoteVeeam -VeeamUrl https://${hostAddress}:4443 -VeeamThumbprint <thumbprint above> -WorkerName w71-vm
     answer the Veeam account and its password (the laptop's rp-veeam) and the install token.
  5. The evidence: the installer's lines ("installed in <s> s"), `rpworker vault list` (names), icacls of C:\ProgramData\RestoreProof, the Cloud's worker row (last_seen_at after the first heartbeat); saved as docs\api\veeam-lab\w7.1-vm-done-when.txt.
  6. Tear down: this script with -Teardown.
"@

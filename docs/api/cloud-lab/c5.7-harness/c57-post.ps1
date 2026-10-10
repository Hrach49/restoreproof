# C5.7 (#60): steps (6) to (9) of the live Done-when by hand (c57-live.ps1's header), for a
# run folder the service already made and the API token c57-live.ps1 left under %TEMP%\rp-c57:
# the folder posted to POST /v1/results twice, the row, the items, the audit rows and the
# objects read back, verify_bundle.py on the objects, a tampered copy refused, the teardown.
#
#   pwsh -File docs\api\cloud-lab\c5.7-harness\c57-post.ps1 -RunId <uuid> -MspId <uuid> -Out <file>
param([string]$RunId, [string]$MspId, [string]$Out)
. (Join-Path $PSScriptRoot '..\..\veeam-lab\w4.8-harness\w48-run.ps1')
$Cloud = 'http://127.0.0.1:8000'
$CloudDir = Join-Path $script:Repo 'cloud'
$Rows = Join-Path $PSScriptRoot 'c57-rows.py'
$C57Temp = Join-Path $env:TEMP 'rp-c57'
$C57Kept = Join-Path $script:W48Root 'c57'
$TsaCa = Join-Path $script:Repo 'shared\tsa\tsa-ca.pem'
$pemPath = Join-Path $C57Temp 'worker.pub.pem'
function Invoke-Rows([string[]]$Arguments) { Push-Location $CloudDir; try { (& uv run python $Rows @Arguments 2>&1) -join "`n" } finally { Pop-Location } }
function Invoke-Curl([string[]]$Arguments) {
    $token = (Get-Content (Join-Path $C57Temp 'api-token.txt') -Raw).Trim()
    (& curl.exe -s -S --max-time 300 -H "Authorization: Bearer $token" @Arguments 2>&1) -join "`n"
}
$t = @()
$sent = Join-Path $script:W48Root "outbox\$RunId"
$result = Get-Content (Join-Path $sent 'result.json') -Raw | ConvertFrom-Json
$t += "result.json client: client_id $($result.client.client_id), tenant_id $($result.client.tenant_id), scope $($result.client.scope), resolved.organization.tenant_id $($result.client.resolved.organization.tenant_id)"
$t += "`n== (6) the folder posted by hand to POST /v1/results, as the Worker will post it =="
$parts = @('-F', 'result=@result.json;type=application/json', '-F', 'signature=@signature.json;type=application/json')
if (Test-Path (Join-Path $sent 'timestamp.tst')) { $parts += @('-F', 'timestamp=@timestamp.tst;type=application/octet-stream') }
foreach ($attachment in $result.attachments) { $parts += @('-F', "$($attachment.name)=@$($attachment.name);type=application/octet-stream") }
Push-Location $sent
try {
    $t += "curl.exe -s -i -X POST $Cloud/v1/results -H 'Authorization: Bearer <token>' $($parts -join ' ')"
    $t += "-- the first upload:`n$(Invoke-Curl (@('-i', '-X', 'POST', "$Cloud/v1/results") + $parts))"
    $t += "-- the same again:`n$(Invoke-Curl (@('-i', '-X', 'POST', "$Cloud/v1/results") + $parts))"
} finally { Pop-Location }
$t += "`n== (7) the row, the items, the audit rows, the objects =="
$t += (Invoke-Rows @('show', $MspId, $RunId))
$downloaded = Join-Path $C57Temp 'downloaded'
New-Item -ItemType Directory -Force $downloaded | Out-Null
$listScript = @"
import boto3
from pathlib import Path
s3 = boto3.client('s3', endpoint_url='http://127.0.0.1:9000', region_name='us-east-1', aws_access_key_id='local-only-minio', aws_secret_access_key='local-only-minio-secret')
prefix = 'msp/$MspId/runs/$RunId/'
for obj in s3.list_objects_v2(Bucket='restoreproof', Prefix=prefix)['Contents']:
    name = obj['Key'][len(prefix):]
    body = s3.get_object(Bucket='restoreproof', Key=obj['Key'])
    Path(r'$downloaded', name).write_bytes(body['Body'].read())
    print(f"{obj['Key']} {obj['Size']} {body['ContentType']}")
"@
$listFile = Join-Path $C57Temp 'list.py'
[IO.File]::WriteAllText($listFile, $listScript, [Text.UTF8Encoding]::new($false))
Push-Location $CloudDir
try { $t += "the bucket under msp/$MspId/runs/$RunId/ (boto3, the stack's local-only MinIO), each downloaded:`n$((& uv run python $listFile 2>&1) -join "`n")" } finally { Pop-Location }
$t += "-- verify_bundle.py on the downloaded objects:`n$((& uv run (Join-Path $script:Repo 'shared\tools\verify_bundle.py') $downloaded --public-key $pemPath --tsa-ca $TsaCa --schemas (Join-Path $script:Repo 'shared\schemas') 2>&1) -join ' | ') (exit code $LASTEXITCODE)"
$t += "-- the same folder, rpworker signer verify:`n$(Invoke-W48 @('signer', 'verify', $downloaded, '--public-key', $pemPath, '--tsa-ca', $TsaCa))"
$t += "result.json sha256 as stored: $((Get-FileHash (Join-Path $downloaded 'result.json') -Algorithm SHA256).Hash.ToLower())"
$t += "`n== (8) a tampered copy: one byte of items.csv =="
$tampered = Join-Path $C57Temp 'tampered'
Copy-Item $sent $tampered -Recurse -Force
$bytes = [IO.File]::ReadAllBytes((Join-Path $tampered 'items.csv')); $bytes[-1] = $bytes[-1] -bxor 1; [IO.File]::WriteAllBytes((Join-Path $tampered 'items.csv'), $bytes)
Push-Location $tampered
try { $t += "-- POST /v1/results with items.csv changed:`n$(Invoke-Curl (@('-i', '-X', 'POST', "$Cloud/v1/results") + $parts))" } finally { Pop-Location }
$t += ((Invoke-Rows @('show', $MspId, $RunId)) -split "`n" | Where-Object { $_ -match 'state:|bundle_sha256|audit_log|result\.' }) -join "`n"
Push-Location $CloudDir
try { $t += "the bucket afterwards: $((& uv run python -c "import boto3; s3 = boto3.client('s3', endpoint_url='http://127.0.0.1:9000', region_name='us-east-1', aws_access_key_id='local-only-minio', aws_secret_access_key='local-only-minio-secret'); print(len(s3.list_objects_v2(Bucket='restoreproof', Prefix='msp/$MspId/runs/$RunId/')['Contents']), 'object(s)')" 2>&1) -join ' ')" } finally { Pop-Location }
$t += "`n== (9) the teardown =="
New-Item -ItemType Directory -Force $C57Kept | Out-Null
Move-Item $sent (Join-Path $C57Kept $RunId) -Force
$t += "outbox\$RunId moved to $C57Kept (outside the repo); the stack's rows left"
$t += (Remove-W48Harness)
$t += "sc query: $((sc.exe query $script:W48Service 2>&1) -join ' ')"
Remove-Item -Recurse -Force $C57Temp -ErrorAction SilentlyContinue
$t += "$C57Temp removed (the tokens, the PEM, the downloaded and tampered copies)"
$text = ($t -join "`n").Replace("`r`n", "`n")
foreach ($s in Get-W48Secrets) { if ($s -and $text.Contains($s)) { throw 'a secret survived; nothing written' } }
if ($text -match 'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.' -or $text -match 'MII[A-Za-z0-9+/]{60,}' -or $text -match 'PRIVATE KEY') { throw 'a token or key-shaped value; nothing written' }
[IO.File]::WriteAllText($Out, $text + "`n", [Text.UTF8Encoding]::new($false))
"saved $Out"

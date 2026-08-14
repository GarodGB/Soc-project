<#
  Fix-WazuhDiskBlock.ps1
  ----------------------
  Clears the OpenSearch flood-stage read-only block on the Wazuh indexer.

  WHY YOU NEED THIS:
  The lab VM disk sits near full. When OpenSearch sees the disk cross 95%
  (flood stage) it sets EVERY wazuh-alerts index to read-only and Wazuh can
  no longer write new alerts. That block does NOT auto-clear when the disk
  drops back down, so after a reboot the platform still reports
  "0 detected / Wazuh not detectable". This script clears the block and
  raises the watermark so a small spike won't re-trip it.

  USAGE (from the project folder, on the Windows attack host):
      powershell -ExecutionPolicy Bypass -File .\Fix-WazuhDiskBlock.ps1

  Run it whenever you turn the PC back on and see the "Wazuh pipeline
  problem" banner. It is safe to run repeatedly.
#>

# --- Read indexer creds from .env ---
$envPath = Join-Path $PSScriptRoot ".env"
$cfg = @{}
Get-Content $envPath | ForEach-Object {
    if ($_ -match '^\s*([^#=]+)=(.*)$') { $cfg[$matches[1].Trim()] = $matches[2].Trim() }
}
$indexer = $cfg['INDEXER_URL']
$user    = $cfg['INDEXER_USER']
$pass    = $cfg['INDEXER_PASSWORD']

$pair    = "$($user):$($pass)"
$b64     = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($pair))
$headers = @{ Authorization = "Basic $b64" }

# PowerShell 5.1: ignore the lab's self-signed cert
add-type @"
using System.Net; using System.Security.Cryptography.X509Certificates;
public class TrustAll : ICertificatePolicy {
  public bool CheckValidationResult(ServicePoint sp, X509Certificate c, WebRequest r, int p) { return true; }
}
"@ -ErrorAction SilentlyContinue
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAll
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

Write-Host "Indexer: $indexer" -ForegroundColor Cyan

# --- 1) Raise watermarks so a small spike won't re-trip the block ---
$wm = @{
  persistent = @{
    "cluster.routing.allocation.disk.watermark.low"         = "97%"
    "cluster.routing.allocation.disk.watermark.high"        = "98%"
    "cluster.routing.allocation.disk.watermark.flood_stage" = "99%"
  }
} | ConvertTo-Json
Invoke-RestMethod -Uri "$indexer/_cluster/settings" -Method Put -Headers $headers `
    -ContentType "application/json" -Body $wm | Out-Null
Write-Host "[1/2] Watermarks raised (low 97 / high 98 / flood 99)." -ForegroundColor Green

# --- 2) Clear the read-only block on every alert index ---
$body = '{"index.blocks.read_only_allow_delete": null}'
$r = Invoke-RestMethod -Uri "$indexer/wazuh-alerts-*/_settings" -Method Put -Headers $headers `
    -ContentType "application/json" -Body $body
Write-Host "[2/2] Read-only block cleared. acknowledged=$($r.acknowledged)" -ForegroundColor Green

# --- Report current disk usage so you know how close you are ---
$alloc = Invoke-RestMethod -Uri "$indexer/_cat/allocation?format=json" -Headers $headers
foreach ($n in $alloc) {
    Write-Host ("Disk: {0}% used  ({1} free of {2})" -f $n.'disk.percent', $n.'disk.avail', $n.'disk.total') -ForegroundColor Yellow
}
Write-Host "Done. Refresh the dashboard and re-run validation." -ForegroundColor Cyan

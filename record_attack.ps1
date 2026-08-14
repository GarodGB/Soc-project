# ABSEGA record helper  ->  run on [DEV] Windows PowerShell
# usage:
#   .\record_attack.ps1 -TestId AD-T1136.002-PRIV-USER-CREATE -File privuser.json -Wazuh 60122 -SigmaSearch "4720"
#   -Wazuh 0        if no Wazuh rule fired (logtest showed no rule.id)
#   -Sigma <id>     force a specific Sigma detection id (overrides -SigmaSearch)
#   -SigmaSearch    text/EID to auto-pick the first matching Sigma rule
param(
  [Parameter(Mandatory=$true)][string]$TestId,
  [Parameter(Mandatory=$true)][string]$File,
  [int]$Wazuh = 0,
  [int]$Sigma = 0,
  [string]$SigmaSearch = "",
  [string]$Notes = "auto-recorded via record_attack.ps1"
)

$API   = "http://127.0.0.1:8000"
$local = "D:\ABSEGA\VMShare\$File"

Write-Host "== pulling evidence from Wazuh ==" -ForegroundColor Cyan
scp "vboxuser@192.168.56.101:/home/vboxuser/$File" $local

$lines = Get-Content $local | Where-Object { $_.Trim() }
Write-Host "evidence lines: $($lines.Count)"
if ($lines.Count -eq 0) { Write-Host "no evidence - aborting" -ForegroundColor Red; return }

# create run
$body = @{ test_id=$TestId; source_host="WIN11"; target_host="DC01"; source_ip="10.10.10.11"; status="running"; notes=$Notes } | ConvertTo-Json
$run  = irm -Method Post "$API/api/ad-validation/runs" -ContentType application/json -Body $body
$rid  = $run.run_id
Write-Host "run: $rid"

# post each event
foreach ($l in $lines) {
  $obj = $l | ConvertFrom-Json
  irm -Method Post "$API/api/ad-validation/runs/$rid/evidence" -ContentType application/json -Body (@{event=$obj} | ConvertTo-Json -Depth 40) | Out-Null
}
Write-Host "evidence recorded"

# auto-find Sigma if not given
if ($Sigma -eq 0 -and $SigmaSearch -ne "") {
  $dets = irm "$API/api/detections/?limit=5000"
  $hit  = $dets | Where-Object { $_.sigma_rule -match $SigmaSearch } | Select-Object -First 1
  if ($hit) { $Sigma = [int]$hit.id; Write-Host "auto-picked Sigma $Sigma : $($hit.title)" -ForegroundColor Yellow }
  else { Write-Host "no Sigma matched '$SigmaSearch'" -ForegroundColor DarkYellow }
}

# link a comparison, then recheck (authoritative behavioral verdict)
if ($Wazuh -gt 0 -and $Sigma -gt 0) {
  irm -Method Post "$API/api/ad-validation/runs/$rid/compare" -ContentType application/json -Body (@{wazuh_rule_id=$Wazuh; detection_id=$Sigma} | ConvertTo-Json) | Out-Null
} elseif ($Sigma -gt 0) {
  irm -Method Post "$API/api/ad-validation/runs/$rid/compare-wazuh-gap" -ContentType application/json -Body (@{detection_id=$Sigma} | ConvertTo-Json) | Out-Null
}
$rc = irm -Method Post "$API/api/ad-validation/runs/$rid/recheck"
Write-Host "== recheck ==" -ForegroundColor Cyan
$rc | ConvertTo-Json -Depth 6

Write-Host "== verdict ==" -ForegroundColor Green
irm "$API/api/ad-catalog/attacks/$TestId" | Select-Object attack_key, latest_verdict, wazuh_result, sigma_result, telemetry_readiness

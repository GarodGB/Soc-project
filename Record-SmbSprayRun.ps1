<#
===============================================================================
 ABSEGA | SMB password spray (T1110.003) FORMAL VALIDATION RECORDER
===============================================================================
 Auto-detects the recording path:
   * Wazuh rule fired (event carries rule.id in catalog)  -> validate-event
       records the full comparison (both_fired / wazuh_only).
   * No Wazuh rule fired (raw-only archive event)          -> compare-wazuh-gap
       records SIGMA_ONLY / NO_DETECTION_IN_EITHER.
 Reuses existing endpoints only. No second evaluator. No invented rule IDs.

 Run from:  D:\ABSEGA\Soc-project-latest
 Requires:  python run.py live on http://127.0.0.1:8000
 Requires:  primary_raw_event.json present in the project root (SCP'd from Ubuntu).
===============================================================================
#>

$ErrorActionPreference = "Stop"

$RootUrl = "http://127.0.0.1:8000"
$BaseUrl = "$RootUrl/api"

$EvidenceFile     = Join-Path $PSScriptRoot "primary_raw_event.json"
$TestId           = "AD-T1110.003-SMB-SPRAY"
$SigmaDetectionId = 179
$BehaviorLabel    = "SMB password spray"
$Technique        = "T1110.003"
$ExpectedEventIds = @("4625","4776")
$SourceHost       = "WIN11"
$SourceIp         = "10.10.10.11"

$LoginEmail    = "admin@absega.local"
$LoginPassword = "absega123"

function Invoke-JsonPost {
    param([Parameter(Mandatory=$true)][string]$Uri,[Parameter(Mandatory=$true)][object]$Body)
    $JsonBody = $Body | ConvertTo-Json -Depth 100 -Compress
    try { return Invoke-RestMethod -Uri $Uri -Method Post -ContentType "application/json" -Body $JsonBody }
    catch {
        $d = $_.ErrorDetails.Message; if ([string]::IsNullOrWhiteSpace($d)) { $d = $_.Exception.Message }
        throw "POST $Uri failed: $d"
    }
}
function Get-ResponseRunId {
    param([object]$Response,[Parameter(Mandatory=$true)][string]$Fallback)
    if ($null -ne $Response) {
        foreach ($n in @("run_id","id")) {
            $p = $Response.PSObject.Properties[$n]
            if ($null -ne $p -and -not [string]::IsNullOrWhiteSpace([string]$p.Value)) { return [string]$p.Value }
        }
    }
    return $Fallback
}
function Map-FinalVerdict {
    param([string]$Raw,[bool]$WazuhFired)
    switch -Regex ($Raw) {
        "both_fired_on_same_event"        { return "VERIFIED_OVERLAP" }
        "wazuh_only_on_event"             { return "WAZUH_ONLY" }
        "sigma_matched_raw_event|SIGMA_ONLY" { return "SIGMA_ONLY" }
        "sigma_missed_raw_event|NO_DETECTION_IN_EITHER" { return "NO_DETECTION_IN_EITHER" }
        "EVALUATOR_UNSUPPORTED"           { return "EVALUATOR_UNSUPPORTED" }
        "EVALUATOR_INVALID_RULE|PARSER"   { return "PARSER_GAP" }
        default { if ($WazuhFired) { return "WAZUH_ONLY" } else { return "NO_DETECTION_IN_EITHER" } }
    }
}

Write-Host ""
Write-Host "[1/6] Backend + authentication..." -ForegroundColor Cyan
$Health = Invoke-RestMethod -Uri "$BaseUrl/ad-validation/health" -Method Get
if ($Health.status -ne "ok") { throw "AD Validation health not OK: $($Health.status)" }
$Auth = Invoke-JsonPost -Uri "$BaseUrl/auth/login" -Body @{ email=$LoginEmail; password=$LoginPassword }
if ($Auth.success -ne $true) { throw "Authentication did not return success=true." }
Write-Host "      authenticated." -ForegroundColor Green

Write-Host "[2/6] Loading primary evidence: primary_raw_event.json ..." -ForegroundColor Cyan
if (-not (Test-Path -LiteralPath $EvidenceFile -PathType Leaf)) { throw "Evidence not found: $EvidenceFile" }
$RawJson  = Get-Content -LiteralPath $EvidenceFile -Raw -Encoding UTF8
$RawEvent = $RawJson | ConvertFrom-Json

$EventId  = [string]$RawEvent.data.win.system.eventID
$Computer = [string]$RawEvent.data.win.system.computer
$Agent    = [string]$RawEvent.agent.name
$FiredRuleProp = $RawEvent.PSObject.Properties["rule"]
$FiredRuleId   = $null
if ($null -ne $FiredRuleProp -and $null -ne $FiredRuleProp.Value) { $FiredRuleId = [string]$RawEvent.rule.id }

if ($ExpectedEventIds -notcontains $EventId) {
    Write-Host "      [WARN] Event ID $EventId not in expected set ($($ExpectedEventIds -join ',')). Continuing." -ForegroundColor Yellow
}
$TargetHost = "DC01"; if (-not [string]::IsNullOrWhiteSpace($Computer)) { $TargetHost = ($Computer -split "\.")[0] }
Write-Host "      Event ID:         $EventId"
Write-Host "      Computer/Agent:   $Computer / $Agent"
Write-Host ("      Wazuh fired rule: " + $(if ($FiredRuleId) { $FiredRuleId } else { "NONE (raw-only)" }))
Write-Host "      loaded." -ForegroundColor Green

Write-Host "[3/6] Creating validation run..." -ForegroundColor Cyan
$RunTs  = Get-Date -Format "yyyyMMdd-HHmmss"
$ReqRun = "RUN-" + ($Technique -replace "\.","-") + "-$RunTs"
$RunResp = Invoke-JsonPost -Uri "$BaseUrl/ad-validation/runs" -Body @{
    test_id=$TestId; run_id=$ReqRun; source_host=$SourceHost; target_host=$TargetHost;
    source_ip=$SourceIp; status="completed";
    notes=("$BehaviorLabel executed inside absega.local. Primary real event primary_raw_event.json collected from Wazuh. " +
           "Recording path auto-detected from fired-rule presence. telemetry_gap=false.")
}
$RunId = Get-ResponseRunId -Response $RunResp -Fallback $ReqRun
Write-Host "      run: $RunId" -ForegroundColor Green

Write-Host "[4/6] Attaching untouched evidence..." -ForegroundColor Cyan
$Ev = Invoke-JsonPost -Uri "$BaseUrl/ad-validation/runs/$RunId/evidence" -Body @{
    event=$RawEvent; evidence_type="wazuh_raw_event"; original_filename="primary_raw_event.json"
}
Write-Host "      evidence attached (wazuh_rule_id = $($Ev.wazuh_rule_id))." -ForegroundColor Green

Write-Host "[5/6] Evaluating Sigma $SigmaDetectionId on the real event..." -ForegroundColor Cyan
$Vr = Invoke-JsonPost -Uri "$BaseUrl/ad-validation/validate-event" -Body @{
    detection_id=$SigmaDetectionId; event=$RawEvent
}
$WazuhFired = [bool]$Vr.wazuh_fired
$RawVerdict = [string]$Vr.behavioral_verdict
Write-Host "      sigma_matched:     $($Vr.sigma_matched)"
Write-Host "      wazuh_fired:       $WazuhFired"
Write-Host "      sigma_status:      $($Vr.sigma_status)"
Write-Host "      validate verdict:  $RawVerdict"

if ($null -ne $Vr.comparison_id) {
    # Fired-rule path: validate-event already recorded the comparison.
    Write-Host "      recorded via validate-event (comparison id=$($Vr.comparison_id))." -ForegroundColor Green
    $FinalRaw = $RawVerdict
} elseif (-not $WazuhFired) {
    # Raw-only path: no rule fired -> gap endpoint.
    Write-Host "[5b] No rule fired - recording via compare-wazuh-gap..." -ForegroundColor Cyan
    $Gap = Invoke-JsonPost -Uri "$BaseUrl/ad-validation/runs/$RunId/compare-wazuh-gap" -Body @{ detection_id=$SigmaDetectionId }
    Write-Host "      gap comparison id=$($Gap.comparison_id) -> $($Gap.behavioral_verdict)" -ForegroundColor Green
    $FinalRaw = [string]$Gap.behavioral_verdict
} else {
    Write-Host "      [WARN] Wazuh fired rule $FiredRuleId but it was not in the catalog; no comparison stored by validate-event." -ForegroundColor Yellow
    Write-Host "      [WARN] Re-run rule sync, or record this as WAZUH_ONLY manually in Phase H." -ForegroundColor Yellow
    $FinalRaw = $RawVerdict
}

$FinalVerdict = Map-FinalVerdict -Raw $FinalRaw -WazuhFired $WazuhFired

Write-Host "[6/6] Exporting + verifying..." -ForegroundColor Cyan
$Csv = Join-Path $PSScriptRoot ("ABSEGA_" + ($Technique -replace "\.","_") + "_" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".csv")
Invoke-RestMethod -Uri "$BaseUrl/ad-validation/export.csv" -Method Get -OutFile $Csv
$Detail = Invoke-RestMethod -Uri "$BaseUrl/ad-validation/runs/$RunId" -Method Get
if ([int]$Detail.evidence_count -lt 1) { throw "Run has no stored evidence." }

Write-Host ""
Write-Host "==============================================================" -ForegroundColor Green
Write-Host " $BehaviorLabel VALIDATION COMPLETE" -ForegroundColor Green
Write-Host "==============================================================" -ForegroundColor Green
Write-Host " Run ID:            $RunId"
Write-Host " Technique:         $Technique"
Write-Host " Primary event ID:  $EventId"
Write-Host " Wazuh fired rule:  $(if($FiredRuleId){$FiredRuleId}else{'NONE'})"
Write-Host " Sigma detection:   $SigmaDetectionId"
Write-Host " Sigma matched:     $($Vr.sigma_matched)"
Write-Host " Raw verdict:       $FinalRaw"
Write-Host " FINAL VERDICT:     $FinalVerdict"
Write-Host " Evidence objects:  $($Detail.evidence_count)"
Write-Host " Comparison objs:   $($Detail.comparison_count)"
Write-Host " CSV:               $Csv"
Write-Host "==============================================================" -ForegroundColor Green
Write-Host ""

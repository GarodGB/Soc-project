<#
===============================================================================
 ABSEGA | AS-REP ROASTING (T1558.004) FORMAL VALIDATION RECORDER
===============================================================================

 Purpose:
   1. Confirm the ABSEGA backend and authentication endpoint.
   2. Validate raw_4768_event.json (real Windows Security Event 4768).
   3. Create the formal AS-REP validation run (executed = completed).
   4. Store the untouched Wazuh archive event as evidence (no rule fired).
   5. Prove Sigma detection 142 matches the SAME real event.
   6. Record SIGMA_ONLY / WAZUH_DETECTION_GAP via the wazuh-gap endpoint.
   7. Export and verify the final CSV.

 Run from:
   D:\ABSEGA\Soc-project-latest

 Requirement:
   python run.py must already be running on http://127.0.0.1:8000
   The compare-wazuh-gap endpoint must be present in app/routes/ad_validation.py
===============================================================================
#>

$ErrorActionPreference = "Stop"

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

$RootUrl = "http://127.0.0.1:8000"
$BaseUrl = "$RootUrl/api"

$EvidenceFile = Join-Path $PSScriptRoot "raw_4768_event.json"

$AsRepTestId      = "AD-T1558.004-ASREP-ROAST"
$SigmaDetectionId = 142

$LoginEmail    = "admin@absega.local"
$LoginPassword = "absega123"

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

function Invoke-JsonPost {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][object]$Body
    )
    $JsonBody = $Body | ConvertTo-Json -Depth 100 -Compress
    try {
        return Invoke-RestMethod -Uri $Uri -Method Post `
            -ContentType "application/json" -Body $JsonBody
    }
    catch {
        $detail = $_.ErrorDetails.Message
        if ([string]::IsNullOrWhiteSpace($detail)) { $detail = $_.Exception.Message }
        throw "POST $Uri failed: $detail"
    }
}

function Get-ResponseRunId {
    param([object]$Response, [Parameter(Mandatory=$true)][string]$Fallback)
    if ($null -ne $Response) {
        foreach ($Name in @("run_id","id")) {
            $p = $Response.PSObject.Properties[$Name]
            if ($null -ne $p -and -not [string]::IsNullOrWhiteSpace([string]$p.Value)) {
                return [string]$p.Value
            }
        }
        $runProp = $Response.PSObject.Properties["run"]
        if ($null -ne $runProp -and $null -ne $runProp.Value) {
            $nested = $runProp.Value.PSObject.Properties["run_id"]
            if ($null -ne $nested) { return [string]$nested.Value }
        }
    }
    return $Fallback
}

# =============================================================================
# 1/7 - Backend + authentication
# =============================================================================

Write-Host ""
Write-Host "[1/7] Checking backend and authentication..." -ForegroundColor Cyan

$Health = Invoke-RestMethod -Uri "$BaseUrl/ad-validation/health" -Method Get
if ($Health.status -ne "ok") {
    throw "AD Validation health is not OK. Returned status: $($Health.status)"
}

$Authentication = Invoke-JsonPost -Uri "$BaseUrl/auth/login" `
    -Body @{ email = $LoginEmail; password = $LoginPassword }
if ($Authentication.success -ne $true) {
    throw "Authentication did not return success=true."
}
Write-Host "      authentication successful." -ForegroundColor Green

# =============================================================================
# 2/7 - Load and validate the untouched 4768 evidence
# =============================================================================

Write-Host "[2/7] Validating raw_4768_event.json..." -ForegroundColor Cyan

if (-not (Test-Path -LiteralPath $EvidenceFile -PathType Leaf)) {
    throw "Evidence file was not found: $EvidenceFile"
}

$RawJson  = Get-Content -LiteralPath $EvidenceFile -Raw -Encoding UTF8
$RawEvent = $RawJson | ConvertFrom-Json

$EventId        = [string]$RawEvent.data.win.system.eventID
$Channel        = [string]$RawEvent.data.win.system.channel
$Computer       = [string]$RawEvent.data.win.system.computer
$EventTimestamp = [string]$RawEvent.timestamp
$AgentName      = [string]$RawEvent.agent.name
$ServiceName    = [string]$RawEvent.data.win.eventdata.serviceName
$EncryptionType = [string]$RawEvent.data.win.eventdata.ticketEncryptionType
$PreAuthType    = [string]$RawEvent.data.win.eventdata.preAuthType
$TargetUser     = [string]$RawEvent.data.win.eventdata.targetUserName

if ($EventId       -ne "4768")      { throw "Expected Event ID 4768, found: $EventId" }
if ($ServiceName   -ne "krbtgt")    { throw "Expected ServiceName krbtgt, found: $ServiceName" }
if ($EncryptionType-ne "0x17")      { throw "Expected TicketEncryptionType 0x17, found: $EncryptionType" }
if ($PreAuthType   -ne "0")         { throw "Expected PreAuthType 0, found: $PreAuthType" }
if ($TargetUser    -ne "asrep_lab") { throw "Expected targetUserName asrep_lab, found: $TargetUser" }

# The archive event must carry NO fired Wazuh rule (pure detection gap).
$RuleProp = $RawEvent.PSObject.Properties["rule"]
if ($null -ne $RuleProp -and $null -ne $RuleProp.Value) {
    throw "Event unexpectedly carries a fired Wazuh rule. Expected none for AS-REP."
}

$TargetHost = "DC01"
if (-not [string]::IsNullOrWhiteSpace($Computer)) {
    $TargetHost = ($Computer -split "\.")[0]
}

Write-Host "      Event ID:            $EventId"
Write-Host "      Target user:         $TargetUser"
Write-Host "      Service name:        $ServiceName"
Write-Host "      Encryption type:     $EncryptionType"
Write-Host "      Pre-auth type:       $PreAuthType  (roastable)"
Write-Host "      Wazuh rule fired:    NONE"
Write-Host "      evidence validated." -ForegroundColor Green

# =============================================================================
# 3/7 - Create the AS-REP validation run
# =============================================================================

Write-Host "[3/7] Creating AS-REP validation run..." -ForegroundColor Cyan

$RunTimestamp   = Get-Date -Format "yyyyMMdd-HHmmss"
$RequestedRunId = "RUN-T1558-004-$RunTimestamp"

$RunResponse = Invoke-JsonPost -Uri "$BaseUrl/ad-validation/runs" -Body @{
    test_id     = $AsRepTestId
    run_id      = $RequestedRunId
    source_host = "WIN11"
    target_host = $TargetHost
    source_ip   = "10.10.10.11"
    status      = "completed"
    notes       = ("Executed AS-REP roast against asrep_lab (DoesNotRequirePreAuth=True). " +
                   "Real Windows Security Event 4768 collected from Wazuh archives. " +
                   "No Wazuh rule fired and no Kerberos 4768 rule exists in the catalog. " +
                   "Sigma detection 142 matched the same real event. " +
                   "Formal result: SIGMA_ONLY / WAZUH_DETECTION_GAP. telemetry_gap=false.")
}

$RunId = Get-ResponseRunId -Response $RunResponse -Fallback $RequestedRunId
Write-Host "      run created: $RunId" -ForegroundColor Green

# =============================================================================
# 4/7 - Attach the untouched raw event
# =============================================================================

Write-Host "[4/7] Attaching untouched 4768 evidence..." -ForegroundColor Cyan

$EvidenceResponse = Invoke-JsonPost -Uri "$BaseUrl/ad-validation/runs/$RunId/evidence" -Body @{
    event             = $RawEvent
    evidence_type     = "wazuh_raw_event"
    original_filename = "raw_4768_event.json"
}

if ($null -ne $EvidenceResponse.wazuh_rule_id) {
    throw "Evidence unexpectedly resolved a Wazuh rule id: $($EvidenceResponse.wazuh_rule_id)"
}
Write-Host "      evidence attached (wazuh_rule_id = null)." -ForegroundColor Green

# =============================================================================
# 5/7 - Prove Sigma 142 matches the SAME real event
# =============================================================================

Write-Host "[5/7] Evaluating Sigma 142 on the real 4768 event..." -ForegroundColor Cyan

$ValidationResult = Invoke-JsonPost -Uri "$BaseUrl/ad-validation/validate-event" -Body @{
    detection_id = $SigmaDetectionId
    event        = $RawEvent
}

if ($ValidationResult.sigma_matched -ne $true) {
    $j = $ValidationResult | ConvertTo-Json -Depth 30
    throw "Sigma 142 did not match the real event. Cannot record SIGMA_ONLY.`n$j"
}
if ([bool]$ValidationResult.wazuh_fired) {
    throw "Evaluator reported wazuh_fired=true. Expected false for AS-REP."
}
Write-Host "      Sigma 142 matched:   true"  -ForegroundColor Green
Write-Host "      Wazuh fired:         false" -ForegroundColor Green

# =============================================================================
# 6/7 - Record SIGMA_ONLY via the wazuh-gap comparison endpoint
# =============================================================================

Write-Host "[6/7] Recording SIGMA_ONLY / WAZUH_DETECTION_GAP..." -ForegroundColor Cyan

$GapResult = Invoke-JsonPost -Uri "$BaseUrl/ad-validation/runs/$RunId/compare-wazuh-gap" -Body @{
    detection_id = $SigmaDetectionId
}

if ($GapResult.behavioral_verdict -ne "SIGMA_ONLY") {
    $j = $GapResult | ConvertTo-Json -Depth 30
    throw "Gap comparison did not return SIGMA_ONLY.`n$j"
}
Write-Host "      comparison saved: id=$($GapResult.comparison_id)" -ForegroundColor Green
Write-Host "      behavioral verdict:  $($GapResult.behavioral_verdict)" -ForegroundColor Green

# =============================================================================
# 7/7 - Export and verify
# =============================================================================

Write-Host "[7/7] Exporting and verifying..." -ForegroundColor Cyan

$OutputCsv = Join-Path $PSScriptRoot ("ABSEGA_AsRep_Validation_" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".csv")
Invoke-RestMethod -Uri "$BaseUrl/ad-validation/export.csv" -Method Get -OutFile $OutputCsv

$RunDetail = Invoke-RestMethod -Uri "$BaseUrl/ad-validation/runs/$RunId" -Method Get

if ([int]$RunDetail.evidence_count -lt 1) {
    throw "AS-REP run has no stored evidence."
}

$LatestComparison = $RunDetail.comparisons |
    Sort-Object { [int]$_.comparison_id } -Descending |
    Select-Object -First 1

if ($null -eq $LatestComparison) { throw "AS-REP run has no stored comparison." }
if ([bool]$LatestComparison.wazuh_fired) { throw "Stored comparison shows wazuh_fired=true." }
if (-not [bool]$LatestComparison.sigma_matched) { throw "Stored comparison shows sigma_matched=false." }
if ([string]$LatestComparison.behavioral_verdict -ne "SIGMA_ONLY") {
    throw "Stored behavioral verdict is not SIGMA_ONLY: $($LatestComparison.behavioral_verdict)"
}

$CsvItem = Get-Item -LiteralPath $OutputCsv
if ($CsvItem.Length -le 0) { throw "The exported CSV is empty." }

Write-Host ""
Write-Host "==============================================================" -ForegroundColor Green
Write-Host " AS-REP VALIDATION COMPLETE" -ForegroundColor Green
Write-Host "==============================================================" -ForegroundColor Green
Write-Host " AS-REP run:           $RunId"
Write-Host " Technique:            T1558.004"
Write-Host " Target user:          asrep_lab"
Write-Host " Telemetry present:    True"
Write-Host " Sigma 142 matched:    True"
Write-Host " Wazuh detection:      False (no rule fired, none in catalog)"
Write-Host " Verdict:              SIGMA_ONLY"
Write-Host " Gap class:            WAZUH_DETECTION_GAP"
Write-Host " Telemetry gap:        False"
Write-Host ""
Write-Host " Evidence objects:     $($RunDetail.evidence_count)"
Write-Host " Comparison objects:   $($RunDetail.comparison_count)"
Write-Host " CSV:                  $OutputCsv"
Write-Host "==============================================================" -ForegroundColor Green
Write-Host ""

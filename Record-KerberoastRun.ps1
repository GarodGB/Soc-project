<#
===============================================================================
 ABSEGA | STEP 21 | FORMAL KERBEROAST VALIDATION RECORDER
===============================================================================

 Purpose:
   1. Confirm the ABSEGA backend and authentication endpoint.
   2. Validate raw_4769_event.json.
   3. Create the formal Kerberoast validation run.
   4. Store the untouched Wazuh event as evidence.
   5. Evaluate Sigma detection 196 against the Windows event fields.
   6. Record SIGMA_ONLY / WAZUH_DETECTION_GAP.
   7. Record AS-REP as NOT_EXECUTED / NO_TEST_EVIDENCE.
   8. Export and verify the final CSV.

 Run from:
   D:\ABSEGA\Soc-project-latest

 Requirement:
   python run.py must already be running on http://127.0.0.1:8000
===============================================================================
#>

$ErrorActionPreference = "Stop"

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

$RootUrl = "http://127.0.0.1:8000"
$BaseUrl = "$RootUrl/api"

$EvidenceFile = Join-Path $PSScriptRoot "raw_4769_event.json"

$KerberoastTestId = "AD-T1558.003-KERBEROAST"
$AsRepTestId      = "AD-T1558.004-ASREP-ROAST"

$SigmaDetectionId = 196

$LoginEmail    = "admin@absega.local"
$LoginPassword = "absega123"

# -----------------------------------------------------------------------------
# Helper: resolve an OpenAPI schema reference
# -----------------------------------------------------------------------------

function Resolve-ApiSchema {
    param(
        [Parameter(Mandatory = $false)]
        [object]$Schema
    )

    if ($null -eq $Schema) {
        return $null
    }

    $ReferenceProperty = $Schema.PSObject.Properties['$ref']

    if ($null -ne $ReferenceProperty) {
        $Reference = [string]$ReferenceProperty.Value
        $SchemaName = ($Reference -split "/")[-1]

        $SchemaProperty =
            $script:OpenApi.components.schemas.PSObject.Properties[$SchemaName]

        if ($null -eq $SchemaProperty) {
            throw "OpenAPI schema reference was not found: $Reference"
        }

        return $SchemaProperty.Value
    }

    foreach ($UnionName in @("allOf", "anyOf", "oneOf")) {
        $UnionProperty = $Schema.PSObject.Properties[$UnionName]

        if ($null -ne $UnionProperty) {
            foreach ($CandidateSchema in @($UnionProperty.Value)) {
                $Resolved = Resolve-ApiSchema -Schema $CandidateSchema

                if ($null -ne $Resolved) {
                    return $Resolved
                }
            }
        }
    }

    return $Schema
}

# -----------------------------------------------------------------------------
# Helper: obtain the request schema for one API endpoint
# -----------------------------------------------------------------------------

function Get-ApiRequestSchema {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [string]$Method = "post"
    )

    $PathProperty = $script:OpenApi.paths.PSObject.Properties[$Path]

    if ($null -eq $PathProperty) {
        throw "Endpoint is not present in OpenAPI: $Path"
    }

    $MethodName = $Method.ToLowerInvariant()

    $MethodProperty =
        $PathProperty.Value.PSObject.Properties[$MethodName]

    if ($null -eq $MethodProperty) {
        throw "Method $Method is not present for endpoint: $Path"
    }

    $RequestBody = $MethodProperty.Value.requestBody

    if ($null -eq $RequestBody) {
        throw "Endpoint has no JSON request body: $Method $Path"
    }

    $JsonContent =
        $RequestBody.content.PSObject.Properties["application/json"]

    if ($null -eq $JsonContent) {
        throw "Endpoint does not expose an application/json schema: $Path"
    }

    return Resolve-ApiSchema -Schema $JsonContent.Value.schema
}

# -----------------------------------------------------------------------------
# Helper: keep only fields supported by the live Pydantic/OpenAPI model
# -----------------------------------------------------------------------------

function New-ApiBody {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Schema,

        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$Candidates,

        [Parameter(Mandatory = $false)]
        [object]$RawEvent,

        [Parameter(Mandatory = $false)]
        [string]$RawJson
    )

    $ResolvedSchema = Resolve-ApiSchema -Schema $Schema

    if ($null -eq $ResolvedSchema) {
        throw "Could not resolve the API request schema."
    }

    $PropertiesProperty =
        $ResolvedSchema.PSObject.Properties["properties"]

    # A permissive object schema may not expose explicit properties.
    if ($null -eq $PropertiesProperty) {
        return $Candidates
    }

    $Body = [ordered]@{}

    foreach ($Property in $PropertiesProperty.Value.PSObject.Properties) {
        $Name = [string]$Property.Name

        if (-not $Candidates.Contains($Name)) {
            continue
        }

        $Value = $Candidates[$Name]

        $ResolvedPropertySchema =
            Resolve-ApiSchema -Schema $Property.Value

        $PropertyType = ""

        if ($null -ne $ResolvedPropertySchema) {
            $TypeProperty =
                $ResolvedPropertySchema.PSObject.Properties["type"]

            if ($null -ne $TypeProperty) {
                $PropertyType = [string]$TypeProperty.Value
            }
        }

        # Adapt event payloads to object-versus-string Pydantic fields.
        if (
            $Name -in @(
                "raw_event",
                "event",
                "payload",
                "evidence",
                "content"
            ) -and
            $null -ne $RawEvent
        ) {
            if ($PropertyType -eq "string") {
                $Value = $RawJson
            }
            else {
                $Value = $RawEvent
            }
        }

        $Body[$Name] = $Value
    }

    $RequiredNames = @()

    $RequiredProperty =
        $ResolvedSchema.PSObject.Properties["required"]

    if ($null -ne $RequiredProperty) {
        $RequiredNames = @($RequiredProperty.Value)
    }

    $MissingRequired = @(
        $RequiredNames |
        Where-Object {
            -not $Body.Contains([string]$_)
        }
    )

    if ($MissingRequired.Count -gt 0) {
        throw (
            "The API requires unsupported field(s): " +
            ($MissingRequired -join ", ")
        )
    }

    return $Body
}

# -----------------------------------------------------------------------------
# Helper: POST a PowerShell object as JSON
# -----------------------------------------------------------------------------

function Invoke-JsonPost {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $true)]
        [object]$Body
    )

    $JsonBody = $Body |
        ConvertTo-Json -Depth 100 -Compress

    return Invoke-RestMethod `
        -Uri $Uri `
        -Method Post `
        -ContentType "application/json" `
        -Body $JsonBody
}

# -----------------------------------------------------------------------------
# Helper: safely extract a run ID from different API response shapes
# -----------------------------------------------------------------------------

function Get-ResponseRunId {
    param(
        [Parameter(Mandatory = $false)]
        [object]$Response,

        [Parameter(Mandatory = $true)]
        [string]$Fallback
    )

    if ($null -ne $Response) {
        foreach ($Name in @("run_id", "id")) {
            $Property = $Response.PSObject.Properties[$Name]

            if (
                $null -ne $Property -and
                -not [string]::IsNullOrWhiteSpace(
                    [string]$Property.Value
                )
            ) {
                return [string]$Property.Value
            }
        }

        $RunProperty = $Response.PSObject.Properties["run"]

        if (
            $null -ne $RunProperty -and
            $null -ne $RunProperty.Value
        ) {
            $NestedRunId =
                $RunProperty.Value.PSObject.Properties["run_id"]

            if ($null -ne $NestedRunId) {
                return [string]$NestedRunId.Value
            }
        }
    }

    return $Fallback
}

# -----------------------------------------------------------------------------
# Helper: SHA-256 fingerprint
# -----------------------------------------------------------------------------

function Get-Sha256Hex {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Text
    )

    $Sha256 =
        [System.Security.Cryptography.SHA256]::Create()

    try {
        $Bytes =
            [System.Text.Encoding]::UTF8.GetBytes($Text)

        $Hash =
            $Sha256.ComputeHash($Bytes)

        return (
            $Hash |
            ForEach-Object {
                $_.ToString("x2")
            }
        ) -join ""
    }
    finally {
        $Sha256.Dispose()
    }
}

# =============================================================================
# 1/7 — Backend, authentication and OpenAPI
# =============================================================================

Write-Host ""
Write-Host "[1/7] Checking backend and authentication..." `
    -ForegroundColor Cyan

$Health = Invoke-RestMethod `
    -Uri "$BaseUrl/ad-validation/health" `
    -Method Get

if ($Health.status -ne "ok") {
    throw (
        "AD Validation health is not OK. Returned status: " +
        [string]$Health.status
    )
}

$LoginBody = @{
    email    = $LoginEmail
    password = $LoginPassword
}

$Authentication = Invoke-JsonPost `
    -Uri "$BaseUrl/auth/login" `
    -Body $LoginBody

if ($Authentication.success -ne $true) {
    throw "Authentication did not return success=true."
}

# The current login route returns no bearer token.
# AD Validation requests therefore use no fake Authorization header.
Write-Host "      authentication successful." `
    -ForegroundColor Green

$script:OpenApi = Invoke-RestMethod `
    -Uri "$RootUrl/openapi.json" `
    -Method Get

Write-Host "      OpenAPI schema loaded." `
    -ForegroundColor Green

# =============================================================================
# 2/7 — Load and validate the untouched evidence
# =============================================================================

Write-Host "[2/7] Validating raw_4769_event.json..." `
    -ForegroundColor Cyan

if (-not (Test-Path -LiteralPath $EvidenceFile -PathType Leaf)) {
    throw "Evidence file was not found: $EvidenceFile"
}

$RawJson = Get-Content `
    -LiteralPath $EvidenceFile `
    -Raw `
    -Encoding UTF8

try {
    $RawEvent = $RawJson | ConvertFrom-Json
}
catch {
    throw "raw_4769_event.json is not valid JSON: $($_.Exception.Message)"
}

$EventId             = [string]$RawEvent.data.win.system.eventID
$Channel             = [string]$RawEvent.data.win.system.channel
$Computer            = [string]$RawEvent.data.win.system.computer
$EventTimestamp      = [string]$RawEvent.timestamp
$AgentName           = [string]$RawEvent.agent.name
$SourceIp            = [string]$RawEvent.agent.ip
$GenericWazuhRuleId  = [string]$RawEvent.rule.id
$ServiceName         = [string]$RawEvent.data.win.eventdata.serviceName
$TicketOptions       = [string]$RawEvent.data.win.eventdata.ticketOptions
$EncryptionType      = [string]$RawEvent.data.win.eventdata.ticketEncryptionType

if ($EventId -ne "4769") {
    throw "Expected Event ID 4769, found: $EventId"
}

if ($TicketOptions -ne "0x40810000") {
    throw "Expected TicketOptions 0x40810000, found: $TicketOptions"
}

if ($EncryptionType -ne "0x17") {
    throw "Expected TicketEncryptionType 0x17, found: $EncryptionType"
}

if ($ServiceName -ne "svc_sql") {
    throw "Expected ServiceName svc_sql, found: $ServiceName"
}

if ($GenericWazuhRuleId -ne "60107") {
    throw "Expected generic Wazuh rule 60107, found: $GenericWazuhRuleId"
}

$TargetHost = "DC01"

if (-not [string]::IsNullOrWhiteSpace($Computer)) {
    $TargetHost = ($Computer -split "\.")[0]
}

$EvidenceFingerprint =
    Get-Sha256Hex -Text $RawJson

try {
    $StartedAt = (
        [DateTimeOffset]::Parse($EventTimestamp)
    ).ToUniversalTime().ToString("o")
}
catch {
    $StartedAt =
        [DateTimeOffset]::UtcNow.ToString("o")
}

$EndedAt = $StartedAt
$CreatedAt = [DateTimeOffset]::UtcNow.ToString("o")

Write-Host "      Event ID:              $EventId"
Write-Host "      Agent:                 $AgentName"
Write-Host "      Computer:              $Computer"
Write-Host "      Generic Wazuh rule:    $GenericWazuhRuleId"
Write-Host "      ServiceName:           $ServiceName"
Write-Host "      TicketOptions:         $TicketOptions"
Write-Host "      Encryption type:       $EncryptionType"
Write-Host "      evidence validated." `
    -ForegroundColor Green

# =============================================================================
# 3/7 — Create the Kerberoast validation run
# =============================================================================

Write-Host "[3/7] Creating Kerberoast validation run..." `
    -ForegroundColor Cyan

$RunTimestamp = Get-Date -Format "yyyyMMdd-HHmmss"

$RequestedKerberoastRunId =
    "RUN-T1558-003-$RunTimestamp"

$RunSchema = Get-ApiRequestSchema `
    -Path "/api/ad-validation/runs" `
    -Method "post"

$KerberoastRunCandidates = @{
    run_id        = $RequestedKerberoastRunId
    test_id       = $KerberoastTestId
    name          = "Kerberoast - svc_sql - Attack Set 1"
    behavior      = "kerberoast"
    behavior_name = "Kerberoasting service ticket request"
    technique     = "T1558.003"
    technique_id  = "T1558.003"
    execution_host= $AgentName
    source_host   = $AgentName
    target_host   = $TargetHost
    target        = "MSSQLSvc/DC01.absega.local:1433"
    source_ip     = $SourceIp
    started_at    = $StartedAt
    ended_at      = $EndedAt
    created_at    = $CreatedAt
    status        = "completed"
    executed      = $true
    notes         = (
        "Telemetry present. Untouched Windows Security Event 4769 " +
        "was collected. Sigma detection 196 matched. " +
        "Wazuh rule 60107 is only the generic service-ticket event " +
        "rule and is not a Kerberoast-specific detection. " +
        "Formal result: SIGMA_ONLY / WAZUH_DETECTION_GAP. " +
        "telemetry_gap=false."
    )
}

$KerberoastRunBody = New-ApiBody `
    -Schema $RunSchema `
    -Candidates $KerberoastRunCandidates

$KerberoastRunResponse = Invoke-JsonPost `
    -Uri "$BaseUrl/ad-validation/runs" `
    -Body $KerberoastRunBody

$KerberoastRunId = Get-ResponseRunId `
    -Response $KerberoastRunResponse `
    -Fallback $RequestedKerberoastRunId

Write-Host "      run created: $KerberoastRunId" `
    -ForegroundColor Green

# =============================================================================
# 4/7 — Attach the untouched raw event
# =============================================================================

Write-Host "[4/7] Attaching untouched 4769 evidence..." `
    -ForegroundColor Cyan

$EvidenceSchema = Get-ApiRequestSchema `
    -Path "/api/ad-validation/runs/{run_id}/evidence" `
    -Method "post"

$EvidenceCandidates = @{
    run_id             = $KerberoastRunId
    source             = "wazuh"
    evidence_type      = "wazuh_raw_event"
    original_filename  = "raw_4769_event.json"
    filename           = "raw_4769_event.json"
    event_fingerprint  = $EvidenceFingerprint
    agent_name         = $AgentName
    channel            = $Channel
    event_id           = $EventId
    event_timestamp    = $EventTimestamp
    timestamp          = $EventTimestamp
    wazuh_rule_id      = [int]$GenericWazuhRuleId
    is_normalized      = $false
    payload_json       = $RawJson
    raw_json           = $RawJson
    raw_event          = $RawEvent
    event              = $RawEvent
    payload            = $RawEvent
    evidence           = $RawEvent
    content            = $RawEvent
}

$EvidenceBody = New-ApiBody `
    -Schema $EvidenceSchema `
    -Candidates $EvidenceCandidates `
    -RawEvent $RawEvent `
    -RawJson $RawJson

$EvidenceResponse = Invoke-JsonPost `
    -Uri "$BaseUrl/ad-validation/runs/$KerberoastRunId/evidence" `
    -Body $EvidenceBody

$EvidenceId = $null

if ($null -ne $EvidenceResponse) {
    foreach ($Name in @("evidence_id", "id")) {
        $Property =
            $EvidenceResponse.PSObject.Properties[$Name]

        if ($null -ne $Property) {
            $EvidenceId = $Property.Value
            break
        }
    }
}

Write-Host "      untouched evidence attached." `
    -ForegroundColor Green

# =============================================================================
# 5/7 — Evaluate Sigma 196 and save the formal comparison
# =============================================================================

Write-Host "[5/7] Evaluating Sigma 196 on the real Windows event..." `
    -ForegroundColor Cyan

# Preserve RawEvent untouched.
# Only the evaluator copy has the generic Wazuh envelope removed.
# All Windows event fields remain exactly the same.
$EvaluatorEvent = $RawJson | ConvertFrom-Json

$EvaluatorEvent.PSObject.Properties.Remove("rule")

$ValidationBody = @{
    detection_id = $SigmaDetectionId
    event        = $EvaluatorEvent
}

$ValidationResult = Invoke-JsonPost `
    -Uri "$BaseUrl/ad-validation/validate-event" `
    -Body $ValidationBody

if ($ValidationResult.sigma_matched -ne $true) {
    $ValidationJson =
        $ValidationResult |
        ConvertTo-Json -Depth 30

    throw (
        "Sigma detection 196 did not match. " +
        "Step 21 must not record SIGMA_ONLY.`n" +
        $ValidationJson
    )
}

if ([bool]$ValidationResult.wazuh_fired) {
    throw (
        "The evaluator classified the diagnostic copy as " +
        "wazuh_fired=true. Expected false."
    )
}

Write-Host "      Sigma 196 matched: true" `
    -ForegroundColor Green

Write-Host "      Kerberoast-specific Wazuh fired: false" `
    -ForegroundColor Green

$EvaluatorTrace = @{
    EventID = @{
        expected = "4769"
        actual   = $EventId
        result   = "matched exact"
    }
    TicketOptions = @{
        expected = "0x40810000"
        actual   = $TicketOptions
        result   = "matched exact"
    }
    TicketEncryptionType = @{
        expected = "0x17"
        actual   = $EncryptionType
        result   = "matched exact"
    }
    ServiceNameReduction = @{
        condition = "ServiceName endswith '$'"
        actual    = $ServiceName
        result    = "reduction did not match; detection remains true"
    }
}

$ComparisonSchema = Get-ApiRequestSchema `
    -Path "/api/ad-validation/runs/{run_id}/compare" `
    -Method "post"

$ComparisonCandidates = @{
    run_id                 = $KerberoastRunId
    wazuh_rule_id          = [int]$GenericWazuhRuleId
    detection_id           = $SigmaDetectionId
    sigma_detection_id     = $SigmaDetectionId
    sigma_matched          = $true
    wazuh_fired            = $false
    telemetry_present      = $true
    telemetry_gap          = $false
    verdict                = "SIGMA_ONLY"
    behavioral_verdict     = "sigma_only_on_event"
    gap_class              = "WAZUH_DETECTION_GAP"
    matched_fields         = @(
        "EventID",
        "TicketOptions",
        "TicketEncryptionType",
        "ServiceName reduction"
    )
    matched_fields_json    = (
        @(
            "EventID",
            "TicketOptions",
            "TicketEncryptionType",
            "ServiceName reduction"
        ) |
        ConvertTo-Json -Compress
    )
    missing_fields         = @()
    missing_fields_json    = "[]"
    evaluator_trace        = $EvaluatorTrace
    evaluator_trace_json   = (
        $EvaluatorTrace |
        ConvertTo-Json -Depth 10 -Compress
    )
    tuning_notes           = (
        "Formal classification: SIGMA_ONLY / " +
        "WAZUH_DETECTION_GAP. Telemetry is present and " +
        "telemetry_gap=false. Wazuh rule 60107 is a generic " +
        "Kerberos service-ticket event rule, not a dedicated " +
        "Kerberoast detection. Sigma 196 matched EventID 4769, " +
        "TicketOptions 0x40810000 and TicketEncryptionType 0x17. " +
        "ServiceName svc_sql did not match the machine-account " +
        "reduction ending in '$'."
    )
}

if ($null -ne $EvidenceId) {
    $ComparisonCandidates["evidence_id"] = $EvidenceId
}

$ComparisonBody = New-ApiBody `
    -Schema $ComparisonSchema `
    -Candidates $ComparisonCandidates

$ComparisonResponse = Invoke-JsonPost `
    -Uri "$BaseUrl/ad-validation/runs/$KerberoastRunId/compare" `
    -Body $ComparisonBody

Write-Host "      formal comparison saved." `
    -ForegroundColor Green

# =============================================================================
# 6/7 — Record AS-REP honestly as NOT_EXECUTED
# =============================================================================

Write-Host "[6/7] Recording AS-REP as NOT_EXECUTED..." `
    -ForegroundColor Cyan

$RequestedAsRepRunId =
    "RUN-T1558-004-NOT-EXECUTED-$RunTimestamp"

$AsRepTimestamp =
    [DateTimeOffset]::UtcNow.ToString("o")

$AsRepRunCandidates = @{
    run_id         = $RequestedAsRepRunId
    test_id        = $AsRepTestId
    name           = "AS-REP - Attack Set 1 - Not Executed"
    behavior       = "asrep_roast"
    behavior_name  = "AS-REP roasting validation"
    technique      = "T1558.004"
    technique_id   = "T1558.004"
    execution_host = "WIN11"
    source_host    = "WIN11"
    target_host    = "DC01"
    target         = "asrep_lab"
    started_at     = $AsRepTimestamp
    ended_at       = $AsRepTimestamp
    created_at     = $AsRepTimestamp
    status         = "NOT_EXECUTED"
    executed       = $false
    verdict        = "NOT_EXECUTED"
    gap_class      = "NO_TEST_EVIDENCE"
    telemetry_gap  = $false
    notes          = (
        "NOT_EXECUTED / NO_TEST_EVIDENCE. " +
        "The AS-REP phase was skipped and no attack was run. " +
        "No telemetry or detection conclusion is claimed. " +
        "telemetry_gap=false."
    )
}

$AsRepRunBody = New-ApiBody `
    -Schema $RunSchema `
    -Candidates $AsRepRunCandidates

$AsRepRunResponse = Invoke-JsonPost `
    -Uri "$BaseUrl/ad-validation/runs" `
    -Body $AsRepRunBody

$AsRepRunId = Get-ResponseRunId `
    -Response $AsRepRunResponse `
    -Fallback $RequestedAsRepRunId

Write-Host "      AS-REP run recorded: $AsRepRunId" `
    -ForegroundColor Green

# =============================================================================
# 7/7 — Export and verify
# =============================================================================

Write-Host "[7/7] Exporting and verifying Step 21..." `
    -ForegroundColor Cyan

$OutputCsv = Join-Path `
    $PSScriptRoot `
    (
        "ABSEGA_Kerberoast_Validation_" +
        (Get-Date -Format "yyyyMMdd-HHmmss") +
        ".csv"
    )

Invoke-RestMethod `
    -Uri "$BaseUrl/ad-validation/export.csv" `
    -Method Get `
    -OutFile $OutputCsv

$KerberoastDetail = Invoke-RestMethod `
    -Uri "$BaseUrl/ad-validation/runs/$KerberoastRunId" `
    -Method Get

$AsRepDetail = Invoke-RestMethod `
    -Uri "$BaseUrl/ad-validation/runs/$AsRepRunId" `
    -Method Get

if ([int]$KerberoastDetail.evidence_count -lt 1) {
    throw "Kerberoast run has no stored evidence."
}

$LatestComparison =
    $KerberoastDetail.comparisons |
    Sort-Object {
        [int]$_.comparison_id
    } -Descending |
    Select-Object -First 1

if ($null -eq $LatestComparison) {
    throw "Kerberoast run has no stored comparison."
}

if (
    $null -eq $LatestComparison.sigma_matched -or
    -not [bool]$LatestComparison.sigma_matched
) {
    throw "Stored comparison does not show sigma_matched=true."
}

if (
    $null -eq $LatestComparison.wazuh_fired -or
    [bool]$LatestComparison.wazuh_fired
) {
    throw "Stored comparison does not show wazuh_fired=false."
}

$StoredBehavioralVerdict =
    [string]$LatestComparison.behavioral_verdict

if (
    $StoredBehavioralVerdict -notmatch
    "(?i)sigma.*only|sigma_matched_raw_event"
) {
    throw (
        "Stored behavioral verdict is not Sigma-only: " +
        $StoredBehavioralVerdict
    )
}

$StoredAsRepStatus =
    [string]$AsRepDetail.run.status

$StoredAsRepNotes =
    [string]$AsRepDetail.run.notes

if (
    $StoredAsRepStatus -notmatch
    "(?i)not[_ -]?executed|skipped"
) {
    throw (
        "AS-REP run does not have a NOT_EXECUTED status: " +
        $StoredAsRepStatus
    )
}

if ($StoredAsRepNotes -notmatch "NO_TEST_EVIDENCE") {
    throw "AS-REP notes do not contain NO_TEST_EVIDENCE."
}

$CsvItem = Get-Item -LiteralPath $OutputCsv

if ($CsvItem.Length -le 0) {
    throw "The exported CSV is empty."
}

Write-Host ""
Write-Host "==============================================================" `
    -ForegroundColor Green

Write-Host " STEP 21 COMPLETE" `
    -ForegroundColor Green

Write-Host "==============================================================" `
    -ForegroundColor Green

Write-Host " Kerberoast run:      $KerberoastRunId"
Write-Host " Technique:            T1558.003"
Write-Host " Telemetry present:    True"
Write-Host " Sigma 196 matched:    True"
Write-Host " Wazuh detection:      False"
Write-Host " Verdict:              SIGMA_ONLY"
Write-Host " Gap class:            WAZUH_DETECTION_GAP"
Write-Host " Telemetry gap:        False"
Write-Host ""
Write-Host " AS-REP run:           $AsRepRunId"
Write-Host " Status:               NOT_EXECUTED"
Write-Host " Reason:               NO_TEST_EVIDENCE"
Write-Host " Telemetry gap:        False"
Write-Host ""
Write-Host " Evidence objects:     $($KerberoastDetail.evidence_count)"
Write-Host " Comparison objects:   $($KerberoastDetail.comparison_count)"
Write-Host " CSV:                  $OutputCsv"

Write-Host "==============================================================" `
    -ForegroundColor Green

Write-Host ""
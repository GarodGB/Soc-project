from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
from app.database import get_connection
try:
    import anthropic
except Exception:
    anthropic = None
import json
import os
import re
import hashlib

router = APIRouter()


# ── Anthropic client / Local Demo Mode ────────────────────────────────────────
# If ANTHROPIC_API_KEY is not configured, the platform uses a local mock client.
# This lets every teammate run the project without sharing a private API key.

class _MockTextBlock:
    def __init__(self, text: str):
        self.text = text

class _MockUsage:
    input_tokens = 0
    output_tokens = 0

class _MockResponse:
    def __init__(self, text: str):
        self.content = [_MockTextBlock(text)]
        self.usage = _MockUsage()

class _MockMessages:
    def create(self, **kwargs):
        messages = kwargs.get("messages", [])
        prompt = "\n".join([m.get("content", "") for m in messages if isinstance(m, dict)])
        system = kwargs.get("system", "")
        return _MockResponse(_mock_ai_answer(prompt, system))

class _MockAnthropicClient:
    def __init__(self):
        self.messages = _MockMessages()

def _extract_first_technique(text: str) -> str:
    match = re.search(r"T\d{4}(?:\.\d{3})?", text)
    return match.group(0) if match else "T1059"

def _mock_ai_answer(prompt: str, system: str = "") -> str:
    """Local demo answers used when no Anthropic API key is available."""
    lower = (prompt + "\n" + system).lower()
    technique = _extract_first_technique(prompt)

    # Endpoints that expect strict JSON
    if '"sigma_rule"' in prompt and '"log_sources_needed"' in prompt:
        return json.dumps({
            "sigma_rule": f"title: Demo Detection for {technique}\nstatus: test\nlogsource:\n  product: windows\n  category: process_creation\ndetection:\n  selection:\n    CommandLine|contains:\n      - powershell\n      - cmd.exe\n  condition: selection\nlevel: medium",
            "explanation": "Demo Mode: this is a local Sigma-style suggestion because ANTHROPIC_API_KEY is not configured.",
            "log_sources_needed": ["Windows Event Logs", "Sysmon Process Creation"],
            "false_positive_rate": "medium",
            "tuning_tips": "Tune by allowlisting known admin scripts and approved management tools."
        })

    if '"primary_technique_id"' in prompt:
        return json.dumps({
            "primary_technique_id": technique,
            "primary_technique_name": "Demo ATT&CK mapping",
            "primary_tactic": "Execution",
            "confidence": "medium",
            "secondary_techniques": [],
            "reasoning": "Demo Mode mapping based on the technique ID or keywords already present in the detection.",
            "tags_suggestion": technique
        })

    if '"coverage_score"' in prompt and '"critical_gaps"' in prompt:
        score_match = re.search(r"Coverage score\s*:\s*([0-9.]+)%", prompt)
        score = float(score_match.group(1)) if score_match else 0
        return json.dumps({
            "coverage_score": score,
            "overall_assessment": "Demo Mode: AI is not connected, but the platform can still calculate coverage from the local database. Focus first on techniques with no rules and techniques that only have draft/testing rules.",
            "critical_gaps": [
                {"technique_id": "T1110", "technique_name": "Brute Force", "tactic": "Credential Access", "risk_level": "high", "why_important": "Credential attacks are common and need strong telemetry coverage.", "quick_win": True},
                {"technique_id": "T1021", "technique_name": "Remote Services", "tactic": "Lateral Movement", "risk_level": "high", "why_important": "Attackers use remote services to move between systems.", "quick_win": True}
            ],
            "priority_order": ["T1110", "T1021"],
            "recommended_next_detections": [
                {"technique_id": "T1110", "technique_name": "Brute Force", "suggested_rule_title": "Multiple Failed Logons Followed by Success", "effort": "low", "impact": "high"},
                {"technique_id": "T1021", "technique_name": "Remote Services", "suggested_rule_title": "Suspicious Remote Service Execution", "effort": "medium", "impact": "high"}
            ],
            "tactical_advice": "Use this demo output for presentation only. For real AI recommendations, configure ANTHROPIC_API_KEY locally in a .env file or environment variable."
        })

    if '"validation_summary"' in prompt and '"test_cases"' in prompt:
        return json.dumps({
            "validation_summary": "Demo Mode: generated local validation cases without calling Claude.",
            "estimated_fp_rate": "medium",
            "rule_quality_score": 75,
            "deployment_readiness": "needs_tuning",
            "test_cases": [
                {"attack_name": "True Positive — suspicious command execution", "sample_type": "positive", "sample_event": 'EventID=4688 Image=powershell.exe CommandLine="powershell -nop -enc AAAA"', "expected_result": "match", "notes": "Should trigger on suspicious command-line keywords."},
                {"attack_name": "True Negative — normal admin command", "sample_type": "negative", "sample_event": 'EventID=4688 Image=cmd.exe CommandLine="cmd.exe /c whoami"', "expected_result": "no_match", "notes": "Benign command with no suspicious indicators."},
                {"attack_name": "False Positive — admin script", "sample_type": "positive", "sample_event": 'EventID=4688 Image=powershell.exe CommandLine="powershell -File backup.ps1"', "expected_result": "match", "notes": "May need allowlisting for approved scripts."}
            ],
            "improvement_suggestions": ["Add more precise process and parent-process conditions", "Document known false positives"],
            "missing_conditions": "Add environment-specific allowlists and telemetry requirements."
        })

    if '"deployment_steps"' in prompt and '"testing_procedure"' in prompt:
        return json.dumps({
            "title": "Demo Deployment Guide",
            "executive_summary": "Demo Mode: local deployment guidance generated without an external API.",
            "prerequisites": {"log_sources": ["Sysmon", "Windows Security Events"], "audit_policy": ["Process Creation"], "siem_requirements": ["Sigma-compatible rule pipeline"]},
            "deployment_steps": [
                {"step": 1, "title": "Review rule logic", "description": "Validate fields and event IDs against available telemetry.", "command": ""},
                {"step": 2, "title": "Deploy in test mode", "description": "Run against sample logs before production.", "command": ""}
            ],
            "tuning_guide": {"initial_threshold": "Start low, then tune after observing alert volume.", "allowlist_candidates": ["admin scripts", "backup tools"], "environment_specific": "Adjust fields to match your SIEM schema."},
            "false_positive_handling": {"known_fps": ["legitimate admin activity"], "triage_steps": ["check user", "check host", "review parent process"], "escalation_criteria": "Escalate if activity is unauthorized or repeated."},
            "testing_procedure": {"pre_deployment_test": "Run validation cases", "validation_command": "Use Test Runner", "expected_alert": "One alert for the positive sample"},
            "maintenance": {"review_frequency": "monthly", "update_triggers": ["new false positives", "new ATT&CK procedure"], "metrics_to_track": ["TP rate", "FP rate", "alert volume"]},
            "references": ["MITRE ATT&CK", "Sigma HQ"]
        })

    if 'return only valid json' in lower and '"results"' in prompt:
        return json.dumps({"results": [], "summary": "Demo Mode: local AI search is enabled, but semantic ranking requires a real API key."})

    # Free-text endpoints
    if "coverage gap" in lower or "coverage gaps" in lower:
        return "Demo Mode: ANTHROPIC_API_KEY is not configured, so this is a local answer. Check the Coverage tab for exact gaps. Prioritize red ATT&CK techniques with no rules, then yellow techniques that only have draft/testing rules. Also verify telemetry sources are healthy before marking a technique as covered."

    if "explain this sigma" in lower:
        return "Demo Mode explanation: this rule should be reviewed by checking what behavior it detects, which log source it needs, and what false positives may appear in normal admin activity."

    if "analyze this raw log" in lower:
        return "**Verdict:** SUSPICIOUS\n**Attack identified:** Demo analysis only.\n**MITRE technique:** Review manually based on process, command line, user, and source host.\n**Recommended action:** Correlate with endpoint and authentication logs."

    if "analyze this ioc" in lower:
        return "**Threat Level:** Unknown\n**Classification:** Demo Mode — no external threat intel lookup.\n**Recommended actions:** Monitor, search internally, and enrich with a real TI source before blocking."

    if "attack chain" in lower:
        return "**INCIDENT SUMMARY:** Demo Mode attack-chain reconstruction. Review timestamps, user accounts, source hosts, and MITRE techniques manually.\n**RECOMMENDED RESPONSE:** contain suspicious hosts and validate credentials."

    if "score this sigma" in lower:
        return "**Overall Score:** 75/100\n**Verdict:** Needs Improvement\n**Top improvements:** add precise fields, document false positives, and validate with positive/negative samples."

    if "threat hunting plan" in lower:
        return "**HUNT HYPOTHESIS:** Demo Mode hunt plan.\n**WHAT TO LOOK FOR:** unusual authentication, suspicious processes, lateral movement, and abnormal network connections.\n**DATA SOURCES NEEDED:** EDR, Windows Event Logs, Sysmon, firewall/DNS logs."

    if "executive threat briefing" in lower:
        return "**CRITICAL FINDINGS:** Demo Mode briefing. Coverage should be reviewed in the Coverage tab.\n**PRIORITY RECOMMENDATIONS:** close high-risk ATT&CK gaps, fix unhealthy telemetry, and validate active rules with sample events."

    return "Demo Mode: ABSEGA AI is running locally because ANTHROPIC_API_KEY is not configured. The platform still works; live Claude answers require a private API key."

def get_client():
    key = os.environ.get("ANTHROPIC_API_KEY")
    provider = os.environ.get("AI_PROVIDER", "mock" if not key else "anthropic").lower()

    if provider in ("mock", "demo", "local") or not key:
        return _MockAnthropicClient()

    if anthropic is None:
        raise HTTPException(status_code=503, detail="anthropic package is not installed. Run: pip install -r requirements.txt")

    return anthropic.Anthropic(api_key=key)

def ask_claude(prompt: str, system: str = None, max_tokens: int = 1500) -> str:
    client = get_client()
    kwargs = {
        "model":      "claude-sonnet-4-6",
        "max_tokens": max_tokens,
        "messages":   [{"role": "user", "content": prompt}],
    }
    if system:
        kwargs["system"] = system
    response = client.messages.create(**kwargs)
    return response.content[0].text


def parse_json(raw: str) -> dict:
    """Handle all formats Claude might return."""
    clean = raw.strip()

    if "```" in clean:
        parts = clean.split("```")
        for part in parts:
            part = part.strip()
            if part.startswith("json"):
                part = part[4:].strip()
            try:
                return json.loads(part)
            except Exception:
                continue

    try:
        return json.loads(clean)
    except Exception:
        pass

    start = clean.find("{")
    end   = clean.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(clean[start:end + 1])
        except Exception:
            pass

    raise ValueError(f"Could not parse JSON from: {clean[:300]}")


# ── Models ────────────────────────────────────────────────────────────────────

class SuggestRuleRequest(BaseModel):
    technique_id: str
    platform:     Optional[str] = "windows"
    context:      Optional[str] = None

class AutoMapRequest(BaseModel):
    detection_id: int        # detection_id is INTEGER in this schema
    save:         bool = True

class GapAnalysisRequest(BaseModel):
    tactic_focus: Optional[str] = None


# ═══════════════════════════════════════════════════════════════════════════════
#  FEATURE 1 — AI RULE SUGGESTION
#  POST /api/ai/suggest-rule
#
#  mitre_techniques: technique_id, name, tactic, description, url
# ═══════════════════════════════════════════════════════════════════════════════

@router.post("/suggest-rule")
def suggest_rule(req: SuggestRuleRequest):
    """Generate a Sigma detection rule for a given MITRE ATT&CK technique."""

    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM mitre_techniques WHERE technique_id = ?",
            (req.technique_id,)
        ).fetchone()
        technique = dict(row) if row else None
    finally:
        conn.close()

    if technique:
        tech_info = (
            f"Technique   : {technique['technique_id']} — {technique['name']}\n"
            f"Tactic      : {technique['tactic']}\n"
            f"Description : {technique.get('description', 'N/A')}\n"
        )
    else:
        tech_info = f"Technique ID: {req.technique_id}\nPlatform: {req.platform}\n"

    if req.context:
        tech_info += f"Additional context: {req.context}\n"

    prompt = f"""You are an expert detection engineer. Generate a production-ready Sigma rule.

{tech_info}
Target platform: {req.platform}

Requirements:
- Write a complete, valid Sigma YAML rule
- Use realistic detection logic based on real attacker behaviour
- Include meaningful false positive notes
- Set the correct logsource block
- Include at least 2-3 detection conditions

Return ONLY a JSON object with these exact fields, no extra text:
{{
  "sigma_rule": "the complete YAML Sigma rule as a string",
  "explanation": "2-3 sentences explaining what this detects and why",
  "log_sources_needed": ["list", "of", "required", "log", "sources"],
  "false_positive_rate": "low|medium|high",
  "tuning_tips": "one paragraph on how to tune this rule"
}}"""

    raw = ask_claude(
        prompt,
        system="You are a senior detection engineer. Return only valid JSON, no explanation before or after."
    )
    try:
        data = parse_json(raw)
    except Exception as e:
        raise HTTPException(500, f"Parse error: {str(e)}")

    data["technique_id"] = req.technique_id
    data["platform"]     = req.platform
    return data


# ═══════════════════════════════════════════════════════════════════════════════
#  FEATURE 2 — AUTOMATIC ATT&CK MAPPING
#  POST /api/ai/auto-map
#
#  detections: detection_id, title, description, rule_logic, severity,
#              status, author, platform, sigma_id, logsource,
#              falsepositives, tags, raw_yaml
#  detection_technique_mapping: id, detection_id, technique_id
# ═══════════════════════════════════════════════════════════════════════════════

@router.post("/auto-map")
def auto_map_detection(req: AutoMapRequest):
    """Automatically map a detection rule to its MITRE ATT&CK technique(s)."""

    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM detections WHERE detection_id = ?", (req.detection_id,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Detection not found")
        detection = dict(row)

        techniques = conn.execute(
            "SELECT technique_id, name, tactic FROM mitre_techniques ORDER BY technique_id"
        ).fetchall()
        techniques = [dict(t) for t in techniques]
    finally:
        conn.close()

    techniques_list = "\n".join([
        f"- {t['technique_id']}: {t['name']} ({t['tactic']})"
        for t in techniques[:200]
    ])

    prompt = f"""You are a MITRE ATT&CK expert. Analyze this detection and map it to the correct technique(s).

Detection title : {detection['title']}
Description     : {detection.get('description', 'N/A')}
Platform        : {detection.get('platform', 'N/A')}
Sigma rule      : {detection.get('raw_yaml', 'N/A')}
Tags            : {detection.get('tags', 'N/A')}

Available techniques:
{techniques_list or "No techniques loaded yet — use your ATT&CK knowledge."}

Return ONLY a JSON object, no extra text:
{{
  "primary_technique_id":   "T1234.001",
  "primary_technique_name": "technique name",
  "primary_tactic":         "tactic name",
  "confidence":             "high|medium|low",
  "secondary_techniques": [
    {{"id": "T1234", "name": "name", "reason": "why this also applies"}}
  ],
  "reasoning":       "explanation of why this mapping is correct",
  "tags_suggestion": "T1234.001"
}}"""

    raw = ask_claude(
        prompt,
        system="You are a MITRE ATT&CK expert. Return only valid JSON, no explanation before or after."
    )
    try:
        data = parse_json(raw)
    except Exception as e:
        raise HTTPException(500, f"Parse error: {str(e)}")

    # Save to detection_technique_mapping: id(auto), detection_id, technique_id
    if req.save and data.get("primary_technique_id"):
        conn = get_connection()
        try:
            existing = conn.execute("""
                SELECT id FROM detection_technique_mapping
                WHERE detection_id = ? AND technique_id = ?
            """, (req.detection_id, data["primary_technique_id"])).fetchone()

            if not existing:
                conn.execute("""
                    INSERT INTO detection_technique_mapping (detection_id, technique_id)
                    VALUES (?, ?)
                """, (req.detection_id, data["primary_technique_id"]))

            conn.execute(
                "UPDATE detections SET tags = ? WHERE detection_id = ?",
                (data.get("tags_suggestion", data["primary_technique_id"]), req.detection_id)
            )
            conn.commit()
            data["saved_to_db"] = True
        except Exception as e:
            data["saved_to_db"] = False
            data["save_error"]  = str(e)
        finally:
            conn.close()

    data["detection_id"] = req.detection_id
    return data


# ═══════════════════════════════════════════════════════════════════════════════
#  FEATURE 3 — GAP ANALYSIS
#  POST /api/ai/gap-analysis
# ═══════════════════════════════════════════════════════════════════════════════

@router.post("/gap-analysis")
def gap_analysis(req: GapAnalysisRequest):
    """Identify ATT&CK coverage gaps and prioritise what to build next."""

    conn = get_connection()
    try:
        rows = conn.execute("""
            SELECT
                mt.technique_id,
                mt.name,
                mt.tactic,
                COUNT(d.detection_id)                                              AS total,
                SUM(CASE WHEN d.status = 'active' THEN 1 ELSE 0 END)              AS active
            FROM mitre_techniques mt
            LEFT JOIN detection_technique_mapping dtm
                   ON mt.technique_id = dtm.technique_id
            LEFT JOIN detections d
                   ON dtm.detection_id = d.detection_id
            GROUP BY mt.technique_id, mt.name, mt.tactic
            ORDER BY mt.tactic, mt.technique_id
        """).fetchall()
        techniques = [dict(r) for r in rows]

        total_detections = conn.execute(
            "SELECT COUNT(*) FROM detections"
        ).fetchone()[0]

        active_detections = conn.execute(
            "SELECT COUNT(*) FROM detections WHERE status = 'active'"
        ).fetchone()[0]
    finally:
        conn.close()

    gaps    = [t for t in techniques if (t["total"]  or 0) == 0]
    partial = [t for t in techniques if (t["total"]  or 0) > 0 and (t["active"] or 0) == 0]
    covered = [t for t in techniques if (t["active"] or 0) > 0]
    total   = len(techniques)
    score   = round(len(covered) / total * 100, 1) if total else 0

    if req.tactic_focus:
        focus = req.tactic_focus.lower()
        gaps    = [t for t in gaps    if focus in (t["tactic"] or "").lower()]
        partial = [t for t in partial if focus in (t["tactic"] or "").lower()]

    gaps_list    = "\n".join([
        f"- [{t['technique_id']}] {t['name']} ({t['tactic']})" for t in gaps[:30]
    ])
    partial_list = "\n".join([
        f"- [{t['technique_id']}] {t['name']} ({t['tactic']})" for t in partial[:20]
    ])

    prompt = f"""You are a senior detection engineer conducting a coverage gap analysis.

Platform status:
- Total detections        : {total_detections}
- Active / deployed       : {active_detections}
- ATT&CK techniques       : {total}
- Covered (active rules)  : {len(covered)}
- Partial (draft/testing) : {len(partial)}
- Gaps (no rules)         : {len(gaps)}
- Coverage score          : {score}%
{f"- Tactic focus: {req.tactic_focus}" if req.tactic_focus else ""}

Techniques with NO detection rules:
{gaps_list or "None — excellent coverage!"}

Techniques with only draft/testing rules:
{partial_list or "None"}

Return ONLY a JSON object, no extra text:
{{
  "coverage_score": {score},
  "overall_assessment": "2-3 sentence summary of the current detection posture",
  "critical_gaps": [
    {{
      "technique_id": "T1234",
      "technique_name": "name",
      "tactic": "tactic name",
      "risk_level": "critical|high|medium",
      "why_important": "why attackers use this and why we need coverage",
      "quick_win": true
    }}
  ],
  "priority_order": ["T1234", "T5678"],
  "recommended_next_detections": [
    {{
      "technique_id": "T1234",
      "technique_name": "name",
      "suggested_rule_title": "specific rule title to write",
      "effort": "low|medium|high",
      "impact": "low|medium|high"
    }}
  ],
  "tactical_advice": "strategic paragraph of advice for the team"
}}"""

    raw = ask_claude(
        prompt,
        system="You are a senior detection engineer. Return only valid JSON, no explanation before or after.",
        max_tokens=2000
    )
    try:
        data = parse_json(raw)
    except Exception as e:
        raise HTTPException(500, f"Parse error: {str(e)}")

    data["stats"] = {
        "total_techniques": total,
        "covered":          len(covered),
        "partial":          len(partial),
        "gaps":             len(gaps),
        "coverage_score":   score,
    }
    return data


# ═══════════════════════════════════════════════════════════════════════════════
#  FEATURE 4 — AI VALIDATION
#  POST /api/ai/validate/{detection_id}
#
#  detections:       detection_id, title, severity, status, platform, raw_yaml, tags
#  validation_cases: case_id(auto), detection_id, detection_title, attack_name,
#                    sample_type, sample_event, expected_result, actual_result,
#                    status, tested_at, source, source_ref, platform
# ═══════════════════════════════════════════════════════════════════════════════

@router.post("/validate/{detection_id}")
def ai_validate_detection(detection_id: int):
    """Generate AI-powered test cases and save them to validation_cases."""

    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM detections WHERE detection_id = ?", (detection_id,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Detection not found")
        detection = dict(row)
    finally:
        conn.close()

    prompt = f"""You are a detection validation expert. Analyze this rule and generate exactly 3 test cases.

Detection title : {detection['title']}
Severity        : {detection.get('severity', 'N/A')}
Platform        : {detection.get('platform', 'N/A')}
Tags            : {detection.get('tags', 'N/A')}
Sigma rule      : {detection.get('raw_yaml', 'N/A')}

Return ONLY a JSON object, no extra text:
{{
  "validation_summary":   "overall assessment of the rule quality",
  "estimated_fp_rate":    "low|medium|high",
  "rule_quality_score":   85,
  "deployment_readiness": "ready|needs_tuning|not_ready",
  "test_cases": [
    {{
      "attack_name":     "True Positive — short description",
      "sample_type":     "positive",
      "sample_event":    "exact log line that SHOULD trigger the rule",
      "expected_result": "match",
      "notes":           "why this triggers"
    }},
    {{
      "attack_name":     "True Negative — short description",
      "sample_type":     "negative",
      "sample_event":    "exact log line that should NOT trigger",
      "expected_result": "no_match",
      "notes":           "why this does not trigger"
    }},
    {{
      "attack_name":     "False Positive — short description",
      "sample_type":     "positive",
      "sample_event":    "log line that might falsely trigger",
      "expected_result": "match",
      "notes":           "why this is a false positive scenario"
    }}
  ],
  "improvement_suggestions": ["suggestion 1", "suggestion 2"],
  "missing_conditions": "what the rule is currently not catching"
}}"""

    raw = ask_claude(
        prompt,
        system="You are a detection validation expert. Return only valid JSON, no explanation before or after.",
        max_tokens=2000
    )
    try:
        data = parse_json(raw)
    except Exception as e:
        raise HTTPException(500, f"Parse error: {str(e)}")

    # Save to validation_cases using exact column names from schema:
    # case_id(auto), detection_id, detection_title, attack_name,
    # sample_type, sample_event, expected_result, status, source
    conn = get_connection()
    saved = 0
    try:
        for tc in data.get("test_cases", []):
            conn.execute("""
                INSERT INTO validation_cases
                    (detection_id, detection_title, attack_name,
                     sample_type, sample_event, expected_result,
                     status, source)
                VALUES (?, ?, ?, ?, ?, ?, 'untested', 'ai')
            """, (
                detection_id,
                detection["title"],
                tc.get("attack_name", "AI Test"),
                tc.get("sample_type", "positive"),
                tc.get("sample_event", ""),
                tc.get("expected_result", "match"),
            ))
            saved += 1
        conn.commit()
    except Exception as e:
        data["db_save_error"] = str(e)
    finally:
        conn.close()

    data["detection_id"] = detection_id
    data["cases_saved"]  = saved
    return data


# ═══════════════════════════════════════════════════════════════════════════════
#  FEATURE 5 — DEPLOYMENT DOCUMENTATION
#  POST /api/ai/deployment-docs/{detection_id}
#
#  detections: detection_id, title, severity, status, platform,
#              description, falsepositives, raw_yaml
# ═══════════════════════════════════════════════════════════════════════════════

@router.post("/deployment-docs/{detection_id}")
def generate_deployment_docs(detection_id: int):
    """Auto-generate deployment documentation for a detection rule."""

    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM detections WHERE detection_id = ?", (detection_id,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Detection not found")
        detection = dict(row)

        # Get mapped ATT&CK technique if exists
        # detection_technique_mapping: id, detection_id, technique_id
        tech_row = conn.execute("""
            SELECT mt.technique_id, mt.name, mt.tactic
            FROM mitre_techniques mt
            JOIN detection_technique_mapping dtm
                ON mt.technique_id = dtm.technique_id
            WHERE dtm.detection_id = ?
            LIMIT 1
        """, (detection_id,)).fetchone()
        technique = dict(tech_row) if tech_row else None
    finally:
        conn.close()

    tech_info = ""
    if technique:
        tech_info = (
            f"ATT&CK Technique : {technique['technique_id']} — {technique['name']}\n"
            f"Tactic           : {technique['tactic']}\n"
        )

    prompt = f"""You are a senior detection engineer writing deployment documentation for a SOC team.

Detection title  : {detection['title']}
Detection ID     : {detection_id}
Severity         : {detection.get('severity', 'N/A')}
Status           : {detection.get('status', 'N/A')}
Platform         : {detection.get('platform', 'N/A')}
Description      : {detection.get('description', 'N/A')}
{tech_info}
Sigma rule:
{detection.get('raw_yaml', 'No Sigma rule defined yet.')}

Known false positives: {detection.get('falsepositives', 'None documented.')}

Return ONLY a JSON object, no extra text:
{{
  "title": "full document title",
  "executive_summary": "2-3 sentence non-technical summary",
  "prerequisites": {{
    "log_sources":       ["required log sources"],
    "audit_policy":      ["Windows audit policies to enable"],
    "siem_requirements": ["SIEM version or feature requirements"]
  }},
  "deployment_steps": [
    {{"step": 1, "title": "step title", "description": "what to do", "command": "optional CLI command"}}
  ],
  "tuning_guide": {{
    "initial_threshold":    "recommended starting threshold",
    "allowlist_candidates": ["processes or accounts to allowlist"],
    "environment_specific": "advice for tuning in specific environments"
  }},
  "false_positive_handling": {{
    "known_fps":           ["known false positive scenarios"],
    "triage_steps":        ["how to investigate an alert step by step"],
    "escalation_criteria": "when to escalate vs close as FP"
  }},
  "testing_procedure": {{
    "pre_deployment_test": "how to test before going live",
    "validation_command":  "command or tool to generate a test event",
    "expected_alert":      "what the resulting alert should look like"
  }},
  "maintenance": {{
    "review_frequency": "how often to review this rule",
    "update_triggers":  ["events that should prompt a rule review"],
    "metrics_to_track": ["TP rate", "FP rate", "alert volume"]
  }},
  "references": ["ATT&CK technique URL", "relevant blog post or paper"]
}}"""

    raw = ask_claude(
        prompt,
        system="You are a senior detection engineer. Return only valid JSON, no explanation before or after.",
        max_tokens=2500
    )
    try:
        data = parse_json(raw)
    except Exception as e:
        raise HTTPException(500, f"Parse error: {str(e)}")

    data["detection_id"] = detection_id
    data["generated_at"] = datetime.utcnow().isoformat()
    return data



# ═══════════════════════════════════════════════════════════════════════════════
#  JASON'S AI FEATURES — Chat, Masking, Analysis, Hunting
# ═══════════════════════════════════════════════════════════════════════════════

# ── System prompt for chat ────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are the AI assistant for ABSEGA's Detection Engineering & Validation Platform.

You help security analysts with:
- Understanding Sigma detection rules and their logic
- Explaining MITRE ATT&CK techniques and tactics
- Analyzing detection coverage gaps
- Explaining log sources (auditd, Sysmon, sshd, Windows Event Logs, etc.)
- Writing and improving Sigma rules
- Understanding validation test results (TP, FP, TN, FN)
- Data masking and de-masking of sensitive log fields

Platform context:
- The platform stores Sigma detection rules mapped to MITRE ATT&CK techniques
- It tracks telemetry sources (log sources) and their health status
- It validates detections using sample log events
- Detection categories: Windows, Linux, Identity/Cloud
- There are 6 database tables: mitre_techniques, telemetry_sources, detections,
  detection_technique_mapping, detection_telemetry, validation_cases

Keep responses concise and actionable. Use technical accuracy.
When discussing detections, reference specific technique IDs (e.g. T1110.001).
Format code blocks with proper syntax highlighting."""


# ═══════════════════════════════════════════════════════════════════════════════
#  FEATURE 6 — AI CHATBOT
# ═══════════════════════════════════════════════════════════════════════════════

class ChatRequest(BaseModel):
    message: str
    context: Optional[str] = None

class ChatResponse(BaseModel):
    reply: str
    tokens_used: int

def _get_platform_context() -> str:
    conn = get_connection()
    try:
        total_det = conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
        total_tech = conn.execute("SELECT COUNT(*) FROM mitre_techniques").fetchone()[0]
        total_telem = conn.execute("SELECT COUNT(*) FROM telemetry_sources").fetchone()[0]
        covered = conn.execute("SELECT COUNT(DISTINCT technique_id) FROM detection_technique_mapping").fetchone()[0]
        sev = {r[0]: r[1] for r in conn.execute("SELECT severity, COUNT(*) FROM detections GROUP BY severity").fetchall()}
        plat = {r[0]: r[1] for r in conn.execute("SELECT platform, COUNT(*) FROM detections GROUP BY platform").fetchall()}
        coverage_pct = round((covered / total_tech * 100), 1) if total_tech else 0
        return f"\nCurrent platform stats:\n- {total_det} detection rules ({json.dumps(sev)})\n- {total_tech} MITRE techniques in database\n- {covered} techniques covered ({coverage_pct}% coverage)\n- {total_telem} telemetry sources\n- Platform breakdown: {json.dumps(plat)}\n"
    except Exception:
        return "Platform stats unavailable."
    finally:
        conn.close()

@router.post("/chat")
def ai_chat(req: ChatRequest):
    client = get_client()
    platform_stats = _get_platform_context()
    messages_content = req.message
    if req.context:
        messages_content = f"[User is viewing: {req.context}]\n\n{req.message}"
    try:
        response = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=1024,
            system=SYSTEM_PROMPT + "\n" + platform_stats,
            messages=[{"role": "user", "content": messages_content}]
        )
        reply = response.content[0].text
        tokens = response.usage.input_tokens + response.usage.output_tokens
        return ChatResponse(reply=reply, tokens_used=tokens)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Claude API error: {str(e)}")


# ═══════════════════════════════════════════════════════════════════════════════
#  FEATURE 7 — DATA MASKING
# ═══════════════════════════════════════════════════════════════════════════════

_mask_store: dict[str, dict] = {}

class MaskRequest(BaseModel):
    log_text: str
    mask_fields: Optional[list[str]] = None

class MaskResponse(BaseModel):
    masked_text: str
    masked_count: int
    masked_fields: list[dict]
    mask_id: str

SENSITIVE_PATTERNS = {
    "ip_address": r'\b(?:10|172|192|185|203|45|91|78)\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
    "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    "xml_user": r'<Data Name="(?:User|TargetUserName|SubjectUserName)">(.*?)</Data>',
    "xml_computer": r'<Computer>(.*?)</Computer>',
    "xml_ip": r'<Data Name="(?:IpAddress|SourceIp|DestinationIp)">(.*?)</Data>',
    "xml_hostname": r'<Data Name="(?:WorkstationName|DestinationHostname)">(.*?)</Data>',
    "xml_domain": r'<Data Name="(?:TargetDomainName|SubjectDomainName)">(.*?)</Data>',
    "username": r'(?:User(?:Name)?|TargetUserName|SubjectUserName)[=:]\s*["\']?([A-Za-z0-9._\\-]+)["\']?',
    "hostname": r'(?:Computer|Hostname|WorkstationName|hostname)[=:]\s*["\']?([A-Za-z0-9._-]+)["\']?',
    "domain": r'(?:Domain(?:Name)?|TargetDomainName|SubjectDomainName)[=:]\s*["\']?([A-Za-z0-9._-]+)["\']?',
    "json_user": r'"(?:email|username|userPrincipalName|actor_user_name)":\s*"(.*?)"',
    "json_ip": r'"(?:ipAddress|ipaddr|IpAddress)":\s*"(.*?)"',
    "json_host": r'"(?:city|country|countryOrRegion)":\s*"(.*?)"',
    "path": r'C:\\Users\\([A-Za-z0-9._-]+)',
    "linux_user": r'for (?:invalid user )?(\w+) from',
    "linux_ip": r'from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
    "sid": r'S-1-5-21-\d+-\d+-\d+-\d+',
}

def _generate_mask(value: str, field_type: str) -> str:
    hash_val = hashlib.md5(value.encode()).hexdigest()[:8]
    prefixes = {
        "ip_address": "10.XXX.XXX", "email": "MASKED_USER",
        "username": "USER", "xml_user": "USER", "json_user": "USER", "linux_user": "USER",
        "hostname": "HOST", "xml_hostname": "HOST", "json_host": "LOCATION",
        "xml_computer": "HOST", "xml_ip": "10.XXX.XXX", "json_ip": "10.XXX.XXX", "linux_ip": "10.XXX.XXX",
        "domain": "DOMAIN", "xml_domain": "DOMAIN",
        "path": "MASKED_USER", "sid": "S-1-5-21-XXXXXXXXX",
    }
    prefix = prefixes.get(field_type, "MASKED")
    return f"{prefix}_{hash_val}"

@router.post("/mask")
def mask_log_data(req: MaskRequest):
    log_text = req.log_text
    masked_fields = []
    mask_mapping = {}
    for field_type, pattern in SENSITIVE_PATTERNS.items():
        if req.mask_fields and field_type not in req.mask_fields:
            continue
        matches = re.finditer(pattern, log_text)
        for match in matches:
            original = match.group(0)
            if match.lastindex and match.lastindex >= 1:
                original_value = match.group(1)
                masked_value = _generate_mask(original_value, field_type)
                log_text = log_text.replace(original_value, masked_value)
                mask_mapping[masked_value] = original_value
                masked_fields.append({"type": field_type, "masked_as": masked_value})
            else:
                masked_value = _generate_mask(original, field_type)
                log_text = log_text.replace(original, masked_value)
                mask_mapping[masked_value] = original
                masked_fields.append({"type": field_type, "masked_as": masked_value})
    mask_id = hashlib.sha256(f"{req.log_text}{datetime.utcnow().isoformat()}".encode()).hexdigest()[:16]
    _mask_store[mask_id] = {"mapping": mask_mapping, "created_at": datetime.utcnow().isoformat(), "original_text": req.log_text}
    return MaskResponse(masked_text=log_text, masked_count=len(masked_fields), masked_fields=masked_fields, mask_id=mask_id)


# ═══════════════════════════════════════════════════════════════════════════════
#  FEATURE 8 — DE-MASKING
# ═══════════════════════════════════════════════════════════════════════════════

class UnmaskRequest(BaseModel):
    mask_id: str
    masked_text: str
    role: str

class UnmaskResponse(BaseModel):
    original_text: str
    unmasked_count: int
    authorized: bool

@router.post("/unmask")
def unmask_log_data(req: UnmaskRequest):
    allowed_roles = {"Admin", "Engineer"}
    if req.role not in allowed_roles:
        raise HTTPException(status_code=403, detail=f"De-masking requires Admin or Engineer role. Your role: {req.role}")
    mask_data = _mask_store.get(req.mask_id)
    if not mask_data:
        raise HTTPException(status_code=404, detail="Mask ID not found.")
    unmasked_text = req.masked_text
    mapping = mask_data["mapping"]
    unmasked_count = 0
    for masked_value, original_value in mapping.items():
        if masked_value in unmasked_text:
            unmasked_text = unmasked_text.replace(masked_value, original_value)
            unmasked_count += 1
    return UnmaskResponse(original_text=unmasked_text, unmasked_count=unmasked_count, authorized=True)


# ═══════════════════════════════════════════════════════════════════════════════
#  FEATURE 9 — RULE EXPLAINER
# ═══════════════════════════════════════════════════════════════════════════════

class ExplainRequest(BaseModel):
    title: str
    description: Optional[str] = ""
    sigma_rule: Optional[str] = ""
    tags: Optional[str] = ""
    severity: Optional[str] = ""

@router.post("/explain")
def explain_rule(req: ExplainRequest):
    client = get_client()
    prompt = f"""Explain this Sigma detection rule in plain English for a SOC analyst.
Title: {req.title}
Description: {req.description}
MITRE Tags: {req.tags}
Severity: {req.severity}
Sigma Rule:
{req.sigma_rule}

Structure your response as:
**What it detects:** (1-2 sentences)
**Attack scenario:** (what an attacker is doing step by step)
**Why it matters:** (risk level and impact)
**Log source needed:** (what logs must be collected)
**False positive tips:** (when this might fire incorrectly)"""
    try:
        response = client.messages.create(model="claude-haiku-4-5-20251001", max_tokens=512,
            system="You are a senior SOC analyst explaining detection rules. Be concise and practical.",
            messages=[{"role": "user", "content": prompt}])
        return {"explanation": response.content[0].text, "tokens_used": response.usage.input_tokens + response.usage.output_tokens}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ═══════════════════════════════════════════════════════════════════════════════
#  FEATURE 10 — LOG ANALYZER
# ═══════════════════════════════════════════════════════════════════════════════

class LogAnalyzeRequest(BaseModel):
    log_text: str

@router.post("/analyze-log")
def analyze_log(req: LogAnalyzeRequest):
    client = get_client()
    conn = get_connection()
    try:
        det_count = conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
    finally:
        conn.close()
    prompt = f"""Analyze this raw log entry and provide:
**Verdict:** MALICIOUS / SUSPICIOUS / BENIGN
**Attack identified:** (what is happening)
**MITRE technique:** (technique ID and name)
**Tactic:** (e.g. Execution, Credential Access)
**Severity:** Critical / High / Medium / Low
**Recommended action:** (what the analyst should do next)
**Sigma rule suggestion:** (a brief Sigma detection logic)
The platform currently has {det_count} detection rules.
Raw log:
{req.log_text}"""
    try:
        response = client.messages.create(model="claude-haiku-4-5-20251001", max_tokens=512,
            system="You are a SOC analyst specialized in log analysis. Be concise and actionable.",
            messages=[{"role": "user", "content": prompt}])
        return {"analysis": response.content[0].text, "tokens_used": response.usage.input_tokens + response.usage.output_tokens}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ═══════════════════════════════════════════════════════════════════════════════
#  FEATURE 11 — IOC ENRICHMENT
# ═══════════════════════════════════════════════════════════════════════════════

class IOCRequest(BaseModel):
    ioc: str
    ioc_type: Optional[str] = None

@router.post("/ioc")
def enrich_ioc(req: IOCRequest):
    client = get_client()
    ioc = req.ioc.strip()
    if req.ioc_type:
        ioc_type = req.ioc_type
    elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc):
        ioc_type = "IP Address"
    elif re.match(r'^[a-fA-F0-9]{32}$', ioc):
        ioc_type = "MD5 Hash"
    elif re.match(r'^[a-fA-F0-9]{64}$', ioc):
        ioc_type = "SHA256 Hash"
    elif re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', ioc):
        ioc_type = "Domain"
    else:
        ioc_type = "Unknown"
    prompt = f"""Analyze this IOC:
IOC: {ioc}
Type: {ioc_type}
Provide:
**Threat Level:** Critical / High / Medium / Low / Unknown
**Classification:** (Known C2, Tor Exit Node, Malware Hash, Clean)
**Associated threats:** (known APT groups, malware families)
**MITRE techniques:** (commonly associated techniques)
**Recommended actions:** (block, monitor, investigate, ignore)
**Detection rules needed:** (what Sigma rules should cover this)"""
    try:
        response = client.messages.create(model="claude-haiku-4-5-20251001", max_tokens=512,
            system="You are a threat intelligence analyst. Provide actionable IOC analysis.",
            messages=[{"role": "user", "content": prompt}])
        return {"ioc": ioc, "ioc_type": ioc_type, "analysis": response.content[0].text, "tokens_used": response.usage.input_tokens + response.usage.output_tokens}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ═══════════════════════════════════════════════════════════════════════════════
#  FEATURE 12 — NATURAL LANGUAGE SEARCH
# ═══════════════════════════════════════════════════════════════════════════════

class NLSearchRequest(BaseModel):
    query: str

@router.post("/search")
def natural_language_search(req: NLSearchRequest):
    conn = get_connection()
    try:
        rows = conn.execute("SELECT detection_id, title, description, severity, status FROM detections LIMIT 50").fetchall()
        det_list = [{"id": r[0], "title": r[1], "description": r[2], "severity": r[3], "status": r[4]} for r in rows]
    finally:
        conn.close()
    client = get_client()
    prompt = f"""Search for detection rules matching this query: "{req.query}"
Detections: {json.dumps(det_list, indent=1)}
Return ONLY valid JSON: {{"results": [{{"id": 1, "title": "...", "reason": "..."}}], "summary": "Found X matching rules..."}}"""
    try:
        response = client.messages.create(model="claude-haiku-4-5-20251001", max_tokens=1024,
            system="You are a detection search engine. Return only valid JSON.",
            messages=[{"role": "user", "content": prompt}])
        result_text = response.content[0].text.strip().replace("```json", "").replace("```", "").strip()
        try:
            start = result_text.find('{')
            end = result_text.rfind('}') + 1
            if start >= 0 and end > start:
                parsed = json.loads(result_text[start:end])
            else:
                parsed = {"results": [], "summary": result_text}
        except json.JSONDecodeError:
            parsed = {"results": [], "summary": result_text}
        return {"results": parsed.get("results", []), "summary": parsed.get("summary", ""), "tokens_used": response.usage.input_tokens + response.usage.output_tokens}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ═══════════════════════════════════════════════════════════════════════════════
#  FEATURE 13 — ATTACK CHAIN RECONSTRUCTION
# ═══════════════════════════════════════════════════════════════════════════════

class AttackChainRequest(BaseModel):
    logs: str

@router.post("/attack-chain")
def reconstruct_attack_chain(req: AttackChainRequest):
    client = get_client()
    prompt = f"""Analyze these logs and build a complete attack chain timeline:
{req.logs}
Respond with:
**INCIDENT SUMMARY** (1-2 sentences)
**ATTACK TIMELINE** [TIMESTAMP] → [ACTION] → [MITRE TECHNIQUE]
**KILL CHAIN PHASE MAPPING**
**SEVERITY ASSESSMENT**
**RECOMMENDED RESPONSE**
**INDICATORS OF COMPROMISE**"""
    try:
        response = client.messages.create(model="claude-haiku-4-5-20251001", max_tokens=1024,
            system="You are a senior incident responder. Provide clear, actionable analysis.",
            messages=[{"role": "user", "content": prompt}])
        return {"chain": response.content[0].text, "tokens_used": response.usage.input_tokens + response.usage.output_tokens}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ═══════════════════════════════════════════════════════════════════════════════
#  FEATURE 14 — DETECTION QUALITY SCORER
# ═══════════════════════════════════════════════════════════════════════════════

@router.post("/quality-score")
def score_detection_quality(req: ExplainRequest):
    client = get_client()
    prompt = f"""Score this Sigma detection rule (0-100):
Title: {req.title}
Description: {req.description}
Tags: {req.tags}
Severity: {req.severity}
Rule: {req.sigma_rule}
Score on: Logic Accuracy (X/20), Coverage Breadth (X/20), False Positive Management (X/20), MITRE Alignment (X/20), Operational Readiness (X/20).
Give TOP 3 IMPROVEMENTS and VERDICT: Production Ready / Needs Improvement / Not Ready."""
    try:
        response = client.messages.create(model="claude-haiku-4-5-20251001", max_tokens=700,
            system="You are a senior detection engineer. Be strict but fair.",
            messages=[{"role": "user", "content": prompt}])
        return {"score": response.content[0].text, "tokens_used": response.usage.input_tokens + response.usage.output_tokens}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ═══════════════════════════════════════════════════════════════════════════════
#  FEATURE 15 — THREAT HUNTING ASSISTANT
# ═══════════════════════════════════════════════════════════════════════════════

class HuntRequest(BaseModel):
    hypothesis: str

@router.post("/threat-hunt")
def generate_hunt_plan(req: HuntRequest):
    client = get_client()
    conn = get_connection()
    try:
        det_count = conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
        covered = conn.execute("SELECT COUNT(DISTINCT technique_id) FROM detection_technique_mapping").fetchone()[0]
    finally:
        conn.close()
    prompt = f"""Generate a threat hunting plan.
Hypothesis: "{req.hypothesis}"
Platform has {det_count} detections covering {covered} MITRE techniques.
Provide: HUNT HYPOTHESIS, WHAT TO LOOK FOR, DATA SOURCES NEEDED, HUNT QUERIES (Sigma YAML), MITRE TECHNIQUES, RECOMMENDED DURATION, SUCCESS CRITERIA."""
    try:
        response = client.messages.create(model="claude-haiku-4-5-20251001", max_tokens=1024,
            system="You are an elite threat hunter. Provide actionable hunt plans.",
            messages=[{"role": "user", "content": prompt}])
        return {"plan": response.content[0].text, "tokens_used": response.usage.input_tokens + response.usage.output_tokens}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ═══════════════════════════════════════════════════════════════════════════════
#  FEATURE 16 — EXECUTIVE THREAT BRIEFING
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/briefing")
def executive_briefing():
    client = get_client()
    conn = get_connection()
    try:
        total_det = conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
        total_tech = conn.execute("SELECT COUNT(*) FROM mitre_techniques").fetchone()[0]
        covered = conn.execute("SELECT COUNT(DISTINCT technique_id) FROM detection_technique_mapping").fetchone()[0]
        total_telem = conn.execute("SELECT COUNT(*) FROM telemetry_sources").fetchone()[0]
        sev = {r[0]: r[1] for r in conn.execute("SELECT severity, COUNT(*) FROM detections GROUP BY severity").fetchall()}
        active = conn.execute("SELECT COUNT(*) FROM detections WHERE status='active'").fetchone()[0]
    finally:
        conn.close()
    coverage_pct = round((covered / total_tech * 100), 1) if total_tech else 0
    prompt = f"""Generate an executive threat briefing.
Data: {total_det} detections, {active} active, {total_tech} techniques, {covered} covered ({coverage_pct}%), {total_telem} telemetry sources, severity: {json.dumps(sev)}.
Include: CRITICAL FINDINGS, COVERAGE METRICS, TOP RISK AREAS, PRIORITY RECOMMENDATIONS, 30-DAY ACTION PLAN."""
    try:
        response = client.messages.create(model="claude-haiku-4-5-20251001", max_tokens=1024,
            system="You are a CISO advisor. Be data-driven and impactful.",
            messages=[{"role": "user", "content": prompt}])
        return {"briefing": response.content[0].text, "tokens_used": response.usage.input_tokens + response.usage.output_tokens}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ═══════════════════════════════════════════════════════════════════════════════
#  HEALTH CHECK
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/health")
def ai_health():
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    return {
        "ai_configured": bool(api_key),
        "api_key_set": bool(api_key),
        "mode": "live" if api_key else "demo_mock",
        "api_key_preview": f"{api_key[:12]}...{api_key[-4:]}" if api_key else None,
        "model": "claude-haiku-4-5-20251001" if api_key else "local-demo-mock",
        "features": ["chat", "mask", "unmask", "explain", "analyze-log", "ioc", "search",
                      "attack-chain", "quality-score", "threat-hunt", "briefing",
                      "suggest-rule", "auto-map", "gap-analysis", "validate", "deployment-docs"],
        "mask_store_size": len(_mask_store),
    }

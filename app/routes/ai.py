from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
from app.database import get_connection
import anthropic
import json
import os

router = APIRouter()


# ── Anthropic client ──────────────────────────────────────────────────────────

def get_client():
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise HTTPException(
            status_code=503,
            detail="ANTHROPIC_API_KEY not set. Set it with: export ANTHROPIC_API_KEY=sk-ant-..."
        )
    return anthropic.Anthropic(api_key=key)


def ask_claude(prompt: str, system: str = None, max_tokens: int = 1500) -> str:
    client = get_client()  # raises 503 directly if no key
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

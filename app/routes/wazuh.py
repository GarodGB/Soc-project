import re
import html
from collections import defaultdict
from datetime import datetime
from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse

from app.database import get_connection
from app.wazuh_client import fetch_all_rules, WazuhError

router = APIRouter()

_TECH_RE = re.compile(r"[Tt](\d{4}(?:\.\d{3})?)")


def _normalize_ids(values) -> set:
    out = set()
    if values is None:
        return out
    if isinstance(values, str):
        values = [values]
    for v in values:
        if not v:
            continue
        for m in _TECH_RE.finditer(str(v)):
            out.add("T" + m.group(1))
    return out


def _wazuh_mitre_ids(rule: dict) -> set:
    mitre = rule.get("mitre") or {}
    ids = set()
    if isinstance(mitre, dict):
        ids |= _normalize_ids(mitre.get("id"))
        ids |= _normalize_ids(mitre.get("technique"))
    elif isinstance(mitre, list):
        ids |= _normalize_ids(mitre)
    return ids


def _attack_url(tid: str) -> str:
    if "." in tid:
        base, sub = tid.split(".", 1)
        return f"https://attack.mitre.org/techniques/{base}/{sub}/"
    return f"https://attack.mitre.org/techniques/{tid}/"


def _compare():
    """Full bidirectional comparison: Sigma ↔ Wazuh."""
    try:
        wazuh_rules = fetch_all_rules()
    except WazuhError as e:
        raise HTTPException(status_code=502, detail=f"Wazuh: {e}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Wazuh connection error: {e}")

    # ── Wazuh side ──
    wazuh_ids = set()
    wazuh_by_technique = defaultdict(list)
    wazuh_with_mitre = 0
    for r in wazuh_rules:
        rule_ids = _wazuh_mitre_ids(r)
        if rule_ids:
            wazuh_with_mitre += 1
        wazuh_ids |= rule_ids
        for tid in rule_ids:
            wazuh_by_technique[tid].append({
                "rule_id": str(r.get("id", "")),
                "description": r.get("description", ""),
                "level": r.get("level", 0),
                "filename": r.get("filename", ""),
            })

    # ── Sigma/DB side ──
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT detection_id, title, tags, severity, status, platform FROM detections"
        ).fetchall()
        # Load MITRE technique names
        mitre_rows = conn.execute(
            "SELECT technique_id, name, tactic FROM mitre_techniques"
        ).fetchall()
    finally:
        conn.close()

    mitre_db = {}
    for mr in mitre_rows:
        mitre_db[mr["technique_id"]] = {"name": mr["name"], "tactic": mr["tactic"]}

    db_ids = set()
    db_by_technique = defaultdict(list)
    platform_counts = defaultdict(int)
    for row in rows:
        platform_counts[row["platform"] or "unknown"] += 1
        ids = _normalize_ids(row["tags"])
        if not ids:
            continue
        db_ids |= ids
        for tid in ids:
            db_by_technique[tid].append({
                "id":       str(row["detection_id"]),
                "title":    row["title"] or "",
                "severity": (row["severity"] or "").lower(),
                "status":   (row["status"] or "").lower(),
                "platform": (row["platform"] or "").lower(),
            })

    # ── Compute overlaps ──
    both = db_ids & wazuh_ids
    sigma_only = db_ids - wazuh_ids
    wazuh_only = wazuh_ids - db_ids
    all_techniques = db_ids | wazuh_ids

    # ── Build missing dicts ──
    missing_in_wazuh = {}
    for tid in sorted(sigma_only):
        missing_in_wazuh[tid] = sorted(db_by_technique[tid], key=lambda d: d["title"].lower())

    missing_in_sigma = {}
    for tid in sorted(wazuh_only):
        missing_in_sigma[tid] = sorted(wazuh_by_technique[tid], key=lambda d: d["description"].lower())

    summary = {
        "wazuh_rules_total":       len(wazuh_rules),
        "wazuh_with_mitre":        wazuh_with_mitre,
        "wazuh_mitre_ids":         len(wazuh_ids),
        "db_detections_total":     len(rows),
        "db_mitre_ids":            len(db_ids),
        "platform_counts":         dict(platform_counts),
        "both_count":              len(both),
        "sigma_only_count":        len(sigma_only),
        "wazuh_only_count":        len(wazuh_only),
        "total_unique_techniques": len(all_techniques),
        "missing_in_wazuh_rules":  sum(len(v) for v in missing_in_wazuh.values()),
        "missing_in_sigma_rules":  sum(len(v) for v in missing_in_sigma.values()),
    }
    return summary, missing_in_wazuh, missing_in_sigma, mitre_db, wazuh_by_technique, db_by_technique, both


@router.post("/import-compare")
def import_and_compare():
    summary, missing_in_wazuh, missing_in_sigma, mitre_db, _, _, _ = _compare()
    return {
        "summary": summary,
        "missing_in_wazuh": missing_in_wazuh,
        "missing_in_sigma": {tid: rules for tid, rules in missing_in_sigma.items()},
    }


@router.get("/import-compare/report", response_class=HTMLResponse)
def import_and_compare_report():
    summary, missing_in_wazuh, missing_in_sigma, mitre_db, wazuh_by_technique, db_by_technique, both = _compare()
    generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    return HTMLResponse(content=_render_report(
        summary, missing_in_wazuh, missing_in_sigma, mitre_db,
        wazuh_by_technique, db_by_technique, both, generated_at
    ))


# ── HTML Report ───────────────────────────────────────────────────────────────

_SEV_COLORS = {
    "critical": "#dc2626", "high": "#ea580c", "medium": "#ca8a04",
    "low": "#16a34a", "informational": "#0891b2",
}

_LEVEL_LABELS = {
    range(0, 4): "Info", range(4, 7): "Low", range(7, 10): "Medium",
    range(10, 13): "High", range(13, 16): "Critical",
}


def _sev_badge(sev: str) -> str:
    color = _SEV_COLORS.get(sev, "#6b7280")
    label = html.escape(sev.upper() if sev else "—")
    return (f'<span style="display:inline-block;padding:2px 8px;border-radius:10px;'
            f'background:{color};color:#fff;font-size:11px;font-weight:600;'
            f'letter-spacing:.3px">{label}</span>')


def _level_badge(level) -> str:
    level = int(level) if level else 0
    label = "Info"
    color = "#0891b2"
    if level >= 13:
        label, color = "Critical", "#dc2626"
    elif level >= 10:
        label, color = "High", "#ea580c"
    elif level >= 7:
        label, color = "Medium", "#ca8a04"
    elif level >= 4:
        label, color = "Low", "#16a34a"
    return (f'<span style="display:inline-block;padding:2px 8px;border-radius:10px;'
            f'background:{color};color:#fff;font-size:11px;font-weight:600">'
            f'Lv{level} {label}</span>')


def _platform_badge(platform: str) -> str:
    colors = {"windows": "#0078d4", "linux": "#e95420", "identity": "#8b5cf6"}
    color = colors.get(platform, "#6b7280")
    label = html.escape(platform.upper() if platform else "—")
    return (f'<span style="display:inline-block;padding:2px 8px;border-radius:10px;'
            f'background:{color};color:#fff;font-size:11px;font-weight:600">{label}</span>')


def _status_badge(status: str) -> str:
    label = html.escape((status or "—").upper())
    return (f'<span style="display:inline-block;padding:2px 8px;border-radius:10px;'
            f'background:#1f2937;color:#cbd5e1;font-size:11px;font-weight:500;'
            f'border:1px solid #334155">{label}</span>')


def _render_report(summary, missing_in_wazuh, missing_in_sigma, mitre_db,
                   wazuh_by_technique, db_by_technique, both, generated_at):
    s = summary
    pc = s.get("platform_counts", {})

    # Coverage percentages
    if s["total_unique_techniques"] > 0:
        both_pct = round(100 * s["both_count"] / s["total_unique_techniques"])
        sigma_only_pct = round(100 * s["sigma_only_count"] / s["total_unique_techniques"])
        wazuh_only_pct = round(100 * s["wazuh_only_count"] / s["total_unique_techniques"])
    else:
        both_pct = sigma_only_pct = wazuh_only_pct = 0

    # ── Tiles ──
    tiles_html = f'''
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px;margin-bottom:24px">
      <div class="tile" style="border-left-color:#0ea5e9">
        <div class="tile-label">Wazuh Rules Loaded</div>
        <div class="tile-value" style="color:#0ea5e9">{s["wazuh_rules_total"]:,}</div>
        <div class="tile-sub">{s["wazuh_with_mitre"]:,} have MITRE tags</div>
      </div>
      <div class="tile" style="border-left-color:#8b5cf6">
        <div class="tile-label">Sigma Platform Rules</div>
        <div class="tile-value" style="color:#8b5cf6">{s["db_detections_total"]:,}</div>
        <div class="tile-sub">Win {pc.get("windows",0)} · Linux {pc.get("linux",0)} · Identity {pc.get("identity",0)}</div>
      </div>
      <div class="tile" style="border-left-color:#16a34a">
        <div class="tile-label">Techniques in Both</div>
        <div class="tile-value" style="color:#16a34a">{s["both_count"]}</div>
        <div class="tile-sub">{both_pct}% of {s["total_unique_techniques"]} total techniques</div>
      </div>
      <div class="tile" style="border-left-color:#f59e0b">
        <div class="tile-label">Wazuh Unique Techniques</div>
        <div class="tile-value" style="color:#f59e0b">{s["wazuh_mitre_ids"]}</div>
        <div class="tile-sub">{s["wazuh_only_count"]} not in your platform</div>
      </div>
      <div class="tile" style="border-left-color:#a855f7">
        <div class="tile-label">Sigma Unique Techniques</div>
        <div class="tile-value" style="color:#a855f7">{s["db_mitre_ids"]}</div>
        <div class="tile-sub">{s["sigma_only_count"]} not in Wazuh</div>
      </div>
      <div class="tile" style="border-left-color:#ef4444">
        <div class="tile-label">Total Gaps (Both Sides)</div>
        <div class="tile-value" style="color:#ef4444">{s["sigma_only_count"] + s["wazuh_only_count"]}</div>
        <div class="tile-sub">{s["sigma_only_count"]} Wazuh gaps + {s["wazuh_only_count"]} Sigma gaps</div>
      </div>
    </div>'''

    # ── Coverage bar ──
    bar_html = f'''
    <div class="section" style="margin-bottom:24px">
      <div style="font-size:15px;font-weight:700;color:#f1f5f9;margin-bottom:16px">
        MITRE ATT&CK Technique Coverage — {s["total_unique_techniques"]} Total Unique Techniques
      </div>
      <div style="display:flex;height:36px;border-radius:8px;overflow:hidden;margin-bottom:12px">
        <div style="width:{both_pct}%;background:#16a34a;display:flex;align-items:center;justify-content:center;
                    color:#fff;font-size:12px;font-weight:700">{s["both_count"]} Both</div>
        <div style="width:{sigma_only_pct}%;background:#3b82f6;display:flex;align-items:center;justify-content:center;
                    color:#fff;font-size:12px;font-weight:700">{s["sigma_only_count"]} Sigma Only</div>
        <div style="width:{wazuh_only_pct}%;background:#f59e0b;display:flex;align-items:center;justify-content:center;
                    color:#fff;font-size:12px;font-weight:700">{s["wazuh_only_count"]} Wazuh Only</div>
      </div>
      <div style="display:flex;gap:24px;font-size:12px;color:#94a3b8">
        <span><span style="display:inline-block;width:12px;height:12px;background:#16a34a;border-radius:3px;
               margin-right:6px;vertical-align:middle"></span>Covered by Both — no action needed</span>
        <span><span style="display:inline-block;width:12px;height:12px;background:#3b82f6;border-radius:3px;
               margin-right:6px;vertical-align:middle"></span>Sigma Only — Wazuh is missing these (deploy to SIEM)</span>
        <span><span style="display:inline-block;width:12px;height:12px;background:#f59e0b;border-radius:3px;
               margin-right:6px;vertical-align:middle"></span>Wazuh Only — Platform is missing these (add Sigma rules)</span>
      </div>
    </div>'''

    # ── How to read ──
    howto_html = '''
    <div class="section" style="margin-bottom:24px;line-height:1.7;font-size:13px;color:#cbd5e1">
      <b style="color:#f1f5f9;font-size:14px">How to Read This Report</b><br><br>
      This report compares your <b style="color:#8b5cf6">ABSEGA Detection Platform</b> (Sigma rules)
      against your live <b style="color:#0ea5e9">Wazuh SIEM</b> by matching MITRE ATT&CK technique IDs.<br><br>
      <b style="color:#3b82f6">Section 1 — Gaps in Wazuh (Sigma Only)</b><br>
      MITRE techniques your platform has Sigma rules for, but Wazuh has <b>no matching rule</b>.
      These are attacks your platform can describe but your SIEM would miss in production.
      <b>Action:</b> Consider deploying these as custom Wazuh rules or decoders.<br><br>
      <b style="color:#f59e0b">Section 2 — Gaps in Platform (Wazuh Only)</b><br>
      MITRE techniques Wazuh actively detects, but your Sigma platform has <b>no rule for</b>.
      Your SIEM catches these attacks, but they are not documented in your detection library.
      <b>Action:</b> Consider writing Sigma rules for these to complete your library.<br><br>
      <b style="color:#16a34a">Section 3 — Covered by Both</b><br>
      Techniques where both systems have rules. These are your strongest areas.
    </div>'''

    # ── SECTION 1: Gaps in Wazuh (Sigma has, Wazuh doesn't) ──
    section1_html = ""
    if missing_in_wazuh:
        toc1 = "".join(
            f'<a href="#wazuh-{html.escape(tid)}" class="toc-link">'
            f'{html.escape(tid)} <span style="color:#94a3b8">·{len(dets)}</span></a>'
            for tid, dets in missing_in_wazuh.items()
        )
        cards1 = ""
        for tid, dets in missing_in_wazuh.items():
            tech_info = mitre_db.get(tid, {"name": "Unknown", "tactic": "Unknown"})
            rows_html = "".join(
                f'''<tr style="border-bottom:1px solid #1f2937">
                  <td style="padding:10px 12px;color:#94a3b8;font-family:monospace;font-size:12px">#{html.escape(d["id"])}</td>
                  <td style="padding:10px 12px;color:#e2e8f0;font-size:13px">{html.escape(d["title"])}</td>
                  <td style="padding:10px 12px">{_platform_badge(d["platform"])}</td>
                  <td style="padding:10px 12px">{_sev_badge(d["severity"])}</td>
                  <td style="padding:10px 12px">{_status_badge(d["status"])}</td>
                </tr>''' for d in dets
            )
            cards1 += f'''
            <section id="wazuh-{html.escape(tid)}" class="card">
              <header class="card-header">
                <div style="display:flex;align-items:baseline;gap:14px;flex-wrap:wrap">
                  <a href="{_attack_url(tid)}" target="_blank" rel="noreferrer" class="tech-id">{html.escape(tid)}</a>
                  <span style="color:#e2e8f0;font-size:14px;font-weight:600">{html.escape(tech_info["name"])}</span>
                  <span style="color:#64748b;font-size:12px">Tactic: {html.escape(tech_info["tactic"])}</span>
                </div>
                <div style="display:flex;align-items:center;gap:10px">
                  <span style="color:#94a3b8;font-size:12px">{len(dets)} rule{"s" if len(dets)!=1 else ""}</span>
                  <span class="badge-missing">WAZUH MISSING</span>
                </div>
              </header>
              <table style="width:100%;border-collapse:collapse">
                <thead><tr style="background:#0b1220">
                  <th class="th">Rule ID</th><th class="th">Title</th><th class="th">Platform</th>
                  <th class="th">Severity</th><th class="th">Status</th>
                </tr></thead>
                <tbody>{rows_html}</tbody>
              </table>
            </section>'''

        section1_html = f'''
        <div class="section-header" style="border-left-color:#3b82f6">
          <div style="font-size:20px;font-weight:700;color:#f1f5f9">
            Gaps in Wazuh — Your SIEM is Missing These
          </div>
          <div style="color:#94a3b8;font-size:13px;margin-top:4px">
            {len(missing_in_wazuh)} MITRE techniques ({s["missing_in_wazuh_rules"]} Sigma rules)
            your platform covers but Wazuh has no detection for.
            Your SIEM would not alert on these attacks.
          </div>
        </div>
        <div class="toc">{toc1}</div>
        {cards1}'''
    else:
        section1_html = '''
        <div class="section-header" style="border-left-color:#3b82f6">
          <div style="font-size:20px;font-weight:700;color:#f1f5f9">Gaps in Wazuh</div>
        </div>
        <div class="success-box">✓ No gaps — Wazuh covers every MITRE technique in your platform.</div>'''

    # ── SECTION 2: Gaps in Sigma (Wazuh has, Sigma doesn't) ──
    section2_html = ""
    if missing_in_sigma:
        toc2 = "".join(
            f'<a href="#sigma-{html.escape(tid)}" class="toc-link">'
            f'{html.escape(tid)} <span style="color:#94a3b8">·{len(rules)}</span></a>'
            for tid, rules in missing_in_sigma.items()
        )
        cards2 = ""
        for tid, rules in missing_in_sigma.items():
            tech_info = mitre_db.get(tid, {"name": "Unknown", "tactic": "Unknown"})
            rows_html = "".join(
                f'''<tr style="border-bottom:1px solid #1f2937">
                  <td style="padding:10px 12px;color:#94a3b8;font-family:monospace;font-size:12px">#{html.escape(str(r["rule_id"]))}</td>
                  <td style="padding:10px 12px;color:#e2e8f0;font-size:13px">{html.escape(r["description"])}</td>
                  <td style="padding:10px 12px">{_level_badge(r["level"])}</td>
                  <td style="padding:10px 12px;color:#64748b;font-size:12px">{html.escape(r["filename"])}</td>
                </tr>''' for r in rules[:20]  # cap at 20 to keep report manageable
            )
            more_note = ""
            if len(rules) > 20:
                more_note = f'<div style="padding:10px 12px;color:#64748b;font-size:12px;text-align:center">… and {len(rules)-20} more rules</div>'
            cards2 += f'''
            <section id="sigma-{html.escape(tid)}" class="card">
              <header class="card-header" style="border-bottom-color:#1f2937">
                <div style="display:flex;align-items:baseline;gap:14px;flex-wrap:wrap">
                  <a href="{_attack_url(tid)}" target="_blank" rel="noreferrer" class="tech-id" style="color:#fbbf24">{html.escape(tid)}</a>
                  <span style="color:#e2e8f0;font-size:14px;font-weight:600">{html.escape(tech_info["name"])}</span>
                  <span style="color:#64748b;font-size:12px">Tactic: {html.escape(tech_info["tactic"])}</span>
                </div>
                <div style="display:flex;align-items:center;gap:10px">
                  <span style="color:#94a3b8;font-size:12px">{len(rules)} Wazuh rule{"s" if len(rules)!=1 else ""}</span>
                  <span class="badge-sigma-missing">PLATFORM MISSING</span>
                </div>
              </header>
              <table style="width:100%;border-collapse:collapse">
                <thead><tr style="background:#0b1220">
                  <th class="th">Wazuh Rule ID</th><th class="th">Description</th>
                  <th class="th">Level</th><th class="th">Source File</th>
                </tr></thead>
                <tbody>{rows_html}</tbody>
              </table>
              {more_note}
            </section>'''

        section2_html = f'''
        <div class="section-header" style="border-left-color:#f59e0b;margin-top:40px">
          <div style="font-size:20px;font-weight:700;color:#f1f5f9">
            Gaps in Platform — Wazuh Detects These But Your Library Doesn't
          </div>
          <div style="color:#94a3b8;font-size:13px;margin-top:4px">
            {len(missing_in_sigma)} MITRE techniques ({s["missing_in_sigma_rules"]} Wazuh rules)
            your SIEM actively detects but your Sigma library has no rule for.
            Consider adding Sigma rules for full documentation.
          </div>
        </div>
        <div class="toc">{toc2}</div>
        {cards2}'''
    else:
        section2_html = '''
        <div class="section-header" style="border-left-color:#f59e0b;margin-top:40px">
          <div style="font-size:20px;font-weight:700;color:#f1f5f9">Gaps in Platform</div>
        </div>
        <div class="success-box">✓ No gaps — Your platform covers every MITRE technique Wazuh detects.</div>'''

    # ── SECTION 3: Covered by Both ──
    both_rows_html = ""
    for tid in sorted(both):
        tech_info = mitre_db.get(tid, {"name": "Unknown", "tactic": "Unknown"})
        sigma_count = len(db_by_technique.get(tid, []))
        wazuh_count = len(wazuh_by_technique.get(tid, []))
        both_rows_html += f'''<tr style="border-bottom:1px solid #1f2937">
          <td style="padding:8px 12px;font-family:monospace;color:#4ade80;font-weight:700;font-size:13px">
            <a href="{_attack_url(tid)}" target="_blank" rel="noreferrer" style="color:#4ade80;text-decoration:none">{html.escape(tid)}</a>
          </td>
          <td style="padding:8px 12px;color:#e2e8f0;font-size:13px">{html.escape(tech_info["name"])}</td>
          <td style="padding:8px 12px;color:#64748b;font-size:12px">{html.escape(tech_info["tactic"])}</td>
          <td style="padding:8px 12px;text-align:center;color:#60a5fa;font-weight:600">{sigma_count}</td>
          <td style="padding:8px 12px;text-align:center;color:#fbbf24;font-weight:600">{wazuh_count}</td>
        </tr>'''

    section3_html = f'''
    <div class="section-header" style="border-left-color:#16a34a;margin-top:40px">
      <div style="font-size:20px;font-weight:700;color:#f1f5f9">
        Covered by Both — Strongest Detection Areas
      </div>
      <div style="color:#94a3b8;font-size:13px;margin-top:4px">
        {len(both)} MITRE techniques are detected by both your Sigma platform and Wazuh SIEM. No action needed.
      </div>
    </div>
    <div class="card" style="overflow:hidden">
      <table style="width:100%;border-collapse:collapse">
        <thead><tr style="background:#0b1220">
          <th class="th">Technique</th><th class="th">Name</th><th class="th">Tactic</th>
          <th class="th" style="text-align:center">Sigma Rules</th>
          <th class="th" style="text-align:center">Wazuh Rules</th>
        </tr></thead>
        <tbody>{both_rows_html}</tbody>
      </table>
    </div>'''

    # ── Tab navigation ──
    tab_html = f'''
    <div style="display:flex;gap:8px;margin-bottom:24px;flex-wrap:wrap" class="no-print">
      <button onclick="showSection('all')" class="tab-btn active" id="tab-all">
        Show All
      </button>
      <button onclick="showSection('s1')" class="tab-btn" id="tab-s1" style="border-color:#3b82f6">
        Wazuh Gaps ({len(missing_in_wazuh)})
      </button>
      <button onclick="showSection('s2')" class="tab-btn" id="tab-s2" style="border-color:#f59e0b">
        Platform Gaps ({len(missing_in_sigma)})
      </button>
      <button onclick="showSection('s3')" class="tab-btn" id="tab-s3" style="border-color:#16a34a">
        Both Covered ({len(both)})
      </button>
    </div>'''

    return f'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>ABSEGA — Wazuh ↔ Sigma Full Gap Analysis</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style>
    @media print {{
      body {{ background:#fff !important; color:#000 !important; }}
      section, .tile {{ break-inside:avoid; }}
      a {{ color:#1d4ed8 !important; }}
      .no-print {{ display:none !important; }}
    }}
    body {{ margin:0; background:#020617; color:#e2e8f0;
           font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
           line-height:1.5; }}
    .wrap {{ max-width:1200px; margin:0 auto; padding:32px 24px 64px; }}
    h1 {{ font-size:28px; margin:0 0 4px; color:#f1f5f9; font-weight:700; }}
    .tile {{ background:#111827; border:1px solid #1f2937; border-radius:12px;
             padding:18px; border-left:4px solid; }}
    .tile-label {{ font-size:11px; color:#94a3b8; text-transform:uppercase;
                   letter-spacing:.6px; font-weight:600; }}
    .tile-value {{ font-size:32px; font-weight:700; margin-top:6px;
                   font-variant-numeric:tabular-nums; }}
    .tile-sub {{ font-size:12px; color:#64748b; margin-top:6px; }}
    .section {{ background:#0f172a; border:1px solid #1f2937; border-radius:12px;
               padding:16px 20px; }}
    .section-header {{ background:#0f172a; border:1px solid #1f2937; border-radius:12px;
                       padding:20px 24px; margin-bottom:16px; border-left:4px solid; }}
    .card {{ background:#111827; border:1px solid #1f2937; border-radius:12px;
             margin-bottom:16px; overflow:hidden; scroll-margin-top:20px; }}
    .card-header {{ display:flex; align-items:center; justify-content:space-between;
                    padding:16px 20px; background:#0f172a; border-bottom:1px solid #1f2937;
                    flex-wrap:wrap; gap:10px; }}
    .tech-id {{ color:#60a5fa; text-decoration:none; font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
               font-size:18px; font-weight:700; }}
    .tech-id:hover {{ text-decoration:underline; }}
    .th {{ text-align:left; padding:8px 12px; color:#64748b; font-size:11px;
           text-transform:uppercase; letter-spacing:.5px; font-weight:600; }}
    .badge-missing {{ background:#dc2626; color:#fff; padding:4px 12px; border-radius:10px;
                      font-size:12px; font-weight:600; }}
    .badge-sigma-missing {{ background:#f59e0b; color:#000; padding:4px 12px; border-radius:10px;
                            font-size:12px; font-weight:700; }}
    .toc {{ background:#0f172a; border:1px solid #1f2937; border-radius:12px;
            padding:14px 18px; margin-bottom:20px; }}
    .toc-link {{ display:inline-block; margin:4px 6px 4px 0; padding:4px 10px;
                 background:#1f2937; color:#cbd5e1; border-radius:6px; text-decoration:none;
                 font-family:monospace; font-size:12px; }}
    .toc-link:hover {{ background:#334155; }}
    .success-box {{ background:#052e16; border:1px solid #14532d; border-radius:12px;
                    padding:32px; text-align:center; color:#86efac; font-size:18px; font-weight:600;
                    margin-bottom:20px; }}
    .tab-btn {{ padding:10px 20px; border:2px solid #334155; background:#111827; color:#ccc;
               border-radius:8px; cursor:pointer; font-size:14px; font-weight:600; }}
    .tab-btn:hover {{ background:#1f2937; }}
    .tab-btn.active {{ background:#1e293b; color:#fff; border-color:#60a5fa; }}
  </style>
</head>
<body>
<div class="wrap">
  <header style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:24px;gap:16px;flex-wrap:wrap">
    <div>
      <h1>Wazuh ↔ Sigma — Full Gap Analysis</h1>
      <div style="color:#94a3b8;font-size:14px">Bidirectional detection-coverage comparison by MITRE ATT&CK technique</div>
      <div style="color:#64748b;font-size:12px;margin-top:6px">Generated {html.escape(generated_at)} · ABSEGA CYBER</div>
    </div>
    <div class="no-print" style="display:flex;gap:8px">
      <button onclick="window.print()" style="background:#1f2937;color:#e2e8f0;border:1px solid #334155;
              padding:8px 14px;border-radius:8px;font-size:13px;cursor:pointer">🖨 Print / PDF</button>
      <a href="/api/wazuh/import-compare/report" download="wazuh-sigma-gap-report.html"
         style="background:#2563eb;color:#fff;border:1px solid #1d4ed8;padding:8px 14px;
                border-radius:8px;font-size:13px;text-decoration:none">⬇ Download HTML</a>
    </div>
  </header>

  {tiles_html}
  {bar_html}
  {howto_html}
  {tab_html}

  <div id="section-s1">{section1_html}</div>
  <div id="section-s2">{section2_html}</div>
  <div id="section-s3">{section3_html}</div>
</div>

<script>
function showSection(which) {{
  const s1 = document.getElementById('section-s1');
  const s2 = document.getElementById('section-s2');
  const s3 = document.getElementById('section-s3');
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  if (which === 'all') {{
    s1.style.display = ''; s2.style.display = ''; s3.style.display = '';
    document.getElementById('tab-all').classList.add('active');
  }} else if (which === 's1') {{
    s1.style.display = ''; s2.style.display = 'none'; s3.style.display = 'none';
    document.getElementById('tab-s1').classList.add('active');
  }} else if (which === 's2') {{
    s1.style.display = 'none'; s2.style.display = ''; s3.style.display = 'none';
    document.getElementById('tab-s2').classList.add('active');
  }} else if (which === 's3') {{
    s1.style.display = 'none'; s2.style.display = 'none'; s3.style.display = '';
    document.getElementById('tab-s3').classList.add('active');
  }}
}}
</script>
</body>
</html>'''
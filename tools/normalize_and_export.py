"""ABSEGA Phase H - verdict normalization + final exports.
Dry-run by default (shows proposals, changes NOTHING).
  python normalize_and_export.py                 # preview only
  python normalize_and_export.py --apply         # backup + normalize verdicts + export
  python normalize_and_export.py --apply --prune # also remove null-run_id ad-hoc duplicate rows
Never deletes evidence-backed, run-linked comparisons unless --prune is set,
and even then only removes comparison rows whose run_id IS NULL (ad-hoc experiments)."""
import json, sys, hashlib, subprocess, datetime, os, csv

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

from app.config import database_settings
from app.database import get_connection

APPLY = "--apply" in sys.argv
PRUNE = "--prune" in sys.argv

# Raw behavioral_verdict -> final vocabulary
VMAP = {
    "both_fired_on_same_event": "VERIFIED_OVERLAP",
    "wazuh_only_on_event":      "WAZUH_ONLY",
    "sigma_matched_raw_event":  "SIGMA_ONLY",
    "sigma_missed_raw_event":   "NO_DETECTION_IN_EITHER",
    # already-final values pass through unchanged:
    "SIGMA_ONLY": "SIGMA_ONLY",
    "NO_DETECTION_IN_EITHER": "NO_DETECTION_IN_EITHER",
    "VERIFIED_OVERLAP": "VERIFIED_OVERLAP",
    "WAZUH_ONLY": "WAZUH_ONLY",
    "EVALUATOR_UNSUPPORTED": "EVALUATOR_UNSUPPORTED",
    "EVALUATOR_INVALID_RULE": "PARSER_GAP",
}

c = get_connection()

def stamp(): return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

print("="*70)
print(" PHASE H - VERDICT NORMALIZATION + EXPORT   (%s)" % ("APPLY" if APPLY else "DRY-RUN"))
print("="*70)

# 1) Normalization preview
rows = c.execute("SELECT comparison_id, run_id, behavioral_verdict FROM ad_rule_comparisons ORDER BY comparison_id").fetchall()
changes = []
for r in rows:
    old = r["behavioral_verdict"]
    if old is None:
        continue
    new = VMAP.get(old, old)
    if new != old:
        changes.append((r["comparison_id"], r["run_id"], old, new))
print("\n[1] Verdict normalization (%d rows to change):" % len(changes))
for cid, rid, old, new in changes:
    print(f"    #{cid:<3} run={str(rid)[:34]:34} {old:26} -> {new}")

# 2) Duplicate / placeholder candidates (null run_id = ad-hoc experiments)
dupes = c.execute("SELECT comparison_id, wazuh_rule_id, detection_id, behavioral_verdict FROM ad_rule_comparisons WHERE run_id IS NULL ORDER BY comparison_id").fetchall()
print("\n[2] Ad-hoc duplicate rows (run_id IS NULL) - candidates for --prune (%d):" % len(dupes))
for r in dupes:
    print(f"    #{r['comparison_id']:<3} w={str(r['wazuh_rule_id']):6} sig={str(r['detection_id']):5} verdict={r['behavioral_verdict']}")

# 3) NOT_EXECUTED placeholder runs (kept, just flagged)
stubs = c.execute("SELECT run_id, test_id, status FROM ad_validation_runs WHERE status LIKE '%NOT_EXECUTED%' OR status LIKE '%skip%'").fetchall()
print("\n[3] NOT_EXECUTED placeholder runs (kept as NOT_EXECUTED, no comparison):")
for r in stubs:
    print(f"    {r['run_id']}  ({r['test_id']})  status={r['status']}")

if not APPLY:
    print("\nDRY-RUN complete. Re-run with --apply to write changes and exports.")
    c.close(); sys.exit(0)

# ---- APPLY ----
settings = database_settings()
bkp = f"detection_platform_before_normalize_{stamp()}.sql"
env = {**os.environ, "PGPASSWORD": settings.password}
subprocess.run(
    ["pg_dump", "-h", settings.host, "-p", str(settings.port),
     "-U", settings.user, "-d", settings.name, "-f", bkp],
    check=True, env=env,
)
print(f"\n[backup] {bkp}")

for cid, rid, old, new in changes:
    c.execute("UPDATE ad_rule_comparisons SET behavioral_verdict=%s WHERE comparison_id=%s", (new, cid))
print(f"[apply] normalized {len(changes)} verdict rows.")

if PRUNE and dupes:
    ids = [r["comparison_id"] for r in dupes]
    placeholders = ",".join(["%s"] * len(ids))
    c.execute(f"DELETE FROM ad_rule_comparisons WHERE comparison_id IN ({placeholders})", ids)
    print(f"[prune] removed {len(ids)} ad-hoc (null run_id) comparison rows.")
c.commit()

# 4) Final summary table export (one primary row per formal run)
q = """
SELECT t.behavior_name, t.technique_id, r.run_id,
       c.detection_id, d.title AS detection_title, c.wazuh_rule_id,
       c.wazuh_fired, c.sigma_matched, c.behavioral_verdict, c.static_verdict, c.total_score,
       c.tuning_notes, c.compared_at
FROM ad_rule_comparisons c
LEFT JOIN ad_validation_runs r ON r.run_id = c.run_id
LEFT JOIN ad_attack_tests    t ON t.test_id = r.test_id
LEFT JOIN detections         d ON d.detection_id = c.detection_id
WHERE c.run_id IS NOT NULL
ORDER BY c.comparison_id
"""
final = [dict(x) for x in c.execute(q).fetchall()]

csv_path  = f"ABSEGA_FINAL_report_{stamp()}.csv"
json_path = f"ABSEGA_FINAL_report_{stamp()}.json"
cols = ["behavior_name","technique_id","run_id","detection_id","detection_title",
        "wazuh_rule_id","wazuh_fired","sigma_matched","behavioral_verdict",
        "static_verdict","total_score","tuning_notes","compared_at"]
with open(csv_path,"w",newline="",encoding="utf-8") as f:
    w=csv.DictWriter(f,fieldnames=cols); w.writeheader()
    for row in final: w.writerow({k:row.get(k) for k in cols})
with open(json_path,"w",encoding="utf-8") as f:
    json.dump(final,f,indent=2,ensure_ascii=False)
print(f"[export] {csv_path}")
print(f"[export] {json_path}")

# 5) Evidence inventory (filename, size, sha256)
inv_path = f"ABSEGA_evidence_inventory_{stamp()}.csv"
n=0
with open(inv_path,"w",newline="",encoding="utf-8") as f:
    w=csv.writer(f); w.writerow(["path","bytes","sha256"])
    for base in ["evidence"]:
        for root,_,files in os.walk(base):
            for fn in files:
                p=os.path.join(root,fn)
                try:
                    b=open(p,"rb").read()
                    w.writerow([p.replace("\\","/"), len(b), hashlib.sha256(b).hexdigest()])
                    n+=1
                except OSError: pass
print(f"[export] {inv_path}  ({n} files hashed)")

print("\n[final summary]")
print(f"  {'BEHAVIOR':28} {'TECH':11} {'EID/RULE':10} {'VERDICT':22}")
for row in final:
    print(f"  {str(row['behavior_name'])[:28]:28} {str(row['technique_id']):11} "
          f"{str(row['wazuh_rule_id'] or '-'):10} {str(row['behavioral_verdict']):22}")
c.close()
print("\nPHASE H APPLY complete.")

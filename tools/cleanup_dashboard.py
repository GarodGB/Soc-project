"""ABSEGA - remove dashboard clutter safely.
  * placeholder comparison rows  = behavioral_verdict IS NULL (the 'unknown' matrix rows)
  * superseded NOT_EXECUTED runs  = a NOT_EXECUTED run whose test_id also has a completed run
Dry-run by default (shows what WOULD be removed, changes nothing).
  python cleanup_dashboard.py            # preview
  python cleanup_dashboard.py --apply    # backup + delete
Never touches any row with a real (non-null) behavioral_verdict."""
import datetime
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

from app.config import database_settings
from app.database import get_connection

APPLY = "--apply" in sys.argv
c = get_connection()

ph = c.execute("""
    SELECT comparison_id, run_id, detection_id, wazuh_rule_id
    FROM ad_rule_comparisons
    WHERE behavioral_verdict IS NULL OR TRIM(behavioral_verdict) = ''
    ORDER BY comparison_id
""").fetchall()

sup = c.execute("""
    SELECT r.run_id, r.test_id, r.status
    FROM ad_validation_runs r
    WHERE (r.status LIKE '%NOT_EXECUTED%' OR r.status LIKE '%skip%')
      AND EXISTS (
        SELECT 1 FROM ad_validation_runs r2
        WHERE r2.test_id = r.test_id AND r2.status = 'completed'
      )
    ORDER BY r.run_id
""").fetchall()

print("="*66)
print(" DASHBOARD CLEANUP  (%s)" % ("APPLY" if APPLY else "DRY-RUN"))
print("="*66)
print(f"\n[1] Placeholder comparison rows (null verdict) to remove: {len(ph)}")
for r in ph:
    print(f"    comparison #{r['comparison_id']}  run={r['run_id']}  sigma={r['detection_id']}  wazuh={r['wazuh_rule_id']}")
print(f"\n[2] Superseded NOT_EXECUTED runs to remove: {len(sup)}")
for r in sup:
    print(f"    {r['run_id']}  ({r['test_id']})  status={r['status']}")

if not APPLY:
    print("\nDRY-RUN only. Re-run with --apply to delete the above.")
    c.close(); sys.exit(0)

settings = database_settings()
bkp = f"detection_platform_before_cleanup_{datetime.datetime.now():%Y%m%d_%H%M%S}.sql"
env = {**os.environ, "PGPASSWORD": settings.password}
subprocess.run(
    ["pg_dump", "-h", settings.host, "-p", str(settings.port),
     "-U", settings.user, "-d", settings.name, "-f", bkp],
    check=True, env=env,
)
print(f"\n[backup] {bkp}")

if ph:
    ids = [r["comparison_id"] for r in ph]
    placeholders = ",".join(["%s"] * len(ids))
    c.execute(f"DELETE FROM ad_rule_comparisons WHERE comparison_id IN ({placeholders})", ids)
    print(f"[apply] removed {len(ids)} placeholder comparison rows")
if sup:
    rids = [r["run_id"] for r in sup]
    q = ",".join(["%s"] * len(rids))
    c.execute(f"DELETE FROM ad_rule_comparisons WHERE run_id IN ({q})", rids)  # orphan comparisons, if any
    c.execute(f"DELETE FROM ad_evidence WHERE run_id IN ({q})", rids)
    c.execute(f"DELETE FROM ad_validation_runs WHERE run_id IN ({q})", rids)
    print(f"[apply] removed {len(rids)} superseded NOT_EXECUTED runs")
c.commit(); c.close()
print("Cleanup complete. Refresh the AD Validation page.")

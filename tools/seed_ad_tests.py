"""ABSEGA - seed the three first-phase attack-test definitions (idempotent).
Run once from the ABSEGA project root before the SMB/LDAP/PsExec runs.
create_validation_run() 404s unless test_id exists in ad_attack_tests."""
import json, os, sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

from app.database import get_connection

TESTS = [
    ("AD-T1110.003-SMB-SPRAY",  "SMB password spray",  "T1110.003", "WIN11", "DC01",
     ["Security"], ["4625","4776"], {"LogonType":"3"},
     "Single wrong-password SMB auth attempt per authorized spray account.",
     "Disable spray01/spray02/spray03 after validation.", "medium"),
    ("AD-T1110.003-LDAP-SPRAY", "LDAP password spray", "T1110.003", "WIN11", "DC01",
     ["Security"], ["4625","4771","4776"], {},
     "Single wrong-password LDAP bind per authorized spray account.",
     "Disable spray01/spray02/spray03 after validation.", "medium"),
    ("AD-T1569.002-PSEXEC",     "PsExec service execution", "T1569.002", "WIN11", "DC01",
     ["System","Security","Microsoft-Windows-Sysmon/Operational"],
     ["7045","4697","4624","5145","1","3"], {},
     "Sysinternals PsExec running a harmless whoami marker; temporary service removed.",
     "Remove PSEXESVC service and marker file after validation.", "medium"),
]

c = get_connection()
try:
    for (tid,bn,tech,eh,th,ch,eids,flds,sim,cln,risk) in TESTS:
        c.execute("""
            INSERT INTO ad_attack_tests
            (test_id,behavior_name,technique_id,execution_host,target_host,
             expected_channels_json,expected_event_ids_json,expected_fields_json,
             simulation_command,cleanup_command,risk_tier,enabled)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,1)
            ON CONFLICT (test_id) DO NOTHING
        """, (tid,bn,tech,eh,th,json.dumps(ch),json.dumps(eids),json.dumps(flds),sim,cln,risk))
    c.commit()
    rows = c.execute("SELECT test_id,behavior_name,technique_id,enabled FROM ad_attack_tests ORDER BY test_id").fetchall()
    print("ad_attack_tests now contains:")
    for r in rows:
        print(f"  {r[0]:32} {r[1]:28} {r[2]:12} enabled={r[3]}")
finally:
    c.close()

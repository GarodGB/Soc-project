"""
ABSEGA - AD Attack Catalog test suite (Phase 4).

Covers the 20 required cases. Runs against a dedicated detection_platform_test
Postgres database (see tests/conftest.py), reset to a clone of the real
database before this module's tests run, so the real database is never
touched.

Run from project root:   python -m pytest tests/test_ad_catalog.py -v
"""
from __future__ import annotations

import importlib.util
import os
import subprocess

import pytest

from tests.conftest import TEST_DB_NAME, _psql_env, reset_test_database

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRESH_DB_NAME = "detection_platform_test_fresh"

LEGACY = {
    "AD-T1059.001-ENCODED-POWERSHELL", "AD-T1558.003-KERBEROAST",
    "AD-T1558.004-ASREP-ROAST", "AD-T1110.003-SMB-SPRAY",
    "AD-T1110.003-LDAP-SPRAY", "AD-T1569.002-PSEXEC",
}


def _load(name: str):
    path = os.path.join(ROOT, "tools", f"{name}.py")
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# --------------------------------------------------------------------------- #
#  Fixtures                                                                    #
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def client():
    """TestClient bound to detection_platform_test, cloned from the real DB."""
    reset_test_database()
    from fastapi.testclient import TestClient
    import app.main as m
    yield TestClient(m.app)


@pytest.fixture()
def fresh_db(monkeypatch):
    """A clean, schema-only DB with just the 6 legacy rows present, so seeding
    can be tested in isolation — a separate Postgres database from the one the
    module-scoped `client` fixture uses, so these tests can never corrupt the
    catalog data client-based tests depend on."""
    from app.database import get_connection

    settings_env = _psql_env()
    common = ["-h", os.environ.get("DB_HOST", "127.0.0.1"),
              "-p", os.environ.get("DB_PORT", "5432"),
              "-U", os.environ.get("DB_USER", "socapp")]
    subprocess.run(["dropdb", *common, "--if-exists", FRESH_DB_NAME], check=True, env=settings_env)
    subprocess.run(["createdb", *common, "-O", os.environ.get("DB_USER", "socapp"), FRESH_DB_NAME],
                    check=True, env=settings_env)
    subprocess.run(["psql", *common, "-d", FRESH_DB_NAME, "-f",
                     os.path.join(ROOT, "database", "schema.sql")],
                    check=True, env=settings_env, stdout=subprocess.DEVNULL)

    monkeypatch.setenv("DB_NAME", FRESH_DB_NAME)
    conn = get_connection()
    try:
        for k in LEGACY:
            conn.execute(
                "INSERT INTO ad_attack_tests (test_id, behavior_name, technique_id) "
                "VALUES (%s,%s,%s)", (k, f"legacy {k}", "T0000"))
        conn.commit()
    finally:
        conn.close()
    yield
    monkeypatch.setenv("DB_NAME", TEST_DB_NAME)


# --------------------------------------------------------------------------- #
#  1-3, 20  seeding / uniqueness / no-dupes / regression                      #
# --------------------------------------------------------------------------- #
def test_01_seed_idempotent(fresh_db):
    from app.database import get_connection

    seed = _load("seed_ad_catalog")
    assert seed.seed() == 0
    conn = get_connection()
    first = conn.execute("SELECT COUNT(*) FROM ad_attack_tests").fetchone()[0]
    assert seed.seed() == 0            # run twice
    second = conn.execute("SELECT COUNT(*) FROM ad_attack_tests").fetchone()[0]
    conn.close()
    assert first == second, "seeding twice must not add rows"


def test_02_at_least_15_new_unique(fresh_db):
    from app.database import get_connection

    _load("seed_ad_catalog").seed()
    conn = get_connection()
    n = conn.execute("SELECT COUNT(*) FROM ad_attack_tests WHERE seed_version=1").fetchone()[0]
    keys = [r[0] for r in conn.execute("SELECT attack_key FROM ad_attack_tests WHERE seed_version=1")]
    conn.close()
    assert n >= 15
    assert len(keys) == len(set(keys)), "attack keys must be unique"


def test_03_no_duplicate_with_legacy(fresh_db):
    from app.database import get_connection

    _load("seed_ad_catalog").seed()
    conn = get_connection()
    dups = conn.execute(
        "SELECT test_id, COUNT(*) c FROM ad_attack_tests GROUP BY test_id HAVING COUNT(*)>1"
    ).fetchall()
    new_keys = {r[0] for r in conn.execute("SELECT attack_key FROM ad_attack_tests WHERE seed_version=1")}
    conn.close()
    assert dups == []
    assert not (new_keys & LEGACY), "new attacks must not collide with legacy keys"


def test_20_regression_legacy_preserved(fresh_db):
    from app.database import get_connection

    _load("seed_ad_catalog").seed()
    conn = get_connection()
    present = {r[0] for r in conn.execute("SELECT test_id FROM ad_attack_tests")}
    conn.close()
    assert LEGACY <= present, "the original 6 attacks must remain intact"


# --------------------------------------------------------------------------- #
#  4-7  listing / detail / filtering / prereq states                          #
# --------------------------------------------------------------------------- #
def test_04_listing(client):
    j = client.get("/api/ad-catalog/attacks").json()
    assert j["count"] >= 15
    assert all(a["attack_key"] not in LEGACY for a in j["attacks"])


def test_05_detail_retrieval(client):
    r = client.get("/api/ad-catalog/attacks/AD-T1003.006-DCSYNC")
    assert r.status_code == 200
    d = r.json()
    assert d["technique_id"] == "T1003.006"
    assert "prerequisites" in d and "run_history" in d
    assert client.get("/api/ad-catalog/attacks/DOES-NOT-EXIST").status_code == 404


def test_06_filtering(client):
    ca = client.get("/api/ad-catalog/attacks", params={"category": "Credential Access"}).json()
    assert ca["count"] >= 1 and all(a["attack_category"] == "Credential Access" for a in ca["attacks"])
    man = client.get("/api/ad-catalog/attacks", params={"support_mode": "manual_only"}).json()
    assert all(a["support_mode"] == "manual_only" for a in man["attacks"])
    kb = client.get("/api/ad-catalog/attacks", params={"technique": "T1558"}).json()
    assert all("T1558" in a["technique_id"] for a in kb["attacks"])


def test_07_prerequisite_blocked(client):
    b = client.get("/api/ad-catalog/attacks", params={"prerequisite_status": "blocked_by_prerequisite"}).json()
    assert b["count"] == 3
    assert all(a["prerequisite_status"] == "blocked_by_prerequisite" for a in b["attacks"])


# --------------------------------------------------------------------------- #
#  8, 9, 16  run creation / multi-event evidence / superseded filtering       #
# --------------------------------------------------------------------------- #
def test_08_run_creation_lab_ok(client):
    r = client.post("/api/ad-validation/runs", json={
        "test_id": "AD-T1087.002-KERB-ENUM", "source_host": "WIN11",
        "target_host": "DC01", "source_ip": "10.10.10.11"})
    assert r.status_code == 200
    assert r.json()["run_id"].startswith("RUN-")


def test_09_multiple_evidence_events(client):
    run = client.post("/api/ad-validation/runs", json={
        "test_id": "AD-T1087.002-KERB-ENUM", "source_host": "WIN11",
        "target_host": "DC01", "source_ip": "10.10.10.11"}).json()["run_id"]
    for eid in ("4768", "4768", "4771"):
        ev = {"channel": "Security", "event_id": eid,
              "data": {"win": {"eventdata": {"status": "0x6"}}}}
        r = client.post(f"/api/ad-validation/runs/{run}/evidence", json={"event": ev})
        assert r.status_code in (200, 201)
    d = client.get("/api/ad-catalog/attacks/AD-T1087.002-KERB-ENUM").json()
    assert d["last_run_id"] is not None


def test_16_superseded_filtering(client):
    run = client.post("/api/ad-validation/runs", json={
        "test_id": "AD-T1053.005-SCHTASK", "source_host": "WIN11",
        "target_host": "DC01", "source_ip": "10.10.10.11"}).json()["run_id"]
    assert client.post(f"/api/ad-catalog/runs/{run}/supersede").status_code == 200
    active = client.get("/api/ad-validation/runs?limit=500").json()
    assert run not in str(active), "superseded run must not appear in active list"


# --------------------------------------------------------------------------- #
#  10-15  verdicts surfaced honestly                                          #
# --------------------------------------------------------------------------- #
def _make_run_with_verdict(client, test_id, *, wfired, smatch, verdict):
    from app.database import get_connection

    run = client.post("/api/ad-validation/runs", json={
        "test_id": test_id, "source_host": "WIN11", "target_host": "DC01",
        "source_ip": "10.10.10.11"}).json()["run_id"]
    conn = get_connection()
    conn.execute(
        """INSERT INTO ad_rule_comparisons
           (run_id, wazuh_rule_id, detection_id, static_verdict, behavioral_verdict,
            wazuh_fired, sigma_matched, total_score, compared_at)
           VALUES (%s,%s,%s,%s,%s,%s,%s,0,now()::text)""",
        (run, 92650 if wfired else None, 196 if smatch else None,
         "NO_CONTENT_OVERLAP", verdict, wfired, smatch))
    conn.commit(); conn.close()
    return run


def test_10_wazuh_only(client):
    _make_run_with_verdict(client, "AD-T1047-REMOTE-WMI", wfired=1, smatch=0, verdict="WAZUH_ONLY")
    d = client.get("/api/ad-catalog/attacks/AD-T1047-REMOTE-WMI").json()
    assert d["latest_verdict"] == "WAZUH_ONLY"
    assert d["wazuh_result"] == "alert" and d["sigma_result"] == "no_match"


def test_11_sigma_only(client):
    _make_run_with_verdict(client, "AD-T1550.003-PTT", wfired=0, smatch=1, verdict="SIGMA_ONLY")
    d = client.get("/api/ad-catalog/attacks/AD-T1550.003-PTT").json()
    assert d["latest_verdict"] == "SIGMA_ONLY"
    assert d["wazuh_result"] == "no_alert" and d["sigma_result"] == "match"


def test_12_verified_overlap(client):
    _make_run_with_verdict(client, "AD-T1543.003-MAL-SERVICE", wfired=1, smatch=1, verdict="VERIFIED_OVERLAP")
    d = client.get("/api/ad-catalog/attacks/AD-T1543.003-MAL-SERVICE").json()
    assert d["latest_verdict"] == "VERIFIED_OVERLAP"


def test_13_telemetry_gap(client):
    _make_run_with_verdict(client, "AD-T1098-RBCD", wfired=0, smatch=0, verdict="TELEMETRY_GAP")
    d = client.get("/api/ad-catalog/attacks/AD-T1098-RBCD").json()
    assert d["latest_verdict"] == "TELEMETRY_GAP"


def test_14_insufficient_evidence(client):
    _make_run_with_verdict(client, "AD-T1134.005-SIDHISTORY", wfired=0, smatch=0, verdict="INSUFFICIENT_EVIDENCE")
    d = client.get("/api/ad-catalog/attacks/AD-T1134.005-SIDHISTORY").json()
    assert d["latest_verdict"] == "INSUFFICIENT_EVIDENCE"


def test_15_blocked_prerequisite_verdict(client):
    # a blocked attack with no run must report BLOCKED_BY_PREREQUISITE, never a detection miss
    d = client.get("/api/ad-catalog/attacks/AD-T1649-ADCS-ESC1").json()
    assert d["prerequisite_status"] == "blocked_by_prerequisite"
    assert d["latest_verdict"] == "BLOCKED_BY_PREREQUISITE"


# --------------------------------------------------------------------------- #
#  17, 18, 19  masking / external rejection / CSV export                      #
# --------------------------------------------------------------------------- #
def test_17_sensitive_masking():
    from app.services.ad_catalog import mask_sensitive, REDACTED
    out = mask_sensitive({
        "user": "svc_sql",
        "password": "Summer2026!",
        "ntHash": "aad3b435b51404eeaad3b435b51404ee",
        "note": "hash is 31d6cfe0d16ae931b73c59d7e0c089c0 here",
        "nested": [{"krbtgt_key": "deadbeef"}],
    })
    assert out["password"] == REDACTED
    assert out["ntHash"] == REDACTED
    assert REDACTED in out["note"]                 # inline hex blob masked
    assert out["nested"][0]["krbtgt_key"] == REDACTED
    assert out["user"] == "svc_sql"                # non-sensitive untouched


def test_18_external_target_rejected(client):
    # public IP + external host must 422
    r = client.post("/api/ad-validation/runs", json={
        "test_id": "AD-T1047-REMOTE-WMI", "source_host": "attacker-vps",
        "target_host": "10.0.0.9", "source_ip": "203.0.113.7"})
    assert r.status_code == 422
    assert r.json()["detail"]["error"] == "target_not_allowlisted"
    # unit-level checks
    from app.services.ad_catalog import validate_targets
    assert validate_targets("DC01", "WIN11", "10.10.10.10", "10.10.10.11")[0] is True
    assert validate_targets(None, None, None, "8.8.8.8")[0] is False


def test_19_csv_export(client):
    r = client.get("/api/ad-validation/export.csv")
    assert r.status_code == 200
    assert "text/csv" in r.headers.get("content-type", "") or "comparison_id" in r.text


# --------------------------------------------------------------------------- #
#  readiness helper (evidence-driven, never event-id-only)                    #
# --------------------------------------------------------------------------- #
def test_readiness_is_evidence_driven():
    from app.services.ad_catalog import attack_readiness
    assert attack_readiness([], set())[0] == "unknown"
    assert attack_readiness(["a", "b"], set())[0] == "missing"
    assert attack_readiness(["a", "b"], {"a"})[0] == "partially_ready"
    assert attack_readiness(["a", "b"], {"a", "b"})[0] == "ready"

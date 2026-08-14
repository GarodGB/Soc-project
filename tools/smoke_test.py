"""
ABSEGA - Phase 5 smoke test (read-only against detection_platform_test).

Runs the full pre-flight in one shot:
  1. Python compile-all  (app/ + root scripts)
  2. Seed idempotency on the dedicated test database
  3. FastAPI app startup (import app.main)
  4. Live endpoint sanity via TestClient (catalog, guard, supersede, CSV)

Never touches the real detection_platform database — everything here runs
against detection_platform_test (see tests/conftest.py), reset to a clone of
the real data before step 2. Exit code 0 = all green.

Run from project root:   python -m tools.smoke_test
"""
from __future__ import annotations

import os
import py_compile
import sys
import traceback

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from tests.conftest import reset_test_database  # noqa: E402

PASS, FAIL = "PASS", "FAIL"
results: list[tuple[str, str, str]] = []


def check(name: str, fn) -> None:
    try:
        detail = fn() or ""
        results.append((PASS, name, str(detail)))
    except Exception as e:  # noqa: BLE001
        results.append((FAIL, name, f"{type(e).__name__}: {e}"))
        if os.environ.get("SMOKE_TRACE"):
            traceback.print_exc()


# --- 1. compile-all --------------------------------------------------------
def compile_all() -> str:
    targets: list[str] = []
    for base in ("app",):
        for dirpath, _dirs, files in os.walk(os.path.join(ROOT, base)):
            if "__pycache__" in dirpath:
                continue
            for f in files:
                if f.endswith(".py"):
                    targets.append(os.path.join(dirpath, f))
    for f in ("tools/seed_ad_catalog.py", "tools/seed_ad_tests.py"):
        p = os.path.join(ROOT, f)
        if os.path.exists(p):
            targets.append(p)
    for f in targets:
        py_compile.compile(f, doraise=True)
    return f"{len(targets)} files compiled"


# --- 2. seed idempotency ----------------------------------------------------
def seed_idempotent() -> str:
    import importlib.util
    from app.database import get_connection

    def load(name):
        spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, "tools", f"{name}.py"))
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m

    reset_test_database()
    seed = load("seed_ad_catalog")
    assert seed.seed() == 0 and seed.seed() == 0, "seed not idempotent"

    conn = get_connection()
    total = conn.execute("SELECT COUNT(*) FROM ad_attack_tests").fetchone()[0]
    new = conn.execute("SELECT COUNT(*) FROM ad_attack_tests WHERE seed_version=1").fetchone()[0]
    dups = conn.execute(
        "SELECT test_id,COUNT(*) c FROM ad_attack_tests GROUP BY test_id HAVING COUNT(*)>1"
    ).fetchall()
    conn.close()
    assert not dups, "duplicate attack keys"
    assert new >= 15, f"only {new} new attacks"
    return f"{new} new attacks, {total} total, 0 dupes, idempotent x2"


# --- 3 + 4. startup + endpoints -------------------------------------------
def app_and_endpoints() -> str:
    from fastapi.testclient import TestClient

    import app.main as m
    c = TestClient(m.app)

    assert c.get("/health").status_code == 200, "/health not 200"

    a = c.get("/api/ad-catalog/attacks").json()
    assert a["count"] >= 15, "catalog listing < 15"

    blocked = c.get("/api/ad-catalog/attacks", params={"prerequisite_status": "blocked_by_prerequisite"}).json()
    assert blocked["count"] == 3, "blocked count != 3"

    # lab run + supersede round-trip
    run = c.post("/api/ad-validation/runs", json={
        "test_id": "AD-T1053.005-SCHTASK", "source_host": "WIN11",
        "target_host": "DC01", "source_ip": "10.10.10.11"})
    assert run.status_code == 200, "lab run creation failed"
    rid = run.json()["run_id"]
    assert c.post(f"/api/ad-catalog/runs/{rid}/supersede").status_code == 200, "supersede failed"

    # CSV export
    csv = c.get("/api/ad-validation/export.csv")
    assert csv.status_code == 200, "CSV export failed"

    return f"health ok, catalog {a['count']}, blocked 3, supersede ok, CSV ok"


if __name__ == "__main__":
    check("1. compile-all", compile_all)
    check("2. seed idempotent", seed_idempotent)
    check("3. app startup + endpoints", app_and_endpoints)

    print("\n" + "=" * 68)
    print("ABSEGA SMOKE TEST")
    print("=" * 68)
    for status, name, detail in results:
        mark = "[PASS]" if status == PASS else "[FAIL]"
        print(f"  {mark}  {name:<34} {detail}")
    print("=" * 68)
    failed = [r for r in results if r[0] == FAIL]
    if failed:
        print(f"RESULT: {len(failed)} FAILED")
        sys.exit(1)
    print("RESULT: ALL GREEN")
    sys.exit(0)

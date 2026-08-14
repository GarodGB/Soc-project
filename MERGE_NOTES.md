# ABSEGA — Branch Merge Record

Merge of the two parallel workstreams into a single project.

| Branch | Scope | Source archive |
|---|---|---|
| **AD branch** | Active Directory + Windows attack validation | `ABSEGA.zip` → `ABSEGA/Soc-project-latest` |
| **Web/Linux branch** | DVWA/web + Linux attack validation, live alerting | `Soc-project__2_.zip` → `Soc-project-main` |

**Base chosen:** Web/Linux branch (cleaner, reduced frontend), with the AD branch grafted on top.
**Credentials:** taken from the AD branch (`ABSEGA.zip`), per the merge decision.

---

## 1. Files that required no decision

Byte-identical in both branches — copied straight through:

```
app/database.py            app/sigma_eval.py          app/routes/__init__.py
app/routes/ai.py           app/routes/atomic.py       app/routes/auth.py
app/routes/detections.py   app/routes/mitre.py        app/routes/telemetry.py
app/routes/validation.py   app/scripts/*              database/schema.sql
homepage.html              run.py                     check.py
```

## 2. Files where one branch was a strict superset

| File | Decision | Reason |
|---|---|---|
| `app/wazuh_client.py` | Web/Linux version | AD branch's 80 lines are byte-identical to its first 80; adds `fetch_alerts()` (Indexer/OpenSearch) and `fetch_agents()` |
| `requirements.txt` | Web/Linux version | Adds `paramiko==5.0.0`, `httpx==0.28.1` — required by the Linux attack runner |
| `login.html` | Web/Linux version | Identical except `const API`: AD hardcoded `http://127.0.0.1:8000`, Web/Linux uses `window.location.origin` (correct behind any host/port) |

## 3. Genuine merges

### `app/routes/wazuh.py` — 1004 + 2165 → 2580 lines

Both branches appended to opposite ends of an identical common ancestor. Everything
from the top of the file down through `_render_report()` is byte-identical in both,
so there was **no conflicting region**.

- Kept from Web/Linux: `/alerts`, `/agents`, `/run-attacks`, `/validate-live`,
  `/run-linux-attacks`, `/validate-linux`, `/import-rules` (POST+DELETE),
  `/compare-coverage`, `/deep-compare`
- Appended from AD: the content-comparison engine — `_CC_STOPWORDS`, `_CC_TOKEN_RE`,
  `_cc_tokens()`, `_cc_wazuh_profile()`, `_cc_sigma_profile()`, `_cc_compatible()`,
  `content_compare()`, `POST /content-compare`,
  `GET /content-compare/detection/{detection_id}`

Result: **13 Wazuh endpoints**, no duplicate symbols. The AD block keeps its own
aliased imports (`_cc_re`, `_cc_yaml`) so it cannot collide with the Web/Linux
block's `_yaml` / `_json`.

### `app/main.py`

Web/Linux version plus:
- `from app.routes import ad_validation, ad_catalog`
- `app.include_router(ad_validation.router)` / `ad_catalog.router` (both self-prefixed)
- `GET /guide.html` route (the file existed in the Web/Linux branch but was unrouted)
- `GET /ad_dashboard.html` route

### `frontend.html` — 3726 → 4521 lines

Base is the Web/Linux frontend, as requested. Five additive grafts from the AD branch:

1. **CSS** — `.badge-blue`, `.ad-chip`, `.ad-sum-card`, `.ad-sxs`, `.ad-col-head`,
   `.ad-cond`, `.ad-scorebar-*` (22 lines, appended to the first `<style>` block)
2. **Nav tab** — `⛨ AD Validation`, inserted before Coverage
3. **Panel** — `#panel-advalidation` (111 lines): surface selector
   (All / AD / Windows / Web / Linux), 8 summary cards, action hero, similarity
   block, per-row and bulk re-check buttons, history table
4. **Drawer** — `#ad-drawer-overlay` / `#ad-drawer` (16 lines)
5. **JS** — 624 lines, 48 functions (`loadADValidation`, `renderADTable`,
   `adFpRender`, `adSurfaceFilter`, `adRecheckRun`, `adRecheckAll`,
   `openADValidationRun`, `renderADDrawer`, …). Verified self-contained: the only
   external reference is the global `API`, declared in the first script block.

`switchNav` was **not edited**. The Web/Linux branch already wraps it in an IIFE for
Live Alerts; the AD hook chains a second wrapper on top. Additive, consistent with
the project's backend design pattern.

Verified after merge: 6 panels ↔ 6 nav tabs, balanced `<script>` tags, zero duplicate
function definitions, both script blocks pass `node --check`.

### `detection_platform.db`

Both databases share the same lineage — the identical 2,629 Sigma detections with
matching `detection_id → sigma_id` and **zero mismatches**, so no re-keying was needed.

Base = Web/Linux DB, which already contained everything the AD DB had except:

| Added from AD branch | Rows |
|---|---|
| `wazuh_rule_catalog` (new table) | 4,490 |
| `ad_evidence` (new table) | 119 |
| `ad_attack_tests` (new table) | 36 |
| `ad_validation_runs` (new table) | 28 |
| `ad_rule_comparisons` (new table) | 25 |
| `ad_telemetry_components` (new table) | 17 |
| `validation_cases` — case 59659 | +1 |
| `simulation_results` — result 366 | +1 |
| `atomic_runs` | +1 |

The two single rows are the T1059.001 Encoded PowerShell run against detection 1514.

Post-merge state: **15 tables**, `PRAGMA integrity_check` = `ok`, 3,648 detections
(2,629 Sigma + 1,019 Wazuh-imported), 4,324 technique mappings, 4,490 catalogued
Wazuh rules. Pre-merge base preserved as `detection_platform_before_merge_20260729.db.bak`.

## 4. Environment

The two branches pointed at different labs. The AD branch's `.env` had **only**
`WAZUH_*` — it lacked `INDEXER_*` and `TARGET_*`, which the Live Alerts panel and the
DVWA/Linux attack runners require. The merged `.env` therefore uses the AD lab's host
and Wazuh credentials, with the missing keys added and pointed at the same host.

**Two values need attention before first run:**

- `INDEXER_PASSWORD` — intentionally left blank; supply the AD lab's indexer admin password
- `WAZUH_PASSWORD` — carried over from the AD branch, but that credential was last seen
  returning **HTTP 401** during an interrupted rotation. Finish the rotation first.

`.env.example` ships alongside with all secrets stripped.

## 5. Housekeeping

Removed: `.venv/`, `venv/`, `__pycache__/`, `.vscode/`, `.claude/`, empty
`soc_detections.db`, and `ad_catalog_router.py` (byte-identical duplicate of
`ad_catalog.py`).

Also copied from the AD branch: `tests/` (3 unit-test modules for the Sigma normalizer,
AD catalog, and scoring) and `database/migrations/003_ad_validation.sql`.

Relocated: 60 historical `dvwa_report_*.json` / `linux_report_*.json` → `reports/archive/`;
22 AD CSV/JSON exports → `reports/ad_branch/`; evidence JSON → `evidence/`;
seeding and export scripts → `tools/`.

Kept in project root by necessity: `attack_dvwa.py` and `attack_linux.py` (resolved via
`_PROJECT_ROOT` in `wazuh.py`), and the `Record-*.ps1` scripts (their `D:\ABSEGA\...`
references are comments only — no code change needed).

Line endings on all merged Python and the AD frontend blocks normalised to LF.

## 6. Known carry-over

The Web/Linux branch removed the Validation, Research, and Test Runner **panels** but
kept their JavaScript (`loadValidation`, `renderValidationTable`, `loadResearch`,
`renderResearchList`, `renderTrRuleList`, …). That code is now orphaned — it is
guarded and does not throw, but nothing reaches it. Left in place rather than removed,
since deleting it is a product decision, not a merge one.

## 7. Verification performed

- `python -m compileall app tools` — clean
- FastAPI app boots; OpenAPI schema resolves **89 endpoints** (13 Wazuh, 26 AD)
- `node --check` on both frontend script blocks — clean
- `PRAGMA integrity_check` — `ok`
- Live request tests, all `200`: `/health`, `/api/detections/`, `/api/telemetry/`,
  `/api/ad-validation/health`, `/api/ad-validation/runs`, `/api/ad-validation/summary`,
  `/api/ad-validation/action-summary`, `/api/ad-validation/similarity-summary`,
  `/api/ad-catalog/summary`, `/api/ad-catalog/attacks`

`/api/ad-validation/health` confirms all five AD tables present with the expected counts.

Endpoints that call out to Wazuh (`/api/wazuh/content-compare`, `/import-rules`,
`/alerts`) return `502` in a sandbox with no route to the lab — expected, and they
resolve once run against the real manager.

"""
Import sample events from the EVTX-ATTACK-SAMPLES repo (Bousseaden) — these
are REAL Windows event logs captured during actual attack simulations.

Setup once:
    git clone --depth 1 https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES /tmp/evtx
    pip install python-evtx       # only needed if reading .evtx directly

Then:
    python -m app.scripts.import_evtx --root /tmp/evtx

The repo ships a `evtx_data.csv` with every event already parsed across all
278 .evtx files (~9,900 events). We use the CSV — no .evtx parsing needed.

Each event becomes one validation_case (source='evtx'), linked to the
detection rules whose selection-block keywords overlap with the event +
filename. These samples come from real attacker tooling running on a real
Windows host — so they have the genuine field values (real Hashes, real
ProcessGuids, real paths) that synthesized samples can't replicate.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from datetime import datetime
from pathlib import Path

import yaml

if __package__ in (None, ""):
    HERE = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(HERE))

from app.database import get_connection
from app.scripts.import_atomics import (
    _tokenize, _rule_signature_tokens, _rule_event_subtype,
    EVENTID_TO_SUBTYPE, ensure_source_column,
)


# Fields we should NOT include in the sample event — they're CSV metadata,
# XML-namespace artefacts, or empty placeholders that pollute matching.
SKIP_FIELDS = {
    "", "EVTX_FileName", "EVTX_Tactic",
}


def _is_skippable_field(key: str) -> bool:
    if not key or key in SKIP_FIELDS:
        return True
    if key.startswith("{"):  # XML namespace garbage like {Event_NS}...
        return True
    return False


def _is_empty(value) -> bool:
    if value is None:
        return True
    s = str(value).strip()
    return s == "" or s == "-"


def _kv_event_string(row: dict) -> str:
    """Build a key=value string of only the non-empty fields."""
    parts = []
    for key, value in row.items():
        if _is_skippable_field(key) or _is_empty(value):
            continue
        v = str(value).replace('"', '\\"')
        if any(c.isspace() for c in v) or any(c in v for c in ['\\', '=', ',', ':', '|', ';', '/']):
            parts.append(f'{key}="{v}"')
        else:
            parts.append(f"{key}={v}")
    return " ".join(parts)


def _event_subtype(event_id_str: str) -> str | None:
    try:
        eid = int(event_id_str)
    except (ValueError, TypeError):
        return None
    return EVENTID_TO_SUBTYPE.get(eid)


def _technique_from_filename(name: str) -> str | None:
    """Extract a MITRE T-ID from an EVTX filename if present."""
    m = re.search(r"T\d{4}(?:[._-]\d{3})?", name, re.IGNORECASE)
    if not m:
        return None
    raw = m.group(0).upper().replace("_", ".").replace("-", ".")
    # Normalise T1003_001 → T1003.001
    return raw


def _event_signature(row: dict) -> tuple:
    """Dedupe key — collapse near-identical events from the same EVTX."""
    return (
        row.get("EVTX_FileName", ""),
        row.get("EventID", ""),
        row.get("Image", ""),
        row.get("CommandLine", "")[:120],
        row.get("TargetFilename", ""),
        row.get("TargetObject", ""),
        row.get("ScriptBlockText", "")[:120],
        row.get("ImageLoaded", ""),
    )


def collect_evtx_events(csv_path: Path, max_per_file: int = 8) -> list[dict]:
    """Yield dedup'd event records from the master CSV."""
    out: list[dict] = []
    seen: dict[str, set] = {}
    per_file: dict[str, int] = {}
    with csv_path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            fname = row.get("EVTX_FileName", "")
            if not fname:
                continue
            if per_file.get(fname, 0) >= max_per_file:
                continue
            sig = _event_signature(row)
            if sig in seen.setdefault(fname, set()):
                continue
            seen[fname].add(sig)
            per_file[fname] = per_file.get(fname, 0) + 1

            kv = _kv_event_string(row)
            if len(kv) < 40:   # very short event — probably useless
                continue
            tactic = row.get("EVTX_Tactic", "")
            technique = _technique_from_filename(fname)
            subtype = _event_subtype(row.get("EventID", ""))
            out.append({
                "filename":     fname,
                "tactic":       tactic,
                "technique_id": technique,
                "subtype":      subtype,
                "event_id":     row.get("EventID", ""),
                "sample_event_kv": kv,
            })
    return out


def import_evtx_samples(samples: list[dict], reset: bool = True, verbose: bool = True) -> dict:
    conn = get_connection()
    try:
        ensure_source_column(conn)
        if reset:
            conn.execute("""
                DELETE FROM simulation_results
                WHERE case_id IN (SELECT case_id FROM validation_cases WHERE source = 'evtx')
            """)
            removed = conn.execute("DELETE FROM validation_cases WHERE source = 'evtx'").rowcount
            if verbose:
                print(f"removed {removed} prior evtx-sourced cases")

        # Per-detection token bag + expected event type.
        det_rows = conn.execute("""
            SELECT d.detection_id, d.title, d.raw_yaml
            FROM detections d
            WHERE d.raw_yaml IS NOT NULL AND length(d.raw_yaml) > 0
        """).fetchall()
        det_tokens: dict[int, set[str]] = {}
        det_titles: dict[int, str] = {}
        det_subtype: dict[int, str | None] = {}
        for row in det_rows:
            det_tokens[row["detection_id"]] = _rule_signature_tokens(row["raw_yaml"] or "", row["title"] or "")
            det_titles[row["detection_id"]] = row["title"] or ""
            det_subtype[row["detection_id"]] = _rule_event_subtype(row["raw_yaml"] or "")

        # technique → detection (used as a narrowing hint when we have one)
        rows = conn.execute("""
            SELECT dtm.technique_id, dtm.detection_id FROM detection_technique_mapping dtm
        """).fetchall()
        by_tech: dict[str, list[int]] = {}
        for r in rows:
            by_tech.setdefault(r["technique_id"], []).append(r["detection_id"])

        inserted = 0
        skipped_no_overlap = 0
        per_event_cap = 3   # at most N rules per event

        for sample in samples:
            text = sample["filename"] + " " + sample["tactic"] + " " + sample["sample_event_kv"]
            sample_tokens = _tokenize(text)
            if not sample_tokens:
                continue

            # Candidate detections: if we know the technique, narrow to those;
            # otherwise consider all rules (slower, but EVTX has no T-ids).
            if sample["technique_id"]:
                candidates = by_tech.get(sample["technique_id"], list(det_tokens.keys()))
                min_overlap = 2
            else:
                candidates = list(det_tokens.keys())
                min_overlap = 3   # stricter when we don't have technique narrowing

            scored: list[tuple[int, int]] = []
            for det_id in candidates:
                rule_expects = det_subtype.get(det_id)
                if rule_expects and sample["subtype"] and rule_expects != sample["subtype"]:
                    continue
                overlap = len(det_tokens.get(det_id, set()) & sample_tokens)
                if overlap < min_overlap:
                    continue
                scored.append((overlap, det_id))

            if not scored:
                skipped_no_overlap += 1
                continue

            scored.sort(reverse=True)
            chosen = [det_id for _, det_id in scored[:per_event_cap]]

            for det_id in chosen:
                attack_name = f"EVTX ({sample['tactic'] or 'sample'}): {sample['filename'][:80]}"
                conn.execute("""
                    INSERT INTO validation_cases
                      (detection_id, sample_event, expected_result, status,
                       attack_name, detection_title, sample_type, source,
                       source_ref, platform)
                    VALUES (?, ?, 'fire', 'untested', ?, ?, 'positive', 'evtx', ?, 'windows')
                """, (
                    det_id,
                    sample["sample_event_kv"],
                    attack_name,
                    det_titles[det_id],
                    f"evtx/{sample['filename']}/{sample['event_id']}",
                ))
                inserted += 1
        conn.commit()
        return {
            "event_samples_seen": len(samples),
            "cases_inserted":     inserted,
            "samples_no_overlap": skipped_no_overlap,
        }
    finally:
        conn.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Import EVTX-ATTACK-SAMPLES")
    parser.add_argument("--root", required=True, help="Path to the EVTX-ATTACK-SAMPLES repo (contains evtx_data.csv)")
    parser.add_argument("--no-reset", action="store_true")
    parser.add_argument("--max-per-file", type=int, default=8)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    root = Path(args.root).expanduser().resolve()
    csv_path = root / "evtx_data.csv"
    if not csv_path.is_file():
        raise SystemExit(f"missing {csv_path} — did you clone EVTX-ATTACK-SAMPLES?")

    if not args.quiet:
        print(f"reading {csv_path} ...")
    samples = collect_evtx_events(csv_path, max_per_file=args.max_per_file)
    if not args.quiet:
        by_eid: dict[str, int] = {}
        with_tid = 0
        for s in samples:
            by_eid[s["event_id"]] = by_eid.get(s["event_id"], 0) + 1
            if s["technique_id"]:
                with_tid += 1
        print(f"collected {len(samples)} unique events ({with_tid} have T-ID in filename)")
        top = sorted(by_eid.items(), key=lambda x: -x[1])[:8]
        print(f"  top EventIDs: {top}")

    summary = import_evtx_samples(samples, reset=not args.no_reset, verbose=not args.quiet)
    print(json.dumps({**summary, "imported_at": datetime.utcnow().isoformat()}, indent=2))


if __name__ == "__main__":
    main()

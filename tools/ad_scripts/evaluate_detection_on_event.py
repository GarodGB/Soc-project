from __future__ import annotations

import json
import sys
from pathlib import Path

from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parents[2] / ".env")

from app.database import get_connection
from app.services.sigma_rule_normalizer import evaluate_sigma_rule


def main() -> int:
    if len(sys.argv) != 3 or not sys.argv[1].isdigit():
        print(
            "Usage: python scripts\\evaluate_detection_on_event.py "
            "<detection_id> <event_json_path>"
        )
        return 2

    detection_id = int(sys.argv[1])
    event_path = Path(sys.argv[2]).expanduser().resolve()
    if not event_path.is_file():
        print(f"FAIL: event file does not exist: {event_path}")
        return 1

    event = json.loads(event_path.read_text(encoding="utf-8-sig"))

    connection = get_connection()
    try:
        row = connection.execute(
            """
            SELECT detection_id, title, raw_yaml, logsource, rule_logic,
                   tags, falsepositives
            FROM detections
            WHERE detection_id = %s
            """,
            (detection_id,),
        ).fetchone()
    finally:
        connection.close()

    if row is None:
        print(f"FAIL: detection {detection_id} was not found")
        return 1

    result = evaluate_sigma_rule(
        row["raw_yaml"] or "",
        event,
        logsource=row["logsource"],
        rule_logic=row["rule_logic"],
        tags=row["tags"],
        falsepositives=row["falsepositives"],
    )

    print(
        json.dumps(
            {
                "detection_id": detection_id,
                "title": row["title"],
                "status": result.get("status"),
                "matched": result.get("matched"),
                "reason": result.get("reason"),
                "selection_results": result.get("selection_results", {}),
                "trace": result.get("trace", {}),
                "canonical_event": result.get("canonical_event", {}),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

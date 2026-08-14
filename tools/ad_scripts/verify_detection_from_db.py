from __future__ import annotations

import json
import sys
from pathlib import Path

from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parents[2] / ".env")

from app.database import get_connection
from app.services.sigma_rule_normalizer import normalize_sigma_rule


def main() -> int:
    if len(sys.argv) != 2 or not sys.argv[1].isdigit():
        print("Usage: python scripts\\verify_detection_from_db.py <detection_id>")
        return 2

    detection_id = int(sys.argv[1])
    database = "postgres:detection_platform"

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
        print(f"FAIL: detection {detection_id} was not found in {database}")
        return 1

    result = normalize_sigma_rule(
        row["raw_yaml"] or "",
        logsource=row["logsource"],
        rule_logic=row["rule_logic"],
        tags=row["tags"],
        falsepositives=row["falsepositives"],
    )

    summary = {
        "database": str(database),
        "detection_id": row["detection_id"],
        "title": row["title"],
        "status": result.get("status"),
        "supported": result.get("supported"),
        "product": result.get("product"),
        "category": result.get("category"),
        "service": result.get("service"),
        "channels": result.get("channels", []),
        "event_ids": result.get("event_ids", []),
        "conditions": result.get("conditions", []),
        "mitre": result.get("mitre", []),
        "unsupported_reasons": result.get("unsupported_reasons", []),
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

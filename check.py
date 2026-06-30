import sqlite3
conn = sqlite3.connect("detection_platform.db")
conn.row_factory = sqlite3.Row
r = conn.execute("SELECT * FROM telemetry_sources LIMIT 1").fetchone()
d = dict(r)
print("Columns:", list(d.keys()))
det = d.get("details")
if det:
    print("HAS DATA:", det[:200])
else:
    print("DETAILS IS EMPTY")
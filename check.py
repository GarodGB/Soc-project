import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

from app.database import get_connection

conn = get_connection()
r = conn.execute("SELECT * FROM telemetry_sources LIMIT 1").fetchone()
d = dict(r)
print("Columns:", list(d.keys()))
det = d.get("details")
if det:
    print("HAS DATA:", det[:200])
else:
    print("DETAILS IS EMPTY")

import sqlite3
import os

# Path to the SQLite database — sits in the project root
DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'detection_platform.db')

def get_connection():
    """Return a SQLite connection with row_factory set to dict-like rows."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

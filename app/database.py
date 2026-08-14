import psycopg2
import psycopg2.extras

from app.config import database_settings


class _ConnectionWrapper:
    """psycopg2 connection with sqlite3-style .execute()/.executemany() shortcuts.

    The app was written against sqlite3.Connection, which lets callers do
    conn.execute(sql, params).fetchone() directly on the connection. psycopg2
    only exposes execute() on a cursor, so this wrapper recreates the
    shortcut instead of touching every call site across the codebase.
    """

    def __init__(self, conn):
        self._conn = conn

    def execute(self, sql, params=None):
        cur = self._conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        # psycopg2 only treats % as a placeholder marker when a params
        # argument is actually supplied — pass nothing at all when there are
        # no params, so literal % in SQL (e.g. LIKE '%foo%') stays literal
        # instead of being parsed as a substitution.
        if params:
            cur.execute(sql, params)
        else:
            cur.execute(sql)
        return cur

    def executemany(self, sql, seq_of_params):
        cur = self._conn.cursor()
        cur.executemany(sql, seq_of_params)
        return cur

    def __getattr__(self, name):
        return getattr(self._conn, name)


def get_connection():
    """Return a Postgres connection with sqlite3-style row/execute behavior."""
    settings = database_settings()
    conn = psycopg2.connect(
        host=settings.host,
        port=settings.port,
        dbname=settings.name,
        user=settings.user,
        password=settings.password,
    )
    return _ConnectionWrapper(conn)

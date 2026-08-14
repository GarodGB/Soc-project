"""Shared pytest setup: points the app at a dedicated detection_platform_test
Postgres database instead of the real one, and provides a helper to reset it
to a clone of the real database's current data before each test module runs.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

TEST_DB_NAME = "detection_platform_test"
SOURCE_DB_NAME = os.environ.get("DB_NAME", "detection_platform")
os.environ["DB_NAME"] = TEST_DB_NAME  # must happen before any app.* module is imported

from app.config import database_settings  # noqa: E402


def _psql_env() -> dict:
    settings = database_settings()
    return {**os.environ, "PGPASSWORD": settings.password}


def reset_test_database() -> None:
    """Clone the real database's current data into detection_platform_test.

    Runs once per test module (called from each test file's top-level
    fixture) so every module starts from the same realistic, known state
    even though tests mutate data via API calls.
    """
    settings = database_settings()
    env = _psql_env()
    common = ["-h", settings.host, "-p", str(settings.port), "-U", settings.user]

    subprocess.run(["dropdb", *common, "--if-exists", TEST_DB_NAME], check=True, env=env)
    subprocess.run(["createdb", *common, "-O", settings.user, TEST_DB_NAME], check=True, env=env)

    # Round-trip through a real file, not a Python text pipe — piping tens of
    # MB of dump output through subprocess text buffers silently corrupted
    # COPY blocks and left most tables missing despite a clean exit code.
    with tempfile.NamedTemporaryFile(suffix=".sql", delete=False) as f:
        dump_path = f.name
    try:
        with open(dump_path, "wb") as f:
            subprocess.run(["pg_dump", *common, "-d", SOURCE_DB_NAME],
                            check=True, env=env, stdout=f)
        restore = subprocess.run(
            ["psql", "-v", "ON_ERROR_STOP=1", *common, "-d", TEST_DB_NAME, "-f", dump_path],
            env=env, capture_output=True, text=True,
        )
        if restore.returncode != 0:
            raise RuntimeError(f"test DB restore failed:\n{restore.stderr[-4000:]}")
    finally:
        os.unlink(dump_path)

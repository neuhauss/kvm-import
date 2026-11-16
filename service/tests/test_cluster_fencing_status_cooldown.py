"""Persistence and anti-repeat protection for physical STONITH status checks."""

import ast
import contextlib
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


def cooldown_helpers():
    source = Path(__file__).resolve().parents[1] / "app.py"
    tree = ast.parse(source.read_text())
    names = {
        "stonith_status_check_view",
        "reserve_stonith_status_check",
        "save_stonith_status_check",
    }
    body = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    if {node.name for node in body} != names:
        raise AssertionError("STONITH cooldown helpers were not found")
    module = ast.Module(body=body, type_ignores=[])
    return compile(module, "<stonith-cooldown-helpers>", "exec")


class ClusterFencingStatusCooldownTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.database = Path(self.tempdir.name) / "checks.sqlite3"
        db = sqlite3.connect(self.database)
        try:
            db.execute("""CREATE TABLE stonith_status_checks (
                host_id TEXT NOT NULL, resource_id TEXT NOT NULL, checked_at TEXT NOT NULL,
                status TEXT NOT NULL, result_code TEXT NOT NULL,
                PRIMARY KEY(host_id, resource_id)
            )""")
        finally:
            db.close()

        @contextlib.contextmanager
        def connect_db():
            db = sqlite3.connect(self.database, timeout=10)
            db.row_factory = sqlite3.Row
            try:
                yield db
                db.commit()
            except Exception:
                db.rollback()
                raise
            finally:
                db.close()

        self.context = {
            "sqlite3": sqlite3,
            "datetime": datetime,
            "timedelta": timedelta,
            "timezone": timezone,
            "STONITH_STATUS_CHECK_COOLDOWN": timedelta(hours=3),
            "connect_db": connect_db,
            "now": lambda: datetime.now(timezone.utc).isoformat(),
        }
        exec(cooldown_helpers(), self.context)

    def tearDown(self):
        self.tempdir.cleanup()

    def test_first_check_reserves_and_repeat_returns_persisted_cooldown(self):
        reserve = self.context["reserve_stonith_status_check"]
        save = self.context["save_stonith_status_check"]
        first, allowed = reserve("host-1", "fence-a")
        self.assertTrue(allowed)
        self.assertEqual(first["status"], "checking")
        self.assertFalse(reserve("host-1", "fence-a")[1])
        saved = save("host-1", "fence-a", "query_succeeded", "status_query_succeeded")
        repeated, allowed = reserve("host-1", "fence-a")
        self.assertFalse(allowed)
        self.assertEqual(repeated["status"], "query_succeeded")
        self.assertEqual(repeated["next_allowed_at"], saved["next_allowed_at"])

    def test_cooldown_is_scoped_per_host_and_device_and_expires(self):
        reserve = self.context["reserve_stonith_status_check"]
        save = self.context["save_stonith_status_check"]
        reserve("host-1", "fence-a")
        self.assertTrue(reserve("host-1", "fence-b")[1])
        self.assertTrue(reserve("host-2", "fence-a")[1])
        db = sqlite3.connect(self.database)
        try:
            expired = (datetime.now(timezone.utc) - timedelta(hours=4)).isoformat()
            db.execute("UPDATE stonith_status_checks SET checked_at=? WHERE host_id='host-1' AND resource_id='fence-a'", (expired,))
            db.commit()
        finally:
            db.close()
        self.assertTrue(reserve("host-1", "fence-a")[1])
        self.assertEqual(save("host-1", "fence-a", "unknown", "status_query_timeout")["status"], "unknown")


if __name__ == "__main__":
    unittest.main()

"""Focused, dependency-light tests for persistent SUSE HA cluster identity."""

from __future__ import annotations

import ast
import hashlib
import json
import re
import unittest
from pathlib import Path


SERVICE_SOURCE = Path(__file__).resolve().parents[1] / "app.py"
TREE = ast.parse(SERVICE_SOURCE.read_text())


class HttpException(Exception):
    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


class Cursor:
    def __init__(self, rows):
        self.rows = rows

    def fetchall(self):
        return self.rows


class Database:
    def __init__(self, hosts):
        self.hosts = hosts

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, *_args):
        return Cursor(self.hosts)


def extract_function(name: str):
    function = next(node for node in TREE.body if isinstance(node, ast.FunctionDef) and node.name == name)
    return compile(ast.Module(body=[function], type_ignores=[]), str(SERVICE_SOURCE), "exec")


class ManagedSuseHaClusterTests(unittest.TestCase):
    def snapshot(self, live_status, source_host_id="host-a"):
        hosts = [
            {"id": "host-a", "name": "node-a", "hostname": "node-a.example.test", "address": "192.0.2.10"},
            {"id": "host-b", "name": "node-b", "hostname": "node-b.example.test", "address": "192.0.2.11"},
        ]
        namespace = {
            "json": json,
            "hashlib": hashlib,
            "re": re,
            "HTTPException": HttpException,
            "cockpit_host_record": lambda host_id: {"id": host_id, "hostname": "node-a.example.test"},
            "run_sudo_python": lambda *_args, **_kwargs: json.dumps(live_status),
            "HA_CLUSTER_STATUS_SCRIPT": "status-script",
            "connect_db": lambda: Database(hosts),
        }
        exec(extract_function("live_suse_cluster_snapshot"), namespace)
        return namespace["live_suse_cluster_snapshot"](source_host_id)

    def test_maps_live_members_to_registered_host_ids(self):
        status, members, host_ids = self.snapshot({
            "cluster_name": "ha-lab", "nodes": [{"name": "node-a.example.test"}, {"name": "node-b"}],
        })
        self.assertEqual(status["cluster_name"], "ha-lab")
        self.assertEqual(members, ["node-a.example.test", "node-b"])
        self.assertEqual(host_ids, ["host-a", "host-b"])

    def test_rejects_uninitialized_cluster_and_unmatched_source_host(self):
        with self.assertRaises(HttpException) as uninitialized:
            self.snapshot({"cluster_name": "ha-lab", "nodes": [{"name": "node-a"}]})
        self.assertEqual(uninitialized.exception.status_code, 409)

        with self.assertRaises(HttpException) as mismatch:
            self.snapshot({"cluster_name": "ha-lab", "nodes": [{"name": "node-b"}, {"name": "node-c"}]})
        self.assertEqual(mismatch.exception.status_code, 409)
        self.assertIn("does not match", mismatch.exception.detail)

    def test_rejects_cluster_names_that_cannot_be_used_as_safe_identity(self):
        with self.assertRaises(HttpException) as invalid:
            self.snapshot({"cluster_name": "ha lab; reboot", "nodes": [{"name": "node-a"}]})
        self.assertEqual(invalid.exception.status_code, 409)


if __name__ == "__main__":
    unittest.main()

"""Regression tests for standalone SSH-only SUSE QNetd witness records."""

from __future__ import annotations

import ast
import base64
import contextlib
import hashlib
import io
import ipaddress
import json
import re
import sqlite3
import subprocess
import sys
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


SOURCE = Path(__file__).resolve().parents[1] / "app.py"


class HttpException(Exception):
    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code


class Cursor:
    def __init__(self, one=None, many=None):
        self.one = one
        self.many = many or []

    def fetchone(self):
        return self.one

    def fetchall(self):
        return self.many

    def __iter__(self):
        return iter(self.many)


class FakeDatabase:
    def __init__(self, plan, witness, nodes):
        self.plan, self.witness, self.nodes = plan, witness, nodes

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, query, _params=()):
        if "FROM cluster_plans" in query:
            return Cursor(one=self.plan)
        if "FROM qnetd_witnesses" in query:
            return Cursor(one=self.witness)
        if "FROM hosts" in query:
            return Cursor(many=self.nodes)
        raise AssertionError(f"Unexpected query: {query}")


def load_helpers():
    tree = ast.parse(SOURCE.read_text())
    wanted = {"normalize_cluster_endpoint", "validate_qnetd_host", "cluster_qnetd_witness_prepare_context", "public_qnetd_witness", "initialize_schema"}
    nodes = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in wanted]
    namespace = {"uuid": uuid, "json": json, "re": re, "ipaddress": ipaddress, "HTTPException": HttpException,
                 "Any": object, "AuthorizationContext": object, "sqlite3": sqlite3, "Path": Path}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(SOURCE), "exec"), namespace)
    return namespace


HELPERS = load_helpers()


def run_witness_preflight(os_release: str, address_json: str):
    tree = ast.parse(SOURCE.read_text())
    supported = next(
        ast.literal_eval(node.value.args[0])
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "SUPPORTED_SLES_HA_RELEASES" for target in node.targets)
    )
    script = next(
        ast.literal_eval(node.value)
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "QNETD_WITNESS_PREFLIGHT_SCRIPT" for target in node.targets)
    )
    renderer = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "render_sles_release_script"
    )
    renderer_namespace = {"SUPPORTED_SLES_HA_RELEASES": supported}
    exec(compile(ast.Module(body=[renderer], type_ignores=[]), str(SOURCE), "exec"), renderer_namespace)
    script = renderer_namespace["render_sles_release_script"](script)
    calls = []

    def fake_run(args, **_kwargs):
        calls.append(args)
        if args == ["SUSEConnect", "--list-extensions"]:
            return subprocess.CompletedProcess(args, 0, "SLE HA (Activated)\nDeactivate with: SUSEConnect -d -p sle-ha/16.0/x86_64", "")
        if args[:3] == ["timedatectl", "show", "-p"]:
            return subprocess.CompletedProcess(args, 0, "yes\n", "")
        if args[:3] == ["ip", "-j", "address"]:
            return subprocess.CompletedProcess(args, 0, address_json, "")
        if args[:2] == ["rpm", "-q"]:
            return subprocess.CompletedProcess(args, 0, "corosync-qnetd-3.0\n", "")
        raise AssertionError(f"Unexpected witness preflight command: {args}")

    real_open = open

    def fake_open(path, *args, **kwargs):
        if path == "/etc/os-release":
            return io.StringIO(os_release)
        return real_open(path, *args, **kwargs)

    stdout = io.StringIO()
    with mock.patch("subprocess.run", side_effect=fake_run), \
         mock.patch("shutil.which", side_effect=lambda name: "/usr/bin/SUSEConnect" if name == "SUSEConnect" else None), \
         mock.patch("builtins.open", side_effect=fake_open), \
         mock.patch.object(sys, "argv", ["witness-preflight", json.dumps({"check_qnetd_package": True, "registered_address": "192.0.2.20"})]), \
         contextlib.redirect_stdout(stdout):
        exec(compile(script, "qnetd-witness-preflight", "exec"), {"__name__": "__main__"})
    return json.loads(stdout.getvalue()), calls


class QnetdWitnessTests(unittest.TestCase):
    def setUp(self):
        self.plan_id = str(uuid.uuid4())
        self.witness_id = str(uuid.uuid4())
        self.plan = {
            "id": self.plan_id, "created_by": "operator", "cluster_type": "suse-ha",
            "host_ids_json": json.dumps(["node-a", "node-b"]),
            "config_json": json.dumps({"quorum": "qdevice", "qnetd_host": "witness.suse.test", "qnetd_outside_cluster": True}),
        }
        self.witness = {
            "id": self.witness_id, "name": "qnetd", "hostname": "witness.suse.test",
            "address": "192.0.2.20", "port": 22, "username": "qnetd-admin", "password": "encrypted",
            "ssh_host_key": "ssh-ed25519 private-key-material", "status": "ready",
        }
        self.nodes = [
            {"id": "node-a", "name": "node-a", "hostname": "node-a", "address": "192.0.2.11", "username": "cluster-user", "status": "ready"},
            {"id": "node-b", "name": "node-b", "hostname": "node-b", "address": "192.0.2.12", "username": "cluster-user", "status": "ready"},
        ]
        self.actor = SimpleNamespace(user_id="operator", permissions=frozenset())

    def test_standalone_witness_can_have_a_distinct_linux_ssh_account(self):
        database = FakeDatabase(self.plan, self.witness, self.nodes)
        HELPERS["connect_db"] = lambda: database
        plan, witness = HELPERS["cluster_qnetd_witness_prepare_context"](self.plan_id, self.witness_id, self.actor)
        self.assertEqual(plan["host_ids"], ["node-a", "node-b"])
        self.assertEqual(witness["username"], "qnetd-admin")

    def test_rejects_witness_that_is_a_selected_cluster_node(self):
        self.plan["config_json"] = json.dumps({"quorum": "qdevice", "qnetd_host": "192.0.2.11", "qnetd_outside_cluster": True})
        self.witness["address"] = "192.0.2.11"
        database = FakeDatabase(self.plan, self.witness, self.nodes)
        HELPERS["connect_db"] = lambda: database
        with self.assertRaisesRegex(HttpException, "outside the selected cluster nodes"):
            HELPERS["cluster_qnetd_witness_prepare_context"](self.plan_id, self.witness_id, self.actor)

    def test_public_witness_view_never_returns_password_or_pinned_host_key(self):
        witness = self.witness | {"ha_active": 1, "qnetd_package_installed": 0, "time_synchronized": 1,
                                  "registered_address_is_dynamic": 0, "created_at": "now", "updated_at": "now",
                                  "last_checked_at": "now", "os_id": "sles", "os_version": "16.0", "ha_product": "sle-ha/16.0/x86_64"}
        public = HELPERS["public_qnetd_witness"](witness)
        self.assertNotIn("password", public)
        self.assertNotIn("ssh_host_key", public)
        self.assertIs(public["ha_active"], True)
        self.assertIs(public["qnetd_package_installed"], False)
        self.assertIs(public["registered_address_is_dynamic"], False)

    def test_schema_creates_separate_qnetd_witness_inventory(self):
        db = sqlite3.connect(":memory:")
        HELPERS["initialize_schema"](db)
        columns = {row[1] for row in db.execute("PRAGMA table_info(qnetd_witnesses)")}
        self.assertTrue({"address", "username", "password", "ssh_host_key", "ha_active", "qnetd_package_installed"}.issubset(columns))
        self.assertNotIn("libvirt_version", columns)
        db.close()

    def test_standalone_preflight_checks_sles_qnetd_facts_without_kvm_or_libvirt(self):
        facts, calls = run_witness_preflight(
            'ID="sles"\nVERSION_ID="16.0"\nPRETTY_NAME="SUSE Linux Enterprise Server 16.0"\n',
            json.dumps([{"ifname": "eth0", "flags": ["UP"], "addr_info": [{"local": "192.0.2.20", "prefixlen": 24, "scope": "global", "flags": []}]}]),
        )
        self.assertTrue(facts["compatibility_supported"])
        self.assertTrue(facts["ha_active"])
        self.assertEqual(facts["ha_product"], "sle-ha/16.0/x86_64")
        self.assertTrue(facts["qnetd_package_installed"])
        self.assertTrue(facts["time_synchronized"])
        self.assertIs(facts["registered_address_is_dynamic"], False)
        self.assertNotIn("libvirt_version", facts)
        commands = {tuple(call) for call in calls}
        self.assertEqual(commands, {
            ("SUSEConnect", "--list-extensions"),
            ("timedatectl", "show", "-p", "NTPSynchronized", "--value"),
            ("ip", "-j", "address", "show"),
            ("rpm", "-q", "corosync-qnetd"),
        })

    def test_fingerprint_probe_completes_ssh_key_exchange_without_authenticating(self):
        tree = ast.parse(SOURCE.read_text())
        function = next(
            node for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "probe_qnetd_witness_fingerprint"
        )
        events = []

        class FakeKey:
            def get_name(self): return "ssh-ed25519"
            def get_base64(self): return "a2V5"
            def asbytes(self): return b"key-bytes"

        class FakeTransport:
            def __init__(self, _connection): events.append("transport")
            def start_client(self, timeout): events.append(("key-exchange", timeout))
            def get_remote_server_key(self): events.append("read-server-key"); return FakeKey()
            def close(self): events.append("close")

        class FakeConnection:
            def close(self): events.append("socket-close")

        namespace = {
            "socket": SimpleNamespace(create_connection=lambda endpoint, timeout: events.append(("connect", endpoint, timeout)) or FakeConnection()),
            "paramiko": SimpleNamespace(Transport=FakeTransport),
            "validate_qnetd_host": lambda value: value,
            "base64": base64,
            "hashlib": hashlib,
        }
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(SOURCE), "exec"), namespace)
        result = namespace["probe_qnetd_witness_fingerprint"](
            SimpleNamespace(address="witness.suse.test", port=2222)
        )
        self.assertEqual(events, [
            ("connect", ("witness.suse.test", 2222), 8), "transport",
            ("key-exchange", 8), "read-server-key", "close", "socket-close",
        ])
        self.assertTrue(result["fingerprint"].startswith("SHA256:"))

    def test_changed_fingerprint_is_rejected_before_password_authentication(self):
        tree = ast.parse(SOURCE.read_text())
        function = next(
            node for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "inspect_qnetd_witness"
        )
        namespace = {
            "validate_qnetd_host": lambda value: value,
            "QnetdWitnessFingerprintInput": lambda **values: SimpleNamespace(**values),
            "probe_qnetd_witness_fingerprint": lambda _payload: {
                "fingerprint": "SHA256:observed-key-fingerprint", "ssh_host_key": "ssh-ed25519 key",
            },
            "HTTPException": HttpException,
        }
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(SOURCE), "exec"), namespace)
        payload = SimpleNamespace(name="witness", address="witness.suse.test", port=22)
        with self.assertRaises(HttpException) as caught:
            namespace["inspect_qnetd_witness"](payload, expected_fingerprint="SHA256:stale-key-fingerprint")
        self.assertEqual(caught.exception.status_code, 409)


if __name__ == "__main__":
    unittest.main()

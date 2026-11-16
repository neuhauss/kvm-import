"""API orchestration tests for the service/VIP workflow, with external systems mocked."""

from __future__ import annotations

import ast
import contextlib
import json
import unittest
from typing import Any
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


APP_SOURCE = Path(__file__).resolve().parents[1] / "app.py"


class ApiException(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


class FakeApp:
    def __init__(self):
        self.routes = {}

    def post(self, path):
        def register(function):
            self.routes[path] = function
            return function
        return register


class FakeDatabase:
    def __init__(self, rows):
        self.rows = rows

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, *_args):
        return self.rows


@contextlib.contextmanager
def no_op_guard(_member_ids):
    yield


def build_route(statuses, rows, run_remote, audit):
    tree = ast.parse(APP_SOURCE.read_text())
    function = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "configure_cluster_service_vip"
    )
    namespace = {
        "Any": Any,
        "app": FakeApp(),
        "Depends": lambda value: value,
        "require_permission": lambda _permission: object(),
        "AuthorizationContext": object,
        "ClusterServiceVipRequest": object,
        "HTTPException": ApiException,
        "require_verified_ha_cluster": lambda _host_id: statuses.pop(0),
        "cluster_member_host_ids": lambda _status, _source: ["host-a", "host-b"],
        "cluster_host_mutation_guard": no_op_guard,
        "connect_db": lambda: FakeDatabase(rows),
        "ThreadPoolExecutor": __import__("concurrent.futures").futures.ThreadPoolExecutor,
        "json": json,
        "HA_SERVICE_VIP_CONFIG_SCRIPT": "test-script",
        "run_sudo_python": run_remote,
        "record_audit": audit,
    }
    exec(compile(ast.Module(body=[function], type_ignores=[]), "<service-vip-route>", "exec"), namespace)
    return namespace["configure_cluster_service_vip"]


def good_status(*, quorate=True, nodes=("node-a", "node-b")):
    return {"nodes": [{"name": name} for name in nodes],
            "quorum": {"quorate": quorate}, "fencing": {"configured": True}}


class ServiceVipApiTests(unittest.TestCase):
    def test_api_preflights_every_cluster_member_then_applies_once_to_source(self):
        statuses = [({"id": "host-a", "hostname": "node-a"}, good_status()), ({"id": "host-a", "hostname": "node-a"}, good_status())]
        rows = [{"id": "host-a", "hostname": "node-a"}, {"id": "host-b", "hostname": "node-b"}]
        ssh_calls = []
        audits = []

        def fake_remote(host, _script, **kwargs):
            payload = json.loads(kwargs["stdin_data"])
            ssh_calls.append((host["id"], payload.get("preflight_only", False)))
            if payload.get("preflight_only"):
                return json.dumps({"success": True, "checked_node": host["hostname"]})
            return json.dumps({"success": True, "message": "created stopped", "resources": {"group": "g-app"}})

        route = build_route(statuses, rows, fake_remote, lambda *args: audits.append(args))
        result = route("host-a", SimpleNamespace(profile="service", resource_prefix="app", model_dump=lambda: {
            "profile": "service", "resource_prefix": "app", "service_unit": "apache2.service", "virtual_ip": "192.0.2.50",
            "cidr_netmask": 24, "shared_network_confirmed": True,
        }), SimpleNamespace(user_id="tester"))

        self.assertTrue(result["success"])
        self.assertEqual(ssh_calls, [("host-a", True), ("host-b", True), ("host-a", False)])
        self.assertEqual(len(audits), 1)
        self.assertEqual(audits[0][1], "cluster.service_vip.configure")

    def test_api_rejects_lost_quorum_before_any_remote_command(self):
        route = build_route([("host-a", good_status(quorate=False))], [], lambda *_a, **_k: self.fail("SSH must not run"), lambda *_a: None)
        with self.assertRaises(ApiException) as raised:
            route("host-a", SimpleNamespace(model_dump=lambda: {}), SimpleNamespace(user_id="tester"))
        self.assertEqual(raised.exception.status_code, 409)
        self.assertIn("quorate", raised.exception.detail)

    def test_api_rejects_membership_change_before_remote_preflight(self):
        statuses = [("host-a", good_status()), ("host-a", good_status(nodes=("node-a", "node-c")))]
        route = build_route(statuses, [], lambda *_a, **_k: self.fail("SSH must not run after membership changes"), lambda *_a: None)
        with self.assertRaises(ApiException) as raised:
            route("host-a", SimpleNamespace(model_dump=lambda: {}), SimpleNamespace(user_id="tester"))
        self.assertEqual(raised.exception.status_code, 409)
        self.assertIn("membership changed", raised.exception.detail)

    def test_api_reports_which_node_failed_preflight(self):
        statuses = [({"id": "host-a", "hostname": "node-a"}, good_status()), ({"id": "host-a", "hostname": "node-a"}, good_status())]
        rows = [{"id": "host-a", "hostname": "node-a"}, {"id": "host-b", "hostname": "node-b"}]

        def fake_remote(host, _script, **kwargs):
            if host["id"] == "host-b":
                raise RuntimeError("No usable host route exists for the selected virtual IP")
            return json.dumps({"success": True})

        route = build_route(statuses, rows, fake_remote, lambda *_a: None)
        with self.assertRaises(ApiException) as raised:
            route("host-a", SimpleNamespace(resource_prefix="app", profile="service", model_dump=lambda: {"profile": "service", "service_unit": "apache2.service"}), SimpleNamespace(user_id="tester"))
        self.assertEqual(raised.exception.status_code, 422)
        self.assertIn("node-b", raised.exception.detail)
        self.assertIn("No usable host route", raised.exception.detail)

    def test_apache_configuration_mismatch_blocks_before_cib_mutation(self):
        statuses = [({"id": "host-a", "hostname": "node-a"}, good_status()), ({"id": "host-a", "hostname": "node-a"}, good_status())]
        rows = [{"id": "host-a", "hostname": "node-a"}, {"id": "host-b", "hostname": "node-b"}]
        applied = []

        def fake_remote(host, _script, **kwargs):
            payload = json.loads(kwargs["stdin_data"])
            if payload.get("preflight_only"):
                return json.dumps({"success": True, "configuration_sha256": "a" * 64 if host["id"] == "host-a" else "b" * 64})
            applied.append(host["id"])
            return json.dumps({"success": True})

        route = build_route(statuses, rows, fake_remote, lambda *_a: None)
        payload = {"profile": "apache", "resource_prefix": "web", "model_dump": lambda: {
            "profile": "apache", "resource_prefix": "web", "service_unit": "apache2.service",
            "apache_configfile": "/etc/apache2/httpd.conf", "apache_start_order_confirmed": True,
            "virtual_ip": "192.0.2.50", "cidr_netmask": 24, "shared_network_confirmed": True,
        }}
        with self.assertRaises(ApiException) as raised:
            route("host-a", SimpleNamespace(**payload), SimpleNamespace(user_id="tester"))
        self.assertEqual(raised.exception.status_code, 422)
        self.assertIn("byte-for-byte identical", raised.exception.detail)
        self.assertEqual(applied, [])

    def test_apache_profile_pins_the_verified_main_config_digest_for_final_apply(self):
        statuses = [({"id": "host-a", "hostname": "node-a"}, good_status()), ({"id": "host-a", "hostname": "node-a"}, good_status())]
        rows = [{"id": "host-a", "hostname": "node-a"}, {"id": "host-b", "hostname": "node-b"}]
        digest = "c" * 64
        apply_payloads = []

        def fake_remote(_host, _script, **kwargs):
            payload = json.loads(kwargs["stdin_data"])
            if payload.get("preflight_only"):
                return json.dumps({"success": True, "configuration_sha256": digest})
            apply_payloads.append(payload)
            return json.dumps({"success": True, "message": "created stopped"})

        route = build_route(statuses, rows, fake_remote, lambda *_a: None)
        request = SimpleNamespace(profile="apache", resource_prefix="web", model_dump=lambda: {
            "profile": "apache", "resource_prefix": "web", "service_unit": "apache2.service",
            "apache_configfile": "/etc/apache2/httpd.conf", "apache_start_order_confirmed": True,
            "virtual_ip": "192.0.2.50", "cidr_netmask": 24, "shared_network_confirmed": True,
        })
        result = route("host-a", request, SimpleNamespace(user_id="tester"))
        self.assertTrue(result["success"])
        self.assertEqual(len(apply_payloads), 1)
        self.assertEqual(apply_payloads[0]["expected_configuration_sha256"], digest)


if __name__ == "__main__":
    unittest.main()

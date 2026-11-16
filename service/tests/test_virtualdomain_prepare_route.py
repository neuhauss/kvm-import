"""Route-level tests for the guided SUSE VirtualDomain preparation flow."""

from __future__ import annotations

import ast
import contextlib
import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock


APP = Path(__file__).resolve().parents[1] / "app.py"


def route_function():
    tree = ast.parse(APP.read_text(encoding="utf-8"))
    route = next(
        item for item in tree.body
        if isinstance(item, ast.FunctionDef) and item.name == "prepare_virtualdomain_vm"
    )
    route.decorator_list = []
    namespace: dict[str, Any] = {
        "Any": Any,
        "AuthorizationContext": object,
        "VirtualDomainPrepareRequest": object,
        "Depends": lambda value: value,
        "require_permission": lambda _permission: object(),
    }
    exec(compile(ast.Module(body=[route], type_ignores=[]), "<virtualdomain-route>", "exec"), namespace)
    return namespace["prepare_virtualdomain_vm"]


class VirtualDomainPrepareRouteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.route = route_function()
        self.status = {
            "nodes": [{"name": "node-a", "online": True}, {"name": "node-b", "online": True}],
        }
        self.host = {"id": "host-a", "name": "node-a"}
        self.access = SimpleNamespace(user_id="test-operator")
        self.payload = SimpleNamespace(
            vm_name="guest", resource_id="ha-guest", config_path="/shared/configs/guest.xml",
        )
        self.assessment = {
            "nodes": [
                {"host_id": "host-a", "cluster_node": "node-a", "uuid": "12345678-1234-1234-1234-123456789abc",
                 "disks": [{"type": "file", "source": "/shared/guest.qcow2"}]},
                {"host_id": "host-b", "cluster_node": "node-b", "uuid": "", "disks": []},
            ],
            "storage_checks": {"nodes": [
                {"cluster_node": "node-a", "config": {"parent_mount": {
                    "uuid": "shared-id", "source": "/dev/shared", "target": "/shared/configs",
                }}},
                {"cluster_node": "node-b", "config": {"parent_mount": {}}},
            ]},
        }
        self.diagnostics = {"locking_topology": {"lock_clone_ids": ["dlm-clone"]}}
        self.result = {"success": True, "resource_state": "Stopped", "resource_id": "ha-guest"}
        self.remote_calls: list[tuple[str, dict[str, Any]]] = []
        self.audits: list[tuple[Any, ...]] = []
        self.guarded_host_ids: list[str] = []
        self.operation = None
        self.operation_host = None
        self.require_verified = Mock(side_effect=[(self.host, self.status)] * 3)

    def namespace(self, blockers: list[str] | None = None) -> dict[str, Any]:
        class FakeHTTPException(Exception):
            def __init__(self, status_code: int, detail: str):
                super().__init__(detail)
                self.status_code = status_code

        def remote(host: dict[str, Any], script: str, **kwargs: Any) -> str:
            self.remote_calls.append((script, {"host": host, **kwargs}))
            if script == "diagnostics-script":
                return json.dumps(self.diagnostics)
            if script == "prepare-script":
                return json.dumps(self.result)
            raise AssertionError(f"Unexpected script sent to the host: {script}")

        def create_job(kind: str, actor: str, hosts: list[dict[str, Any]], operation):
            self.assertEqual(kind, "cluster_virtualdomain_prepare")
            self.assertEqual(actor, "test-operator")
            self.assertEqual([item["id"] for item in hosts], ["host-a"])
            self.operation = operation
            self.operation_host = hosts[0]
            return {"job_id": "operation-1", "kind": kind, "status": "queued", "results": [{"status": "queued"}]}

        return {
            "cluster_host_mutation_guard": lambda host_ids: self._guard(host_ids),
            "cluster_member_host_ids": lambda _status, _host_id: ["host-a", "host-b"],
            "require_verified_ha_cluster": self.require_verified,
            "cockpit_host_record": lambda _host_id: self.host,
            "get_virtualdomain_vm_preflight": Mock(return_value=self.assessment),
            "HA_CLUSTER_DIAGNOSTICS_SCRIPT": "diagnostics-script",
            "HA_VIRTUALDOMAIN_PREPARE_SCRIPT": "prepare-script",
            "virtualdomain_prepare_blockers": lambda *_args: blockers or [],
            "create_operation_job": create_job,
            "run_sudo_python": remote,
            "record_audit": lambda *args: self.audits.append(args),
            "json": json,
            "HTTPException": FakeHTTPException,
        }

    @contextlib.contextmanager
    def _guard(self, host_ids: list[str]):
        self.guarded_host_ids.extend(host_ids)
        yield

    def test_revalidates_inside_mutation_guard_and_sends_only_allowlisted_facts(self) -> None:
        namespace = self.namespace()
        self.route.__globals__.update(namespace)
        queued = self.route("host-a", self.payload, self.access)

        self.assertEqual(queued["job_id"], "operation-1")
        self.assertEqual(queued["status"], "queued")
        self.assertEqual(self.remote_calls, [])
        self.assertEqual(self.operation(self.operation_host), {"status": "completed", **self.result})
        self.assertEqual(self.require_verified.call_count, 3)
        self.assertEqual(self.guarded_host_ids, ["host-a", "host-b"])
        self.assertEqual([call[0] for call in self.remote_calls], ["diagnostics-script", "prepare-script"])
        call = self.remote_calls[1]
        self.assertEqual(call[1]["host"], self.host)
        self.assertEqual(call[1]["timeout"], 100)
        payload = json.loads(call[1]["stdin_data"])
        self.assertEqual(payload["expected_uuid"], self.assessment["nodes"][0]["uuid"])
        self.assertEqual(payload["expected_disk_paths"], ["/shared/guest.qcow2"])
        self.assertEqual(payload["expected_mount_identity"], "shared-id")
        self.assertEqual(payload["expected_mount_target"], "/shared/configs")
        self.assertEqual(payload["lock_clone_id"], "dlm-clone")
        self.assertEqual(self.audits, [("test-operator", "cluster.virtualdomain.prepare", "host-a/ha-guest")])

    def test_preflight_blocker_prevents_remote_resource_creation(self) -> None:
        namespace = self.namespace(["cluster_must_have_confirmed_quorum"])
        self.route.__globals__.update(namespace)

        queued = self.route("host-a", self.payload, self.access)
        self.assertEqual(queued["status"], "queued")
        with self.assertRaises(namespace["HTTPException"]) as error:
            self.operation(self.operation_host)

        self.assertEqual(error.exception.status_code, 409)
        self.assertIn("cluster_must_have_confirmed_quorum", str(error.exception))
        self.assertEqual([call[0] for call in self.remote_calls], ["diagnostics-script"])
        self.assertEqual(self.audits, [("test-operator", "cluster.virtualdomain.prepare", "host-a/ha-guest", "failure")])

    def test_membership_change_stops_before_preflight_or_host_mutation(self) -> None:
        changed = {"nodes": [{"name": "node-a", "online": True}]}
        self.require_verified.side_effect = [(self.host, self.status), (self.host, changed)]
        namespace = self.namespace()
        namespace["cluster_member_host_ids"] = Mock(side_effect=[["host-a", "host-b"], ["host-a"]])
        self.route.__globals__.update(namespace)

        queued = self.route("host-a", self.payload, self.access)
        self.assertEqual(queued["status"], "queued")
        with self.assertRaises(namespace["HTTPException"]) as error:
            self.operation(self.operation_host)

        self.assertEqual(error.exception.status_code, 409)
        self.assertEqual(namespace["get_virtualdomain_vm_preflight"].call_count, 0)
        self.assertEqual(self.remote_calls, [])


if __name__ == "__main__":
    unittest.main()

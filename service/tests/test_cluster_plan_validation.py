"""Dependency-light regression tests for saved Corosync plans and bootstrap guards."""

from __future__ import annotations

import ast
import ipaddress
import json
import re
import shlex
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace


SERVICE_SOURCE = Path(__file__).resolve().parents[1] / "app.py"


class HttpException(Exception):
    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code


class Cursor:
    def __init__(self, one=None, many=None) -> None:
        self.one = one
        self.many = many or []

    def fetchone(self):
        return self.one

    def fetchall(self):
        return self.many

    def __iter__(self):
        return iter(self.many)


class Database:
    def __init__(self, plan, hosts) -> None:
        self.plan = plan
        self.hosts = hosts
        self.query_count = 0

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, _query, _params=()):
        self.query_count += 1
        if self.query_count == 1:
            return Cursor(one=self.plan)
        return Cursor(many=self.hosts)


def load_cluster_plan_helpers():
    tree = ast.parse(SERVICE_SOURCE.read_text())
    names = {
        "validate_qnetd_host", "normalize_cluster_endpoint", "validate_corosync_networks",
        "validate_cluster_plan", "cluster_bootstrap_context", "cluster_bootstrap_command",
        "cluster_qnetd_prepare_context", "cluster_qdevice_prepare_nodes_context",
    }
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    namespace = {
        "ipaddress": ipaddress, "json": json, "re": re, "uuid": uuid,
        "HTTPException": HttpException, "ClusterPlanInput": object, "shlex": shlex,
        "AuthorizationContext": object, "Any": object,
    }
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(SERVICE_SOURCE), "exec"), namespace)
    return namespace


HELPERS = load_cluster_plan_helpers()
validate_corosync_networks = HELPERS["validate_corosync_networks"]
validate_cluster_plan = HELPERS["validate_cluster_plan"]
cluster_bootstrap_context = HELPERS["cluster_bootstrap_context"]
cluster_bootstrap_command = HELPERS["cluster_bootstrap_command"]
cluster_qnetd_prepare_context = HELPERS["cluster_qnetd_prepare_context"]
cluster_qdevice_prepare_nodes_context = HELPERS["cluster_qdevice_prepare_nodes_context"]


class ClusterPlanNetworkValidationTests(unittest.TestCase):
    def test_canonicalizes_ipv4_and_ipv6_subnet_hints(self) -> None:
        self.assertEqual(
            validate_corosync_networks(["10.20.0.11/24", "2001:db8:1::42/64"]),
            ["10.20.0.0/24", "2001:db8:1::/64"],
        )

    def test_rejects_invalid_duplicate_blank_and_excess_channels(self) -> None:
        for values in (
            ["not-a-subnet"],
            ["10.20.0.0/24", "10.20.0.9/24"],
            [""],
            ["10.0.0.0/24", "10.1.0.0/24", "10.2.0.0/24"],
        ):
            with self.subTest(values=values), self.assertRaises(HttpException) as raised:
                validate_corosync_networks(values)
            self.assertEqual(raised.exception.status_code, 422)

    def test_saved_plan_normalizes_only_address_hints_and_keeps_attestation(self) -> None:
        payload = SimpleNamespace(
            name="ha-lab", host_ids=["node-a", "node-b"], quorum="standard", qnetd_host="",
            qnetd_outside_cluster=False, fencing="hardware", corosync_networks=["10.20.0.11/24"],
            corosync_network_reviewed=True,
        )
        name, host_ids, config = validate_cluster_plan(payload)
        self.assertEqual((name, host_ids), ("ha-lab", ["node-a", "node-b"]))
        self.assertEqual(config["corosync_networks"], ["10.20.0.0/24"])
        self.assertTrue(config["corosync_network_reviewed"])

    def test_bootstrap_context_requires_review_and_returns_saved_network_plan(self) -> None:
        plan_id = str(uuid.uuid4())
        hosts = [
            {"id": "node-a", "name": "node-a", "hostname": "node-a", "address": "192.0.2.11", "username": "sles", "status": "ready"},
            {"id": "node-b", "name": "node-b", "hostname": "node-b", "address": "192.0.2.12", "username": "sles", "status": "ready"},
        ]
        plan = {
            "id": plan_id, "created_by": "operator", "host_ids_json": json.dumps(["node-a", "node-b"]),
            "cluster_type": "suse-ha", "name": "ha-lab",
            "config_json": json.dumps({"quorum": "standard", "fencing": "hardware", "corosync_networks": ["10.20.0.0/24"], "corosync_network_reviewed": False}),
        }
        actor = SimpleNamespace(user_id="operator", permissions=frozenset())
        database = Database(plan, hosts)
        HELPERS["connect_db"] = lambda: database
        with self.assertRaisesRegex(HttpException, "Review static Corosync addressing"):
            cluster_bootstrap_context(plan_id, "node-a", "init", actor)

        plan["config_json"] = json.dumps({"quorum": "standard", "fencing": "hardware", "corosync_networks": ["10.20.0.0/24"], "corosync_network_reviewed": True})
        database.query_count = 0
        context, _ = cluster_bootstrap_context(plan_id, "node-a", "init", actor)
        self.assertEqual(context["config"]["corosync_networks"], ["10.20.0.0/24"])

        plan["config_json"] = json.dumps({
            "quorum": "qdevice", "qnetd_host": "witness.example.test",
            "qnetd_outside_cluster": True, "fencing": "hardware",
            "corosync_networks": ["10.20.0.0/24"], "corosync_network_reviewed": True,
        })
        HELPERS["connect_db"] = lambda: Database(plan, hosts)
        context, _ = cluster_bootstrap_context(plan_id, "node-a", "qdevice", actor)
        self.assertEqual(context["config"]["qnetd_host"], "witness.example.test")

        plan["config_json"] = json.dumps({
            "quorum": "qdevice", "qnetd_host": "192.0.2.11",
            "qnetd_outside_cluster": True, "fencing": "hardware",
            "corosync_networks": [], "corosync_network_reviewed": True,
        })
        HELPERS["connect_db"] = lambda: Database(plan, hosts)
        with self.assertRaisesRegex(HttpException, "outside the selected cluster nodes"):
            cluster_bootstrap_context(plan_id, "node-a", "qdevice", actor)

        plan["config_json"] = json.dumps({
            "quorum": "standard", "qnetd_host": "witness.example.test",
            "qnetd_outside_cluster": False, "fencing": "hardware",
            "corosync_networks": [], "corosync_network_reviewed": True,
        })
        HELPERS["connect_db"] = lambda: Database(plan, hosts)
        with self.assertRaisesRegex(HttpException, "Choose and save the QDevice/QNetd topology"):
            cluster_bootstrap_context(plan_id, "node-a", "qdevice", actor)

    def test_qdevice_bootstrap_command_is_fixed_and_only_targets_the_first_saved_node(self) -> None:
        plan = {"host_ids": ["node-a", "node-b"], "config": {"quorum": "qdevice"}}
        hosts = [{"id": "node-a"}, {"id": "node-b"}]
        self.assertEqual(cluster_bootstrap_command(plan, hosts, "qdevice", "node-a"), "crm cluster init qdevice")

        with self.assertRaisesRegex(HttpException, "first selected host"):
            cluster_bootstrap_command(plan, hosts, "qdevice", "node-b")
        with self.assertRaisesRegex(HttpException, "QDevice/QNetd plan"):
            cluster_bootstrap_command(
                {"host_ids": ["node-a", "node-b"], "config": {"quorum": "standard"}},
                hosts, "qdevice", "node-a",
            )

    def test_qnetd_prepare_context_requires_exact_external_ready_registered_host(self) -> None:
        plan_id = str(uuid.uuid4())
        hosts = [
            {"id": "node-a", "name": "node-a", "hostname": "node-a", "address": "192.0.2.11", "username": "sles", "status": "ready"},
            {"id": "node-b", "name": "node-b", "hostname": "node-b", "address": "192.0.2.12", "username": "sles", "status": "ready"},
            {"id": "witness", "name": "witness.example.test", "hostname": "witness.example.test", "address": "192.0.2.20", "username": "sles", "status": "ready"},
        ]
        plan = {
            "id": plan_id, "created_by": "operator", "host_ids_json": json.dumps(["node-a", "node-b"]),
            "cluster_type": "suse-ha", "name": "ha-lab",
            "config_json": json.dumps({"quorum": "qdevice", "qnetd_host": "witness.example.test.", "qnetd_outside_cluster": True}),
        }
        actor = SimpleNamespace(user_id="operator", permissions=frozenset())
        database = Database(plan, hosts)
        HELPERS["connect_db"] = lambda: database
        saved, witness = cluster_qnetd_prepare_context(plan_id, "witness", actor)
        self.assertEqual(saved["host_ids"], ["node-a", "node-b"])
        self.assertEqual(witness["id"], "witness")

        database.query_count = 0
        with self.assertRaisesRegex(HttpException, "outside the selected cluster nodes"):
            cluster_qnetd_prepare_context(plan_id, "node-a", actor)
        plan["config_json"] = json.dumps({"quorum": "standard", "qnetd_host": "witness.example.test", "qnetd_outside_cluster": False})
        database.query_count = 0
        with self.assertRaisesRegex(HttpException, "confirm that its QNetd host is outside"):
            cluster_qnetd_prepare_context(plan_id, "witness", actor)

        plan["config_json"] = json.dumps({"quorum": "qdevice", "qnetd_host": "other.example.test", "qnetd_outside_cluster": True})
        database.query_count = 0
        with self.assertRaisesRegex(HttpException, "exactly matches the saved QNetd endpoint"):
            cluster_qnetd_prepare_context(plan_id, "witness", actor)

    def test_qnetd_prepare_context_allows_separate_witness_user_and_requires_ready_hosts(self) -> None:
        plan_id = str(uuid.uuid4())
        hosts = [
            {"id": "node-a", "name": "node-a", "hostname": "node-a", "address": "192.0.2.11", "username": "sles", "status": "ready"},
            {"id": "node-b", "name": "node-b", "hostname": "node-b", "address": "192.0.2.12", "username": "sles", "status": "ready"},
            {"id": "witness", "name": "witness", "hostname": "witness", "address": "192.0.2.20", "username": "root", "status": "ready"},
        ]
        plan = {
            "id": plan_id, "created_by": "operator", "host_ids_json": json.dumps(["node-a", "node-b"]),
            "cluster_type": "suse-ha", "name": "ha-lab",
            "config_json": json.dumps({"quorum": "qdevice", "qnetd_host": "witness", "qnetd_outside_cluster": True}),
        }
        actor = SimpleNamespace(user_id="operator", permissions=frozenset())
        database = Database(plan, hosts)
        HELPERS["connect_db"] = lambda: database
        saved, witness = cluster_qnetd_prepare_context(plan_id, "witness", actor)
        self.assertEqual(saved["host_ids"], ["node-a", "node-b"])
        self.assertEqual(witness["username"], "root")
        hosts[2]["status"] = "unreachable"
        database.query_count = 0
        with self.assertRaisesRegex(HttpException, "must be reachable and ready"):
            cluster_qnetd_prepare_context(plan_id, "witness", actor)

    def test_qdevice_package_context_accepts_prerequisites_before_full_bootstrap_review(self) -> None:
        plan_id = str(uuid.uuid4())
        hosts = [
            {"id": "node-a", "name": "node-a", "hostname": "node-a", "address": "192.0.2.11", "username": "sles", "status": "ready"},
            {"id": "node-b", "name": "node-b", "hostname": "node-b", "address": "192.0.2.12", "username": "sles", "status": "ready"},
        ]
        plan = {
            "id": plan_id, "created_by": "operator", "host_ids_json": json.dumps(["node-a", "node-b"]),
            "cluster_type": "suse-ha", "name": "ha-lab",
            "config_json": json.dumps({"quorum": "qdevice", "qnetd_host": "witness.example.test", "qnetd_outside_cluster": True}),
        }
        actor = SimpleNamespace(user_id="operator", permissions=frozenset())
        database = Database(plan, hosts)
        HELPERS["connect_db"] = lambda: database
        saved, selected = cluster_qdevice_prepare_nodes_context(plan_id, actor)
        self.assertEqual(saved["host_ids"], ["node-a", "node-b"])
        self.assertEqual([host["id"] for host in selected], ["node-a", "node-b"])

        plan["config_json"] = json.dumps({"quorum": "qdevice", "qnetd_host": "node-a", "qnetd_outside_cluster": True})
        database.query_count = 0
        with self.assertRaisesRegex(HttpException, "outside the selected cluster nodes"):
            cluster_qdevice_prepare_nodes_context(plan_id, actor)


if __name__ == "__main__":
    unittest.main()

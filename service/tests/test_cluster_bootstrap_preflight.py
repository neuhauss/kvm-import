"""Standalone HA bootstrap hostname checks without loading API dependencies."""

import ast
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
import unittest


def load_preflight_validators():
    source_path = Path(__file__).resolve().parents[1] / "app.py"
    tree = ast.parse(source_path.read_text())
    function_nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                      and node.name in {"require_peer_host_file_entries", "require_consistent_ha_product_release", "cluster_bootstrap_preflight"}]
    namespace = {"RuntimeError": RuntimeError, "Any": Any, "json": json,
                 "ThreadPoolExecutor": ThreadPoolExecutor, "HA_PREFLIGHT_SCRIPT": "preflight-test-only",
                 "HA_CLUSTER_STATUS_SCRIPT": "cluster-status-test-only"}
    exec(compile(ast.Module(body=function_nodes, type_ignores=[]), str(source_path), "exec"), namespace)
    return namespace


_validators = load_preflight_validators()
require_peer_host_file_entries = _validators["require_peer_host_file_entries"]
require_consistent_ha_product_release = _validators["require_consistent_ha_product_release"]
cluster_bootstrap_preflight = _validators["cluster_bootstrap_preflight"]


class ClusterBootstrapPreflightTests(unittest.TestCase):
    def test_allows_peers_with_static_name_entries(self):
        require_peer_host_file_entries({
            "ssh_peer_connectivity": [
                {"host_name": "node-b", "hosts_file_entry_present": True},
                {"host_name": "node-c", "hosts_file_entry_present": True},
            ],
        }, "node-a")

    def test_blocks_missing_peer_name_with_specific_fix(self):
        with self.assertRaisesRegex(RuntimeError, "node-a cannot find selected peer names in /etc/hosts") as error:
            require_peer_host_file_entries({
                "ssh_peer_connectivity": [
                    {"host_name": "node-b", "hosts_file_entry_present": True},
                    {"host_name": "node-c", "address": "192.0.2.13", "hosts_file_entry_present": False},
                ],
            }, "node-a")
        self.assertIn("Add stable SUSE cluster node name mappings on every node", str(error.exception))

    def test_keeps_legacy_missing_diagnostic_as_unverified_not_false(self):
        require_peer_host_file_entries({"ssh_peer_connectivity": [{"host_name": "node-b"}]}, "node-a")

    def test_allows_fresh_bootstrap_when_all_nodes_use_one_confirmed_sle_ha_release(self):
        require_consistent_ha_product_release([
            {"checks": {"ha_product": "sle-ha/15.6/x86_64"}},
            {"checks": {"ha_product": "sle-ha/15.6/x86_64"}},
        ])

    def test_blocks_fresh_bootstrap_when_active_sle_ha_release_is_unknown(self):
        with self.assertRaisesRegex(RuntimeError, "release could not be confirmed"):
            require_consistent_ha_product_release([
                {"checks": {"ha_product": "sle-ha/15.6/x86_64"}},
                {"checks": {"ha_product": ""}},
            ])

    def test_blocks_fresh_bootstrap_when_sle_ha_releases_differ(self):
        with self.assertRaisesRegex(RuntimeError, "different active SLE HA product releases"):
            require_consistent_ha_product_release([
                {"checks": {"ha_product": "sle-ha/15.6/x86_64"}},
                {"checks": {"ha_product": "sle-ha/15.7/x86_64"}},
            ])

    def test_bootstrap_preflight_revalidates_each_planned_corosync_subnet(self):
        hosts = [
            {"id": "node-a", "hostname": "node-a", "address": "192.0.2.41", "port": 22},
            {"id": "node-b", "hostname": "node-b", "address": "192.0.2.42", "port": 22},
        ]
        checks_by_id = {
            host["id"]: {
                "compatibility_supported": True, "ha_active": True,
                "ha_product": "sle-ha/15.6/x86_64", "time_synchronized": True,
                "tools": {"crm": True, "crm_mon": True, "corosync-cfgtool": True},
                "ssh_peer_connectivity": [], "cluster_configured": False,
                "cluster_detected": False, "cluster_name": "",
                "interfaces": [{"name": "bond0.100", "subnets": ["10.20.0.0/24"]}]
                if host["id"] == "node-a" else [],
            }
            for host in hosts
        }
        namespace = _validators
        namespace["cockpit_host_record"] = lambda host_id: {"id": host_id}
        namespace["run_sudo_python"] = lambda current, _script, **_kwargs: json.dumps(checks_by_id[current["id"]])
        plan = {"name": "ha-lab", "host_ids": ["node-a", "node-b"],
                "config": {"corosync_networks": ["10.20.0.0/24"]}}
        with self.assertRaisesRegex(RuntimeError, "node-b no longer reports planned Corosync subnet"):
            cluster_bootstrap_preflight(plan, hosts, "init", "node-a")

        checks_by_id["node-b"]["interfaces"] = [{"name": "bond1.100", "subnets": ["10.20.0.0/24"]}]
        cluster_bootstrap_preflight(plan, hosts, "init", "node-a")

    def test_bootstrap_preflight_blocks_mixed_release_only_for_new_cluster_init(self):
        hosts = [
            {"id": "node-a", "hostname": "node-a", "address": "192.0.2.41", "port": 22},
            {"id": "node-b", "hostname": "node-b", "address": "192.0.2.42", "port": 22},
        ]
        products = {"node-a": "sle-ha/15.6/x86_64", "node-b": "sle-ha/15.7/x86_64"}
        checks_by_id = {
            host["id"]: {
                "compatibility_supported": True, "ha_active": True,
                "ha_product": products[host["id"]], "time_synchronized": True,
                "tools": {"crm": True, "crm_mon": True, "corosync-cfgtool": True},
                "ssh_peer_connectivity": [{"host_name": "peer", "reachable": True, "hosts_file_entry_present": True}],
                "cluster_configured": host["id"] == "node-a",
                "cluster_detected": host["id"] == "node-a",
                "cluster_name": "ha-lab" if host["id"] == "node-a" else "",
            }
            for host in hosts
        }
        namespace = _validators
        namespace["cockpit_host_record"] = lambda host_id: {"id": host_id}
        namespace["run_sudo_python"] = lambda current, _script, **_kwargs: json.dumps(checks_by_id[current["id"]])
        plan = {"name": "ha-lab", "host_ids": ["node-a", "node-b"]}
        with self.assertRaisesRegex(RuntimeError, "different active SLE HA product releases"):
            cluster_bootstrap_preflight(plan, hosts, "init", "node-a")
        cluster_bootstrap_preflight(plan, hosts, "join", "node-b")

    def test_qnetd_can_be_configured_during_init_but_must_be_reachable_before_join(self):
        hosts = [
            {"id": "node-a", "hostname": "node-a", "address": "192.0.2.41", "port": 22},
            {"id": "node-b", "hostname": "node-b", "address": "192.0.2.42", "port": 22},
        ]
        checks_by_id = {
            "node-a": {
                "compatibility_supported": True, "ha_active": True,
                "ha_product": "sle-ha/15.6/x86_64", "time_synchronized": True,
                "tools": {"crm": True, "crm_mon": True, "corosync-cfgtool": True},
                "ssh_peer_connectivity": [{"host_name": "node-b", "reachable": True, "hosts_file_entry_present": True}],
                "qnetd_tcp_connectivity": {"host": "witness.example.test", "port": 5403, "reachable": False},
                "cluster_configured": False, "cluster_detected": False, "cluster_name": "",
                "interfaces": [],
            },
            "node-b": {
                "compatibility_supported": True, "ha_active": True,
                "ha_product": "sle-ha/15.6/x86_64", "time_synchronized": True,
                "tools": {"crm": True, "crm_mon": True, "corosync-cfgtool": True},
                "ssh_peer_connectivity": [{"host_name": "node-a", "reachable": True, "hosts_file_entry_present": True}],
                "qnetd_tcp_connectivity": {"host": "witness.example.test", "port": 5403, "reachable": False},
                "cluster_configured": False, "cluster_detected": False, "cluster_name": "",
                "interfaces": [],
            },
        }
        namespace = _validators
        namespace["cockpit_host_record"] = lambda host_id: {"id": host_id}
        namespace["run_sudo_python"] = lambda current, _script, **_kwargs: json.dumps(checks_by_id[current["id"]])
        plan = {"name": "ha-lab", "host_ids": ["node-a", "node-b"],
                "config": {"quorum": "qdevice", "qnetd_host": "witness.example.test", "corosync_networks": []}}

        # The SUSE init command is what configures QDevice and starts QNetd.
        cluster_bootstrap_preflight(plan, hosts, "init", "node-a")

        checks_by_id["node-a"].update({"cluster_configured": True, "cluster_detected": True, "cluster_name": "ha-lab"})
        with self.assertRaisesRegex(RuntimeError, "cannot reach QNetd.*before joining"):
            cluster_bootstrap_preflight(plan, hosts, "join", "node-b")

        for checks in checks_by_id.values():
            checks["qnetd_tcp_connectivity"]["reachable"] = True
        cluster_bootstrap_preflight(plan, hosts, "join", "node-b")

    def test_qdevice_setup_requires_consistent_live_membership_quorum_and_unconfigured_witness(self):
        hosts = [
            {"id": "node-a", "hostname": "node-a", "address": "192.0.2.41", "port": 22},
            {"id": "node-b", "hostname": "node-b", "address": "192.0.2.42", "port": 22},
        ]
        checks_by_id = {
            "node-a": {
                "compatibility_supported": True, "ha_active": True,
                "time_synchronized": True,
                "tools": {"crm": True, "crm_mon": True, "corosync-cfgtool": True},
                "ssh_peer_connectivity": [{"host_name": "node-b", "reachable": True, "hosts_file_entry_present": True}],
                "cluster_configured": True, "cluster_detected": True,
                "cluster_name": "ha-lab", "cluster_members": ["node-a", "node-b"],
                "interfaces": [],
            },
            "node-b": {
                "compatibility_supported": True, "ha_active": True,
                "time_synchronized": True,
                "tools": {"crm": True, "crm_mon": True, "corosync-cfgtool": True},
                "ssh_peer_connectivity": [{"host_name": "node-a", "reachable": True, "hosts_file_entry_present": True}],
                "cluster_configured": True, "cluster_detected": True,
                "cluster_name": "ha-lab", "cluster_members": ["node-a", "node-b"],
                "interfaces": [],
            },
        }
        live_status = {
            "cluster_name": "ha-lab",
            "nodes": [{"name": "node-a", "online": True}, {"name": "node-b", "online": True}],
            "quorum": {"available": True, "quorate": True},
            "qdevice": {"available": True, "configured": False},
        }
        namespace = _validators
        namespace["cockpit_host_record"] = lambda host_id: {"id": host_id}

        def run_script(current, script, **_kwargs):
            value = live_status if script == "cluster-status-test-only" else checks_by_id[current["id"]]
            return json.dumps(value)

        namespace["run_sudo_python"] = run_script
        plan = {
            "name": "ha-lab", "host_ids": ["node-a", "node-b"],
            "config": {"quorum": "qdevice", "qnetd_host": "witness.example.test", "corosync_networks": []},
        }

        # A complete, quorate cluster with every planned member online is ready.
        cluster_bootstrap_preflight(plan, hosts, "qdevice", "node-a")

        checks_by_id["node-b"]["cluster_members"] = ["node-a", "node-b", "node-c"]
        with self.assertRaisesRegex(RuntimeError, "different live cluster membership"):
            cluster_bootstrap_preflight(plan, hosts, "qdevice", "node-a")
        checks_by_id["node-b"]["cluster_members"] = ["node-a", "node-b"]

        live_status["nodes"][1]["online"] = False
        with self.assertRaisesRegex(RuntimeError, "Every planned cluster node must be online"):
            cluster_bootstrap_preflight(plan, hosts, "qdevice", "node-a")
        live_status["nodes"][1]["online"] = True

        live_status["quorum"]["quorate"] = False
        with self.assertRaisesRegex(RuntimeError, "must have confirmed quorum"):
            cluster_bootstrap_preflight(plan, hosts, "qdevice", "node-a")
        live_status["quorum"]["quorate"] = True

        live_status["qdevice"]["available"] = False
        with self.assertRaisesRegex(RuntimeError, "could not confirm whether QDevice is already configured"):
            cluster_bootstrap_preflight(plan, hosts, "qdevice", "node-a")
        live_status["qdevice"]["available"] = True

        live_status["qdevice"]["configured"] = True
        with self.assertRaisesRegex(RuntimeError, "QDevice is already configured"):
            cluster_bootstrap_preflight(plan, hosts, "qdevice", "node-a")


if __name__ == "__main__":
    unittest.main()

"""Isolated tests for the remote HA preflight script (standard library only)."""

from __future__ import annotations

import ast
import contextlib
import io
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


SERVICE_SOURCE = Path(__file__).resolve().parents[1] / "app.py"


def remote_preflight_script() -> str:
    tree = ast.parse(SERVICE_SOURCE.read_text())
    supported = next(
        ast.literal_eval(node.value.args[0])
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "SUPPORTED_SLES_HA_RELEASES" for target in node.targets)
    )
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "HA_PREFLIGHT_SCRIPT"
            for target in node.targets
        ):
            script = ast.literal_eval(node.value)
            renderer = next(
                item for item in tree.body
                if isinstance(item, ast.FunctionDef) and item.name == "render_sles_release_script"
            )
            namespace = {"SUPPORTED_SLES_HA_RELEASES": supported}
            exec(compile(ast.Module(body=[renderer], type_ignores=[]), str(SERVICE_SOURCE), "exec"), namespace)
            return namespace["render_sles_release_script"](script)
    raise AssertionError("HA_PREFLIGHT_SCRIPT was not found in service/app.py")


class HaPreflightScriptTests(unittest.TestCase):
    def run_watchdog_preflight(self, watchdog_result, payload=None, watchdog_driver="iTCO_wdt", watchdog_paths=("/dev/watchdog0",)):
        def fake_open(path, *args, **kwargs):
            if path == "/etc/hosts": return io.StringIO("127.0.0.1 localhost\n")
            if path == "/etc/os-release": return io.StringIO('ID="sles"\nVERSION_ID="16.1"\n')
            if path.endswith("/identity"): return io.StringIO("Intel TCO Watchdog\n")
            raise FileNotFoundError(path)

        def fake_run(command, **_kwargs):
            if command[:2] == ["rpm", "-q"]:
                return SimpleNamespace(returncode=0, stdout="installed", stderr="")
            if command[0] == "SUSEConnect":
                return SimpleNamespace(returncode=0, stdout=("SLE HA 16.1 (Activated)\nDeactivate with: SUSEConnect -d -p sle-ha/16.1/x86_64\n"), stderr="")
            if command[:2] == ["timedatectl", "show"]: return SimpleNamespace(returncode=0, stdout="yes\n", stderr="")
            if command[:2] == ["ip", "-j"]: return SimpleNamespace(returncode=0, stdout="[]", stderr="")
            if command[:2] == ["virsh", "-c"]: return SimpleNamespace(returncode=0, stdout="", stderr="")
            if command[0] == "crm_mon": return SimpleNamespace(returncode=1, stdout="", stderr="cluster not configured")
            if command == ["sbd", "query-watchdog"]: return watchdog_result
            if command[:2] == ["systemctl", "show"]: return SimpleNamespace(returncode=0, stdout="not-found\n", stderr="")
            if command[:2] == ["systemctl", "is-active"]: return SimpleNamespace(returncode=3, stdout="inactive\n", stderr="")
            return SimpleNamespace(returncode=1, stdout="", stderr="not available")

        output = io.StringIO()
        with patch("shutil.which", return_value="/usr/bin/mock"), \
             patch("subprocess.run", side_effect=fake_run), \
             patch("builtins.open", side_effect=fake_open), \
                 patch("glob.glob", side_effect=lambda path: {
                 "/dev/watchdog*": list(watchdog_paths),
                 "/usr/lib/ocf/resource.d/heartbeat/*": ["/usr/lib/ocf/resource.d/heartbeat/Filesystem", "/usr/lib/ocf/resource.d/heartbeat/exportfs", "/usr/lib/ocf/resource.d/heartbeat/nfsserver", "/usr/lib/ocf/resource.d/heartbeat/IPaddr2"],
                 "/usr/lib/ocf/resource.d/linbit/*": ["/usr/lib/ocf/resource.d/linbit/drbd"],
             }.get(path, [])), \
             patch("os.path.islink", side_effect=lambda path: path.endswith("/device/driver")), \
             patch("os.path.realpath", return_value=f"/sys/bus/platform/drivers/{watchdog_driver}"), \
             patch("os.path.exists", return_value=True), \
             patch("os.path.isfile", side_effect=lambda path: "/usr/lib/ocf/resource.d/" in path), \
             patch("os.access", return_value=True), \
             patch("socket.create_connection", side_effect=OSError("not reachable")), \
             patch.object(sys, "argv", ["ha-preflight", json.dumps(payload or {})]), \
             contextlib.redirect_stdout(output):
            exec(compile(remote_preflight_script(), "<ha-preflight>", "exec"), {"__name__": "__main__"})
        return json.loads(output.getvalue())

    def test_queries_watchdog_availability_without_running_rebooting_watchdog_test(self):
        checks = self.run_watchdog_preflight(SimpleNamespace(returncode=0, stdout="Watchdog available: /dev/watchdog0", stderr=""))
        self.assertEqual(checks["watchdog_query"], {"available": True, "ok": True, "summary": "Watchdog available: /dev/watchdog0", "device_path": "/dev/watchdog0"})
        self.assertEqual(checks["watchdog_details"], [{"path": "/dev/watchdog0", "driver": "iTCO_wdt", "identity": "Intel TCO Watchdog"}])

    def test_reports_softdog_driver_without_claiming_hardware_fencing(self):
        checks = self.run_watchdog_preflight(SimpleNamespace(returncode=0, stdout="Watchdog available: /dev/watchdog0", stderr=""), watchdog_driver="softdog")
        self.assertEqual(checks["watchdog_details"][0]["driver"], "softdog")

    def test_does_not_guess_selected_watchdog_when_query_output_is_ambiguous(self):
        result = SimpleNamespace(returncode=0, stdout="Available: /dev/watchdog0, /dev/watchdog1", stderr="")
        checks = self.run_watchdog_preflight(result, watchdog_paths=("/dev/watchdog0", "/dev/watchdog1"))
        self.assertEqual(checks["watchdog_query"]["device_path"], "")

    def test_detects_linbit_drbd_resource_agent_for_suse_ha_nfs_profile(self):
        checks = self.run_watchdog_preflight(SimpleNamespace(returncode=0, stdout="", stderr=""))
        self.assertIn("linbit:drbd", checks["resource_agents"])
        self.assertIn("heartbeat:Filesystem", checks["resource_agents"])

    def test_watchdog_query_failure_is_reported_without_claiming_availability(self):
        checks = self.run_watchdog_preflight(SimpleNamespace(returncode=1, stdout="", stderr="No watchdog device found"))
        self.assertTrue(checks["watchdog_query"]["available"])
        self.assertFalse(checks["watchdog_query"]["ok"])
        self.assertEqual(checks["watchdog_query"]["summary"], "No watchdog device found")

    def test_qdevice_and_qnetd_packages_are_checked_only_when_qdevice_plan_requests_them(self):
        checks = self.run_watchdog_preflight(
            SimpleNamespace(returncode=0, stdout="", stderr=""),
            {"qnetd_host": "witness.example.test", "check_qnetd_package": True},
        )
        self.assertTrue(checks["qdevice_package_installed"])
        self.assertTrue(checks["qnetd_package_installed"])

    def test_reports_subnets_and_flags_a_dynamically_assigned_registered_address(self) -> None:
        address_json = [
            {"ifname": "lo", "flags": ["UP", "LOOPBACK"], "addr_info": [{"local": "127.0.0.1", "prefixlen": 8, "scope": "host"}]},
            {"ifname": "bond0.100", "flags": ["UP", "LOWER_UP"], "addr_info": [
                {"local": "10.20.0.11", "prefixlen": 24, "scope": "global"},
                {"local": "10.20.0.12", "prefixlen": 24, "scope": "global", "flags": ["dynamic"]},
                {"local": "169.254.1.4", "prefixlen": 16, "scope": "link"},
                {"local": "10.20.0.12", "prefixlen": 24, "scope": "global", "flags": ["deprecated"]},
            ]},
            {"ifname": "eth-down", "flags": ["NO-CARRIER"], "addr_info": [{"local": "192.0.2.5", "prefixlen": 24, "scope": "global"}]},
        ]

        def fake_open(path, *args, **kwargs):
            if path == "/etc/hosts":
                return io.StringIO("127.0.0.1 localhost\n")
            if path == "/etc/os-release":
                return io.StringIO('ID="sles"\nVERSION_ID="15.6"\n')
            raise FileNotFoundError(path)

        def fake_run(command, **_kwargs):
            if command[0] == "SUSEConnect":
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            if command[:2] == ["timedatectl", "show"]:
                return SimpleNamespace(returncode=0, stdout="yes\n", stderr="")
            if command[:2] == ["ip", "-j"]:
                return SimpleNamespace(returncode=0, stdout=json.dumps(address_json), stderr="")
            if command[:2] == ["virsh", "-c"]:
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            if command[0] == "crm_mon":
                return SimpleNamespace(returncode=1, stdout="", stderr="not configured")
            if command[:2] == ["systemctl", "show"]:
                return SimpleNamespace(returncode=0, stdout="not-found\n", stderr="")
            if command[:2] == ["systemctl", "is-active"]:
                return SimpleNamespace(returncode=3, stdout="inactive\n", stderr="")
            return SimpleNamespace(returncode=1, stdout="", stderr="not available")

        output = io.StringIO()
        with patch("shutil.which", return_value="/usr/bin/mock"), \
             patch("subprocess.run", side_effect=fake_run), \
             patch("os.path.isfile", return_value=False), \
             patch.object(sys, "argv", ["ha-preflight", json.dumps({"registered_address": "10.20.0.12"})]), \
             contextlib.redirect_stdout(output):
            exec(compile(remote_preflight_script(), "<ha-preflight>", "exec"), {"__name__": "__main__", "open": fake_open})

        interfaces = json.loads(output.getvalue())["interfaces"]
        self.assertEqual(interfaces, [{"name": "bond0.100", "addresses": ["10.20.0.11", "10.20.0.12"], "dynamic_addresses": ["10.20.0.12"], "dynamic_subnets": ["10.20.0.0/24"], "subnets": ["10.20.0.0/24"]}])
        self.assertTrue(json.loads(output.getvalue())["registered_address_is_dynamic"])

    def test_does_not_call_an_unmatched_registered_address_static(self) -> None:
        address_json = [{"ifname": "eth0", "flags": ["UP"], "addr_info": [{"local": "192.0.2.10", "prefixlen": 24, "scope": "global"}]}]

        def fake_open(path, *args, **kwargs):
            if path == "/etc/hosts": return io.StringIO("127.0.0.1 localhost\n")
            if path == "/etc/os-release": return io.StringIO('ID="sles"\nVERSION_ID="15.6"\n')
            raise FileNotFoundError(path)

        def fake_run(command, **_kwargs):
            if command[0] == "SUSEConnect": return SimpleNamespace(returncode=0, stdout="", stderr="")
            if command[:2] == ["timedatectl", "show"]: return SimpleNamespace(returncode=0, stdout="yes\n", stderr="")
            if command[:2] == ["ip", "-j"]: return SimpleNamespace(returncode=0, stdout=json.dumps(address_json), stderr="")
            if command[:2] == ["virsh", "-c"]: return SimpleNamespace(returncode=0, stdout="", stderr="")
            if command[0] == "crm_mon": return SimpleNamespace(returncode=1, stdout="", stderr="not configured")
            if command[:2] == ["systemctl", "show"]: return SimpleNamespace(returncode=0, stdout="not-found\n", stderr="")
            if command[:2] == ["systemctl", "is-active"]: return SimpleNamespace(returncode=3, stdout="inactive\n", stderr="")
            return SimpleNamespace(returncode=1, stdout="", stderr="not available")

        output = io.StringIO()
        with patch("shutil.which", return_value="/usr/bin/mock"), \
             patch("subprocess.run", side_effect=fake_run), \
             patch("os.path.isfile", return_value=False), \
             patch.object(sys, "argv", ["ha-preflight", json.dumps({"registered_address": "192.0.2.99"})]), \
             contextlib.redirect_stdout(output):
            exec(compile(remote_preflight_script(), "<ha-preflight>", "exec"), {"__name__": "__main__", "open": fake_open})

        self.assertIsNone(json.loads(output.getvalue())["registered_address_is_dynamic"])

    def test_installed_but_inactive_workload_units_are_available_for_pacemaker(self) -> None:
        def fake_run(command, **_kwargs):
            if command[0] == "SUSEConnect":
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            if command[:2] == ["timedatectl", "show"]:
                return SimpleNamespace(returncode=0, stdout="yes\n", stderr="")
            if command[:2] == ["ip", "-j"]:
                return SimpleNamespace(returncode=0, stdout="[]", stderr="")
            if command[:2] == ["virsh", "-c"]:
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            if command[0] == "crm_mon":
                return SimpleNamespace(returncode=1, stdout="", stderr="not configured")
            if command[:2] == ["systemctl", "show"]:
                return SimpleNamespace(returncode=0, stdout="loaded\n", stderr="")
            if command[:2] == ["systemctl", "is-active"]:
                unit = command[-1]
                if unit in {"apache2.service", "nfsserver.service", "nfs-server.service"}:
                    return SimpleNamespace(returncode=3, stdout="inactive\n", stderr="")
                return SimpleNamespace(returncode=0, stdout="active\n", stderr="")
            return SimpleNamespace(returncode=1, stdout="", stderr="not available")

        output = io.StringIO()
        with patch("shutil.which", return_value="/usr/bin/mock"), \
             patch("subprocess.run", side_effect=fake_run), \
             patch("os.path.isfile", return_value=False), \
             patch.object(sys, "argv", ["ha-preflight", "{}"]), \
             contextlib.redirect_stdout(output):
            exec(compile(remote_preflight_script(), "<ha-preflight>", "exec"), {"__name__": "__main__"})

        checks = json.loads(output.getvalue())
        for service in ("apache2", "nfsserver"):
            self.assertEqual(checks["workload_service_units"][service]["installed"], True)
            self.assertEqual(checks["workload_service_units"][service]["active"], "inactive")
            self.assertFalse(checks["workload_services"][service])

    def test_reports_the_active_sle_ha_product_identifier(self) -> None:
        def fake_open(path, *args, **kwargs):
            if path == "/etc/os-release":
                return io.StringIO('ID="sles"\nVERSION_ID="16.1"\nPRETTY_NAME="SUSE Linux Enterprise Server 16.1"\n')
            raise FileNotFoundError(path)

        def fake_run(command, **_kwargs):
            if command[0] == "SUSEConnect":
                return SimpleNamespace(returncode=0, stdout=(
                    "SLE HA 16.1 (Activated)\n"
                    "Deactivate with: SUSEConnect -d -p sle-ha/16.1/x86_64\n"
                ), stderr="")
            if command[:2] == ["timedatectl", "show"]:
                return SimpleNamespace(returncode=0, stdout="yes\n", stderr="")
            if command[:2] == ["ip", "-j"]:
                return SimpleNamespace(returncode=0, stdout="[]", stderr="")
            if command[:2] == ["virsh", "-c"]:
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            if command[0] == "crm_mon":
                return SimpleNamespace(returncode=1, stdout="", stderr="not configured")
            if command[:2] == ["systemctl", "show"]:
                return SimpleNamespace(returncode=0, stdout="not-found\n", stderr="")
            return SimpleNamespace(returncode=1, stdout="not available", stderr="")

        output = io.StringIO()
        with patch("shutil.which", return_value="/usr/bin/mock"), \
             patch("subprocess.run", side_effect=fake_run), \
             patch("os.path.isfile", return_value=False), \
             patch.object(sys, "argv", ["ha-preflight", "{}"]), \
             contextlib.redirect_stdout(output):
            exec(compile(remote_preflight_script(), "<ha-preflight>", "exec"), {"__name__": "__main__", "open": fake_open})

        checks = json.loads(output.getvalue())
        self.assertTrue(checks["ha_active"])
        self.assertTrue(checks["compatibility_supported"])
        self.assertEqual(checks["ha_product"], "sle-ha/16.1/x86_64")

    def test_available_but_inactive_sle_ha_product_is_not_reported_active(self) -> None:
        def fake_open(path, *args, **kwargs):
            if path == "/etc/os-release":
                return io.StringIO('ID="sles"\nVERSION_ID="15.6"\nPRETTY_NAME="SLES 15 SP6"\n')
            raise FileNotFoundError(path)

        def fake_run(command, **_kwargs):
            if command[0] == "SUSEConnect":
                return SimpleNamespace(returncode=0, stdout=(
                    "SLE HA 15 SP6\n"
                    "Activate with: SUSEConnect -p sle-ha/15.6/x86_64\n"
                ), stderr="")
            if command[:2] == ["timedatectl", "show"]:
                return SimpleNamespace(returncode=0, stdout="yes\n", stderr="")
            if command[:2] == ["ip", "-j"]:
                return SimpleNamespace(returncode=0, stdout="[]", stderr="")
            if command[:2] == ["virsh", "-c"]:
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            if command[0] == "crm_mon":
                return SimpleNamespace(returncode=1, stdout="", stderr="not configured")
            if command[:2] == ["systemctl", "show"]:
                return SimpleNamespace(returncode=0, stdout="not-found\n", stderr="")
            return SimpleNamespace(returncode=1, stdout="not available", stderr="")

        output = io.StringIO()
        with patch("shutil.which", return_value="/usr/bin/mock"), \
             patch("subprocess.run", side_effect=fake_run), \
             patch("os.path.isfile", return_value=False), \
             patch.object(sys, "argv", ["ha-preflight", "{}"]), \
             contextlib.redirect_stdout(output):
            exec(compile(remote_preflight_script(), "<ha-preflight>", "exec"), {"__name__": "__main__", "open": fake_open})

        checks = json.loads(output.getvalue())
        self.assertFalse(checks["ha_active"])
        self.assertEqual(checks["ha_product"], "")

    def test_peer_check_reports_static_hosts_file_name_entry(self) -> None:
        def fake_open(path, *args, **kwargs):
            if path == "/etc/hosts":
                return io.StringIO("127.0.0.1 localhost\n192.0.2.42 node-b.example.test node-b\n")
            if path == "/etc/os-release":
                return io.StringIO('ID="sles"\nVERSION_ID="16.0"\nPRETTY_NAME="SLES"\n')
            raise FileNotFoundError(path)

        def fake_run(command, **_kwargs):
            if command[:2] == ["timedatectl", "show"]:
                return SimpleNamespace(returncode=0, stdout="yes\n", stderr="")
            if command[:2] == ["ip", "-j"]:
                return SimpleNamespace(returncode=0, stdout="[]", stderr="")
            if command[:2] == ["virsh", "-c"]:
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            if command[0] == "crm_mon":
                return SimpleNamespace(returncode=1, stdout="", stderr="not configured")
            if command[:2] == ["systemctl", "show"]:
                return SimpleNamespace(returncode=0, stdout="not-found\n", stderr="")
            return SimpleNamespace(returncode=1, stdout="", stderr="not available")

        request = {"peers": [{"host_name": "node-b.example.test", "address": "192.0.2.42", "port": 22}]}
        output = io.StringIO()
        with patch("shutil.which", return_value="/usr/bin/mock"), \
             patch("subprocess.run", side_effect=fake_run), \
             patch("socket.create_connection", return_value=contextlib.nullcontext()), \
             patch("os.path.isfile", return_value=False), \
             patch.object(sys, "argv", ["ha-preflight", json.dumps(request)]), \
             contextlib.redirect_stdout(output):
            exec(compile(remote_preflight_script(), "<ha-preflight>", "exec"), {"__name__": "__main__", "open": fake_open})

        peer = json.loads(output.getvalue())["ssh_peer_connectivity"][0]
        self.assertTrue(peer["reachable"])
        self.assertTrue(peer["hosts_file_entry_present"])
        self.assertTrue(peer["short_name_entry_present"])
        self.assertEqual(peer["hosts_file_addresses"], ["192.0.2.42"])
        self.assertTrue(peer["hosts_file_address_matches_ssh_address"])

    def test_peer_check_warns_when_hosts_file_address_differs_from_ssh_address(self) -> None:
        def fake_open(path, *args, **kwargs):
            if path == "/etc/hosts":
                return io.StringIO("192.0.2.99 node-b.example.test node-b\n")
            if path == "/etc/os-release":
                return io.StringIO('ID="sles"\nVERSION_ID="15.7"\n')
            raise FileNotFoundError(path)

        def fake_run(command, **_kwargs):
            if command[:2] == ["timedatectl", "show"]:
                return SimpleNamespace(returncode=0, stdout="yes\n", stderr="")
            if command[:2] == ["ip", "-j"]:
                return SimpleNamespace(returncode=0, stdout="[]", stderr="")
            if command[:2] == ["virsh", "-c"]:
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            if command[0] == "crm_mon":
                return SimpleNamespace(returncode=1, stdout="", stderr="not configured")
            if command[:2] == ["systemctl", "show"]:
                return SimpleNamespace(returncode=0, stdout="not-found\n", stderr="")
            return SimpleNamespace(returncode=1, stdout="not available", stderr="")

        request = {"peers": [{"host_name": "node-b.example.test", "address": "192.0.2.42", "port": 22}]}
        output = io.StringIO()
        with patch("shutil.which", return_value="/usr/bin/mock"), \
             patch("subprocess.run", side_effect=fake_run), \
             patch("socket.create_connection", return_value=contextlib.nullcontext()), \
             patch("os.path.isfile", return_value=False), \
             patch.object(sys, "argv", ["ha-preflight", json.dumps(request)]), \
             contextlib.redirect_stdout(output):
            exec(compile(remote_preflight_script(), "<ha-preflight>", "exec"), {"__name__": "__main__", "open": fake_open})

        peer = json.loads(output.getvalue())["ssh_peer_connectivity"][0]
        self.assertTrue(peer["hosts_file_entry_present"])
        self.assertFalse(peer["hosts_file_address_matches_ssh_address"])
        self.assertEqual(peer["hosts_file_addresses"], ["192.0.2.99"])


if __name__ == "__main__":
    unittest.main()

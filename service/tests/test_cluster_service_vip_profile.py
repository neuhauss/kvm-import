"""Safety and rendering tests for the guided SUSE service/VIP profile."""

from __future__ import annotations

import ast
import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


APP = Path(__file__).resolve().parents[1] / "app.py"


def service_vip_script() -> str:
    for node in ast.parse(APP.read_text()).body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "HA_SERVICE_VIP_CONFIG_SCRIPT"
            for target in node.targets
        ):
            return ast.literal_eval(node.value)
    raise AssertionError("HA_SERVICE_VIP_CONFIG_SCRIPT was not found")


class ServiceVipProfileTests(unittest.TestCase):
    def execute(self, payload, *, cib=None, unit_installed=True, service_active=False, service_enabled=False,
                apache_valid=True, route=True, duplicate_vip=False, service_agent=True, apache_agent=True, ip_agent=True):
        commands = []
        applied = []
        existing = '[{"addr_info":[{"local":"192.0.2.50"}]}]' if duplicate_vip else "[]"

        def fake_run(command, **_kwargs):
            commands.append(command)
            if command[:2] == ["systemctl", "cat"]:
                return SimpleNamespace(returncode=0 if unit_installed else 1, stdout="[Service]\n" if unit_installed else "", stderr="")
            if command[:3] == ["systemctl", "is-active", "--quiet"]:
                return SimpleNamespace(returncode=0 if service_active else 3, stdout="", stderr="")
            if command[:3] == ["systemctl", "is-enabled", "--quiet"]:
                return SimpleNamespace(returncode=0 if service_enabled else 1, stdout="", stderr="")
            if command[:3] == ["crm", "ra", "info"]:
                available = service_agent if command[3].startswith("service:") else apache_agent if command[3] == "ocf:heartbeat:apache" else ip_agent
                return SimpleNamespace(returncode=0 if available else 1, stdout="resource agent details" if available else "missing agent", stderr="")
            if command and command[0] == "/usr/sbin/apachectl":
                return SimpleNamespace(returncode=0 if apache_valid else 1, stdout="Syntax OK" if apache_valid else "Syntax error", stderr="")
            if command[:4] == ["ip", "-j", "address", "show"]:
                return SimpleNamespace(returncode=0, stdout=existing, stderr="")
            if command[:4] == ["ip", "-j", "route", "get"]:
                data = '[{"dst":"192.0.2.50","dev":"eth0","prefsrc":"192.0.2.2"}]' if route else "[]"
                return SimpleNamespace(returncode=0 if route else 2, stdout=data, stderr="no route")
            if command == ["cibadmin", "-Q"]:
                return SimpleNamespace(returncode=0, stdout=cib or '<cib><configuration><crm_config/><resources/><constraints/></configuration></cib>', stderr="")
            if command[:4] == ["crm", "configure", "load", "update"]:
                applied.append(Path(command[-1]).read_text())
                return SimpleNamespace(returncode=0, stdout="updated", stderr="")
            return SimpleNamespace(returncode=1, stdout="", stderr="unexpected command")

        output = io.StringIO()
        with patch("subprocess.run", side_effect=fake_run), \
             patch("shutil.which", return_value="/usr/sbin/apachectl"), \
             patch.object(sys, "stdin", io.StringIO(json.dumps(payload))), \
             contextlib.redirect_stdout(output):
            try:
                exec(compile(service_vip_script(), "<ha-service-vip>", "exec"), {"__name__": "__main__"})
            except SystemExit as exc:
                if exc.code not in (None, 0):
                    raise
        return json.loads(output.getvalue()), commands, applied

    def payload(self, **overrides):
        return {
            "resource_prefix": "portal", "service_unit": "apache2.service",
            "virtual_ip": "192.0.2.50", "cidr_netmask": 24,
            "shared_network_confirmed": True, **overrides,
        }

    def test_preflight_validates_every_node_without_changing_cib(self):
        result, commands, applied = self.execute(self.payload(preflight_only=True))
        self.assertTrue(result["success"])
        self.assertEqual(result["route_device"], "eth0")
        self.assertFalse(applied)
        self.assertFalse(any(command[:2] == ["crm", "configure"] for command in commands))
        self.assertFalse(any(command == ["cibadmin", "-Q"] for command in commands))

    def test_profile_creates_vip_before_service_and_remains_stopped(self):
        result, _commands, applied = self.execute(self.payload())
        self.assertTrue(result["success"])
        self.assertEqual(len(applied), 1)
        config = applied[0]
        self.assertIn('primitive vip-portal ocf:heartbeat:IPaddr2 params ip="192.0.2.50" cidr_netmask=24', config)
        self.assertIn('primitive service-portal service:apache2.service', config)
        self.assertIn('group g-portal vip-portal service-portal meta target-role="Stopped"', config)
        self.assertLess(config.index("primitive vip-portal"), config.index("primitive service-portal"))

    def test_profile_rejects_service_not_installed_or_active_outside_pacemaker(self):
        with self.assertRaisesRegex(SystemExit, "not installed"):
            self.execute(self.payload(), unit_installed=False)
        with self.assertRaisesRegex(SystemExit, "active outside"):
            self.execute(self.payload(), service_active=True)

    def test_profile_rejects_missing_agent_or_client_network_route(self):
        with self.assertRaisesRegex(SystemExit, "service:apache2.service"):
            self.execute(self.payload(), service_agent=False)
        with self.assertRaisesRegex(SystemExit, "No usable host route"):
            self.execute(self.payload(), route=False)

    def test_profile_rejects_duplicate_vip_disabled_fencing_and_resource_id_collision(self):
        with self.assertRaisesRegex(SystemExit, "already assigned"):
            self.execute(self.payload(), duplicate_vip=True)
        cib_disabled = ('<cib><configuration><crm_config><cluster_property_set id="properties">'
                        '<nvpair id="stonith" name="stonith-enabled" value="false"/>'
                        '</cluster_property_set></crm_config><resources/><constraints/></configuration></cib>')
        with self.assertRaisesRegex(SystemExit, "stonith-enabled disabled"):
            self.execute(self.payload(), cib=cib_disabled)
        cib_collision = '<cib><configuration><crm_config/><resources><primitive id="vip-portal"/></resources><constraints/></configuration></cib>'
        with self.assertRaisesRegex(SystemExit, "IDs already exist"):
            self.execute(self.payload(), cib=cib_collision)

    def test_profile_rejects_unconfirmed_network_and_invalid_unit(self):
        with self.assertRaisesRegex(SystemExit, "Confirm that the virtual IP"):
            self.execute(self.payload(shared_network_confirmed=False))
        with self.assertRaisesRegex(SystemExit, "systemd service unit"):
            self.execute(self.payload(service_unit="apache2.service;touch /tmp/pwned"))

    def test_suse_apache_profile_checks_config_and_creates_stopped_group_in_documented_order(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".conf") as config:
            config.write("ServerName web.example.test\n")
            config.flush()
            payload = self.payload(profile="apache", apache_configfile=config.name,
                                   apache_start_order_confirmed=True)
            result, commands, applied = self.execute(payload)

        self.assertTrue(result["success"])
        self.assertEqual(len(result["configuration_sha256"]), 64)
        self.assertTrue(any(command[0] == "/usr/sbin/apachectl" and command[1:3] == ["-t", "-f"] for command in commands))
        config = applied[0]
        self.assertIn('primitive service-portal apache params configfile=', config)
        self.assertIn('primitive vip-portal ocf:heartbeat:IPaddr params ip="192.0.2.50" cidr_netmask=24', config)
        self.assertIn('group g-portal service-portal vip-portal meta target-role="Stopped"', config)

    def test_apache_profile_requires_explicit_order_confirmation_and_disabled_boot_unit(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".conf") as config:
            config.write("ServerName web.example.test\n")
            config.flush()
            with self.assertRaisesRegex(SystemExit, "Confirm Apache can start before the VIP"):
                self.execute(self.payload(profile="apache", apache_configfile=config.name))
            with self.assertRaisesRegex(SystemExit, "Disable its standalone boot activation"):
                self.execute(self.payload(profile="apache", apache_configfile=config.name,
                                          apache_start_order_confirmed=True), service_enabled=True)

    def test_apache_profile_requires_agent_and_valid_configuration(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".conf") as config:
            config.write("ServerName web.example.test\n")
            config.flush()
            payload = self.payload(profile="apache", apache_configfile=config.name,
                                   apache_start_order_confirmed=True)
            with self.assertRaisesRegex(SystemExit, "ocf:heartbeat:apache"):
                self.execute(payload, apache_agent=False)
            with self.assertRaisesRegex(SystemExit, "Apache configuration validation failed"):
                self.execute(payload, apache_valid=False)

    def test_apache_profile_rejects_configuration_changed_after_preflight(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".conf") as config:
            config.write("ServerName web.example.test\n")
            config.flush()
            payload = self.payload(profile="apache", apache_configfile=config.name,
                                   apache_start_order_confirmed=True,
                                   expected_configuration_sha256="0" * 64)
            with self.assertRaisesRegex(SystemExit, "changed after the all-node preflight"):
                self.execute(payload)


if __name__ == "__main__":
    unittest.main()

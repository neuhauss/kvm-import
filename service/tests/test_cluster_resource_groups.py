"""Focused tests for the extension's SUSE crmsh group-management script."""

from __future__ import annotations

import ast
import contextlib
import io
import json
import sys
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


SERVICE_SOURCE = Path(__file__).resolve().parents[1] / "app.py"


def remote_group_script() -> str:
    tree = ast.parse(SERVICE_SOURCE.read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "HA_RESOURCE_MUTATION_SCRIPT"
            for target in node.targets
        ):
            return ast.literal_eval(node.value)
    raise AssertionError("HA_RESOURCE_MUTATION_SCRIPT was not found in service/app.py")


def remote_status_script() -> str:
    tree = ast.parse(SERVICE_SOURCE.read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "HA_CLUSTER_STATUS_SCRIPT"
            for target in node.targets
        ):
            return ast.literal_eval(node.value)
    raise AssertionError("HA_CLUSTER_STATUS_SCRIPT was not found in service/app.py")


def remote_fencing_agents_script() -> str:
    tree = ast.parse(SERVICE_SOURCE.read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "HA_STONITH_AGENTS_SCRIPT"
            for target in node.targets
        ):
            return ast.literal_eval(node.value)
    raise AssertionError("HA_STONITH_AGENTS_SCRIPT was not found in service/app.py")


class ClusterResourceGroupTests(unittest.TestCase):
    def execute(self, payload, resources_xml, status_xml="<crm_mon><resources/></crm_mon>", current_cib_xml=None, crm_error=None):
        commands = []
        loaded_config = []
        loaded_xml = []
        current_cib_reads = list(current_cib_xml) if isinstance(current_cib_xml, list) else None

        def fake_run(command, **_kwargs):
            commands.append(command)
            if command == ["cibadmin", "-Q"]:
                current_resources = (current_cib_reads.pop(0) if current_cib_reads else current_cib_xml) or resources_xml
                current_cib = current_resources if current_resources.lstrip().startswith("<cib") else f"<cib admin_epoch=\"0\" epoch=\"1\" num_updates=\"2\" validate-with=\"pacemaker-3.10\"><configuration>{current_resources}</configuration></cib>"
                return SimpleNamespace(returncode=0, stdout=current_cib, stderr="")
            if command[:3] == ["cibadmin", "-Q", "-o"]:
                return SimpleNamespace(returncode=0, stdout=resources_xml, stderr="")
            if command[0] == "crm_mon":
                return SimpleNamespace(returncode=0, stdout=status_xml, stderr="")
            if command[:3] == ["crm", "ra", "info"]:
                return SimpleNamespace(returncode=0, stdout="Actions: start stop monitor promote demote notify", stderr="")
            if command[:4] == ["crm", "configure", "load", "update"]:
                loaded_config.append(Path(command[-1]).read_text())
                return SimpleNamespace(returncode=0, stdout="updated", stderr="")
            if command[:5] == ["crm", "configure", "load", "xml", "update"]:
                if crm_error:
                    return SimpleNamespace(returncode=1, stdout="", stderr=crm_error)
                loaded_xml.append(Path(command[-1]).read_text())
                return SimpleNamespace(returncode=0, stdout="updated", stderr="")
            if command[:2] == ["crm", "configure"]:
                return SimpleNamespace(returncode=0, stdout="updated", stderr="")
            return SimpleNamespace(returncode=1, stdout="", stderr="unexpected command")

        output = io.StringIO()
        with patch("subprocess.run", side_effect=fake_run), \
             patch.object(sys, "stdin", io.StringIO(json.dumps(payload))), \
             contextlib.redirect_stdout(output):
            exec(compile(remote_group_script(), "<ha-resource-mutation>", "exec"), {"__name__": "__main__"})
        return output.getvalue(), commands, loaded_config, loaded_xml

    def test_create_single_member_group_is_stopped_and_preserves_start_order(self):
        output, commands, loaded, _loaded_xml = self.execute(
            {"action": "create_group", "resource_id": "service-group", "children": ["service"]},
            '<resources><primitive id="service" class="ocf" provider="heartbeat" type="apache"/></resources>',
        )
        self.assertIn("created in Stopped state", output)
        self.assertEqual(len(loaded), 1)
        self.assertIn('group service-group service meta target-role="Stopped"', loaded[0])
        self.assertTrue(any(command[:4] == ["crm", "configure", "load", "update"] for command in commands))

    def test_create_primitive_adds_requested_monitor_operations_and_keeps_it_stopped(self):
        output, _commands, loaded, _loaded_xml = self.execute(
            {
                "action": "create",
                "resource_id": "replica",
                "agent": "ocf:heartbeat:Stateful",
                "parameters": {"state_dir": "/var/lib/replica"},
                "operations": [
                    {"interval": "30s", "role": "Unpromoted", "timeout": "10s"},
                    {"interval": "60s", "role": "Promoted"},
                    {"interval": "0", "role": "Stopped", "timeout": "20s"},
                ],
            },
            "<resources/>",
        )
        self.assertIn("created in Stopped state", output)
        self.assertEqual(len(loaded), 1)
        self.assertIn('op monitor interval=30s role=Unpromoted timeout=10s', loaded[0])
        self.assertIn('op monitor interval=60s role=Promoted', loaded[0])
        self.assertIn('op monitor interval=0 role=Stopped timeout=20s', loaded[0])
        self.assertIn('meta target-role="Stopped"', loaded[0])

    def test_create_primitive_keeps_backward_compatible_default_monitor(self):
        _output, _commands, loaded, _loaded_xml = self.execute(
            {"action": "create", "resource_id": "service", "agent": "ocf:heartbeat:apache"},
            "<resources/>",
        )
        self.assertIn("op monitor interval=30s", loaded[0])

    def test_create_stonith_device_uses_current_node_mapping_and_leaves_it_stopped(self):
        output, commands, loaded, _loaded_xml = self.execute(
            {"action": "create_stonith", "resource_id": "fence-node-a", "agent": "stonith:fence_ipmilan",
             "fencing_target": "node-a", "parameters": {"ip": "192.0.2.20", "password": "secret"},
             "monitor_interval": "30min", "monitor_timeout": "120s"},
            "<resources/>",
            '<crm_mon><nodes><node name="node-a"/><node name="node-b"/></nodes><resources/></crm_mon>',
        )
        self.assertIn("created in Stopped state", output)
        self.assertEqual(len(loaded), 1)
        self.assertIn('primitive fence-node-a stonith:fence_ipmilan', loaded[0])
        self.assertIn('pcmk_host_list="node-a"', loaded[0])
        self.assertIn('password="secret"', loaded[0])
        self.assertIn('op monitor interval=30min timeout=120s', loaded[0])
        self.assertIn('meta target-role="Stopped"', loaded[0])
        self.assertIn(["crm", "ra", "info", "stonith:fence_ipmilan"], commands)

    def test_fencing_agent_discovery_returns_only_valid_suse_stonith_agent_names(self):
        output = io.StringIO()
        with patch("subprocess.run", return_value=SimpleNamespace(returncode=0, stdout="fence_ipmilan fence_rsa external/fence_rsa invalid/name/extra\n", stderr="")), contextlib.redirect_stdout(output):
            exec(compile(remote_fencing_agents_script(), "<ha-stonith-agents>", "exec"), {"__name__": "__main__"})
        self.assertEqual(json.loads(output.getvalue()), {"agents": ["stonith:external/fence_rsa", "stonith:fence_ipmilan", "stonith:fence_rsa"]})

    def test_create_stonith_rejects_stale_target_duplicate_mapping_and_reserved_mapping_fields(self):
        payload = {"action": "create_stonith", "resource_id": "fence-a", "agent": "stonith:fence_ipmilan",
                   "fencing_target": "node-old", "parameters": {"ip": "192.0.2.20"}}
        with self.assertRaises(SystemExit) as stale:
            self.execute(payload, "<resources/>", '<crm_mon><nodes><node name="node-a"/></nodes><resources/></crm_mon>')
        self.assertIn("no longer a member", str(stale.exception))

        payload["fencing_target"] = "node-a"
        payload["parameters"] = {"pcmk_host_list": "node-a"}
        with self.assertRaises(SystemExit) as reserved:
            self.execute(payload, "<resources/>", '<crm_mon><nodes><node name="node-a"/></nodes><resources/></crm_mon>')
        self.assertIn("sets the target-node mapping", str(reserved.exception))

        payload["parameters"] = {"ip": "192.0.2.20"}
        existing = '<resources><primitive id="existing-fence" class="stonith" type="fence_ipmilan"><instance_attributes id="existing-attrs"><nvpair id="host-list" name="pcmk_host_list" value="node-a"/></instance_attributes></primitive></resources>'
        with self.assertRaises(SystemExit) as duplicate:
            self.execute(payload, existing, '<crm_mon><nodes><node name="node-a"/></nodes><resources/></crm_mon>')
        self.assertIn("already targets this node", str(duplicate.exception))

    def test_delete_stonith_requires_stopped_top_level_device(self):
        resources = '<resources><primitive id="fence-a" class="stonith" type="fence_ipmilan"/></resources>'
        with self.assertRaises(SystemExit) as active:
            self.execute({"action": "delete_stonith", "resource_id": "fence-a"}, resources,
                         '<crm_mon><resources><resource id="fence-a" active="true"/></resources></crm_mon>')
        self.assertIn("Stop this fencing resource", str(active.exception))
        output, commands, _loaded, _loaded_xml = self.execute(
            {"action": "delete_stonith", "resource_id": "fence-a"}, resources,
            '<crm_mon><resources><resource id="fence-a" active="false" failed="false"/></resources></crm_mon>',
        )
        self.assertIn("Stopped fencing resource removed", output)
        self.assertIn(["crm", "configure", "delete", "fence-a"], commands)

    def test_delete_clone_removes_only_stopped_single_primitive_clone(self):
        resources = ('<resources><clone id="replica-clone"><primitive id="replica" class="ocf" '
                     'provider="heartbeat" type="Stateful"/></clone></resources>')
        status = ('<crm_mon><resources><resource id="replica-clone" active="false" failed="false"/>'
                  '<resource id="replica" active="false" failed="false"/></resources></crm_mon>')
        output, commands, _loaded, _loaded_xml = self.execute(
            {"action": "delete_clone", "resource_id": "replica-clone", "child_id": "replica"},
            resources, status,
        )
        self.assertIn("clone and its child primitive removed", output)
        self.assertIn(["crm", "configure", "delete", "replica-clone"], commands)

    def test_delete_clone_rejects_active_or_failed_child(self):
        resources = '<resources><clone id="replica-clone"><primitive id="replica" class="ocf" type="Stateful"/></clone></resources>'
        payload = {"action": "delete_clone", "resource_id": "replica-clone", "child_id": "replica"}
        with self.assertRaises(SystemExit) as active:
            self.execute(payload, resources,
                         '<crm_mon><resources><resource id="replica" active="true"/></resources></crm_mon>')
        self.assertIn("Stop every instance", str(active.exception))
        with self.assertRaises(SystemExit) as failed:
            self.execute(payload, resources,
                         '<crm_mon><resources><resource id="replica" active="false" failed="true"/></resources></crm_mon>')
        self.assertIn("Clean up failed", str(failed.exception))

    def test_delete_clone_rejects_wrapped_children_and_related_constraints(self):
        payload = {"action": "delete_clone", "resource_id": "replica-clone", "child_id": "replica"}
        nested = '<resources><clone id="replica-clone"><group id="replica-group"><primitive id="replica" class="ocf" type="Stateful"/></group></clone></resources>'
        with self.assertRaises(SystemExit) as wrapped:
            self.execute(payload, nested)
        self.assertIn("exactly one primitive", str(wrapped.exception))

        resources = '<resources><clone id="replica-clone"><primitive id="replica" class="ocf" type="Stateful"/></clone></resources>'
        cib = ('<cib><configuration>' + resources +
               '<constraints><rsc_order id="replica-before-vip" first="replica-clone" then="vip"/></constraints>' +
               '</configuration></cib>')
        with self.assertRaises(SystemExit) as constrained:
            self.execute(payload, resources, current_cib_xml=cib)
        self.assertIn("referenced by a Pacemaker constraint", str(constrained.exception))

    def test_delete_clone_rechecks_configuration_before_apply(self):
        resources = '<resources><clone id="replica-clone"><primitive id="replica" class="ocf" type="Stateful"/></clone></resources>'
        first_read = '<cib><configuration>' + resources + '<constraints/></configuration></cib>'
        second_read = ('<cib><configuration>' + resources +
                       '<constraints><rsc_location id="new-location" rsc="replica" node="node-a" score="INFINITY"/>'
                       '</constraints></configuration></cib>')
        with self.assertRaises(SystemExit) as stale:
            self.execute(
                {"action": "delete_clone", "resource_id": "replica-clone", "child_id": "replica"},
                resources,
                current_cib_xml=[first_read, second_read],
            )
        self.assertIn("changed while this form was open", str(stale.exception))

    def test_edit_stonith_updates_and_removes_parameters_without_returning_values(self):
        resources = ('<resources><primitive id="fence-a" class="stonith" type="fence_ipmilan">'
                     '<instance_attributes id="fence-a-params"><nvpair id="host-list" name="pcmk_host_list" value="node-a"/>'
                     '<nvpair id="ip" name="ip" value="192.0.2.20"/><nvpair id="password" name="password" value="old-secret"/></instance_attributes>'
                     '<operations id="fence-a-operations"><op id="fence-a-monitor" name="monitor" interval="30min" timeout="120s"/></operations>'
                     '<meta_attributes id="fence-a-meta"><nvpair id="stopped" name="target-role" value="Stopped"/></meta_attributes></primitive></resources>')
        payload = {"action": "edit_stonith", "resource_id": "fence-a", "agent": "stonith:fence_ipmilan",
                   "fencing_target": "node-a", "parameters": {"password": "new-secret", "lanplus": "1"},
                   "parameter_removals": ["ip"]}
        output, commands, _loaded, loaded_xml = self.execute(
            payload, resources,
            '<crm_mon><nodes><node name="node-a"/><node name="node-b"/></nodes><resources><resource id="fence-a" active="false" failed="false"/></resources></crm_mon>',
            current_cib_xml=resources,
        )
        self.assertIn("parameters updated", output)
        self.assertNotIn("new-secret", output)
        self.assertNotIn("old-secret", output)
        self.assertEqual(len(loaded_xml), 1)
        cib = ET.fromstring(loaded_xml[0])
        primitive = cib.find("./configuration/resources/primitive")
        values = {item.get("name"): item.get("value") for item in primitive.findall("./instance_attributes/nvpair")}
        self.assertEqual(values["pcmk_host_list"], "node-a")
        self.assertEqual(values["password"], "new-secret")
        self.assertEqual(values["lanplus"], "1")
        self.assertNotIn("ip", values)
        self.assertEqual(primitive.find("./operations/op").get("timeout"), "120s")
        self.assertEqual(primitive.find("./meta_attributes/nvpair").get("value"), "Stopped")
        self.assertIn(["crm", "configure", "load", "xml", "update", commands[-1][-1]], commands)

    def test_edit_stonith_rejects_active_resource_and_target_mapping_changes(self):
        resources = ('<resources><primitive id="fence-a" class="stonith" type="fence_ipmilan">'
                     '<instance_attributes id="fence-a-params"><nvpair id="host-list" name="pcmk_host_list" value="node-a"/>'
                     '<nvpair id="password" name="password" value="secret"/></instance_attributes></primitive></resources>')
        payload = {"action": "edit_stonith", "resource_id": "fence-a", "agent": "stonith:fence_ipmilan",
                   "fencing_target": "node-a", "parameters": {"password": "new"}}
        with self.assertRaises(SystemExit) as active:
            self.execute(payload, resources,
                         '<crm_mon><nodes><node name="node-a"/></nodes><resources><resource id="fence-a" active="true"/></resources></crm_mon>',
                         current_cib_xml=resources)
        self.assertIn("Stop this fencing resource", str(active.exception))
        payload["parameters"] = {"pcmk_host_list": "node-b"}
        with self.assertRaises(SystemExit) as reserved:
            self.execute(payload, resources,
                         '<crm_mon><nodes><node name="node-a"/></nodes><resources><resource id="fence-a" active="false"/></resources></crm_mon>',
                         current_cib_xml=resources)
        self.assertIn("target mapping cannot be edited", str(reserved.exception))

    def test_edit_stonith_does_not_echo_existing_secrets_from_crmsh_errors(self):
        resources = ('<resources><primitive id="fence-a" class="stonith" type="fence_ipmilan">'
                     '<instance_attributes id="fence-a-params"><nvpair id="host-list" name="pcmk_host_list" value="node-a"/>'
                     '<nvpair id="password" name="password" value="stored-secret"/></instance_attributes></primitive></resources>')
        payload = {"action": "edit_stonith", "resource_id": "fence-a", "agent": "stonith:fence_ipmilan",
                   "fencing_target": "node-a", "parameters": {"username": "operator"}}
        with self.assertRaises(SystemExit) as rejected:
            self.execute(payload, resources,
                         '<crm_mon><nodes><node name="node-a"/></nodes><resources><resource id="fence-a" active="false"/></resources></crm_mon>',
                         current_cib_xml=resources, crm_error="rejecting XML containing stored-secret")
        self.assertIn("Stored device values were not returned", str(rejected.exception))
        self.assertNotIn("stored-secret", str(rejected.exception))

    def test_monitor_edit_preserves_parameters_metadata_and_non_monitor_operations(self):
        resources = ('<resources><primitive id="replica" class="ocf" provider="heartbeat" type="Stateful">'
                     '<instance_attributes id="replica-params"><nvpair id="state-dir" name="state_dir" value="/var/lib/replica"/></instance_attributes>'
                     '<operations id="replica-operations"><op id="mon-up" name="monitor" interval="10s" role="Unpromoted" on-fail="restart"/>'
                     '<op id="start-op" name="start" interval="0" timeout="60s"/><op id="mon-primary" name="monitor" interval="11s" role="Promoted"/></operations>'
                     '<meta_attributes id="replica-meta"><nvpair id="target-role" name="target-role" value="Stopped"/></meta_attributes></primitive></resources>')
        _output, commands, _loaded, loaded_xml = self.execute(
            {
                "action": "set_monitor_ops",
                "resource_id": "replica",
                "expected_operation_ids": ["mon-up", "mon-primary"],
                "expected_operations": [
                    {"operation_id": "mon-up", "interval": "10s", "role": "Unpromoted", "timeout": ""},
                    {"operation_id": "mon-primary", "interval": "11s", "role": "Promoted", "timeout": ""},
                ],
                "operations": [
                    {"operation_id": "mon-up", "interval": "30s", "role": "Unpromoted", "timeout": "8s"},
                    {"operation_id": "mon-primary", "interval": "1min", "role": "Promoted"},
                ],
            },
            resources,
        )
        self.assertTrue(any(command[:5] == ["crm", "configure", "load", "xml", "update"] for command in commands))
        cib = ET.fromstring(loaded_xml[0])
        primitive = cib.find("./configuration/resources/primitive")
        self.assertEqual(primitive.find("instance_attributes/nvpair").get("value"), "/var/lib/replica")
        self.assertEqual(primitive.find("meta_attributes/nvpair").get("value"), "Stopped")
        operations = primitive.find("operations")
        monitors = {op.get("id"): op for op in operations.findall("op") if op.get("name") == "monitor"}
        self.assertEqual(monitors["mon-up"].get("interval"), "30s")
        self.assertEqual(monitors["mon-up"].get("timeout"), "8s")
        self.assertEqual(monitors["mon-up"].get("on-fail"), "restart")
        self.assertEqual(monitors["mon-primary"].get("interval"), "1min")
        self.assertIsNone(monitors["mon-primary"].get("timeout"))
        self.assertTrue(any(op.get("id") == "start-op" and op.get("timeout") == "60s" for op in operations.findall("op")))

    def test_monitor_edit_rejects_active_or_stale_resource_without_cib_update(self):
        resources = ('<resources><primitive id="replica" class="ocf" provider="heartbeat" type="Stateful">'
                     '<operations><op id="mon-a" name="monitor" interval="30s"/></operations></primitive></resources>')
        payload = {"action": "set_monitor_ops", "resource_id": "replica", "expected_operation_ids": ["mon-a"],
                   "expected_operations": [{"operation_id": "mon-a", "interval": "30s", "role": "", "timeout": ""}],
                   "operations": [{"operation_id": "mon-a", "interval": "40s", "role": ""}]}
        with self.assertRaises(SystemExit) as active:
            self.execute(payload, resources, '<crm_mon><resources><resource id="replica" active="true"/></resources></crm_mon>')
        self.assertIn("Stop the primitive", str(active.exception))
        with self.assertRaises(SystemExit) as stale:
            self.execute({**payload, "expected_operation_ids": ["old-id"]}, resources)
        self.assertIn("changed while this form was open", str(stale.exception))

        changed = resources.replace('interval="30s"', 'interval="35s"')
        with self.assertRaises(SystemExit) as stale_values:
            self.execute(payload, changed)
        self.assertIn("interval, role, or timeout changed", str(stale_values.exception))

    def test_monitor_edit_rejects_duplicate_intervals_and_shell_like_values(self):
        resources = ('<resources><primitive id="replica" class="ocf" provider="heartbeat" type="Stateful">'
                     '<operations><op id="mon-a" name="monitor" interval="30s"/></operations></primitive></resources>')
        payload = {"action": "set_monitor_ops", "resource_id": "replica", "expected_operation_ids": ["mon-a"],
                   "expected_operations": [{"operation_id": "mon-a", "interval": "30s", "role": "", "timeout": ""}],
                   "operations": [{"operation_id": "mon-a", "interval": "30s", "role": ""},
                                  {"interval": "30", "role": "Promoted"}]}
        with self.assertRaises(SystemExit) as duplicate:
            self.execute(payload, resources)
        self.assertIn("distinct explicit roles", str(duplicate.exception))
        payload["operations"][0]["interval"] = "30s;touch /tmp/untrusted"
        with self.assertRaises(SystemExit) as malformed:
            self.execute(payload, resources)
        self.assertIn("whole number", str(malformed.exception))

    def test_create_standard_clone_wraps_only_a_stopped_standalone_primitive(self):
        output, _commands, loaded, _loaded_xml = self.execute(
            {"action": "create_clone", "resource_id": "web-clone", "child_id": "web", "clone_type": "standard"},
            '<resources><primitive id="web" class="ocf" provider="heartbeat" type="apache"/></resources>',
        )
        self.assertIn("Standard clone created in Stopped state", output)
        self.assertEqual(loaded, ["clone web-clone web meta target-role=Stopped\n"])

    def test_create_standard_clone_can_wrap_a_stopped_top_level_group(self):
        output, _commands, loaded, _loaded_xml = self.execute(
            {"action": "create_clone", "resource_id": "web-clone", "child_id": "web-group", "clone_type": "standard"},
            '<resources><group id="web-group"><primitive id="web" class="ocf" provider="heartbeat" type="apache"/></group></resources>',
        )
        self.assertIn("Standard clone created in Stopped state", output)
        self.assertEqual(loaded, ["clone web-clone web-group meta target-role=Stopped\n"])

    def test_promotable_clone_rejects_group_children_instead_of_guessing_agent_support(self):
        with self.assertRaises(SystemExit) as raised:
            self.execute(
                {"action": "create_clone", "resource_id": "web-clone", "child_id": "web-group", "clone_type": "promotable"},
                '<resources><group id="web-group"><primitive id="web" class="ocf" provider="heartbeat" type="apache"/></group></resources>',
            )
        self.assertIn("require one primitive child", str(raised.exception))

    def test_create_clone_rejects_active_child_and_duplicate_id(self):
        with self.assertRaises(SystemExit) as active:
            self.execute(
                {"action": "create_clone", "resource_id": "web-clone", "child_id": "web"},
                '<resources><primitive id="web" class="ocf" type="apache"/></resources>',
                '<crm_mon><resources><resource id="web" active="true"/></resources></crm_mon>',
            )
        self.assertIn("Stop the selected resource", str(active.exception))
        with self.assertRaises(SystemExit) as duplicate:
            self.execute(
                {"action": "create_clone", "resource_id": "web-clone", "child_id": "web"},
                '<resources><clone id="web-clone"><primitive id="web" class="ocf" type="apache"/></clone></resources>',
            )
        self.assertIn("already exists", str(duplicate.exception))

    def test_create_promotable_clone_requires_role_monitors_and_agent_actions(self):
        resources = ('<resources><primitive id="replica" class="ocf" provider="heartbeat" type="Stateful">'
                     '<operations><op id="mon-up" name="monitor" interval="10s" role="Unpromoted"/>'
                     '<op id="mon-primary" name="monitor" interval="11s" role="Promoted"/></operations></primitive></resources>')
        output, commands, loaded, _loaded_xml = self.execute(
            {"action": "create_clone", "resource_id": "replica-clone", "child_id": "replica", "clone_type": "promotable"},
            resources,
        )
        self.assertIn("Promotable clone created in Stopped state", output)
        self.assertEqual(loaded, ["clone replica-clone replica meta promotable=true target-role=Stopped\n"])
        self.assertIn(["crm", "ra", "info", "ocf:heartbeat:Stateful"], commands)

        no_monitors = resources.replace('<op id="mon-primary" name="monitor" interval="11s" role="Promoted"/>', '').replace(' role="Unpromoted"', '')
        with self.assertRaises(SystemExit) as raised:
            self.execute(
                {"action": "create_clone", "resource_id": "replica-clone", "child_id": "replica", "clone_type": "promotable"},
                no_monitors,
            )
        self.assertIn("separate monitor operations", str(raised.exception))

    def test_edit_clone_updates_only_supported_metadata_and_preserves_child_and_unknown_meta(self):
        resources = ('<resources><clone id="replica-clone"><primitive id="replica" class="ocf" provider="heartbeat" type="Stateful"/>'
                    '<meta_attributes id="replica-clone-meta"><nvpair id="clone-max" name="clone-max" value="2"/>'
                    '<nvpair id="notify" name="notify" value="false"/><nvpair id="private-meta" name="custom-note" value="keep-me"/>'
                    '</meta_attributes></clone></resources>')
        allowed = {"clone-max": "3", "clone-node-max": "", "globally-unique": "", "notify": "true", "interleave": ""}
        output, commands, _loaded, loaded_xml = self.execute(
            {"action": "edit_clone", "resource_id": "replica-clone", "clone_type": "standard", "expected_clone_metadata": {"clone-max": "2", "notify": "false"}, "clone_metadata": allowed},
            resources,
            '<crm_mon><resources><resource id="replica" active="false" failed="false"/></resources></crm_mon>',
        )
        self.assertIn("Stopped clone options updated", output)
        self.assertTrue(any(command[:5] == ["crm", "configure", "load", "xml", "update"] for command in commands))
        updated = ET.fromstring(loaded_xml[0]).find("./configuration/resources/clone")
        self.assertEqual(updated.find("primitive").get("id"), "replica")
        values = {nv.get("name"): nv.get("value") for nv in updated.findall("meta_attributes/nvpair")}
        self.assertEqual(values["clone-max"], "3")
        self.assertEqual(values["notify"], "true")
        self.assertEqual(values["custom-note"], "keep-me")

    def test_edit_clone_rejects_running_failed_stale_and_unsupported_options(self):
        resources = ('<resources><clone id="replica-clone"><primitive id="replica" class="ocf" type="Dummy"/>'
                    '<meta_attributes id="clone-meta"><nvpair id="max" name="clone-max" value="2"/></meta_attributes></clone></resources>')
        payload = {"action": "edit_clone", "resource_id": "replica-clone", "clone_type": "standard", "expected_clone_metadata": {"clone-max": "2"},
                   "clone_metadata": {"clone-max": "3", "clone-node-max": "", "globally-unique": "", "notify": "", "interleave": ""}}
        cases = [
            (payload, '<crm_mon><resources><resource id="replica" active="true"/></resources></crm_mon>', "Stop every instance"),
            (payload, '<crm_mon><resources><resource id="replica" failed="true"/></resources></crm_mon>', "Clean up failed"),
            ({**payload, "expected_clone_metadata": {"clone-max": "1"}}, '<crm_mon><resources/></crm_mon>', "changed while this form was open"),
            ({**payload, "clone_metadata": {**payload["clone_metadata"], "promotable": "true"}}, '<crm_mon><resources/></crm_mon>', "incomplete or contains unsupported options"),
        ]
        for request, status, expected in cases:
            with self.subTest(expected=expected):
                with self.assertRaises(SystemExit) as raised:
                    self.execute(request, resources, status)
                self.assertIn(expected, str(raised.exception))

    def test_promotable_clone_editor_limits_promoted_options_to_promotable_clones(self):
        resources = ('<resources><clone id="replica-clone"><primitive id="replica" class="ocf" type="Dummy"/>'
                    '<meta_attributes id="clone-meta"><nvpair id="promotable" name="promotable" value="true"/>'
                    '<nvpair id="promoted-max" name="promoted-max" value="1"/></meta_attributes></clone></resources>')
        desired = {"clone-max": "", "clone-node-max": "", "globally-unique": "", "notify": "", "interleave": "", "promoted-max": "2", "promoted-node-max": ""}
        output, _commands, _loaded, loaded_xml = self.execute(
            {"action": "edit_clone", "resource_id": "replica-clone", "clone_type": "promotable", "expected_clone_metadata": {"promoted-max": "1"}, "clone_metadata": desired},
            resources,
            '<crm_mon><resources/></crm_mon>',
        )
        self.assertIn("Stopped clone options updated", output)
        updated = ET.fromstring(loaded_xml[0]).find("./configuration/resources/clone")
        values = {nv.get("name"): nv.get("value") for nv in updated.findall("meta_attributes/nvpair")}
        self.assertEqual(values["promotable"], "true")
        self.assertEqual(values["promoted-max"], "2")

    def test_promotable_clone_requires_agent_to_advertise_promote_and_demote(self):
        script = remote_group_script()
        payload = {"action": "create_clone", "resource_id": "replica-clone", "child_id": "replica", "clone_type": "promotable"}
        resources = ('<resources><primitive id="replica" class="ocf" provider="heartbeat" type="Stateful">'
                     '<operations><op name="monitor" interval="10s" role="Unpromoted"/>'
                     '<op name="monitor" interval="11s" role="Promoted"/></operations></primitive></resources>')
        commands = []

        def fake_run(command, **_kwargs):
            commands.append(command)
            if command[:3] == ["cibadmin", "-Q", "-o"]:
                return SimpleNamespace(returncode=0, stdout=resources, stderr="")
            if command[0] == "crm_mon":
                return SimpleNamespace(returncode=0, stdout="<crm_mon><resources/></crm_mon>", stderr="")
            if command[:3] == ["crm", "ra", "info"]:
                return SimpleNamespace(returncode=0, stdout="Actions: start stop monitor", stderr="")
            raise AssertionError(f"Unexpected command: {command}")

        with patch("subprocess.run", side_effect=fake_run), patch.object(sys, "stdin", io.StringIO(json.dumps(payload))):
            with self.assertRaises(SystemExit) as raised:
                exec(compile(script, "<ha-resource-mutation>", "exec"), {"__name__": "__main__"})
        self.assertIn("does not advertise both promote and demote", str(raised.exception))

    def test_create_rejects_running_or_fencing_members_without_mutating_cib(self):
        fixtures = [
            ('<resources><primitive id="service" class="ocf" type="apache"/></resources>',
             '<crm_mon><resources><resource id="service" active="true"/></resources></crm_mon>',
             "Stop every selected resource"),
            ('<resources><primitive id="fence" class="stonith" type="external/sbd"/></resources>',
             '<crm_mon><resources/></crm_mon>', "Fencing devices cannot"),
        ]
        for resources_xml, status_xml, expected in fixtures:
            with self.subTest(expected=expected):
                with self.assertRaises(SystemExit) as raised:
                    self.execute({"action": "create_group", "resource_id": "g", "children": ["service" if "service" in resources_xml else "fence"]}, resources_xml, status_xml)
                self.assertIn(expected, str(raised.exception))

    def test_create_rejects_duplicate_members_before_any_configuration_change(self):
        with self.assertRaises(SystemExit) as raised:
            self.execute(
                {"action": "create_group", "resource_id": "g", "children": ["service", "service"]},
                '<resources><primitive id="service" class="ocf" type="apache"/></resources>',
            )
        self.assertIn("different primitive resources", str(raised.exception))

    def test_delete_group_uses_supported_crmsh_delete_and_names_member_loss(self):
        output, commands, loaded, _loaded_xml = self.execute(
            {"action": "delete_group", "resource_id": "service-group"},
            '<resources><group id="service-group"><primitive id="service" class="ocf" type="apache"/></group></resources>',
        )
        self.assertIn("group and its member primitives were removed", output)
        self.assertIn(["crm", "configure", "delete", "service-group"], commands)
        self.assertEqual(loaded, [])

    def test_reorders_group_members_via_xml_update_and_preserves_group_metadata(self):
        output, commands, _loaded, loaded_xml = self.execute(
            {"action": "reorder_group", "resource_id": "service-group", "children": ["vip", "service"]},
            '<resources><group id="service-group"><primitive id="service" class="ocf" type="apache"><operations><op name="monitor" interval="10s"/></operations></primitive><primitive id="vip" class="ocf" type="IPaddr2"/><meta_attributes id="service-group-meta"><nvpair id="meta-target" name="target-role" value="Stopped"/></meta_attributes></group></resources>',
        )
        cib = ET.fromstring(loaded_xml[0])
        group = cib.find("./configuration/resources/group")
        self.assertIn("order updated", output)
        self.assertTrue(any(command[:5] == ["crm", "configure", "load", "xml", "update"] for command in commands))
        self.assertEqual(cib.get("validate-with"), "pacemaker-3.10")
        self.assertEqual(len(cib.findall("./configuration/resources/*")), 1)
        self.assertEqual([item.get("id") for item in list(group) if item.tag == "primitive"], ["vip", "service"])
        self.assertEqual(group.find("meta_attributes/nvpair").get("value"), "Stopped")
        self.assertEqual(group.find("primitive/operations/op").get("interval"), "10s")

    def test_reorder_requires_exact_current_members_and_stopped_group(self):
        resources_xml = '<resources><group id="service-group"><primitive id="service" class="ocf" type="apache"/><primitive id="vip" class="ocf" type="IPaddr2"/></group></resources>'
        with self.assertRaises(SystemExit) as invalid:
            self.execute({"action": "reorder_group", "resource_id": "service-group", "children": ["service", "other"]}, resources_xml)
        self.assertIn("every current group primitive exactly once", str(invalid.exception))
        with self.assertRaises(SystemExit) as active:
            self.execute(
                {"action": "reorder_group", "resource_id": "service-group", "children": ["vip", "service"]},
                resources_xml,
                '<crm_mon><resources><resource id="service-group" active="true"><resource id="service" active="true"/></resource></resources></crm_mon>',
            )
        self.assertIn("Stop the group resources before changing membership", str(active.exception))

    def test_reorder_refuses_a_group_changed_after_the_editor_loaded(self):
        original = '<resources><group id="service-group"><primitive id="service" class="ocf" type="apache"/><primitive id="vip" class="ocf" type="IPaddr2"/></group></resources>'
        changed = '<resources><group id="service-group"><primitive id="service" class="ocf" type="apache"/><primitive id="monitor" class="ocf" type="Dummy"/><primitive id="vip" class="ocf" type="IPaddr2"/></group></resources>'
        with self.assertRaises(SystemExit) as raised:
            self.execute(
                {"action": "reorder_group", "resource_id": "service-group", "children": ["vip", "service"]},
                original,
                current_cib_xml=changed,
            )
        self.assertIn("changed while this form was open", str(raised.exception))

    def test_cannot_remove_the_last_member_from_a_group(self):
        with self.assertRaises(SystemExit) as raised:
            self.execute(
                {"action": "remove_group_member", "resource_id": "service-group", "child_id": "service"},
                '<resources><group id="service-group"><primitive id="service" class="ocf" type="apache"/></group></resources>',
            )
        self.assertIn("retain at least one primitive", str(raised.exception))

    def test_stops_editing_a_group_when_a_nested_primitive_is_active(self):
        with self.assertRaises(SystemExit) as raised:
            self.execute(
                {"action": "remove_group_member", "resource_id": "service-group", "child_id": "service"},
                '<resources><group id="service-group"><primitive id="service" class="ocf" type="apache"/><primitive id="vip" class="ocf" type="IPaddr2"/></group></resources>',
                '<crm_mon><resources><resource id="service-group" active="true"><resource id="service" active="true"/></resource></resources></crm_mon>',
            )
        self.assertIn("Stop the group resources before changing membership", str(raised.exception))

    def test_primitive_operations_cannot_bypass_group_management(self):
        with self.assertRaises(SystemExit) as raised:
            self.execute(
                {"action": "delete", "resource_id": "service"},
                '<resources><group id="service-group"><primitive id="service" class="ocf" type="apache"/></group></resources>',
            )
        self.assertIn("inside a group or clone", str(raised.exception))

    def test_nested_group_cannot_be_deleted_as_a_standalone_group(self):
        with self.assertRaises(SystemExit) as raised:
            self.execute(
                {"action": "delete_group", "resource_id": "service-group"},
                '<resources><clone id="service-clone"><group id="service-group"><primitive id="service" class="ocf" type="apache"/></group></clone></resources>',
            )
        self.assertIn("Nested groups", str(raised.exception))

    def test_cluster_status_exposes_monitor_operation_ids_roles_intervals_and_timeouts(self):
        status_xml = ('<crm_mon><summary><current_dc>node-a</current_dc></summary><nodes><node name="node-a" id="1" online="true"/></nodes>'
                      '<resources><resource id="replica" resource_agent="ocf:heartbeat:Stateful" role="Stopped" active="false" managed="true"/></resources></crm_mon>')
        cib_xml = ('<resources><primitive id="replica" class="ocf" provider="heartbeat" type="Stateful"><operations>'
                   '<op id="mon-up" name="monitor" interval="30s" role="Unpromoted" timeout="10s"/>'
                   '<op id="mon-primary" name="monitor" interval="60s" role="Promoted"/>'
                   '<op id="start-op" name="start" interval="0"/></operations></primitive></resources>')

        def fake_run(command, **_kwargs):
            if command[0] == "crm_mon":
                return SimpleNamespace(returncode=0, stdout=status_xml, stderr="")
            if command[:4] == ["cibadmin", "-Q", "-o", "resources"]:
                return SimpleNamespace(returncode=0, stdout=cib_xml, stderr="")
            if command[0] == "corosync-quorumtool":
                return SimpleNamespace(returncode=0, stdout="Quorate: Yes", stderr="")
            if command[0] == "stonith_admin":
                return SimpleNamespace(returncode=0, stdout="No devices configured", stderr="")
            raise AssertionError(f"Unexpected command: {command}")

        output = io.StringIO()
        with patch("subprocess.run", side_effect=fake_run), patch("shutil.which", return_value="/usr/bin/tool"), contextlib.redirect_stdout(output):
            exec(compile(remote_status_script(), "<ha-cluster-status>", "exec"), {"__name__": "__main__"})
        body = json.loads(output.getvalue())
        operation_map = {item["operation_id"]: item for item in body["resources"][0]["monitor_operations"]}
        self.assertEqual(operation_map["mon-up"], {"operation_id": "mon-up", "interval": "30s", "role": "Unpromoted", "timeout": "10s"})
        self.assertEqual(operation_map["mon-primary"]["role"], "Promoted")
        self.assertNotIn("start-op", operation_map)

    def test_cluster_status_reports_fencing_targets_without_exposing_device_credentials(self):
        status_xml = ('<crm_mon><summary><current_dc>node-a</current_dc></summary><nodes><node name="node-a" id="1" online="true"/></nodes>'
                      '<resources><resource id="fence-a" resource_agent="stonith:fence_ipmilan" role="Stopped" active="false" managed="true"/></resources></crm_mon>')
        cib_xml = ('<resources><primitive id="fence-a" class="stonith" type="fence_ipmilan">'
                   '<instance_attributes id="fence-a-params"><nvpair id="host-list" name="pcmk_host_list" value="node-a"/>'
                   '<nvpair id="password" name="password" value="private-secret"/></instance_attributes></primitive></resources>')
        def fake_run(command, **_kwargs):
            if command[0] == "crm_mon": return SimpleNamespace(returncode=0, stdout=status_xml, stderr="")
            if command[:4] == ["cibadmin", "-Q", "-o", "resources"]: return SimpleNamespace(returncode=0, stdout=cib_xml, stderr="")
            if command[0] == "corosync-quorumtool": return SimpleNamespace(returncode=0, stdout="Quorate: Yes", stderr="")
            if command[0] == "stonith_admin": return SimpleNamespace(returncode=0, stdout="fence-a", stderr="")
            raise AssertionError(f"Unexpected command: {command}")
        output = io.StringIO()
        with patch("subprocess.run", side_effect=fake_run), patch("shutil.which", return_value="/usr/bin/tool"), contextlib.redirect_stdout(output):
            exec(compile(remote_status_script(), "<ha-cluster-status>", "exec"), {"__name__": "__main__"})
        serialized = output.getvalue()
        resource = json.loads(serialized)["resources"][0]
        self.assertEqual(resource["class"], "stonith")
        self.assertEqual(resource["fencing_targets"], ["node-a"])
        self.assertEqual(resource["fencing_parameter_names"], ["password"])
        self.assertNotIn("private-secret", serialized)

    def test_cluster_status_lists_group_once_and_marks_nested_members(self):
        crm_status = '''<crm_mon><summary/><nodes><node name="node-a" id="1" online="true"/></nodes><resources>
          <resource id="web-group" resource_agent="group" role="Started" active="true"><node name="node-a" running="true"/>
            <resource id="vip" resource_agent="ocf:heartbeat:IPaddr2" role="Started" active="true"><node name="node-a" running="true"/></resource>
          </resource>
        </resources></crm_mon>'''
        cib_resources = '''<resources><group id="web-group"><primitive id="vip" class="ocf" provider="heartbeat" type="IPaddr2"/></group></resources>'''

        def fake_run(command, **_kwargs):
            if command[0] == "crm_mon": return SimpleNamespace(returncode=0, stdout=crm_status, stderr="")
            if command[0] == "cibadmin": return SimpleNamespace(returncode=0, stdout=cib_resources, stderr="")
            raise AssertionError(f"Unexpected command: {command}")

        output = io.StringIO()
        which = lambda name: f"/usr/bin/{name}" if name in {"crm_mon", "crm", "cibadmin"} else None
        with patch("shutil.which", side_effect=which), patch("subprocess.run", side_effect=fake_run), contextlib.redirect_stdout(output):
            exec(compile(remote_status_script(), "<ha-cluster-status>", "exec"), {"__name__": "__main__"})
        resources = json.loads(output.getvalue())["resources"]
        self.assertEqual([resource["id"] for resource in resources].count("web-group"), 1)
        group = next(resource for resource in resources if resource["id"] == "web-group")
        member = next(resource for resource in resources if resource["id"] == "vip")
        self.assertEqual(group["children"], ["vip"])
        self.assertEqual(member["group_id"], "web-group")
        self.assertEqual(member["parent_id"], "web-group")

    def test_cluster_status_aggregates_clone_and_reports_clone_role(self):
        crm_status = '''<crm_mon><summary/><nodes><node name="node-a" id="1" online="true"/></nodes><resources>
          <resource id="replica" resource_agent="ocf:heartbeat:Stateful" role="Promoted" active="true"><node name="node-a" running="true"/></resource>
        </resources></crm_mon>'''
        cib_resources = '''<resources><clone id="replica-clone"><primitive id="replica" class="ocf" provider="heartbeat" type="Stateful"/><meta_attributes id="replica-clone-meta"><nvpair id="promotable" name="promotable" value="true"/></meta_attributes></clone></resources>'''

        def fake_run(command, **_kwargs):
            if command[0] == "crm_mon": return SimpleNamespace(returncode=0, stdout=crm_status, stderr="")
            if command[0] == "cibadmin": return SimpleNamespace(returncode=0, stdout=cib_resources, stderr="")
            raise AssertionError(f"Unexpected command: {command}")

        output = io.StringIO()
        which = lambda name: f"/usr/bin/{name}" if name in {"crm_mon", "crm", "cibadmin"} else None
        with patch("shutil.which", side_effect=which), patch("subprocess.run", side_effect=fake_run), contextlib.redirect_stdout(output):
            exec(compile(remote_status_script(), "<ha-cluster-status>", "exec"), {"__name__": "__main__"})
        resources = json.loads(output.getvalue())["resources"]
        clone = next(resource for resource in resources if resource["id"] == "replica-clone")
        child = next(resource for resource in resources if resource["id"] == "replica")
        self.assertEqual(clone["agent"], "promotable clone")
        self.assertEqual(clone["role"], "Promoted")
        self.assertEqual(clone["children"], ["replica"])
        self.assertEqual(child["parent_id"], "replica-clone")

    def test_cluster_status_exposes_only_allowlisted_clone_options(self):
        crm_status = '<crm_mon><summary/><nodes/><resources/></crm_mon>'
        cib_resources = ('<resources><clone id="web-clone"><primitive id="web" class="ocf" provider="heartbeat" type="apache"/>'
                         '<meta_attributes id="web-clone-meta"><nvpair id="max" name="clone-max" value="3"/>'
                         '<nvpair id="notify" name="notify" value="true"/><nvpair id="private" name="custom-token" value="do-not-return"/>'
                         '</meta_attributes></clone></resources>')

        def fake_run(command, **_kwargs):
            if command[0] == "crm_mon": return SimpleNamespace(returncode=0, stdout=crm_status, stderr="")
            if command[0] == "cibadmin": return SimpleNamespace(returncode=0, stdout=cib_resources, stderr="")
            raise AssertionError(f"Unexpected command: {command}")

        output = io.StringIO()
        which = lambda name: f"/usr/bin/{name}" if name in {"crm_mon", "crm", "cibadmin"} else None
        with patch("shutil.which", side_effect=which), patch("subprocess.run", side_effect=fake_run), contextlib.redirect_stdout(output):
            exec(compile(remote_status_script(), "<ha-cluster-status>", "exec"), {"__name__": "__main__"})
        serialized = output.getvalue()
        clone = next(item for item in json.loads(serialized)["resources"] if item["id"] == "web-clone")
        self.assertEqual(clone["clone_metadata"], {"clone-max": "3", "notify": "true"})
        self.assertTrue(clone["clone_metadata_editable"])
        self.assertNotIn("do-not-return", serialized)

    def test_cluster_status_disables_clone_editing_when_structure_has_multiple_children(self):
        crm_status = '<crm_mon><summary/><nodes/><resources/></crm_mon>'
        cib_resources = ('<resources><clone id="web-clone"><primitive id="web-a" class="ocf" type="apache"/>'
                         '<primitive id="web-b" class="ocf" type="apache"/></clone></resources>')

        def fake_run(command, **_kwargs):
            if command[0] == "crm_mon": return SimpleNamespace(returncode=0, stdout=crm_status, stderr="")
            if command[0] == "cibadmin": return SimpleNamespace(returncode=0, stdout=cib_resources, stderr="")
            raise AssertionError(f"Unexpected command: {command}")

        output = io.StringIO()
        which = lambda name: f"/usr/bin/{name}" if name in {"crm_mon", "crm", "cibadmin"} else None
        with patch("shutil.which", side_effect=which), patch("subprocess.run", side_effect=fake_run), contextlib.redirect_stdout(output):
            exec(compile(remote_status_script(), "<ha-cluster-status>", "exec"), {"__name__": "__main__"})
        clone = next(item for item in json.loads(output.getvalue())["resources"] if item["id"] == "web-clone")
        self.assertEqual(clone["children"], ["web-a", "web-b"])
        self.assertFalse(clone["clone_metadata_editable"])

    def test_cluster_status_reports_group_child_inside_clone(self):
        crm_status = '''<crm_mon><summary/><nodes><node name="node-a" id="1" online="true"/></nodes><resources>
          <resource id="web-group" resource_agent="group" role="Started" active="true"><node name="node-a" running="true"/>
            <resource id="web" resource_agent="ocf:heartbeat:apache" role="Started" active="true"><node name="node-a" running="true"/></resource>
          </resource>
        </resources></crm_mon>'''
        cib_resources = '''<resources><clone id="web-clone"><group id="web-group"><primitive id="web" class="ocf" provider="heartbeat" type="apache"/></group></clone></resources>'''

        def fake_run(command, **_kwargs):
            if command[0] == "crm_mon": return SimpleNamespace(returncode=0, stdout=crm_status, stderr="")
            if command[0] == "cibadmin": return SimpleNamespace(returncode=0, stdout=cib_resources, stderr="")
            raise AssertionError(f"Unexpected command: {command}")

        output = io.StringIO()
        which = lambda name: f"/usr/bin/{name}" if name in {"crm_mon", "crm", "cibadmin"} else None
        with patch("shutil.which", side_effect=which), patch("subprocess.run", side_effect=fake_run), contextlib.redirect_stdout(output):
            exec(compile(remote_status_script(), "<ha-cluster-status>", "exec"), {"__name__": "__main__"})
        resources = json.loads(output.getvalue())["resources"]
        clone = next(resource for resource in resources if resource["id"] == "web-clone")
        group = next(resource for resource in resources if resource["id"] == "web-group")
        self.assertEqual(clone["children"], ["web-group"])
        self.assertEqual(group["parent_id"], "web-clone")


if __name__ == "__main__":
    unittest.main()

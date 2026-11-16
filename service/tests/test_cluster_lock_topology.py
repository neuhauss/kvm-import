"""Focused tests for the read-only SLE HA lock-topology diagnostic script."""

from __future__ import annotations

import ast
import builtins
import contextlib
import io
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


APP_PATH = Path(__file__).resolve().parents[1] / "app.py"
APP_TREE = ast.parse(APP_PATH.read_text(encoding="utf-8"))
SCRIPT = next(
    node.value.value
    for node in APP_TREE.body
    if isinstance(node, ast.Assign)
    and any(isinstance(target, ast.Name) and target.id == "HA_CLUSTER_DIAGNOSTICS_SCRIPT" for target in node.targets)
)


def run_script(cib: str, crm_mon: str | None = None) -> dict:
    real_open = builtins.open

    def fake_open(path, *args, **kwargs):
        if path == "/etc/libvirt/qemu-lockd.conf":
            return io.StringIO('file_lockspace_dir = "/mnt/shared/lockd"\n')
        return real_open(path, *args, **kwargs)

    def fake_run(args, capture_output=True, text=True, timeout=12):
        command = args[0]
        if command == "cibadmin":
            return subprocess.CompletedProcess(args, 0, stdout=cib, stderr="")
        if command == "crm_mon":
            default_status = """<crm_mon><nodes>
              <node name="node-a" type="member" online="true"/>
              <node name="node-b" type="member" online="true"/>
              <node name="node-c" type="member" online="false"/>
            </nodes><resources><clone id="cl-virt-lock">
              <resource id="dlm:0" role="Started" active="true" failed="false"><node name="node-a"/></resource>
              <resource id="gfs2:0" role="Started" active="true" failed="false"><node name="node-a"/></resource>
              <resource id="dlm:1" role="Started" active="true" failed="false"><node name="node-b"/></resource>
              <resource id="gfs2:1" role="Started" active="true" failed="false"><node name="node-b"/></resource>
            </clone></resources></crm_mon>"""
            return subprocess.CompletedProcess(args, 0, stdout=crm_mon or default_status, stderr="")
        if command == "crm":
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")
        if command == "corosync-cfgtool":
            return subprocess.CompletedProcess(args, 0, stdout="ring 0 active", stderr="")
        if command == "journalctl":
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")
        raise AssertionError(f"Unexpected diagnostic command: {args!r}")

    output = io.StringIO()
    with patch("subprocess.run", side_effect=fake_run), patch("shutil.which", return_value="/usr/bin/tool"), patch("builtins.open", side_effect=fake_open), contextlib.redirect_stdout(output):
        exec(compile(SCRIPT, str(APP_PATH), "exec"), {})
    return json.loads(output.getvalue())


class ClusterLockTopologyTests(unittest.TestCase):
    def test_detects_suse_documented_cloned_dlm_gfs2_and_vm_constraints(self) -> None:
        cib = """<cib><configuration><resources>
          <clone id="cl-virt-lock"><group id="g-virt-lock">
            <primitive id="dlm" class="ocf" provider="pacemaker" type="controld"/>
            <primitive id="gfs2" class="ocf" provider="heartbeat" type="Filesystem">
              <instance_attributes><nvpair name="directory" value="/mnt/shared"/><nvpair name="fstype" value="gfs2"/></instance_attributes>
            </primitive>
          </group></clone>
          <primitive id="vm-one" class="ocf" provider="heartbeat" type="VirtualDomain"/>
        </resources><constraints>
          <rsc_order id="o-lock-vm" first="cl-virt-lock" then="vm-one" kind="Mandatory"/>
          <rsc_colocation id="col-lock-vm" rsc="vm-one" with-rsc="cl-virt-lock" score="INFINITY"/>
        </constraints></configuration></cib>"""
        topology = run_script(cib)["locking_topology"]
        self.assertTrue(topology["available"])
        self.assertTrue(topology["complete"])
        self.assertTrue(topology["runtime_available"])
        self.assertTrue(topology["runtime_active_on_all_online_nodes"])
        self.assertEqual(topology["runtime_active_nodes"], ["node-a", "node-b"])
        self.assertEqual(topology["runtime_online_nodes"], ["node-a", "node-b"])
        self.assertEqual(topology["runtime_component_nodes"], {"dlm": ["node-a", "node-b"], "gfs2": ["node-a", "node-b"]})
        self.assertEqual(topology["lock_clone_ids"], ["cl-virt-lock"])
        self.assertEqual(topology["lock_group_ids"], ["g-virt-lock"])
        self.assertTrue(topology["lockspace_matches_gfs2"])
        self.assertEqual(topology["gfs2_resources"], [{"id": "gfs2", "directory": "/mnt/shared"}])
        self.assertEqual(topology["vm_constraints"]["vm-one"], {"ordered_after_lock": True, "colocated_with_lock": True})

    def test_does_not_approve_missing_ordering_or_colocation(self) -> None:
        cib = """<cib><configuration><resources>
          <clone id="cl-virt-lock"><group id="g-virt-lock">
            <primitive id="dlm" class="ocf" provider="pacemaker" type="controld"/>
            <primitive id="gfs2" class="ocf" provider="heartbeat" type="Filesystem"><instance_attributes><nvpair name="directory" value="/mnt/shared"/><nvpair name="fstype" value="gfs2"/></instance_attributes></primitive>
          </group></clone><primitive id="vm-one" class="ocf" provider="heartbeat" type="VirtualDomain"/>
        </resources><constraints/></configuration></cib>"""
        topology = run_script(cib)["locking_topology"]
        self.assertTrue(topology["available"])
        self.assertFalse(topology["complete"])
        self.assertTrue(topology["lock_stack_detected"])
        self.assertEqual(topology["vm_constraints"]["vm-one"], {"ordered_after_lock": False, "colocated_with_lock": False})

    def test_does_not_report_lock_clone_active_on_all_online_nodes_from_partial_runtime(self) -> None:
        cib = """<cib><configuration><resources>
          <clone id="cl-virt-lock"><group id="g-virt-lock">
            <primitive id="dlm" class="ocf" provider="pacemaker" type="controld"/>
            <primitive id="gfs2" class="ocf" provider="heartbeat" type="Filesystem"><instance_attributes><nvpair name="directory" value="/mnt/shared"/><nvpair name="fstype" value="gfs2"/></instance_attributes></primitive>
          </group></clone><primitive id="vm-one" class="ocf" provider="heartbeat" type="VirtualDomain"/>
        </resources><constraints><rsc_order first="cl-virt-lock" then="vm-one"/><rsc_colocation rsc="vm-one" with-rsc="cl-virt-lock"/></constraints></configuration></cib>"""
        runtime = """<crm_mon><nodes><node name="node-a" type="member" online="true"/><node name="node-b" type="member" online="true"/></nodes><resources><clone id="cl-virt-lock"><resource id="dlm:0" role="Started" active="true" failed="false"><node name="node-a"/></resource><resource id="gfs2:0" role="Started" active="true" failed="false"><node name="node-a"/></resource></clone></resources></crm_mon>"""
        topology = run_script(cib, runtime)["locking_topology"]
        self.assertTrue(topology["runtime_available"])
        self.assertFalse(topology["runtime_active_on_all_online_nodes"])
        self.assertFalse(topology["complete"])

    def test_does_not_treat_separate_resources_in_a_clone_as_the_documented_group(self) -> None:
        cib = """<cib><configuration><resources>
          <clone id="cl-virt-lock">
            <primitive id="dlm" class="ocf" provider="pacemaker" type="controld"/>
            <primitive id="gfs2" class="ocf" provider="heartbeat" type="Filesystem"><instance_attributes><nvpair name="directory" value="/mnt/shared"/><nvpair name="fstype" value="gfs2"/></instance_attributes></primitive>
          </clone>
        </resources><constraints/></configuration></cib>"""
        topology = run_script(cib)["locking_topology"]
        self.assertTrue(topology["available"])
        self.assertFalse(topology["lock_group_ids"])
        self.assertFalse(topology["lock_clone_ids"])
        self.assertFalse(topology["lock_stack_detected"])
        self.assertFalse(topology["complete"])


if __name__ == "__main__":
    unittest.main()

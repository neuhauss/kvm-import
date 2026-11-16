"""Read-only tests for VirtualDomain peer SSH and QEMU storage checks."""

from __future__ import annotations

import ast
import builtins
import contextlib
import io
import json
import sys
import stat
import subprocess
import tempfile
import unittest
import contextlib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from typing import Any


APP = Path(__file__).resolve().parents[1] / "app.py"


def remote_script(name: str) -> str:
    tree = ast.parse(APP.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == name
            for target in node.targets
        ):
            return ast.literal_eval(node.value)
    raise AssertionError(f"{name} was not found")


class VirtualDomainStorageProbeTests(unittest.TestCase):
    def test_virtualdomain_prepare_gate_requires_live_suse_ha_and_operator_confirmations(self):
        tree = ast.parse(APP.read_text(encoding="utf-8"))
        node = next(item for item in tree.body if isinstance(item, ast.FunctionDef) and item.name == "virtualdomain_prepare_blockers")
        namespace = {"Any": Any, "re": __import__("re"), "VirtualDomainPrepareRequest": object}
        exec(compile(ast.Module(body=[node], type_ignores=[]), "<virtualdomain-prepare-gate>", "exec"), namespace)
        request = SimpleNamespace(config_path="/shared/vm-configs/guest.xml", shared_disks_confirmed=True,
            networks_confirmed=True, remote_libvirt_confirmed=True, fencing_tested=True, security_reviewed=True)
        assessment = {
            "mapping_complete": True, "source_host_id": "host-a", "source_vm_found": True,
            "virtualdomain_agent_on_all_nodes": True, "vm_running_on_nodes": [],
            "nodes": [
                {"host_id": "host-a", "mapping_status": "mapped", "node_online": True, "vm_status": "present",
                 "state": "shut off", "persistent": "yes", "autostart": "no", "uuid": "12345678-1234-1234-1234-123456789abc"},
                {"host_id": "host-b", "mapping_status": "mapped", "node_online": True, "vm_status": "not_defined"},
            ],
            "storage_checks": {
                "config_path": request.config_path, "shared_mount_candidate": True,
                "lockspace_gfs2": {"status": "candidate"}, "disk_paths_not_checked": 0,
                "disk_paths": [{"path": "/shared/guest.qcow2", "writable": True, "exists_on_all_nodes": True, "same_mount_candidate": True}],
                "host_security_settings_consistent": True,
                "nodes": [{"status": "checked", "config": {"parent_exists": True, "file_exists": False,
                    "parent_mount": {"fstype": "gfs2"}}, "ssh_peer_auth": [{"status": "authenticated"}],
                    "disk_paths": [{"path": "/shared/guest.qcow2", "configured_identity_access": "read_write"}]},
                    {"status": "checked", "config": {"parent_exists": True, "file_exists": False,
                    "parent_mount": {"fstype": "gfs2"}}, "ssh_peer_auth": [{"status": "authenticated"}],
                    "disk_paths": [{"path": "/shared/guest.qcow2", "configured_identity_access": "read_write"}]}],
            },
        }
        status = {"nodes": [{"name": "node-a", "online": True, "unclean": False},
                            {"name": "node-b", "online": True, "unclean": False}],
                  "quorum": {"available": True, "quorate": True},
                  "fencing": {"available": True, "configured": True, "stonith_configured": False}}
        diagnostics = {"locking_topology": {"lock_stack_detected": True,
            "runtime_active_on_all_online_nodes": True, "complete": False, "lock_clone_ids": ["dlm-clone"]}}
        blockers = namespace["virtualdomain_prepare_blockers"]
        self.assertEqual(blockers(assessment, status, diagnostics, request), [])

        unsafe = dict(assessment)
        unsafe["nodes"] = [dict(assessment["nodes"][0], state="running"), assessment["nodes"][1]]
        self.assertIn("vm_must_be_shut_off_on_source", blockers(unsafe, status, diagnostics, request))
        no_fence = {**status, "fencing": {"available": True, "configured": False}}
        self.assertIn("cluster_fencing_must_be_configured", blockers(assessment, no_fence, diagnostics, request))
        untested = SimpleNamespace(**{**request.__dict__, "fencing_tested": False})
        self.assertIn("operator_confirmation_required:fencing_tested", blockers(assessment, status, diagnostics, untested))
        self.assertIn("active_suse_dlm_gfs2_lock_clone_required", blockers(assessment, status,
            {"locking_topology": {"lock_stack_detected": True, "runtime_active_on_all_online_nodes": False,
             "complete": False, "lock_clone_ids": []}}, request))

    def test_virtualdomain_prepare_remote_script_exports_xml_and_creates_stopped_resource_only(self):
        script = remote_script("HA_VIRTUALDOMAIN_PREPARE_SCRIPT")
        compile(script, "<virtualdomain-prepare>", "exec")
        with tempfile.TemporaryDirectory() as directory:
            config_path = str(Path(directory) / "guest.xml")
            payload = {"vm_name": "guest", "resource_id": "ha-guest", "config_path": config_path,
                "expected_uuid": "12345678-1234-1234-1234-123456789abc", "lock_clone_id": "dlm-clone",
                "expected_disk_paths": ["/shared/guest.qcow2"],
                "expected_mount_identity": "shared-id", "expected_mount_target": directory}
            calls = []
            crm_config = {}

            def fake_run(command, **kwargs):
                calls.append(command)
                if command[:2] == ["findmnt", "-T"]:
                    return subprocess.CompletedProcess(command, 0, stdout=json.dumps({"filesystems": [{
                        "source": "/dev/shared", "fstype": "gfs2", "uuid": "shared-id", "target": directory,
                        "options": "rw,relatime"}]}), stderr="")
                if command[:4] == ["virsh", "-c", "qemu:///system", "dominfo"]:
                    return subprocess.CompletedProcess(command, 0, stdout="State: shut off\nPersistent: yes\nAutostart: disable\nUUID: " + payload["expected_uuid"] + "\n", stderr="")
                if command[:4] == ["virsh", "-c", "qemu:///system", "dumpxml"]:
                    xml = f"<domain><name>guest</name><uuid>{payload['expected_uuid']}</uuid><devices><disk device='disk'><source file='/shared/guest.qcow2'/></disk></devices></domain>"
                    return subprocess.CompletedProcess(command, 0, stdout=xml, stderr="")
                if command[:4] == ["cibadmin", "-Q", "-o", "resources"]:
                    return subprocess.CompletedProcess(command, 0, stdout='<resources><clone id="dlm-clone"/></resources>', stderr="")
                if command[:4] == ["cibadmin", "-Q", "-o", "constraints"]:
                    return subprocess.CompletedProcess(command, 0, stdout="<constraints/>", stderr="")
                if command[:4] == ["crm", "ra", "info", "ocf:heartbeat:VirtualDomain"]:
                    return subprocess.CompletedProcess(command, 0, stdout="VirtualDomain", stderr="")
                if command[:4] == ["crm", "configure", "load", "update"]:
                    with open(command[4], encoding="utf-8") as handle:
                        crm_config["text"] = handle.read()
                    return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
                raise AssertionError(f"Unexpected command {command!r}")

            output = io.StringIO()
            with patch("subprocess.run", side_effect=fake_run), patch.object(sys, "stdin", io.StringIO(json.dumps(payload))), \
                    contextlib.redirect_stdout(output):
                exec(compile(script, "<virtualdomain-prepare>", "exec"), {"__name__": "__main__"})
            result = json.loads(output.getvalue())
            self.assertTrue(result["success"])
            self.assertEqual(result["resource_state"], "Stopped")
            self.assertEqual(Path(config_path).read_text(encoding="utf-8"),
                f"<domain><name>guest</name><uuid>{payload['expected_uuid']}</uuid><devices><disk device='disk'><source file='/shared/guest.qcow2'/></disk></devices></domain>")
            self.assertIn('meta target-role="Stopped"', crm_config["text"])
            self.assertIn("order ha-guest-after-lock Mandatory: dlm-clone ha-guest", crm_config["text"])
            self.assertIn("colocation ha-guest-with-lock inf: ha-guest dlm-clone", crm_config["text"])
            self.assertFalse(any(command[:3] == ["crm", "resource", "start"] for command in calls))

    def test_virtualdomain_remote_script_never_overwrites_existing_xml(self):
        script = remote_script("HA_VIRTUALDOMAIN_PREPARE_SCRIPT")
        compile(script, "<virtualdomain-prepare>", "exec")
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "guest.xml"
            config_path.write_text("keep", encoding="utf-8")
            payload = {"vm_name": "guest", "resource_id": "ha-guest", "config_path": str(config_path),
                "expected_uuid": "12345678-1234-1234-1234-123456789abc", "lock_clone_id": "dlm-clone",
                "expected_disk_paths": [],
                "expected_mount_identity": "shared-id", "expected_mount_target": directory}
            output = io.StringIO()
            with patch.object(sys, "stdin", io.StringIO(json.dumps(payload))), contextlib.redirect_stdout(output):
                with self.assertRaises(SystemExit) as error:
                    exec(compile(script, "<virtualdomain-prepare>", "exec"), {"__name__": "__main__"})
            self.assertIn("already exists", str(error.exception))
            self.assertEqual(config_path.read_text(encoding="utf-8"), "keep")

    def test_generic_resource_api_rejects_virtualdomain_bypass(self):
        tree = ast.parse(APP.read_text(encoding="utf-8"))
        node = next(item for item in tree.body if isinstance(item, ast.FunctionDef) and item.name == "mutate_cluster_resource")
        node.decorator_list = []

        class FakeHTTPException(Exception):
            def __init__(self, status_code, detail): super().__init__(detail); self.status_code = status_code

        namespace = {"Any": Any, "ClusterResourceMutation": object, "AuthorizationContext": object,
            "Depends": lambda value: value, "require_permission": lambda _role: object(), "HTTPException": FakeHTTPException}
        exec(compile(ast.Module(body=[node], type_ignores=[]), "<generic-resource-route>", "exec"), namespace)
        request = SimpleNamespace(action="create", agent="OCF:HEARTBEAT:VirtualDomain", parameters={}, resource_id="ha-test")
        with self.assertRaises(FakeHTTPException) as error:
            namespace["mutate_cluster_resource"]("host-a", request, SimpleNamespace(user_id="operator"))
        self.assertEqual(error.exception.status_code, 409)
        self.assertIn("guided VM preflight", str(error.exception))
    def test_security_profile_comparison_requires_complete_fresh_facts(self):
        tree = ast.parse(APP.read_text(encoding="utf-8"))
        node = next(item for item in tree.body if isinstance(item, ast.FunctionDef) and item.name == "virtualdomain_security_settings_consistent")
        namespace = {"Any": Any, "json": json}
        exec(compile(ast.Module(body=[node], type_ignores=[]), "<security-profile>", "exec"), namespace)
        compare = namespace["virtualdomain_security_settings_consistent"]
        profile = {"selinux_mode": "enforcing", "apparmor_enabled": True,
                   "configured_libvirt_security_drivers": ["apparmor"],
                   "security_default_confined": True, "security_require_confined": True,
                   "vm_process_context": "vm-specific-label"}
        same = [{"status": "checked", "security": profile},
                {"status": "checked", "security": {**profile, "vm_process_context": "other-vm-label"}}]
        self.assertTrue(compare(same, True))
        self.assertFalse(compare([same[0], {"status": "checked", "security": {**profile, "selinux_mode": "permissive"}}], True))
        self.assertIsNone(compare([same[0], {"status": "inspection_failed", "security": None}], True))
        self.assertIsNone(compare(same, False))

    def test_lockspace_gfs2_assessment_requires_matching_complete_mapped_nodes(self):
        tree = ast.parse(APP.read_text(encoding="utf-8"))
        node = next(item for item in tree.body if isinstance(item, ast.FunctionDef) and item.name == "virtualdomain_lockspace_gfs2_assessment")
        namespace = {"Any": Any, "os": __import__("os")}
        exec(compile(ast.Module(body=[node], type_ignores=[]), "<lockspace-gfs2>", "exec"), namespace)
        assess = namespace["virtualdomain_lockspace_gfs2_assessment"]

        def member(name="node-a", *, source="/dev/disk/by-uuid/shared", uuid="gfs-id", lockd=True, mount_type="gfs2"):
            mount = {"source": source, "fstype": mount_type, "uuid": uuid, "target": "/mnt/gfs"}
            return {"cluster_node": name, "mapping_status": "mapped", "node_online": True,
                    "virtualization_locking": {"lock_manager_is_lockd": lockd,
                        "file_lockspace_dir": "/mnt/gfs/lockspace", "lockspace_path_safe": True,
                        "lockspace_directory_exists": True, "lockspace_mount": mount,
                        "gfs2_resources": [{"id": "gfs2", "directory": "/mnt/gfs", "mount": mount}],
                        "gfs2_resources_available": True}}

        result = assess([member(), member("node-b", source="/dev/gfs-alias")], True)
        self.assertEqual(result["status"], "candidate")
        self.assertFalse(result["is_proof_of_shared_storage"])
        self.assertEqual([item["status"] for item in result["nodes"]], ["candidate", "candidate"])
        self.assertEqual(assess([member(), member("node-b", uuid="other-id")], True)["status"], "inconsistent")
        self.assertEqual(assess([member(lockd=False)], True)["nodes"][0]["reason"], "lock_manager_not_lockd")
        self.assertEqual(assess([member(), {"cluster_node": "node-b", "mapping_status": "unmapped", "node_online": True}], False)["status"], "unknown")
        unavailable = member()
        unavailable["virtualization_locking"]["gfs2_resources_available"] = None
        self.assertEqual(assess([unavailable], True)["status"], "unknown")

    def test_resource_agent_script_compiles_and_exports_only_gfs2_mount_facts(self):
        script = remote_script("HA_RESOURCE_AGENTS_SCRIPT")
        compile(script, "<ha-resource-agents>", "exec")
        self.assertIn("'gfs2_resources':gfs2_resources", script)
        self.assertIn("('directory','fstype')", script)
        self.assertNotIn("password", script.lower())

    def test_resource_agent_script_reads_safe_gfs2_cib_settings_without_exposing_other_parameters(self):
        script = remote_script("HA_RESOURCE_AGENTS_SCRIPT")
        cib = '''<cib><configuration><resources><primitive id="lockfs" class="ocf" provider="heartbeat" type="Filesystem">
          <instance_attributes><nvpair name="directory" value="/mnt/shared"/><nvpair name="fstype" value="gfs2"/><nvpair name="device" value="/dev/secret-device"/></instance_attributes>
        </primitive><primitive id="ignored" class="ocf" provider="heartbeat" type="Filesystem"><instance_attributes>
          <nvpair name="directory" value="/unsafe/../path"/><nvpair name="fstype" value="gfs2"/></instance_attributes></primitive></resources></configuration></cib>'''
        real_open = builtins.open

        def fake_open(path, *args, **kwargs):
            if path == "/etc/libvirt/qemu.conf": return io.StringIO('lock_manager = "lockd"\n')
            if path == "/etc/libvirt/qemu-lockd.conf": return io.StringIO('file_lockspace_dir = "/mnt/shared/locks"\n')
            return real_open(path, *args, **kwargs)

        def fake_run(args, **_kwargs):
            if args[:3] == ["crm", "ra", "classes"]:
                return subprocess.CompletedProcess(args, 0, stdout="ocf\nsystemd\n", stderr="")
            if args[:3] == ["crm", "ra", "list"]:
                return subprocess.CompletedProcess(args, 0, stdout="heartbeat:Filesystem\n", stderr="")
            if args[0] == "cibadmin":
                return subprocess.CompletedProcess(args, 0, stdout=cib, stderr="")
            if args[0] == "findmnt":
                return subprocess.CompletedProcess(args, 0, stdout=json.dumps({"filesystems": [{"source": "/dev/shared", "fstype": "gfs2", "uuid": "gfs-id", "target": "/mnt/shared"}]}), stderr="")
            if args[:2] == ["systemctl", "is-active"]:
                return subprocess.CompletedProcess(args, 0, stdout="active\n", stderr="")
            raise AssertionError(f"Unexpected command: {args!r}")

        output = io.StringIO()
        with patch("builtins.open", side_effect=fake_open), patch("subprocess.run", side_effect=fake_run), \
                patch("os.path.isdir", return_value=True), patch.object(sys, "argv", ["probe"]), \
                contextlib.redirect_stdout(output):
            exec(compile(script, "<ha-resource-agents>", "exec"), {"__name__": "__main__"})
        result = json.loads(output.getvalue())
        locking = result["virtualization_locking"]
        self.assertTrue(locking["lock_manager_is_lockd"])
        self.assertTrue(locking["gfs2_resources_available"])
        self.assertEqual(locking["gfs2_resources"], [{"id": "lockfs", "directory": "/mnt/shared", "mount": {"source": "/dev/shared", "fstype": "gfs2", "uuid": "gfs-id", "target": "/mnt/shared"}}])
        self.assertNotIn("secret-device", output.getvalue())

    def test_preflight_route_runs_peer_and_disk_checks_without_an_xml_path(self):
        tree = ast.parse(APP.read_text(encoding="utf-8"))
        route_node = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "get_virtualdomain_vm_preflight")
        security_node = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "virtualdomain_security_settings_consistent")
        locking_node = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "virtualdomain_lockspace_gfs2_assessment")
        route_node.decorator_list = []
        hosts = [
            {"id": "host-a", "name": "node-a", "hostname": "node-a", "address": "192.0.2.10"},
            {"id": "host-b", "name": "node-b", "hostname": "node-b", "address": "192.0.2.11"},
        ]
        calls = []
        detail = {"name": "guest", "uuid": "guest-uuid", "state": "shut off", "disks": [
            {"type": "file", "target": "vda", "source": "/shared/guest.qcow2", "format": "qcow2", "device": "disk", "readonly": False},
        ], "interfaces": []}

        class FakeDb:
            def __enter__(self): return self
            def __exit__(self, *_args): return False
            def execute(self, _query): return hosts

        def run_remote(host, script, *args, **_kwargs):
            calls.append((host["id"], script, args))
            if script == "VM_DETAIL": return json.dumps(detail)
            if script == "AGENTS": return json.dumps({"agents": ["ocf:heartbeat:VirtualDomain"]})
            if script == "STORAGE": return json.dumps({"config": None, "disk_paths": [], "ssh_peer_auth": [], "security": {
                "selinux_mode": "enforcing", "apparmor_enabled": True,
                "configured_libvirt_security_drivers": ["apparmor"],
                "security_default_confined": True, "security_require_confined": True,
                "vm_process_context": "vm-specific-label",
            }})
            raise AssertionError(f"Unexpected remote script {script!r}")

        class FakeHTTPException(Exception):
            def __init__(self, status_code, detail): super().__init__(detail); self.status_code = status_code

        namespace = {
            "Any": Any, "Depends": lambda value: value, "require_permission": lambda _role: object(),
            "AuthorizationContext": type("AuthorizationContext", (), {}), "HTTPException": FakeHTTPException,
            "re": __import__("re"), "json": json, "os": __import__("os"), "ThreadPoolExecutor": ThreadPoolExecutor,
            "require_verified_ha_cluster": lambda _host_id: (hosts[0], {"nodes": [{"name": "node-a"}, {"name": "node-b"}]}),
            "connect_db": FakeDb, "cockpit_host_record": lambda host_id: next(host for host in hosts if host["id"] == host_id),
            "run_sudo_python": run_remote, "VM_DETAIL_SCRIPT": "VM_DETAIL", "HA_RESOURCE_AGENTS_SCRIPT": "AGENTS",
            "VM_HA_STORAGE_PROBE_SCRIPT": "STORAGE", "record_audit": lambda *_args: None,
        }
        exec(compile(ast.Module(body=[security_node, locking_node, route_node], type_ignores=[]), "<preflight-route>", "exec"), namespace)
        result = namespace["get_virtualdomain_vm_preflight"]("host-a", "guest", access=SimpleNamespace(user_id="test-user"))
        self.assertEqual(result["storage_checks"]["config_path"], "")
        self.assertTrue(result["storage_checks"]["host_security_settings_consistent"])
        self.assertEqual(result["storage_checks"]["lockspace_gfs2"]["status"], "unknown")
        storage_calls = [call for call in calls if call[1] == "STORAGE"]
        self.assertEqual(len(storage_calls), 2)
        self.assertEqual(json.loads(storage_calls[0][2][0][1]), [{"path": "/shared/guest.qcow2", "writable": True}])
        self.assertEqual(json.loads(storage_calls[0][2][0][2]), ["node-b"])

    def test_vm_detail_remote_script_compiles_and_exports_disk_access_modes(self):
        script = remote_script("VM_DETAIL_SCRIPT")
        compile(script, "<vm-detail>", "exec")
        self.assertIn("'readonly':disk.find('./readonly') is not None", script)
        self.assertIn("'device':access_mode['device']", script)

    def run_probe(self, *, qemu_config="", ssh_rc=0, access_rc=0, peer_names=None, disk_paths=None,
                  selinux_mode="Enforcing", apparmor_rc=0, vm_name="", vm_pid=None,
                  process_context="unconfined"):
        calls = []

        def fake_open(path, *args, **kwargs):
            if path == "/etc/libvirt/qemu.conf":
                return io.StringIO(qemu_config)
            if path == "/proc/42/attr/current" and vm_pid == "42":
                return io.StringIO(process_context)
            raise FileNotFoundError(path)

        def fake_run(command, **kwargs):
            calls.append((command, kwargs))
            if command[0] == "findmnt":
                return SimpleNamespace(returncode=0, stdout=json.dumps({"filesystems": [{
                    "source": "shared:/vm", "fstype": "nfs4", "uuid": None, "target": "/shared", "options": "rw",
                }]}), stderr="")
            if command[0] == "ssh":
                return SimpleNamespace(returncode=ssh_rc, stdout="", stderr="")
            if command[0] == "getenforce":
                return SimpleNamespace(returncode=0, stdout=selinux_mode, stderr="")
            if command[:2] == ["aa-status", "--enabled"]:
                return SimpleNamespace(returncode=apparmor_rc, stdout="", stderr="")
            if command[:4] == ["virsh", "-c", "qemu:///system", "dominfo"]:
                stdout = "State: running\nPID: 42\n" if vm_pid == "42" else "State: shut off\nPID: -\n"
                return SimpleNamespace(returncode=0, stdout=stdout, stderr="")
            if "-c" in command and "os.access" in command[command.index("-c") + 1]:
                return SimpleNamespace(returncode=access_rc, stdout="", stderr="")
            raise AssertionError(f"Unexpected command: {command}")

        output = io.StringIO()
        argv = ["storage-probe", "", json.dumps(disk_paths or []), json.dumps(peer_names or ["node-b"]), vm_name]
        with patch("builtins.open", side_effect=fake_open), \
             patch("subprocess.run", side_effect=fake_run), \
             patch("os.path.exists", return_value=True), \
             patch("os.path.isfile", return_value=True), \
             patch("os.stat", return_value=SimpleNamespace(st_mode=stat.S_IFREG | 0o600)), \
             patch("os.path.isdir", return_value=False), \
             patch("pwd.getpwnam", return_value=SimpleNamespace(pw_uid=1001)), \
             patch("grp.getgrnam", return_value=SimpleNamespace(gr_gid=1002)), \
             patch("os.getgrouplist", return_value=[1002]), \
             patch("shutil.which", return_value="/usr/sbin/aa-status"), \
             patch.object(sys, "argv", argv), \
             contextlib.redirect_stdout(output):
            exec(compile(remote_script("VM_HA_STORAGE_PROBE_SCRIPT"), "<vm-storage-probe>", "exec"), {"__name__": "__main__"})
        return json.loads(output.getvalue()), calls

    def test_checks_noninteractive_root_ssh_and_qemu_rw_access_with_explicit_identity(self):
        result, calls = self.run_probe(
            qemu_config='user = "qemu"\ngroup = "qemu"\n',
            disk_paths=[{"path": "/shared/guest.qcow2", "writable": True}],
        )
        self.assertEqual(result["ssh_peer_auth"], [{"peer": "node-b", "status": "authenticated"}])
        self.assertEqual(result["qemu_identity"], {"user": "qemu", "group": "qemu"})
        self.assertEqual(result["disk_paths"][0]["configured_identity_access"], "read_write")
        ssh_command = next(command for command, _ in calls if command[0] == "ssh")
        self.assertIn("BatchMode=yes", ssh_command)
        self.assertIn("StrictHostKeyChecking=yes", ssh_command)
        self.assertIn("PasswordAuthentication=no", ssh_command)
        self.assertEqual(ssh_command[-2:], ["root@node-b", "true"])

    def test_reports_unknown_qemu_identity_without_guessing_defaults(self):
        result, _ = self.run_probe(disk_paths=[{"path": "/shared/guest.qcow2", "writable": False}])
        self.assertIsNone(result["qemu_identity"])
        self.assertEqual(result["disk_paths"][0]["configured_identity_access"], "identity_unknown")

    def test_reports_read_only_selinux_apparmor_libvirt_and_vm_process_context(self):
        result, _ = self.run_probe(
            qemu_config='security_driver = ["apparmor", "selinux"]\nsecurity_default_confined = 1\nsecurity_require_confined = 1\n',
            vm_name="guest", vm_pid="42", process_context="libvirt-guest (enforce)",
        )
        self.assertEqual(result["security"]["selinux_mode"], "enforcing")
        self.assertTrue(result["security"]["apparmor_enabled"])
        self.assertEqual(result["security"]["configured_libvirt_security_drivers"], ["apparmor", "selinux"])
        self.assertTrue(result["security"]["security_default_confined"])
        self.assertTrue(result["security"]["security_require_confined"])
        self.assertEqual(result["security"]["vm_process_context"], "libvirt-guest (enforce)")
        self.assertNotIn("stderr", json.dumps(result))

    def test_reports_disabled_apparmor_and_non_running_vm_without_claiming_confinement(self):
        result, _ = self.run_probe(selinux_mode="Permissive", apparmor_rc=1)
        self.assertEqual(result["security"]["selinux_mode"], "permissive")
        self.assertFalse(result["security"]["apparmor_enabled"])
        self.assertEqual(result["security"]["vm_process_context"], "not_checked")

    def test_reports_failed_ssh_and_denied_qemu_access_without_returning_stderr(self):
        result, _ = self.run_probe(
            qemu_config='user = "qemu"\ngroup = "qemu"\n', ssh_rc=255, access_rc=1,
            disk_paths=[{"path": "/shared/guest.qcow2", "writable": True}],
        )
        self.assertEqual(result["ssh_peer_auth"][0]["status"], "authentication_failed")
        self.assertEqual(result["disk_paths"][0]["configured_identity_access"], "access_denied")
        self.assertNotIn("stderr", json.dumps(result))

    def test_rejects_invalid_peer_names_without_running_ssh(self):
        result, calls = self.run_probe(peer_names=["-oProxyCommand=bad", "node/bad"])
        self.assertEqual([item["status"] for item in result["ssh_peer_auth"]], ["invalid_peer_name", "invalid_peer_name"])
        self.assertFalse(any(command[0] == "ssh" for command, _ in calls))


if __name__ == "__main__":
    unittest.main()

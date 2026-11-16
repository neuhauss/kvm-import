"""Prevent direct libvirt administration of VMs owned by SUSE Pacemaker."""

from __future__ import annotations

import ast
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


APP = Path(__file__).resolve().parents[1] / "app.py"
TREE = ast.parse(APP.read_text(encoding="utf-8"))


def guard_source() -> str:
    assignment = next(
        item for item in TREE.body
        if isinstance(item, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "VM_PACEMAKER_VM_GUARD_SCRIPT" for target in item.targets)
    )
    assert isinstance(assignment.value, ast.Constant)
    return assignment.value.value


class PacemakerVmOwnershipGuardTests(unittest.TestCase):
    def run_guard(self, responses: list[subprocess.CompletedProcess[str]], *, cibadmin: bool = True) -> None:
        script = guard_source() + "\nensure_vm_not_pacemaker_managed('guest')\n"
        namespace: dict[str, object] = {}
        with patch("subprocess.run", side_effect=responses), patch("shutil.which", return_value="/usr/sbin/cibadmin" if cibadmin else None):
            exec(compile(script, "<pacemaker-vm-guard>", "exec"), namespace)

    @staticmethod
    def completed(args: list[str], returncode: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args, returncode, stdout, stderr)

    def test_inactive_pacemaker_does_not_block_regular_kvm_administration(self) -> None:
        self.run_guard([self.completed(["systemctl", "is-active", "pacemaker"], 3, "inactive\n")])

    def test_managed_vm_is_blocked_by_matching_domain_uuid(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "guest.xml"
            config_path.write_text(
                "<domain><name>guest</name><uuid>12345678-1234-1234-1234-123456789abc</uuid></domain>",
                encoding="utf-8",
            )
            cib = f'<cib><configuration><resources><primitive id="ha-guest" class="ocf" provider="heartbeat" type="VirtualDomain"><instance_attributes><nvpair name="config" value="{config_path}"/></instance_attributes></primitive></resources></configuration></cib>'
            responses = [
                self.completed(["systemctl", "is-active", "pacemaker"], stdout="active\n"),
                self.completed(["cibadmin", "-Q"], stdout=cib),
                self.completed(["virsh", "-c", "qemu:///system", "domuuid", "guest"], stdout="12345678-1234-1234-1234-123456789ABC\n"),
            ]
            with self.assertRaisesRegex(SystemExit, "managed by Pacemaker resource ha-guest"):
                self.run_guard(responses)

    def test_unmanaged_vm_remains_available_when_cib_maps_a_different_guest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "other.xml"
            config_path.write_text("<domain><name>other</name><uuid>aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa</uuid></domain>", encoding="utf-8")
            cib = f'<cib><configuration><resources><primitive id="ha-other" class="ocf" provider="heartbeat" type="VirtualDomain"><instance_attributes><nvpair name="config" value="{config_path}"/></instance_attributes></primitive></resources></configuration></cib>'
            self.run_guard([
                self.completed(["systemctl", "is-active", "pacemaker"], stdout="active\n"),
                self.completed(["cibadmin", "-Q"], stdout=cib),
                self.completed(["virsh", "-c", "qemu:///system", "domuuid", "guest"], stdout="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb\n"),
            ])

    def test_new_vm_name_cannot_collide_with_a_configured_pacemaker_guest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "guest.xml"
            config_path.write_text("<domain><name>guest</name><uuid>aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa</uuid></domain>", encoding="utf-8")
            cib = f'<cib><configuration><resources><primitive id="ha-guest" class="ocf" provider="heartbeat" type="VirtualDomain"><instance_attributes><nvpair name="config" value="{config_path}"/></instance_attributes></primitive></resources></configuration></cib>'
            namespace = {"__name__": "__main__"}
            script = guard_source() + "\nensure_vm_name_not_pacemaker_managed('guest')\n"
            responses = [
                self.completed(["systemctl", "is-active", "pacemaker"], stdout="active\n"),
                self.completed(["cibadmin", "-Q"], stdout=cib),
            ]
            with patch("subprocess.run", side_effect=responses), patch("shutil.which", return_value="/usr/sbin/cibadmin"):
                with self.assertRaisesRegex(SystemExit, "name is reserved by Pacemaker resource ha-guest"):
                    exec(compile(script, "<pacemaker-vm-guard>", "exec"), namespace)

    def test_active_cluster_cib_failure_fails_closed(self) -> None:
        with self.assertRaisesRegex(SystemExit, "configuration cannot be read"):
            self.run_guard([
                self.completed(["systemctl", "is-active", "pacemaker"], stdout="active\n"),
                self.completed(["cibadmin", "-Q"], 1, stderr="not connected"),
            ])

    def test_unreadable_virtualdomain_config_fails_closed(self) -> None:
        cib = '<cib><configuration><resources><primitive id="ha-guest" class="ocf" provider="heartbeat" type="VirtualDomain"><instance_attributes><nvpair name="config" value="/missing/guest.xml"/></instance_attributes></primitive></resources></configuration></cib>'
        responses = [
            self.completed(["systemctl", "is-active", "pacemaker"], stdout="active\n"),
            self.completed(["cibadmin", "-Q"], stdout=cib),
            self.completed(["virsh", "-c", "qemu:///system", "domuuid", "guest"], stdout="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb\n"),
        ]
        with self.assertRaisesRegex(SystemExit, "cannot be verified"):
            self.run_guard(responses)

    def test_mutating_vm_endpoints_include_the_guard(self) -> None:
        guarded_routes = {
            "create_vm", "control_vm", "delete_vms", "configure_vm", "set_vm_autostart",
            "configure_vm_details", "configure_vm_devices", "control_vm_snapshot",
            "download_vm_snapshot", "configure_vm_graphics",
        }
        route_names = {
            item.name for item in TREE.body
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name in guarded_routes
        }
        self.assertEqual(route_names, guarded_routes)
        source = APP.read_text(encoding="utf-8")
        for name in guarded_routes - {"configure_vm_graphics", "create_vm"}:
            route = next(item for item in TREE.body if isinstance(item, ast.FunctionDef) and item.name == name)
            rendered = ast.get_source_segment(source, route) or ""
            self.assertIn("VM_PACEMAKER_VM_GUARD_SCRIPT", rendered, name)
            self.assertIn("ensure_vm_not_pacemaker_managed", rendered, name)
        create_route = next(item for item in TREE.body if isinstance(item, ast.FunctionDef) and item.name == "create_vm")
        self.assertIn("ensure_vm_name_not_pacemaker_managed", ast.get_source_segment(source, create_route) or "")
        graphics_constant = next(
            item for item in TREE.body if isinstance(item, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "VM_GRAPHICS_CONFIG_SCRIPT" for target in item.targets)
        )
        self.assertIn("VM_PACEMAKER_VM_GUARD_SCRIPT", ast.unparse(graphics_constant))
        self.assertIn("ensure_vm_not_pacemaker_managed(name)", ast.unparse(graphics_constant))


if __name__ == "__main__":
    unittest.main()

"""Offline API regression tests. No Rancher, SSH host, libvirt, or S3 calls."""

from __future__ import annotations

import os
import base64
import json
import subprocess
import shlex
import sys
import tempfile
import unittest
from contextlib import ExitStack, redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch


SERVICE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVICE_DIR))

# These values are deliberately test-only and are set before importing the API,
# which reads its encryption key and role mappings during module initialization.
os.environ["KVM_CREDENTIAL_KEY"] = "offline-test-key-that-is-not-a-real-secret"
os.environ["KVM_ALLOWED_GLOBAL_ROLES"] = "admin"
os.environ["KVM_VIEWER_GLOBAL_ROLES"] = "kvm-viewer"
os.environ["KVM_VM_OPERATOR_GLOBAL_ROLES"] = "kvm-vm-operator"
os.environ["KVM_HOST_OPERATOR_GLOBAL_ROLES"] = "kvm-host-operator"
os.environ["KVM_NETWORK_OPERATOR_GLOBAL_ROLES"] = "kvm-network-operator"
os.environ["KVM_STORAGE_OPERATOR_GLOBAL_ROLES"] = "kvm-storage-operator"
os.environ["KVM_SOFTWARE_OPERATOR_GLOBAL_ROLES"] = "kvm-software-operator"
os.environ["KVM_SUBSCRIPTION_OPERATOR_GLOBAL_ROLES"] = "kvm-subscription-operator"
os.environ["KVM_ACCOUNT_OPERATOR_GLOBAL_ROLES"] = "kvm-account-operator"
os.environ["KVM_SERVICE_OPERATOR_GLOBAL_ROLES"] = "kvm-service-operator"
os.environ["KVM_CLUSTER_OPERATOR_GLOBAL_ROLES"] = "kvm-cluster-operator"
os.environ["KVM_S3_ALLOWED_ENDPOINT_HOSTS"] = ""
os.environ["RANCHER_API_URL"] = "https://rancher.invalid"
_test_data = tempfile.TemporaryDirectory(prefix="rancher-kvm-tests-")
os.environ["KVM_DB_PATH"] = str(Path(_test_data.name) / "bootstrap.sqlite3")

import app as api  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


class KvmApiTests(unittest.TestCase):
    def test_cluster_resource_mutation_model_accepts_clone_modes_and_rejects_unknown_mode(self) -> None:
        standard = api.ClusterResourceMutation.model_validate({
            "action": "create_clone", "resource_id": "web-clone", "child_id": "web", "clone_type": "standard",
        })
        promotable = api.ClusterResourceMutation.model_validate({
            "action": "create_clone", "resource_id": "db-clone", "child_id": "db", "clone_type": "promotable",
        })
        delete_clone = api.ClusterResourceMutation.model_validate({
            "action": "delete_clone", "resource_id": "db-clone", "child_id": "db",
        })
        self.assertEqual(standard.clone_type, "standard")
        self.assertEqual(promotable.clone_type, "promotable")
        self.assertEqual(delete_clone.action, "delete_clone")
        self.assertEqual(delete_clone.child_id, "db")
        fencing = api.ClusterResourceMutation.model_validate({
            "action": "create_stonith", "resource_id": "fence-node-a", "agent": "stonith:fence_ipmilan",
            "fencing_target": "node-a", "parameters": {"password": "test-secret"},
        })
        fencing_edit = api.ClusterResourceMutation.model_validate({
            "action": "edit_stonith", "resource_id": "fence-node-a", "agent": "stonith:fence_ipmilan",
            "fencing_target": "node-a", "parameters": {"password": "replacement-secret"},
            "parameter_removals": ["lanplus"],
        })
        self.assertEqual(fencing.fencing_target, "node-a")
        self.assertEqual(fencing.monitor_interval, "30min")
        self.assertEqual(fencing_edit.action, "edit_stonith")
        self.assertEqual(fencing_edit.parameter_removals, ["lanplus"])
        with self.assertRaises(ValueError):
            api.ClusterResourceMutation.model_validate({
                "action": "create_clone", "resource_id": "db-clone", "child_id": "db", "clone_type": "unsupported",
            })

    def test_fencing_mutation_does_not_echo_or_audit_device_credentials_on_failure(self) -> None:
        host = self.create_test_host(name="fencing-cluster-node")
        cluster_status = json.dumps({"nodes": [{"name": "node-a"}, {"name": "node-b"}], "resources": []})
        secret = "test-device-password-not-for-logs"
        def remote(_host, script, **_kwargs):
            if script == api.HA_CLUSTER_STATUS_SCRIPT:
                return cluster_status
            if script == api.HA_RESOURCE_MUTATION_SCRIPT:
                raise RuntimeError(f"crm configure rejected password={secret}")
            raise AssertionError("Unexpected remote SUSE HA script")
        with patch.object(api, "cockpit_host_record", return_value=host), patch.object(api, "run_sudo_python", side_effect=remote):
            response = self.client.post(
                f"/kvm-api/clusters/{host['id']}/resources/config", headers=self.headers("cluster-token"),
                json={"action": "create_stonith", "resource_id": "fence-node-a", "agent": "stonith:fence_ipmilan",
                      "fencing_target": "node-a", "parameters": {"password": secret}},
            )
        self.assertEqual(response.status_code, 422, response.text)
        self.assertNotIn(secret, response.text)
        self.assertIn("[redacted]", response.text)
        with api.connect_db() as db:
            audit = db.execute("SELECT action,target,detail FROM audit_events ORDER BY occurred_at DESC LIMIT 1").fetchone()
        self.assertIsNotNone(audit)
        self.assertEqual(audit["action"], "cluster.resource.create_stonith")
        self.assertNotIn(secret, " ".join(str(value or "") for value in audit))

    def test_fencing_edit_mutation_redacts_replacement_credentials(self) -> None:
        host = self.create_test_host(name="fencing-edit-node")
        cluster_status = json.dumps({"nodes": [{"name": "node-a"}], "resources": []})
        secret = "new-fencing-password-never-returned"
        def remote(_host, script, **_kwargs):
            if script == api.HA_CLUSTER_STATUS_SCRIPT:
                return cluster_status
            if script == api.HA_RESOURCE_MUTATION_SCRIPT:
                raise RuntimeError(f"crmsh error near {secret}")
            raise AssertionError("Unexpected remote SUSE HA script")
        with patch.object(api, "cockpit_host_record", return_value=host), patch.object(api, "run_sudo_python", side_effect=remote):
            response = self.client.post(
                f"/kvm-api/clusters/{host['id']}/resources/config", headers=self.headers("cluster-token"),
                json={"action": "edit_stonith", "resource_id": "fence-node-a", "agent": "stonith:fence_ipmilan",
                      "fencing_target": "node-a", "parameters": {"password": secret}},
            )
        self.assertEqual(response.status_code, 422, response.text)
        self.assertNotIn(secret, response.text)
        with api.connect_db() as db:
            audit = db.execute("SELECT action,target,detail FROM audit_events ORDER BY occurred_at DESC LIMIT 1").fetchone()
        self.assertIsNotNone(audit)
        self.assertEqual(audit["action"], "cluster.resource.edit_stonith")
        self.assertNotIn(secret, " ".join(str(value or "") for value in audit))

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="rancher-kvm-case-")
        self.role_by_token = {
            "admin-token": ("admin",),
            "viewer-token": ("kvm-viewer",),
            "vm-operator-token": ("kvm-vm-operator",),
            "host-operator-token": ("kvm-host-operator",),
            "network-token": ("kvm-network-operator",),
            "storage-token": ("kvm-storage-operator",),
            "software-token": ("kvm-software-operator",),
            "subscription-token": ("kvm-subscription-operator",),
            "account-token": ("kvm-account-operator",),
            "service-token": ("kvm-service-operator",),
            "cluster-token": ("kvm-cluster-operator",),
            "network-storage-token": ("kvm-network-operator", "kvm-storage-operator"),
            "unmapped-token": (),
        }
        self.stack = ExitStack()
        self.stack.enter_context(patch.object(api, "DB_PATH", Path(self.temp_dir.name) / "test.sqlite3"))
        self.stack.enter_context(patch.object(api, "rancher_get", side_effect=self.fake_rancher_get))
        self.stack.enter_context(patch.object(api, "probe", side_effect=self.fake_probe))
        self.client = self.stack.enter_context(TestClient(api.app))

    def tearDown(self) -> None:
        self.stack.close()
        self.temp_dir.cleanup()

    def fake_rancher_get(self, path: str, token: str | None = None, session_cookie: str | None = None):
        if not token and not session_cookie:
            raise AssertionError("The API tried to contact Rancher without test credentials")
        user_id = f"user-{token or 'cookie-test'}"
        if path == "/v3/token":
            return {"userId": user_id}
        if path == f"/v3/users/{user_id}":
            return {"id": user_id, "username": "test-user"}
        if path == f"/v3/globalRoleBindings?userId={user_id}":
            roles = self.role_by_token.get(token or "", ())
            return {"data": [{"globalRoleId": role} for role in roles]}
        raise AssertionError(f"Unexpected Rancher API request in offline test: {path}")

    @staticmethod
    def fake_probe(host: dict, **kwargs):
        return {
            "hostname": "kvm-test.example.invalid",
            "status": "ready",
            "cpu_count": 4,
            "memory_total_bytes": 8 * 1024**3,
            "last_checked_at": "2026-01-01T00:00:00+00:00",
            "ssh_host_key": "ssh-ed25519 dGVzdC1ob3N0LWtleQ==",
        }

    @staticmethod
    def headers(token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    def test_remote_iso_url_accepts_public_https_iso(self):
        with patch.object(api.socket, "getaddrinfo", return_value=[(2, 1, 6, "", ("93.184.216.34", 443))]):
            self.assertEqual(api.validate_public_iso_url(" https://example.org/test.iso "), "https://example.org/test.iso")

    def test_remote_iso_url_rejects_unsafe_targets(self):
        for value in ("http://example.org/test.iso", "https://user@example.org/test.iso", "https://example.org:8443/test.iso", "https://example.org/test.iso#fragment", "https://example.org/not-an-iso"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                api.validate_public_iso_url(value)
        with patch.object(api.socket, "getaddrinfo", return_value=[(2, 1, 6, "", ("127.0.0.1", 443))]), self.assertRaises(ValueError):
            api.validate_public_iso_url("https://example.org/test.iso")

    def test_vm_create_model_supports_remote_iso_and_keeps_local_iso(self):
        remote = api.VMCreate(name="test-vm", pool="default", volume="disk.qcow2", network="default", vcpus=1, memory_mib=512, iso_url="https://example.org/alpine.iso")
        local = api.VMCreate(name="test-vm", pool="default", volume="disk.qcow2", network="default", vcpus=1, memory_mib=512, iso_path="/var/lib/libvirt/images/test.iso")
        self.assertTrue(remote.iso_url)
        self.assertEqual(local.iso_path, "/var/lib/libvirt/images/test.iso")

    def test_vm_create_model_allows_iso_install_to_create_a_new_disk(self):
        payload = api.VMCreate(
            name="test-vm", pool="default", network="default", vcpus=1,
            memory_mib=512, iso_url="https://example.org/alpine.iso",
            create_disk=True, disk_size_gib=2,
        )
        self.assertIsNone(payload.volume)
        self.assertTrue(payload.create_disk)
        self.assertEqual(payload.disk_size_gib, 2)

    def test_vm_create_creates_qcow2_boot_disk_without_existing_volume(self):
        host = self.create_test_host()
        payload = {
            "name": "test-vm", "pool": "default", "volume": None,
            "network": "default", "vcpus": 1, "memory_mib": 512,
            "iso_path": "/var/lib/libvirt/images/alpine.iso",
            "create_disk": True, "disk_size_gib": 2,
        }
        with patch.object(api, "run_sudo_python", return_value="VM created and started") as remote:
            response = self.client.post(
                f"/kvm-api/hosts/{host['id']}/vms/create",
                headers=self.headers("admin-token"), json=payload,
            )
        self.assertEqual(response.status_code, 200, response.text)
        script = remote.call_args.args[1]
        self.assertIn("vol-create-as", script)
        self.assertIn("vol-delete", script)
        self.assertIn("Creating a new boot disk requires a directory-based storage pool", script)
        self.assertIn("vol-list','--pool',pool", script)
        self.assertNotIn("vol-list','--pool',pool,'--name'", script)
        self.assertIn("net-list','--name'", script)
        self.assertIn("The selected virtual network is not active", script)
        self.assertNotIn("net-info',network", script)
        self.assertIn("os.makedirs(cache_dir,mode=0o755,exist_ok=True)", script)
        self.assertIn("os.chmod(cache_dir,0o755)", script)
        compile(script, "<vm-create-remote>", "exec")
        self.assertEqual(remote.call_args.args[2][-3:], ["true", "2", ""])

    def test_vm_create_can_use_library_qcow2_and_queues_an_independent_copy(self):
        host = self.create_test_host()
        image_id = "a" * 32
        payload = {"name": "template-vm", "pool": "default", "network": "default", "vcpus": 2,
                   "memory_mib": 1024, "create_disk": True, "image_id": image_id}
        queued_job = {"job_id": "00000000-0000-4000-8000-000000000001", "status": "queued"}
        with patch.object(api, "create_operation_job", return_value=queued_job) as queue:
            response = self.client.post(f"/kvm-api/hosts/{host['id']}/vms/create", headers=self.headers("admin-token"), json=payload)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json(), queued_job)
        operation = queue.call_args.args[3]
        with patch.object(api, "run_sudo_python", return_value="VM created") as remote:
            result = operation(api.cockpit_host_record(host["id"]))
        self.assertEqual(result["status"], "completed")
        script = remote.call_args.args[1]
        self.assertIn("qemu-img','convert", script)
        self.assertIn("without backing files", script)
        self.assertIn("independent copy", script)
        self.assertEqual(remote.call_args.args[2][-1], image_id)
        compile(script, "<vm-image-library-create>", "exec")

    def test_image_library_scripts_compile_and_upload_requires_storage_admin(self):
        host = self.create_test_host()
        for script in (api.IMAGE_LIBRARY_LIST_SCRIPT, api.IMAGE_LIBRARY_IMPORT_SCRIPT, api.IMAGE_LIBRARY_DELETE_SCRIPT):
            compile(script, "<image-library-remote>", "exec")
        denied = self.client.post(
            f"/kvm-api/hosts/{host['id']}/images?pool=default&name=iso&image_type=iso&filename=test.iso",
            headers={**self.headers("viewer-token"), "Content-Type": "application/octet-stream"}, content=b"x" * 40960,
        )
        self.assertEqual(denied.status_code, 403)
        bad_type = self.client.post(
            f"/kvm-api/hosts/{host['id']}/images?pool=default&name=iso&image_type=iso&filename=test.iso",
            headers={**self.headers("admin-token"), "Content-Type": "application/json"}, content=b"x" * 40960,
        )
        self.assertEqual(bad_type.status_code, 415)
        self.assertIn("checksum", api.IMAGE_LIBRARY_IMPORT_SCRIPT)
        self.assertIn("backing-filename", api.IMAGE_LIBRARY_IMPORT_SCRIPT)
        self.assertIn("attached to virtual machine", api.IMAGE_LIBRARY_DELETE_SCRIPT)

    def test_vm_shutdown_waits_for_real_libvirt_state_and_reports_guest_timeout(self):
        host = self.create_test_host()
        with patch.object(api, "create_operation_job", return_value={"job_id": "00000000-0000-4000-8000-000000000001", "status": "queued"}) as queued:
            response = self.client.post(
                f"/kvm-api/hosts/{host['id']}/vms/actions?vm_name=test-vm",
                headers=self.headers("admin-token"), json={"action": "shutdown"},
            )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["status"], "queued")
        self.assertEqual(queued.call_args.args[0], "vm_shutdown")
        perform_action = queued.call_args.args[3]
        with patch.object(api, "run_sudo_python", return_value="") as remote:
            self.assertEqual(perform_action(api.cockpit_host_record(host["id"])), {"status": "completed"})
        script = remote.call_args.args[1]
        compile(script, "<vm-action-remote>", "exec")
        self.assertIn("domstate", script)
        self.assertIn("The guest may not support ACPI shutdown", script)

        encoded_name = base64.b64encode(b"test-vm").decode()
        state_sequence = iter(("running", "shut off"))

        def successful_transition(command, **_kwargs):
            operation = command[3]
            stdout = "test-vm\n" if operation == "list" else next(state_sequence) if operation == "domstate" else ""
            return subprocess.CompletedProcess(command, 0, stdout, "")

        with patch.object(sys, "argv", ["vm-action", encoded_name, "shutdown"]), \
             patch.object(subprocess, "run", side_effect=successful_transition), \
             patch.object(api.time, "monotonic", side_effect=(0, 1)), \
             patch.object(api.time, "sleep"):
            exec(compile(script, "<vm-action-remote>", "exec"), {"__name__": "__main__"})

        def guest_ignores_shutdown(command, **_kwargs):
            operation = command[3]
            stdout = "test-vm\n" if operation == "list" else "running\n" if operation == "domstate" else ""
            return subprocess.CompletedProcess(command, 0, stdout, "")

        with patch.object(sys, "argv", ["vm-action", encoded_name, "shutdown"]), \
             patch.object(subprocess, "run", side_effect=guest_ignores_shutdown), \
             patch.object(api.time, "monotonic", side_effect=(0, 46)), \
             patch.object(api.time, "sleep") as sleep:
            with self.assertRaises(SystemExit) as error:
                exec(compile(script, "<vm-action-remote>", "exec"), {"__name__": "__main__"})
        self.assertIn("remained running after 45 seconds", str(error.exception))
        sleep.assert_not_called()

    def test_vm_force_stop_uses_libvirt_destroy_and_verifies_powered_off_state(self):
        host = self.create_test_host()
        route = f"/kvm-api/hosts/{host['id']}/vms/actions?vm_name=test-vm"
        denied = self.client.post(route, headers=self.headers("viewer-token"), json={"action": "force_stop"})
        self.assertEqual(denied.status_code, 403)

        fake_job = {"job_id": "00000000-0000-4000-8000-000000000001", "status": "queued"}
        with patch.object(api, "create_operation_job", return_value=fake_job) as queued:
            response = self.client.post(route, headers=self.headers("admin-token"), json={"action": "force_stop"})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(queued.call_args.args[0], "vm_force_stop")
        perform_action = queued.call_args.args[3]
        with patch.object(api, "run_sudo_python", return_value="") as remote:
            self.assertEqual(perform_action(api.cockpit_host_record(host["id"])), {"status": "completed"})
        script = remote.call_args.args[1]
        compile(script, "<vm-force-stop-remote>", "exec")
        self.assertIn("'force_stop':'destroy'", script)

        encoded_name = base64.b64encode(b"test-vm").decode()
        def powered_off(command, **_kwargs):
            operation = command[3]
            stdout = "test-vm\n" if operation == "list" else "shut off\n" if operation == "domstate" else ""
            return subprocess.CompletedProcess(command, 0, stdout, "")

        with patch.object(sys, "argv", ["vm-action", encoded_name, "force_stop"]), \
             patch.object(subprocess, "run", side_effect=powered_off) as virsh, \
             patch.object(api.time, "monotonic", return_value=100), \
             patch.object(api.time, "sleep") as sleep:
            exec(compile(script, "<vm-force-stop-remote>", "exec"), {"__name__": "__main__"})
        self.assertTrue(any(command.args[0][3] == "destroy" for command in virsh.call_args_list))
        sleep.assert_not_called()

    def test_activity_queries_scope_to_host_and_vm_with_target_index(self):
        host = self.create_test_host()
        host_id = host["id"]
        for action, target in (
            ("host.refresh", host_id),
            ("vm.start", f"{host_id}/test-vm"),
            ("vm.configuration", f"{host_id}/test-vm/cpu"),
            ("vm.start", f"{host_id}/test-vm-extra"),
            ("vm.start", f"{host_id}-other/test-vm"),
        ):
            api.record_audit("user-test", action, target)

        host_events = self.client.get(f"/kvm-api/hosts/{host_id}/activity", headers=self.headers("viewer-token"))
        self.assertEqual(host_events.status_code, 200, host_events.text)
        self.assertEqual({event["target"] for event in host_events.json()}, {
            host_id, f"{host_id}/test-vm", f"{host_id}/test-vm/cpu", f"{host_id}/test-vm-extra",
        })

        vm_events = self.client.get(f"/kvm-api/hosts/{host_id}/activity?vm_name=test-vm", headers=self.headers("viewer-token"))
        self.assertEqual(vm_events.status_code, 200, vm_events.text)
        self.assertEqual({event["target"] for event in vm_events.json()}, {
            f"{host_id}/test-vm", f"{host_id}/test-vm/cpu",
        })
        with api.connect_db() as db:
            indexes = {row[1] for row in db.execute("PRAGMA index_list(audit_events)")}
        self.assertIn("idx_audit_events_target_occurred", indexes)

    def test_vm_bulk_delete_is_rbac_protected_validated_and_preserves_storage(self):
        host = self.create_test_host()
        route = f"/kvm-api/hosts/{host['id']}/vms/delete"
        denied = self.client.post(route, headers=self.headers("viewer-token"), json={"vm_names": ["test-vm"]})
        self.assertEqual(denied.status_code, 403)
        duplicate = self.client.post(route, headers=self.headers("admin-token"), json={"vm_names": ["test-vm", "test-vm"]})
        self.assertEqual(duplicate.status_code, 422)
        invalid = self.client.post(route, headers=self.headers("admin-token"), json={"vm_names": ["x" * 256]})
        self.assertEqual(invalid.status_code, 422)

        fake_job = {"job_id": "00000000-0000-4000-8000-000000000001", "status": "queued"}
        remote_json = '{"vms":[{"name":"test-vm","status":"deleted","message":"Virtual machine definition removed; storage volumes were preserved."}]}'
        with patch.object(api, "create_operation_job", return_value=fake_job) as create_job:
            response = self.client.post(route, headers=self.headers("admin-token"), json={"vm_names": ["test-vm"]})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(create_job.call_args.args[0], "vm_delete")
        perform_delete = create_job.call_args.args[3]
        with patch.object(api, "run_sudo_python", return_value=remote_json) as remote:
            result = perform_delete(api.cockpit_host_record(host["id"]))
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["vms"][0]["status"], "deleted")
        self.assertEqual(remote.call_args.kwargs["stdin_data"], '["test-vm"]')
        script = remote.call_args.args[1]
        compile(script, "<vm-delete-remote>", "exec")
        self.assertIn("['undefine',name]", script)
        self.assertNotIn("--remove-all-storage", script)
        self.assertNotIn("test-vm", script)

    def test_vm_device_attach_network_rejects_duplicate_configured_network(self) -> None:
        host = self.create_test_host()
        with patch.object(api, "run_sudo_python", return_value="Persistent VM device configuration updated") as remote:
            response = self.client.post(
                f"/kvm-api/hosts/{host['id']}/vms/devices?vm_name=test-vm",
                headers=self.headers("admin-token"),
                json={"action": "attach_network", "network": "kvm-nat"},
            )
        self.assertEqual(response.status_code, 200, response.text)
        script = remote.call_args.args[1]
        compile(script, "<vm-device-remote>", "exec")
        self.assertIn("configured_networks", script)
        self.assertIn("This virtual network is already configured on this VM", script)

    def test_vm_detail_reports_persistent_networks_and_live_status(self) -> None:
        host = self.create_test_host()
        with patch.object(api, "run_sudo_python", return_value='{"interfaces":[]}') as remote:
            response = self.client.get(
                f"/kvm-api/hosts/{host['id']}/vms/detail?vm_name=test-vm",
                headers=self.headers("admin-token"),
            )
        self.assertEqual(response.status_code, 200, response.text)
        script = remote.call_args.args[1]
        compile(script, "<vm-detail-remote>", "exec")
        self.assertIn("dumpxml','--inactive'", script)
        self.assertIn("active_interfaces", script)
        self.assertIn("'active':bool(live)", script)

    def test_virtualdomain_preflight_compares_vm_and_agent_across_mapped_nodes(self) -> None:
        host_a = self.create_test_host(name="node-a")
        response = self.client.post("/kvm-api/hosts", headers=self.headers("admin-token"), json={
            "name": "node-b", "address": "192.0.2.21", "port": 22,
            "username": "operator", "password": "test-password",
        })
        self.assertEqual(response.status_code, 201, response.text)
        host_b = response.json()
        status = {"nodes": [{"name": "node-a"}, {"name": "node-b"}]}
        detail = {
            "name": "ha-guest", "uuid": "guest-uuid", "state": "shut off",
            "persistent": "yes", "autostart": "no", "configured_vcpus": 2,
            "configured_memory_kib": 1048576,
            "disks": [{"type": "file", "target": "vda", "source": "/shared/guest.qcow2", "format": "qcow2"}],
            "interfaces": [{"type": "network", "source": "ha-net", "model": "virtio", "mac": "52:54:00:00:00:01"}],
        }
        def remote(host, script, *args, **kwargs):
            if script is api.VM_DETAIL_SCRIPT:
                return json.dumps(detail)
            if script is api.HA_RESOURCE_AGENTS_SCRIPT:
                return json.dumps({"agents": ["ocf:heartbeat:VirtualDomain"], "virtualization_locking": {
                    "profile": "suse-sle-ha-15-sp7", "lock_manager": "lockd",
                    "lock_manager_is_lockd": True, "file_lockspace_dir": "/shared/lockd",
                    "lockspace_directory_exists": True, "virtlockd_active": True,
                }})
            if script is api.VM_HA_STORAGE_PROBE_SCRIPT:
                self.assertEqual(json.loads(args[0][1]), [{"path": "/shared/guest.qcow2", "writable": True}])
                return json.dumps({"config": None, "disk_paths": [{
                    "path": "/shared/guest.qcow2", "exists": True, "readable": True,
                    "configured_identity_access": "read_write", "kind": "file",
                }], "qemu_identity": {"user": "qemu", "group": "qemu"}, "ssh_peer_auth": []})
            self.fail("Unexpected remote script")
        with patch.object(api, "require_verified_ha_cluster", return_value=(api.cockpit_host_record(host_a["id"]), status)), \
             patch.object(api, "run_sudo_python", side_effect=remote):
            response = self.client.get(
                f"/kvm-api/clusters/{host_a['id']}/vms/virtualdomain-preflight?vm_name=ha-guest",
                headers=self.headers("admin-token"),
            )
        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()
        self.assertTrue(result["mapping_complete"])
        self.assertTrue(result["source_vm_found"])
        self.assertTrue(result["virtualdomain_agent_on_all_nodes"])
        self.assertTrue(result["vm_uuid_consistent"])
        self.assertTrue(result["disk_layout_consistent"])
        self.assertTrue(result["network_mapping_consistent"])
        self.assertEqual({node["host_id"] for node in result["nodes"]}, {host_a["id"], host_b["id"]})
        self.assertTrue(all(node["virtualization_locking"]["lock_manager_is_lockd"] for node in result["nodes"]))
        self.assertIsNotNone(result["storage_checks"])
        self.assertEqual(result["storage_checks"]["config_path"], "")
        self.assertTrue(all(node["qemu_identity"]["user"] == "qemu" for node in result["storage_checks"]["nodes"]))

    def test_virtualdomain_preflight_reports_unmapped_cluster_members(self) -> None:
        host = self.create_test_host(name="node-a")
        status = {"nodes": [{"name": "node-a"}, {"name": "unregistered-node"}]}
        with patch.object(api, "require_verified_ha_cluster", return_value=(api.cockpit_host_record(host["id"]), status)), \
             patch.object(api, "run_sudo_python", return_value='{}'):
            response = self.client.get(
                f"/kvm-api/clusters/{host['id']}/vms/virtualdomain-preflight?vm_name=ha-guest",
                headers=self.headers("admin-token"),
            )
        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()
        self.assertFalse(result["mapping_complete"])
        unresolved = next(node for node in result["nodes"] if node["cluster_node"] == "unregistered-node")
        self.assertEqual(unresolved["mapping_status"], "unmapped")
        self.assertEqual(unresolved["vm_status"], "not_checked")

    def test_virtualdomain_preflight_reports_storage_paths_as_candidate_only(self) -> None:
        host_a = self.create_test_host(name="node-a")
        response = self.client.post("/kvm-api/hosts", headers=self.headers("admin-token"), json={
            "name": "node-b", "address": "192.0.2.21", "port": 22,
            "username": "operator", "password": "test-password",
        })
        host_b = response.json()
        status = {"nodes": [{"name": "node-a"}, {"name": "node-b"}]}
        detail = {"name": "ha-guest", "uuid": "guest-uuid", "state": "shut off",
                  "disks": [{"type": "file", "target": "vda", "source": "/shared/guest.qcow2", "format": "qcow2"}],
                  "interfaces": []}
        def remote(_host, script, *args, **kwargs):
            if script is api.VM_DETAIL_SCRIPT:
                return json.dumps(detail)
            if script is api.HA_RESOURCE_AGENTS_SCRIPT:
                return json.dumps({"agents": ["ocf:heartbeat:VirtualDomain"]})
            if script is api.VM_HA_STORAGE_PROBE_SCRIPT:
                self.assertEqual(json.loads(args[0][1]), [{"path": "/shared/guest.qcow2", "writable": True}])
                self.assertEqual(json.loads(args[0][2]), ["node-b"])
                return json.dumps({
                    "config": {"path": args[0][0], "parent_path": "/shared/vm-configs",
                               "parent_exists": True, "file_exists": False,
                               "parent_mount": {"source": "nas:/exports/ha", "fstype": "nfs4", "uuid": None}},
                    "disk_paths": [{"path": "/shared/guest.qcow2", "exists": True, "readable": True,
                                    "kind": "file", "mount": {"source": "nas:/exports/ha", "fstype": "nfs4", "uuid": None}}],
                })
            self.fail("Unexpected remote script")
        with patch.object(api, "require_verified_ha_cluster", return_value=(api.cockpit_host_record(host_a["id"]), status)), \
             patch.object(api, "run_sudo_python", side_effect=remote):
            response = self.client.get(
                f"/kvm-api/clusters/{host_a['id']}/vms/virtualdomain-preflight",
                params={"vm_name": "ha-guest", "config_path": "/shared/vm-configs/ha-guest.xml"},
                headers=self.headers("admin-token"),
            )
        self.assertEqual(response.status_code, 200, response.text)
        checks = response.json()["storage_checks"]
        self.assertTrue(checks["shared_mount_candidate"])
        self.assertFalse(checks["is_proof_of_shared_storage"])
        self.assertTrue(checks["disk_paths"][0]["exists_on_all_nodes"])
        self.assertTrue(checks["disk_paths"][0]["same_mount_candidate"])
        self.assertTrue(all(node["config"]["parent_exists"] for node in checks["nodes"]))

    def test_virtualdomain_preflight_rejects_unsafe_configuration_path(self) -> None:
        host = self.create_test_host(name="node-a")
        with patch.object(api, "require_verified_ha_cluster") as cluster_status:
            response = self.client.get(
                f"/kvm-api/clusters/{host['id']}/vms/virtualdomain-preflight",
                params={"vm_name": "ha-guest", "config_path": "/shared/../etc/guest.xml"},
                headers=self.headers("admin-token"),
            )
        self.assertEqual(response.status_code, 422, response.text)
        cluster_status.assert_not_called()

    def create_test_host(self, *, token: str = "admin-token", name: str = "test-host") -> dict:
        response = self.client.post("/kvm-api/hosts", headers=self.headers(token), json={
            "name": name, "address": "192.0.2.20", "port": 22,
            "username": "operator", "password": "test-password",
        })
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()

    def test_api_rejects_requests_without_rancher_session(self) -> None:
        response = self.client.get("/kvm-api/hosts")
        self.assertEqual(response.status_code, 401)

    def test_health_endpoint_reports_extension_api_ready(self) -> None:
        response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json().get("status"))

    def test_database_file_is_private_after_api_startup(self) -> None:
        database_mode = api.DB_PATH.stat().st_mode & 0o777
        self.assertEqual(database_mode, 0o600)

    def test_viewer_can_read_but_cannot_import_host(self) -> None:
        headers = self.headers("viewer-token")
        self.assertEqual(self.client.get("/kvm-api/hosts", headers=headers).status_code, 200)
        response = self.client.post("/kvm-api/hosts", headers=headers, json={
            "name": "test-host", "address": "192.0.2.10", "username": "operator", "password": "test-password",
        })
        self.assertEqual(response.status_code, 403)

    def test_scoped_network_role_does_not_grant_host_administration(self) -> None:
        response = self.client.get("/kvm-api/permissions", headers=self.headers("network-token"))
        self.assertEqual(response.status_code, 200)
        permissions = response.json()
        self.assertTrue(permissions["canManageNetwork"])
        self.assertFalse(permissions["canAdministerHost"])

    def test_scoped_network_role_cannot_change_storage(self) -> None:
        response = self.client.post(
            "/kvm-api/hosts/missing/storage-volumes",
            headers=self.headers("network-token"),
            json={"action": "delete", "pool": "default", "name": "test-volume"},
        )
        self.assertEqual(response.status_code, 403)

    def test_rancher_role_matrix_grants_only_configured_kvm_permissions(self) -> None:
        cases = {
            "viewer-token": {"canView": True},
            "vm-operator-token": {"canView": True, "canOperateVms": True},
            "network-token": {"canManageNetwork": True},
            "storage-token": {"canManageStorage": True},
            "software-token": {"canManageRepositories": True},
            "subscription-token": {"canManageSubscriptions": True},
            "account-token": {"canManageAccounts": True},
            "service-token": {"canManageServices": True},
            "cluster-token": {"canManageClusters": True},
        }
        managed_permissions = {
            "canOperateVms", "canManageHostResources", "canManageNetwork", "canManageStorage",
            "canManageRepositories", "canManageSubscriptions", "canManageAccounts",
            "canManageServices", "canManageClusters", "canAdministerHost",
        }
        for token, expected_true in cases.items():
            with self.subTest(token=token):
                response = self.client.get("/kvm-api/permissions", headers=self.headers(token))
                self.assertEqual(response.status_code, 200, response.text)
                permissions = response.json()
                for permission in managed_permissions:
                    self.assertEqual(permissions[permission], permission in expected_true, permission)
                self.assertTrue(permissions["canView"])

        host_operator = self.client.get("/kvm-api/permissions", headers=self.headers("host-operator-token"))
        self.assertEqual(host_operator.status_code, 200, host_operator.text)
        self.assertEqual(host_operator.json()["accessLevel"], "host_operator")
        self.assertTrue(all(host_operator.json()[permission] for permission in managed_permissions - {"canAdministerHost"}))
        self.assertFalse(host_operator.json()["canAdministerHost"])

        host_admin = self.client.get("/kvm-api/permissions", headers=self.headers("admin-token"))
        self.assertEqual(host_admin.status_code, 200, host_admin.text)
        self.assertTrue(all(host_admin.json()[permission] for permission in managed_permissions))

    def test_multiple_scoped_roles_combine_without_escalating_to_host_admin(self) -> None:
        response = self.client.get("/kvm-api/permissions", headers=self.headers("network-storage-token"))
        self.assertEqual(response.status_code, 200, response.text)
        permissions = response.json()
        self.assertEqual(permissions["accessLevel"], "scoped_operator")
        self.assertTrue(permissions["canManageNetwork"])
        self.assertTrue(permissions["canManageStorage"])
        self.assertFalse(permissions["canManageAccounts"])
        self.assertFalse(permissions["canOperateVms"])
        self.assertFalse(permissions["canAdministerHost"])

    def test_unmapped_rancher_role_is_denied(self) -> None:
        response = self.client.get("/kvm-api/permissions", headers=self.headers("unmapped-token"))
        self.assertEqual(response.status_code, 403)

    def test_host_import_pins_key_and_never_returns_saved_credentials(self) -> None:
        response = self.client.post("/kvm-api/hosts", headers=self.headers("admin-token"), json={
            "name": "test-host", "address": "192.0.2.10", "port": 22,
            "username": "operator", "password": "test-password",
        })
        self.assertEqual(response.status_code, 201, response.text)
        host = response.json()
        self.assertEqual(host["status"], "ready")
        self.assertNotIn("password", host)
        self.assertNotIn("ssh_private_key_enc", host)
        with api.connect_db() as db:
            row = db.execute("SELECT password,ssh_host_key FROM hosts WHERE id=?", (host["id"],)).fetchone()
        self.assertNotEqual(row["password"], "test-password")
        self.assertTrue(row["password"])
        self.assertEqual(row["ssh_host_key"], "ssh-ed25519 dGVzdC1ob3N0LWtleQ==")

    def test_passwordless_key_import_is_optional_and_keeps_password_flow_available(self) -> None:
        response = self.client.post("/kvm-api/hosts", headers=self.headers("admin-token"), json={
            "name": "key-host", "address": "192.0.2.11", "port": 22,
            "username": "operator", "ssh_private_key": "test-only-private-key",
        })
        self.assertEqual(response.status_code, 201, response.text)
        with api.connect_db() as db:
            row = db.execute("SELECT password,ssh_private_key_enc FROM hosts WHERE id=?", (response.json()["id"],)).fetchone()
        self.assertEqual(api.cipher.decrypt(row["password"].encode()).decode(), "")
        self.assertNotEqual(row["ssh_private_key_enc"], "test-only-private-key")
        self.assertEqual(api.cipher.decrypt(row["ssh_private_key_enc"].encode()).decode(), "test-only-private-key")

    def test_host_cannot_be_deleted_while_it_belongs_to_a_kvm_group(self) -> None:
        headers = self.headers("admin-token")
        host_ids = []
        for index in (12, 13):
            response = self.client.post("/kvm-api/hosts", headers=headers, json={
                "name": f"test-host-{index}", "address": f"192.0.2.{index}",
                "username": "operator", "password": "test-password",
            })
            self.assertEqual(response.status_code, 201, response.text)
            host_ids.append(response.json()["id"])
        group = self.client.post("/kvm-api/managed-clusters", headers=headers,
                                 json={"name": "test-group", "host_ids": host_ids})
        self.assertEqual(group.status_code, 201, group.text)
        deletion = self.client.delete(f"/kvm-api/hosts/{host_ids[0]}", headers=headers)
        self.assertEqual(deletion.status_code, 409)

    def test_kvm_group_inventory_passes_viewer_rbac_context_to_host_inventory(self) -> None:
        host = self.create_test_host(name="inventory-node")
        created = self.client.post(
            "/kvm-api/managed-clusters",
            headers=self.headers("admin-token"),
            json={"name": "inventory-group", "host_ids": [host["id"], self.create_test_host(name="inventory-node-2")["id"]]},
        )
        self.assertEqual(created.status_code, 201, created.text)
        host_inventory = {
            "system": {"cpu_count": 8, "memory_total_kib": 16384, "memory_available_kib": 8192},
            "vms": [{"name": "guest-a", "state": "running"}],
            "storage": {"filesystems": [{"device": "nas.example:/exports/vms", "type": "nfs4", "mountpoint": "/srv/vms"}]},
            "network": {"interfaces": [{"ifname": "br0", "mtu": 9000, "operstate": "UP"}]}, "libvirt_networks": [], "storage_pools": [],
            "subscription": {"products": [{"registration_code": "must-not-be-returned"}]},
        }

        with patch.object(api, "run_sudo_python", return_value=json.dumps(host_inventory)) as remote:
            response = self.client.get(
                f"/kvm-api/managed-clusters/{created.json()['id']}/inventory",
                headers=self.headers("viewer-token"),
            )

        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()
        self.assertEqual(result["hosts"][0]["status"], "ready")
        self.assertEqual(result["hosts"][0]["metrics"]["cpu_count"], 8)
        self.assertEqual(result["hosts"][0]["filesystems"][0]["type"], "nfs4")
        self.assertEqual(result["hosts"][0]["filesystems"][0]["device"], "nas.example:/exports/vms")
        self.assertEqual(result["hosts"][0]["network_interfaces"][0]["ifname"], "br0")
        self.assertEqual(result["vms"][0]["name"], "guest-a")
        self.assertEqual(remote.call_count, 2)
        self.assertNotIn("must-not-be-returned", response.text)

    def test_kvm_group_inventory_returns_actionable_safe_errors_without_remote_diagnostics(self) -> None:
        headers = self.headers("admin-token")
        first = self.create_test_host(name="inventory-error-node")
        second = self.create_test_host(name="inventory-error-peer")
        created = self.client.post("/kvm-api/managed-clusters", headers=headers,
                                   json={"name": "inventory-error-group", "host_ids": [first["id"], second["id"]]})
        self.assertEqual(created.status_code, 201, created.text)

        with patch.object(api, "get_host_cloud_native", side_effect=api.HTTPException(
            502, "Could not load host administration data: password=test-password /private/path/key"
        )):
            response = self.client.get(
                f"/kvm-api/managed-clusters/{created.json()['id']}/inventory",
                headers=self.headers("viewer-token"),
            )

        self.assertEqual(response.status_code, 200, response.text)
        hosts = response.json()["hosts"]
        self.assertEqual([host["error_code"] for host in hosts], ["inventory_failed", "inventory_failed"])
        self.assertNotIn("error", hosts[0])
        self.assertNotIn("test-password", response.text)
        self.assertNotIn("/private/path/key", response.text)
        self.assertEqual(api.managed_cluster_inventory_error_code(api.HTTPException(502, "SSH authentication failed")), "ssh_auth_failed")
        self.assertEqual(api.managed_cluster_inventory_error_code(TimeoutError("connection timed out")), "ssh_unreachable")
        self.assertEqual(api.managed_cluster_inventory_error_code(RuntimeError("virsh connection unavailable")), "host_services_unavailable")

    def test_cluster_plan_is_a_private_draft_and_never_contains_preflight_or_credentials(self) -> None:
        headers = self.headers("cluster-token")
        first = self.create_test_host(name="draft-node-a")
        second = self.create_test_host(name="draft-node-b")
        payload = {"name": "test-ha", "host_ids": [first["id"], second["id"]], "template_id": "nfs",
                   "step": 2, "quorum": "qdevice", "qnetd_host": "witness.example.invalid",
                   "qnetd_outside_cluster": True, "fencing": "sbd",
                   "password": "must-not-persist", "preflight_results": [{"secret": "must-not-persist"}]}
        created = self.client.post("/kvm-api/cluster-plans", headers=headers, json=payload)
        self.assertEqual(created.status_code, 201, created.text)
        plan = created.json()
        self.assertEqual(plan["state"], "draft")
        self.assertTrue(plan["preflight_required"])
        self.assertNotIn("password", plan)
        self.assertNotIn("preflight_results", plan)
        self.assertEqual(plan["config"]["qnetd_host"], "witness.example.invalid")
        with api.connect_db() as db:
            stored_config = db.execute("SELECT config_json FROM cluster_plans WHERE id=?", (plan["id"],)).fetchone()["config_json"]
        self.assertNotIn("must-not-persist", stored_config)
        listed = self.client.get("/kvm-api/cluster-plans", headers=headers)
        self.assertEqual([item["id"] for item in listed.json()], [plan["id"]])
        self.assertEqual(self.client.get("/kvm-api/cluster-plans", headers=self.headers("viewer-token")).json(), [])
        self.assertEqual(self.client.get("/kvm-api/managed-clusters", headers=headers).json(), [])
        self.assertEqual(self.client.put(f"/kvm-api/cluster-plans/{plan['id']}", headers=self.headers("viewer-token"), json=payload).status_code, 403)
        payload["name"] = "resumed-ha"
        updated = self.client.put(f"/kvm-api/cluster-plans/{plan['id']}", headers=headers, json=payload)
        self.assertEqual(updated.status_code, 200, updated.text)
        self.assertEqual(updated.json()["name"], "resumed-ha")
        self.assertEqual(self.client.delete(f"/kvm-api/cluster-plans/{plan['id']}", headers=headers).status_code, 204)

    def test_suse_ha_cluster_registry_requires_live_membership_and_tracks_membership_changes(self) -> None:
        headers = self.headers("cluster-token")
        first = self.create_test_host(name="node-a")
        second = self.create_test_host(name="node-b")
        live = {"cluster_name": "ha-lab", "nodes": [{"name": "node-a", "online": True}]}
        with patch.object(api, "run_sudo_python", side_effect=lambda *_args, **_kwargs: json.dumps(live)):
            created = self.client.post("/kvm-api/suse-ha-clusters", headers=headers, json={"host_id": first["id"]})
            self.assertEqual(created.status_code, 201, created.text)
            record = created.json()
            self.assertEqual(record["name"], "ha-lab")
            self.assertEqual(record["members"][0]["host_id"], first["id"])
            self.assertNotIn("password", created.text)

            listed = self.client.get("/kvm-api/suse-ha-clusters", headers=self.headers("viewer-token"))
            self.assertEqual(listed.status_code, 200, listed.text)
            self.assertEqual([item["id"] for item in listed.json()], [record["id"]])

            live["nodes"] = [{"name": "node-a", "online": True}, {"name": "node-b", "online": True}]
            updated = self.client.post("/kvm-api/suse-ha-clusters", headers=headers, json={"host_id": first["id"]})
            self.assertEqual(updated.status_code, 201, updated.text)
            self.assertEqual(updated.json()["id"], record["id"])
            self.assertEqual({member["host_id"] for member in updated.json()["members"]}, {first["id"], second["id"]})

            forbidden = self.client.post("/kvm-api/suse-ha-clusters", headers=self.headers("viewer-token"), json={"host_id": first["id"]})
            self.assertEqual(forbidden.status_code, 403)

    def test_suse_ha_cluster_registry_rejects_hosts_without_live_membership(self) -> None:
        host = self.create_test_host(name="standalone-node")
        with patch.object(api, "run_sudo_python", return_value=json.dumps({"cluster_name": "", "nodes": []})):
            response = self.client.post("/kvm-api/suse-ha-clusters", headers=self.headers("cluster-token"), json={"host_id": host["id"]})
        self.assertEqual(response.status_code, 409, response.text)
        self.assertIn("not reporting an initialized SUSE HA cluster", response.json()["detail"])

    def test_cluster_plan_canonicalizes_corosync_network_hints_and_bootstrap_requires_fresh_review(self) -> None:
        headers = self.headers("cluster-token")
        first = self.create_test_host(name="corosync-node-a")
        second = self.create_test_host(name="corosync-node-b")
        payload = {
            "name": "corosync-plan", "host_ids": [first["id"], second["id"]],
            "quorum": "standard", "fencing": "hardware",
            "corosync_networks": ["10.20.0.11/24", "192.0.2.22/24"],
            "corosync_network_reviewed": True,
        }
        created = self.client.post("/kvm-api/cluster-plans", headers=headers, json=payload)
        self.assertEqual(created.status_code, 201, created.text)
        plan = created.json()
        self.assertEqual(plan["config"]["corosync_networks"], ["10.20.0.0/24", "192.0.2.0/24"])
        actor = api.require_permission("cluster_admin")("Bearer cluster-token", None)
        context, _hosts = api.cluster_bootstrap_context(plan["id"], first["id"], "init", actor)
        self.assertEqual(context["config"]["corosync_networks"], ["10.20.0.0/24", "192.0.2.0/24"])

        payload["corosync_networks"] = ["10.20.0.0/24", "10.20.0.0/24"]
        duplicate = self.client.post("/kvm-api/cluster-plans", headers=headers, json=payload)
        self.assertEqual(duplicate.status_code, 422, duplicate.text)
        payload["corosync_networks"] = ["not-a-subnet"]
        invalid = self.client.post("/kvm-api/cluster-plans", headers=headers, json=payload)
        self.assertEqual(invalid.status_code, 422, invalid.text)

        payload["corosync_networks"] = ["10.20.0.0/24"]
        payload["corosync_network_reviewed"] = False
        updated = self.client.put(f"/kvm-api/cluster-plans/{plan['id']}", headers=headers, json=payload)
        self.assertEqual(updated.status_code, 200, updated.text)
        with self.assertRaisesRegex(api.HTTPException, "Review static Corosync addressing"):
            api.cluster_bootstrap_context(plan["id"], first["id"], "init", actor)

    def test_cluster_plan_rejects_duplicate_nodes_and_qnetd_inside_selected_nodes(self) -> None:
        headers = self.headers("cluster-token")
        first = self.create_test_host(name="draft-node-a")
        second = self.create_test_host(name="draft-node-b")
        duplicate = self.client.post("/kvm-api/cluster-plans", headers=headers, json={"host_ids": [first["id"], first["id"]]})
        self.assertEqual(duplicate.status_code, 422)
        inside = self.client.post("/kvm-api/cluster-plans", headers=headers, json={
            "host_ids": [first["id"], second["id"]], "quorum": "qdevice", "qnetd_host": "draft-node-a"})
        self.assertEqual(inside.status_code, 422)

    def test_cluster_plan_normalizes_qnetd_dns_and_ip_before_external_witness_check(self) -> None:
        headers = self.headers("cluster-token")
        first = self.create_test_host(name="draft-node-a")
        second = self.create_test_host(name="draft-node-b")
        with api.connect_db() as db:
            db.execute("UPDATE hosts SET hostname='draft-node-a.' WHERE id=?", (first["id"],))
            db.execute("UPDATE hosts SET address='2001:0db8:0:0::2' WHERE id=?", (second["id"],))
        for witness in ("draft-node-a", "2001:db8::2"):
            response = self.client.post("/kvm-api/cluster-plans", headers=headers, json={
                "host_ids": [first["id"], second["id"]], "quorum": "qdevice", "qnetd_host": witness,
                "qnetd_outside_cluster": True,
            })
            self.assertEqual(response.status_code, 422, response.text)

    def test_cluster_mutations_require_verified_live_membership(self) -> None:
        host = self.create_test_host(name="not-yet-clustered")
        mutations = (
            (f"/kvm-api/clusters/{host['id']}/actions", {"action": "node_standby", "target": "node-a"}),
            (f"/kvm-api/clusters/{host['id']}/resources/config", {
                "action": "create", "resource_id": "test-vip", "agent": "ocf:heartbeat:IPaddr2",
            }),
            (f"/kvm-api/clusters/{host['id']}/constraints/config", {
                "action": "create_location", "constraint_id": "prefer-node-a",
                "resource": "test-vip", "node": "node-a", "score": "INFINITY",
            }),
        )
        for path, payload in mutations:
            with self.subTest(path=path), \
                 patch.object(api, "cockpit_host_record", return_value={"id": host["id"], "name": host["name"]}), \
                 patch.object(api, "run_sudo_python", return_value=json.dumps({"nodes": [{"name": "node-a"}]})) as remote:
                response = self.client.post(path, headers=self.headers("cluster-token"), json=payload)
                self.assertEqual(response.status_code, 409, response.text)
                self.assertIn("at least two reported members", response.json()["detail"])
                remote.assert_called_once_with(
                    {"id": host["id"], "name": host["name"]}, api.HA_CLUSTER_STATUS_SCRIPT, timeout=35,
                )

    def test_cluster_host_mutation_locks_reject_overlaps_and_allow_independent_hosts(self) -> None:
        first = api.acquire_cluster_host_mutation_locks(["host-a", "host-b"])
        self.assertIsNotNone(first)
        independent = None
        retry = None
        try:
            self.assertIsNone(api.acquire_cluster_host_mutation_locks(["host-b", "host-c"]))
            independent = api.acquire_cluster_host_mutation_locks(["host-c"])
            self.assertIsNotNone(independent)
        finally:
            if independent is not None:
                api.release_cluster_host_mutation_locks(independent)
            if first is not None:
                api.release_cluster_host_mutation_locks(first)
        retry = api.acquire_cluster_host_mutation_locks(["host-a", "host-b"])
        self.assertIsNotNone(retry)
        if retry is not None:
            api.release_cluster_host_mutation_locks(retry)

    def test_cluster_node_and_resource_actions_reject_targets_missing_from_live_status(self) -> None:
        host = self.create_test_host(name="active-cluster-node")
        live_status = json.dumps({
            "nodes": [{"name": "node-a"}, {"name": "node-b"}],
            "resources": [{"id": "web-vip"}],
        })
        cases = (
            ("node_standby", "not-a-member", "node is not in the current SUSE HA membership"),
            ("resource_stop", "not-a-resource", "Pacemaker resource is not in the current cluster status"),
        )
        for action, target, message in cases:
            with self.subTest(action=action), \
                 patch.object(api, "cockpit_host_record", return_value={"id": host["id"], "name": host["name"]}), \
                 patch.object(api, "run_sudo_python", return_value=live_status) as remote:
                response = self.client.post(
                    f"/kvm-api/clusters/{host['id']}/actions",
                    headers=self.headers("cluster-token"), json={"action": action, "target": target},
                )
                self.assertEqual(response.status_code, 422, response.text)
                self.assertIn(message, response.json()["detail"])
                remote.assert_called_once()

    def test_cluster_preflight_checks_registered_ssh_ports_from_each_selected_host(self) -> None:
        first = self.create_test_host(name="preflight-node-a")
        second = self.create_test_host(name="preflight-node-b")
        with api.connect_db() as db:
            db.execute("UPDATE hosts SET address='192.0.2.31',port=2222 WHERE id=?", (first["id"],))
            db.execute("UPDATE hosts SET address='192.0.2.32',port=22 WHERE id=?", (second["id"],))
        def inspect(_host, _script, *, args, **_kwargs):
            peers = json.loads(args[0])["peers"]
            return json.dumps({"hostname": "test-node", "ssh_peer_connectivity": [
                {**peer, "reachable": peer["port"] == 22} for peer in peers
            ]})

        with patch.object(api, "run_sudo_python", side_effect=inspect) as remote:
            response = self.client.post("/kvm-api/clusters/preflight", headers=self.headers("viewer-token"),
                                        json={"host_ids": [first["id"], second["id"]]})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(remote.call_count, 2)
        peer_sets = [json.loads(call.kwargs["args"][0])["peers"] for call in remote.call_args_list]
        expected = [
            [{"host_name": "kvm-test.example.invalid", "address": "192.0.2.32", "port": 22}],
            [{"host_name": "kvm-test.example.invalid", "address": "192.0.2.31", "port": 2222}],
        ]
        self.assertEqual(sorted(peer_sets, key=lambda peers: peers[0]["address"]),
                         sorted(expected, key=lambda peers: peers[0]["address"]))
        results = {result["host_id"]: result for result in response.json()}
        self.assertEqual(results[first["id"]]["checks"]["ssh_peer_connectivity"][0]["host_name"], "kvm-test.example.invalid")
        self.assertTrue(results[first["id"]]["checks"]["ssh_peer_connectivity"][0]["reachable"])
        self.assertFalse(results[second["id"]]["checks"]["ssh_peer_connectivity"][0]["reachable"])

    def test_cluster_preflight_rejects_non_list_host_ids_before_connecting_to_hosts(self) -> None:
        with patch.object(api, "run_sudo_python") as remote:
            response = self.client.post(
                "/kvm-api/clusters/preflight",
                headers=self.headers("viewer-token"),
                json={"host_ids": {"type": "click"}},
            )

        self.assertEqual(response.status_code, 422, response.text)
        self.assertEqual(response.headers.get("X-KVM-API-Version"), api.app.version)
        self.assertEqual(response.headers.get("X-KVM-Preflight-Host-Ids-Type"), "dict")
        self.assertTrue(any("host_ids" in error.get("loc", []) for error in response.json()["detail"]))
        remote.assert_not_called()

    def test_cluster_preflight_accepts_json_encoded_host_id_list(self) -> None:
        first = self.create_test_host(name="preflight-json-node-a")
        second = self.create_test_host(name="preflight-json-node-b")
        with patch.object(api, "run_sudo_python", return_value=json.dumps({"hostname": "test-node"})) as remote:
            response = self.client.post(
                "/kvm-api/clusters/preflight",
                headers=self.headers("viewer-token"),
                json={"host_ids": json.dumps([first["id"], second["id"]])},
            )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.headers.get("X-KVM-API-Version"), api.app.version)
        self.assertEqual(remote.call_count, 2)

    def test_cluster_preflight_accepts_known_legacy_selection_wrappers(self) -> None:
        first = self.create_test_host(name="preflight-wrapper-node-a")
        second = self.create_test_host(name="preflight-wrapper-node-b")
        expected_ids = [first["id"], second["id"]]
        payloads = [
            {"host_ids": {"host_ids": expected_ids}},
            {"host_ids": {expected_ids[0]: True, expected_ids[1]: True}},
        ]

        with patch.object(api, "run_sudo_python", return_value=json.dumps({"hostname": "test-node"})) as remote:
            for payload in payloads:
                with self.subTest(payload=payload):
                    response = self.client.post(
                        "/kvm-api/clusters/preflight",
                        headers=self.headers("viewer-token"),
                        json=payload,
                    )
                    self.assertEqual(response.status_code, 200, response.text)
                    self.assertEqual({item["host_id"] for item in response.json()}, set(expected_ids))

        self.assertEqual(remote.call_count, 4)

    def test_template_workload_fix_installs_unit_without_enabling_or_starting_service(self) -> None:
        calls: list[list[str]] = []

        def fake_run(command, **_kwargs):
            calls.append(command)
            if command[:2] == ["rpm", "-q"]:
                return api.subprocess.CompletedProcess(command, 1, "", "package is not installed")
            if command[:2] == ["systemctl", "show"]:
                return api.subprocess.CompletedProcess(command, 0, "loaded\n", "")
            return api.subprocess.CompletedProcess(command, 0, "", "")

        output = io.StringIO()
        with patch.object(sys, "argv", ["template-workload", "nfs"]), \
             patch.object(api.subprocess, "run", side_effect=fake_run), \
             patch.object(Path, "is_file", return_value=False), \
             redirect_stdout(output):
            exec(api.TEMPLATE_WORKLOAD_PACKAGE_SCRIPT, {"__name__": "__main__"})

        self.assertIn("zypper", [command[0] for command in calls])
        self.assertTrue(any(command[:3] == ["systemctl", "show", "-p"] for command in calls))
        self.assertFalse(any(command[:2] == ["systemctl", "enable"] for command in calls))
        self.assertFalse(any(command[:2] == ["systemctl", "start"] for command in calls))
        self.assertIn("not enabled or started", output.getvalue())

    def test_cluster_preflight_probes_qnetd_on_fixed_port_for_cluster_admin(self) -> None:
        first = self.create_test_host(name="qnetd-node-a")
        second = self.create_test_host(name="qnetd-node-b")

        def inspect(_host, _script, *, args, **_kwargs):
            request = json.loads(args[0])
            self.assertEqual(request["qnetd_host"], "witness.example.invalid")
            return json.dumps({"hostname": "test-node", "qnetd_tcp_connectivity": {
                "host": request["qnetd_host"], "port": 5403, "reachable": True
            }})

        with patch.object(api, "run_sudo_python", side_effect=inspect) as remote:
            response = self.client.post("/kvm-api/clusters/preflight", headers=self.headers("cluster-token"), json={
                "host_ids": [first["id"], second["id"]], "qnetd_host": "witness.example.invalid"
            })
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(remote.call_count, 2)
        for result in response.json():
            check = result["checks"]["qnetd_tcp_connectivity"]
            self.assertEqual(check, {"host": "witness.example.invalid", "port": 5403, "reachable": True})

    def test_cluster_preflight_rejects_qnetd_probe_from_non_cluster_admin(self) -> None:
        first = self.create_test_host(name="qnetd-viewer-a")
        second = self.create_test_host(name="qnetd-viewer-b")
        response = self.client.post("/kvm-api/clusters/preflight", headers=self.headers("viewer-token"), json={
            "host_ids": [first["id"], second["id"]], "qnetd_host": "witness.example.invalid"
        })
        self.assertEqual(response.status_code, 403)

    def test_suse_bootstrap_commands_are_fixed_and_preserve_selected_node_order(self) -> None:
        first = {"id": "node-a", "username": "sles", "address": "192.0.2.41"}
        second = {"id": "node-b", "username": "sles", "address": "192.0.2.42"}
        hosts = [first, second]
        plan = {"id": "plan-1", "name": "ha-lab", "host_ids": ["node-a", "node-b"]}

        self.assertEqual(
            api.cluster_bootstrap_command(plan, hosts, "init", "node-a"),
            "crm cluster init --name ha-lab",
        )
        self.assertEqual(
            shlex.split(api.cluster_bootstrap_command(plan, hosts, "join", "node-b")),
            ["crm", "cluster", "join", "-c", "sles@192.0.2.41"],
        )
        with self.assertRaises(api.HTTPException):
            api.cluster_bootstrap_command(plan, hosts, "init", "node-b")
        with self.assertRaises(api.HTTPException):
            api.cluster_bootstrap_command(plan, hosts, "join", "node-a")

    def test_suse_bootstrap_preflight_blocks_when_a_peer_is_unreachable(self) -> None:
        first = {"id": "node-a", "hostname": "node-a", "address": "192.0.2.41", "port": 22, "username": "sles"}
        second = {"id": "node-b", "hostname": "node-b", "address": "192.0.2.42", "port": 22, "username": "sles"}
        plan = {"id": "plan-1", "name": "ha-lab", "host_ids": ["node-a", "node-b"]}

        def preflight(host, _script, *, args, **_kwargs):
            peers = json.loads(args[0])["peers"]
            return json.dumps({
                "compatibility_supported": True, "ha_active": True,
                "time_synchronized": True,
                "tools": {"crm": True, "crm_mon": True, "corosync-cfgtool": True},
                "ssh_peer_connectivity": [{**peer, "reachable": host["id"] == "node-a"} for peer in peers],
                "cluster_configured": False, "cluster_detected": False, "cluster_name": "",
            })

        with patch.object(api, "cockpit_host_record", side_effect=lambda host_id: {"id": host_id}), \
             patch.object(api, "run_sudo_python", side_effect=preflight):
            with self.assertRaisesRegex(RuntimeError, "cannot reach the SSH port"):
                api.cluster_bootstrap_preflight(plan, [first, second], "init", "node-a")

    def test_suse_bootstrap_preflight_blocks_a_corosync_subnet_missing_from_a_node(self) -> None:
        first = {"id": "node-a", "hostname": "node-a", "address": "192.0.2.41", "port": 22, "username": "sles"}
        second = {"id": "node-b", "hostname": "node-b", "address": "192.0.2.42", "port": 22, "username": "sles"}
        plan = {"id": "plan-1", "name": "ha-lab", "host_ids": ["node-a", "node-b"],
                "config": {"corosync_networks": ["10.20.0.0/24"]}}

        def preflight(host, _script, *, args, **_kwargs):
            return json.dumps({
                "compatibility_supported": True, "ha_active": True, "time_synchronized": True,
                "tools": {"crm": True, "crm_mon": True, "corosync-cfgtool": True},
                "ssh_peer_connectivity": [],
                "interfaces": [{"name": "eth1", "subnets": ["10.20.0.0/24"]}] if host["id"] == "node-a" else [],
                "cluster_configured": False, "cluster_detected": False, "cluster_name": "",
            })

        with patch.object(api, "cockpit_host_record", side_effect=lambda host_id: {"id": host_id}), \
             patch.object(api, "run_sudo_python", side_effect=preflight):
            with self.assertRaisesRegex(RuntimeError, "no longer reports planned Corosync subnet"):
                api.cluster_bootstrap_preflight(plan, [first, second], "join", "node-b")

    def test_suse_bootstrap_init_blocks_mixed_sle_ha_product_releases(self) -> None:
        first = {"id": "node-a", "hostname": "node-a", "address": "192.0.2.41", "port": 22, "username": "sles"}
        second = {"id": "node-b", "hostname": "node-b", "address": "192.0.2.42", "port": 22, "username": "sles"}
        plan = {"id": "plan-1", "name": "ha-lab", "host_ids": ["node-a", "node-b"]}

        def preflight(host, _script, *, args, **_kwargs):
            peers = json.loads(args[0])["peers"]
            return json.dumps({
                "compatibility_supported": True, "ha_active": True,
                "ha_product": "sle-ha/15.6/x86_64" if host["id"] == "node-a" else "sle-ha/15.7/x86_64",
                "time_synchronized": True,
                "tools": {"crm": True, "crm_mon": True, "corosync-cfgtool": True},
                "ssh_peer_connectivity": [{**peer, "reachable": True, "hosts_file_entry_present": True} for peer in peers],
                "cluster_configured": False, "cluster_detected": False, "cluster_name": "",
            })

        with patch.object(api, "cockpit_host_record", side_effect=lambda host_id: {"id": host_id}), \
             patch.object(api, "run_sudo_python", side_effect=preflight):
            with self.assertRaisesRegex(RuntimeError, "different active SLE HA product releases"):
                api.cluster_bootstrap_preflight(plan, [first, second], "init", "node-a")

    def test_suse_bootstrap_join_allows_temporary_mixed_product_releases(self) -> None:
        first = {"id": "node-a", "hostname": "node-a", "address": "192.0.2.41", "port": 22, "username": "sles"}
        second = {"id": "node-b", "hostname": "node-b", "address": "192.0.2.42", "port": 22, "username": "sles"}
        plan = {"id": "plan-1", "name": "ha-lab", "host_ids": ["node-a", "node-b"]}

        def preflight(host, _script, *, args, **_kwargs):
            peers = json.loads(args[0])["peers"]
            is_anchor = host["id"] == "node-a"
            return json.dumps({
                "compatibility_supported": True, "ha_active": True,
                "ha_product": "sle-ha/15.6/x86_64" if is_anchor else "sle-ha/15.7/x86_64",
                "time_synchronized": True,
                "tools": {"crm": True, "crm_mon": True, "corosync-cfgtool": True},
                "ssh_peer_connectivity": [{**peer, "reachable": True, "hosts_file_entry_present": True} for peer in peers],
                "cluster_configured": is_anchor, "cluster_detected": is_anchor,
                "cluster_name": "ha-lab" if is_anchor else "",
            })

        with patch.object(api, "cockpit_host_record", side_effect=lambda host_id: {"id": host_id}), \
             patch.object(api, "run_sudo_python", side_effect=preflight):
            api.cluster_bootstrap_preflight(plan, [first, second], "join", "node-b")

    def test_suse_bootstrap_init_blocks_when_active_sle_ha_product_is_unknown(self) -> None:
        first = {"id": "node-a", "hostname": "node-a", "address": "192.0.2.41", "port": 22, "username": "sles"}
        second = {"id": "node-b", "hostname": "node-b", "address": "192.0.2.42", "port": 22, "username": "sles"}
        plan = {"id": "plan-1", "name": "ha-lab", "host_ids": ["node-a", "node-b"]}

        def preflight(host, _script, *, args, **_kwargs):
            peers = json.loads(args[0])["peers"]
            return json.dumps({
                "compatibility_supported": True, "ha_active": True,
                "ha_product": "sle-ha/15.6/x86_64" if host["id"] == "node-a" else "",
                "time_synchronized": True,
                "tools": {"crm": True, "crm_mon": True, "corosync-cfgtool": True},
                "ssh_peer_connectivity": [{**peer, "reachable": True, "hosts_file_entry_present": True} for peer in peers],
                "cluster_configured": False, "cluster_detected": False, "cluster_name": "",
            })

        with patch.object(api, "cockpit_host_record", side_effect=lambda host_id: {"id": host_id}), \
             patch.object(api, "run_sudo_python", side_effect=preflight):
            with self.assertRaisesRegex(RuntimeError, "active SLE HA product release could not be confirmed"):
                api.cluster_bootstrap_preflight(plan, [first, second], "init", "node-a")

    def test_suse_bootstrap_preflight_blocks_when_peer_name_is_missing_from_hosts_file(self) -> None:
        first = {"id": "node-a", "hostname": "node-a", "address": "192.0.2.41", "port": 22, "username": "sles"}
        second = {"id": "node-b", "hostname": "node-b", "address": "192.0.2.42", "port": 22, "username": "sles"}
        plan = {"id": "plan-1", "name": "ha-lab", "host_ids": ["node-a", "node-b"]}

        def preflight(host, _script, *, args, **_kwargs):
            peers = json.loads(args[0])["peers"]
            return json.dumps({
                "compatibility_supported": True, "ha_active": True,
                "time_synchronized": True,
                "tools": {"crm": True, "crm_mon": True, "corosync-cfgtool": True},
                "ssh_peer_connectivity": [{**peer, "reachable": True, "hosts_file_entry_present": False} for peer in peers],
                "cluster_configured": False, "cluster_detected": False, "cluster_name": "",
            })

        with patch.object(api, "cockpit_host_record", side_effect=lambda host_id: {"id": host_id}), \
             patch.object(api, "run_sudo_python", side_effect=preflight):
            with self.assertRaisesRegex(RuntimeError, "cannot find selected peer names in /etc/hosts"):
                api.cluster_bootstrap_preflight(plan, [first, second], "init", "node-a")

    def test_suse_bootstrap_preflight_blocks_when_qnetd_is_unreachable(self) -> None:
        first = {"id": "node-a", "hostname": "node-a", "address": "192.0.2.41", "port": 22, "username": "sles"}
        second = {"id": "node-b", "hostname": "node-b", "address": "192.0.2.42", "port": 22, "username": "sles"}
        plan = {"id": "plan-1", "name": "ha-lab", "host_ids": ["node-a", "node-b"],
                "config": {"quorum": "qdevice", "qnetd_host": "witness.example.invalid"}}

        def preflight(host, _script, *, args, **_kwargs):
            request = json.loads(args[0])
            self.assertEqual(request["qnetd_host"], "witness.example.invalid")
            return json.dumps({
                "compatibility_supported": True, "ha_active": True,
                "time_synchronized": True,
                "tools": {"crm": True, "crm_mon": True, "corosync-cfgtool": True},
                "ssh_peer_connectivity": [{**peer, "reachable": True} for peer in request["peers"]],
                "qnetd_tcp_connectivity": {"host": request["qnetd_host"], "port": 5403, "reachable": False},
                "cluster_configured": False, "cluster_detected": False, "cluster_name": "",
            })

        with patch.object(api, "cockpit_host_record", side_effect=lambda host_id: {"id": host_id}), \
             patch.object(api, "run_sudo_python", side_effect=preflight):
            with self.assertRaisesRegex(RuntimeError, "cannot reach QNetd at witness.example.invalid:5403/TCP"):
                api.cluster_bootstrap_preflight(plan, [first, second], "init", "node-a")

    def test_operation_queue_rejects_work_when_capacity_is_full(self) -> None:
        with api.connect_db() as db:
            db.execute("INSERT INTO operation_jobs (id,actor,kind,status,results_json,created_at,updated_at) VALUES (?,?,?,?,?,?,?)",
                       ("queued-test", "user-test", "test", "queued", "[]", api.now(), api.now()))
        with patch.object(api, "MAX_ACTIVE_OPERATION_JOBS", 1):
            with self.assertRaises(api.HTTPException) as error:
                api.create_operation_job("test", "user-test", [], lambda _host: {})
        self.assertEqual(error.exception.status_code, 429)

    def test_stale_refresh_checks_three_hosts_and_returns_partial_connectivity_results(self) -> None:
        headers = self.headers("admin-token")
        hosts = [
            self.create_test_host(name=f"kvm-test-{index}")
            for index in range(1, 4)
        ]
        stale_time = (api.datetime.now(api.timezone.utc) - api.timedelta(minutes=10)).isoformat()
        with api.connect_db() as db:
            db.executemany("UPDATE hosts SET last_checked_at=? WHERE id=?", [(stale_time, host["id"]) for host in hosts])

        def probe_host(host: dict, **_kwargs):
            if host["name"] == "kvm-test-2":
                return {"status": "unreachable", "last_checked_at": api.now(), "last_error": "Connection refused"}
            return {
                "hostname": host["name"], "status": "ready", "cpu_count": 4,
                "memory_total_bytes": 8 * 1024**3, "last_checked_at": api.now(),
                "ssh_host_key": host["ssh_host_key"],
            }

        with patch.object(api, "probe", side_effect=probe_host) as probe:
            response = self.client.post("/kvm-api/hosts/refresh-stale?max_age_seconds=30&limit=10", headers=headers)

        self.assertEqual(response.status_code, 200, response.text)
        refreshed = {host["name"]: host for host in response.json()}
        self.assertEqual(set(refreshed), {"kvm-test-1", "kvm-test-2", "kvm-test-3"})
        self.assertEqual([refreshed[f"kvm-test-{index}"]["status"] for index in range(1, 4)], ["ready", "unreachable", "ready"])
        self.assertEqual(refreshed["kvm-test-2"]["last_error"], "Connection refused")
        self.assertTrue(all(refreshed[f"kvm-test-{index}"]["last_checked_at"] != stale_time for index in range(1, 4)))
        self.assertEqual(probe.call_count, 3)

    def test_backup_endpoint_requires_https_and_rejects_embedded_credentials(self) -> None:
        headers = self.headers("admin-token")
        base = {"name": "test-s3", "bucket": "test-bucket", "access_key_id": "test-id",
                "secret_access_key": "test-secret"}
        for endpoint in ("http://objects.example.invalid", "https://user:pass@objects.example.invalid"):
            with self.subTest(endpoint=endpoint):
                response = self.client.post("/kvm-api/backups/destinations", headers=headers,
                                            json=base | {"endpoint_url": endpoint})
                self.assertEqual(response.status_code, 422)

    def test_custom_s3_endpoint_requires_an_operator_allowlist(self) -> None:
        response = self.client.post("/kvm-api/backups/destinations", headers=self.headers("admin-token"), json={
            "name": "test-s3", "endpoint_url": "https://objects.example.invalid",
            "bucket": "test-bucket", "access_key_id": "test-id", "secret_access_key": "test-secret",
        })
        self.assertEqual(response.status_code, 422)

    def test_approved_custom_s3_endpoint_saves_secrets_without_returning_them(self) -> None:
        api.KVM_S3_ALLOWED_ENDPOINT_HOSTS.add("objects.example.invalid")
        try:
            response = self.client.post("/kvm-api/backups/destinations", headers=self.headers("admin-token"), json={
                "name": "test-s3", "endpoint_url": "https://objects.example.invalid",
                "bucket": "test-bucket", "access_key_id": "test-id", "secret_access_key": "test-secret",
            })
        finally:
            api.KVM_S3_ALLOWED_ENDPOINT_HOSTS.discard("objects.example.invalid")
        self.assertEqual(response.status_code, 201, response.text)
        self.assertTrue(response.json()["has_credentials"])
        self.assertNotIn("secret_access_key", response.json())

    def test_viewer_cannot_operate_vm_and_operator_action_uses_libvirt_boundary(self) -> None:
        host = self.create_test_host()
        denied = self.client.post(
            f"/kvm-api/hosts/{host['id']}/vms/actions?vm_name=test-vm",
            headers=self.headers("viewer-token"), json={"action": "start"},
        )
        self.assertEqual(denied.status_code, 403)

        with patch.object(api, "create_operation_job", return_value={"job_id": "00000000-0000-4000-8000-000000000002", "status": "queued"}) as queued:
            response = self.client.post(
                f"/kvm-api/hosts/{host['id']}/vms/actions?vm_name=test-vm",
                headers=self.headers("vm-operator-token"), json={"action": "start"},
            )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["status"], "queued")
        self.assertEqual(queued.call_args.args[0], "vm_start")
        perform_action = queued.call_args.args[3]
        with patch.object(api, "run_sudo_python", return_value="") as remote:
            self.assertEqual(perform_action(api.cockpit_host_record(host["id"])), {"status": "completed"})
        self.assertIn("virsh", remote.call_args.args[1])

    def test_vm_cpu_memory_update_validates_limits_and_calls_remote_boundary(self) -> None:
        host = self.create_test_host()
        invalid = self.client.post(
            f"/kvm-api/hosts/{host['id']}/vms/config?vm_name=test-vm",
            headers=self.headers("admin-token"), json={"vcpus": 0, "memory_mib": 512},
        )
        self.assertEqual(invalid.status_code, 422)

        with patch.object(api, "run_sudo_python", return_value="") as remote:
            response = self.client.post(
                f"/kvm-api/hosts/{host['id']}/vms/config?vm_name=test-vm",
                headers=self.headers("admin-token"), json={"vcpus": 2, "memory_mib": 1024},
            )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(remote.call_args.args[2][1:], ["2", str(1024 * 1024)])

    def test_vm_details_reject_duplicate_boot_devices_before_remote_call(self) -> None:
        host = self.create_test_host()
        with patch.object(api, "run_sudo_python") as remote:
            response = self.client.post(
                f"/kvm-api/hosts/{host['id']}/vms/details-config?vm_name=test-vm",
                headers=self.headers("admin-token"),
                json={"boot_order": ["hd", "hd"], "cpu_mode": "host-model", "autostart": False},
            )
        self.assertEqual(response.status_code, 422)
        remote.assert_not_called()

    def test_network_configuration_rejects_bad_address_before_remote_call(self) -> None:
        host = self.create_test_host()
        with patch.object(api, "configure_network_with_checkpoint") as network_change:
            response = self.client.post(
                f"/kvm-api/hosts/{host['id']}/network-connections/config",
                headers=self.headers("network-token"),
                json={"uuid": "00000000-0000-0000-0000-000000000001", "method": "manual", "addresses": ["not-an-ip"]},
            )
        self.assertEqual(response.status_code, 422)
        network_change.assert_not_called()

    def test_network_configuration_routes_validated_change_through_checkpoint(self) -> None:
        host = self.create_test_host()
        with patch.object(api, "configure_network_with_checkpoint") as network_change:
            response = self.client.post(
                f"/kvm-api/hosts/{host['id']}/network-connections/config",
                headers=self.headers("network-token"),
                json={"uuid": "00000000-0000-0000-0000-000000000001", "method": "manual",
                      "addresses": ["192.0.2.20/24"], "gateway": "192.0.2.1", "dns": ["192.0.2.53"]},
            )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(network_change.call_args.args[1:5], ("00000000-0000-0000-0000-000000000001", "manual", "192.0.2.20/24", "192.0.2.1"))

    def test_libvirt_bridge_network_requires_bridge_name(self) -> None:
        host = self.create_test_host()
        with patch.object(api, "run_sudo_python") as remote:
            response = self.client.post(
                f"/kvm-api/hosts/{host['id']}/libvirt/networks/config",
                headers=self.headers("network-token"), json={"action": "create", "name": "test-bridge", "forward_mode": "bridge"},
            )
        self.assertEqual(response.status_code, 422)
        remote.assert_not_called()

    def test_storage_volume_create_uses_validated_remote_boundary(self) -> None:
        host = self.create_test_host()
        with patch.object(api, "run_sudo_python", return_value='{"name":"test-volume.qcow2","capacity_bytes":1048576}') as remote:
            response = self.client.post(
                f"/kvm-api/hosts/{host['id']}/storage-volumes",
                headers=self.headers("admin-token"),
                json={"action": "create", "pool": "default", "name": "test-volume.qcow2", "capacity_bytes": 1048576, "format": "qcow2"},
            )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["name"], "test-volume.qcow2")
        self.assertIn("virsh", remote.call_args.args[1])

    def test_repository_action_rejects_invalid_uri_before_remote_call(self) -> None:
        host = self.create_test_host()
        with patch.object(api, "run_sudo_python") as remote:
            response = self.client.post(
                f"/kvm-api/hosts/{host['id']}/repositories/actions",
                headers=self.headers("admin-token"),
                json={"alias": "test-repo", "action": "add", "name": "Test", "uri": "javascript:alert(1)"},
            )
        self.assertEqual(response.status_code, 422)
        remote.assert_not_called()

    def test_account_protection_blocks_locking_the_imported_ssh_user(self) -> None:
        host = self.create_test_host()
        with patch.object(api, "run_sudo_python") as remote:
            response = self.client.post(
                f"/kvm-api/hosts/{host['id']}/accounts/actions",
                headers=self.headers("admin-token"), json={"username": "operator", "action": "lock"},
            )
        self.assertEqual(response.status_code, 422)
        remote.assert_not_called()

    def test_subscription_extension_without_registration_key_uses_noninteractive_path(self) -> None:
        host = self.create_test_host()
        with patch.object(api, "run_sudo_python", return_value="") as remote:
            response = self.client.post(
                f"/kvm-api/hosts/{host['id']}/subscriptions/actions",
                headers=self.headers("admin-token"),
                json={"action": "activate_extension", "product": "PackageHub/16.0/x86_64"},
            )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIsNone(remote.call_args.kwargs["stdin_data"])

    def test_subscription_registration_does_not_persist_or_return_registration_code(self) -> None:
        host = self.create_test_host()
        registration_code = "test-registration-code-123"
        with patch.object(api, "run_sudo_python", return_value="Registration successful") as remote:
            response = self.client.post(
                f"/kvm-api/hosts/{host['id']}/subscriptions/actions",
                headers=self.headers("admin-token"),
                json={"action": "register", "email": "operator@example.invalid", "regcode": registration_code},
            )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertNotIn(registration_code, response.text)
        self.assertGreaterEqual(remote.call_args.kwargs["stdin_data"].find(registration_code), 0)
        with api.connect_db() as db:
            audit_text = " ".join(row[0] or "" for row in db.execute("SELECT detail FROM audit_events"))
        self.assertNotIn(registration_code, audit_text)

    def test_subscription_failure_redacts_registration_code(self) -> None:
        host = self.create_test_host()
        registration_code = "test-registration-code-456"
        with patch.object(api, "run_sudo_python", side_effect=RuntimeError(f"remote returned {registration_code}")):
            response = self.client.post(
                f"/kvm-api/hosts/{host['id']}/subscriptions/actions",
                headers=self.headers("admin-token"),
                json={"action": "activate_extension", "product": "PackageHub/16.0/x86_64", "regcode": registration_code},
            )
        self.assertEqual(response.status_code, 502)
        self.assertNotIn(registration_code, response.text)
        self.assertIn("[redacted]", response.text)

    def test_backup_destination_test_calls_object_storage_boundary(self) -> None:
        headers = self.headers("admin-token")
        created = self.client.post("/kvm-api/backups/destinations", headers=headers, json={
            "name": "test-s3", "bucket": "test-bucket", "access_key_id": "test-id", "secret_access_key": "test-secret",
        })
        self.assertEqual(created.status_code, 201, created.text)
        s3 = Mock()
        with patch.object(api, "backup_s3_client", return_value=s3):
            response = self.client.post(f"/kvm-api/backups/destinations/{created.json()['id']}/test", headers=headers)
        self.assertEqual(response.status_code, 200, response.text)
        s3.head_bucket.assert_called_once_with(Bucket="test-bucket")

    def test_host_delete_removes_only_inventory_record_and_audits_action(self) -> None:
        host = self.create_test_host()
        with patch.object(api, "restore_cockpit_proxy") as restore:
            response = self.client.delete(f"/kvm-api/hosts/{host['id']}", headers=self.headers("admin-token"))
        self.assertEqual(response.status_code, 204)
        restore.assert_not_called()
        listed = self.client.get("/kvm-api/hosts", headers=self.headers("admin-token"))
        self.assertEqual(listed.json(), [])
        audit = self.client.get("/kvm-api/audit", headers=self.headers("admin-token"))
        self.assertEqual(audit.status_code, 200)
        self.assertEqual(audit.json()[0]["action"], "host.remove")

    def test_database_schema_migration_adds_optional_ssh_columns(self) -> None:
        old_path = Path(self.temp_dir.name) / "old-schema.sqlite3"
        db = api.sqlite3.connect(old_path)
        db.execute("CREATE TABLE hosts (id TEXT PRIMARY KEY, name TEXT NOT NULL, address TEXT NOT NULL, port INTEGER NOT NULL, username TEXT NOT NULL, password TEXT NOT NULL, hostname TEXT, status TEXT NOT NULL, cpu_count INTEGER, memory_total_bytes INTEGER, last_checked_at TEXT, last_error TEXT)")
        api.initialize_schema(db)
        columns = {row[1] for row in db.execute("PRAGMA table_info(hosts)")}
        db.close()
        self.assertTrue({"ssh_host_key", "cockpit_proxy_enabled", "ssh_private_key_enc", "ssh_key_passphrase_enc"}.issubset(columns))


if __name__ == "__main__":
    unittest.main()

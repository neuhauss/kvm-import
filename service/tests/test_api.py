"""Offline API regression tests. No Rancher, SSH host, libvirt, or S3 calls."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import Mock, patch


SERVICE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVICE_DIR))

# These values are deliberately test-only and are set before importing the API,
# which reads its encryption key and role mappings during module initialization.
os.environ["KVM_CREDENTIAL_KEY"] = "offline-test-key-that-is-not-a-real-secret"
os.environ["KVM_ALLOWED_GLOBAL_ROLES"] = "admin"
os.environ["KVM_VIEWER_GLOBAL_ROLES"] = "kvm-viewer"
os.environ["KVM_NETWORK_OPERATOR_GLOBAL_ROLES"] = "kvm-network-operator"
os.environ["KVM_STORAGE_OPERATOR_GLOBAL_ROLES"] = "kvm-storage-operator"
os.environ["KVM_S3_ALLOWED_ENDPOINT_HOSTS"] = ""
os.environ["RANCHER_API_URL"] = "https://rancher.invalid"
_test_data = tempfile.TemporaryDirectory(prefix="rancher-kvm-tests-")
os.environ["KVM_DB_PATH"] = str(Path(_test_data.name) / "bootstrap.sqlite3")

import app as api  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


class KvmApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="rancher-kvm-case-")
        self.role_by_token = {
            "admin-token": "admin",
            "viewer-token": "kvm-viewer",
            "network-token": "kvm-network-operator",
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
        user_id = "user-test"
        if path == "/v3/token":
            return {"userId": user_id}
        if path == f"/v3/users/{user_id}":
            return {"id": user_id, "username": "test-user"}
        if path == f"/v3/globalRoleBindings?userId={user_id}":
            role = self.role_by_token.get(token or "", "")
            return {"data": [{"globalRoleId": role}] if role else []}
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

        with patch.object(api, "run_sudo_python", return_value="") as remote:
            response = self.client.post(
                f"/kvm-api/hosts/{host['id']}/vms/actions?vm_name=test-vm",
                headers=self.headers("admin-token"), json={"action": "start"},
            )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(response.json()["success"])
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

"""Regression tests for the extension's guided SUSE HA NFS profile."""

from __future__ import annotations

import ast
import contextlib
import io
import json
import os
import stat
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


SERVICE_SOURCE = Path(__file__).resolve().parents[1] / "app.py"


def nfs_profile_script() -> str:
    tree = ast.parse(SERVICE_SOURCE.read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "HA_NFS_SERVICE_CONFIG_SCRIPT"
            for target in node.targets
        ):
            return ast.literal_eval(node.value)
    raise AssertionError("HA_NFS_SERVICE_CONFIG_SCRIPT was not found")


class ClusterNfsProfileTests(unittest.TestCase):
    def execute(self, payload, *, cib=None, ip_output="[]", drbd_output="resource role:Primary\n disk:UpToDate\n peer-disk:UpToDate\n", filesystem="ext4", nfs_active=False):
        commands = []
        applied = []

        def fake_run(command, **_kwargs):
            commands.append(command)
            if command[0] == "blkid":
                return SimpleNamespace(returncode=0, stdout=filesystem + "\n", stderr="")
            if command[0] == "drbdadm":
                return SimpleNamespace(returncode=0, stdout=drbd_output, stderr="")
            if command[:3] == ["crm", "ra", "info"]:
                return SimpleNamespace(returncode=0, stdout="SUSE resource agent", stderr="")
            if command[:2] == ["systemctl", "cat"]:
                return SimpleNamespace(returncode=0, stdout="[Service]\n", stderr="")
            if command[:2] == ["systemctl", "is-active"]:
                return SimpleNamespace(returncode=0 if nfs_active else 3, stdout="active" if nfs_active else "inactive", stderr="")
            if command[:3] == ["ip", "-j", "address"]:
                return SimpleNamespace(returncode=0, stdout=ip_output, stderr="")
            if command == ["cibadmin", "-Q"]:
                return SimpleNamespace(returncode=0, stdout=cib or '<cib><configuration><crm_config/><resources/><constraints/></configuration></cib>', stderr="")
            if command[:4] == ["crm", "configure", "load", "update"]:
                applied.append(Path(command[-1]).read_text())
                return SimpleNamespace(returncode=0, stdout="updated", stderr="")
            return SimpleNamespace(returncode=1, stdout="", stderr="unexpected command")

        original_open = open

        def fake_open(path, *args, **kwargs):
            if path == "/proc/mounts":
                return io.StringIO("")
            return original_open(path, *args, **kwargs)

        block_stat = os.stat_result((stat.S_IFBLK | 0o600, 1, 0, 1, 0, 0, 0, 0, 0, 0))
        stdout = io.StringIO()
        with patch("subprocess.run", side_effect=fake_run), \
             patch("builtins.open", side_effect=fake_open), \
             patch("os.path.exists", return_value=True), \
             patch("os.path.isdir", return_value=True), \
             patch("os.path.realpath", side_effect=lambda value: value), \
             patch("os.stat", return_value=block_stat), \
             patch.object(sys, "stdin", io.StringIO(json.dumps(payload))), \
             contextlib.redirect_stdout(stdout):
            try:
                exec(compile(nfs_profile_script(), "<ha-nfs-profile>", "exec"), {"__name__": "__main__"})
            except SystemExit as exc:
                if exc.code not in (None, 0):
                    raise
        return json.loads(stdout.getvalue()), commands, applied

    def payload(self, **overrides):
        return {
            "storage_mode": "drbd", "resource_prefix": "nfs-prod", "drbd_resource": "nfs",
            "state_device": "/dev/drbd0", "data_device": "/dev/drbd1",
            "share_directory": "/srv/nfs/share", "filesystem": "ext4",
            "clientspec": "192.0.2.0/24", "virtual_ip": "192.0.2.50", "cidr_netmask": 24,
            "cluster_node_count": 2,
            **overrides,
        }

    def test_drbd_profile_creates_suse_ordered_resources_stopped_in_one_update(self):
        result, commands, applied = self.execute(self.payload())
        self.assertTrue(result["success"])
        self.assertEqual(result["storage_mode"], "drbd")
        self.assertEqual(len(applied), 1)
        config = applied[0]
        self.assertIn('clone cl-drbd-nfs-prod drbd-nfs-prod meta promotable="true"', config)
        self.assertIn('nfs_server_scope="SUSE"', config)
        self.assertIn('options="rw,mountpoint"', config)
        self.assertIn('colocation col-nfs-prod-on-drbd inf: g-nfs-prod cl-drbd-nfs-prod:Promoted', config)
        self.assertIn('order ord-nfs-prod-drbd-before-service Mandatory: cl-drbd-nfs-prod:promote g-nfs-prod:start', config)
        self.assertIn('target-role="Stopped"', config)
        self.assertGreater(result["export_timeout_seconds"], 60)
        self.assertFalse(any(command[:3] == ["crm", "resource", "start"] for command in commands))
        self.assertFalse(any(command[0] == "mkfs" for command in commands))

    def test_shared_profile_uses_stable_shared_devices_and_does_not_add_drbd(self):
        result, _commands, applied = self.execute(self.payload(
            storage_mode="shared", shared_storage_confirmed=True,
            state_device="/dev/disk/by-id/wwn-state", data_device="/dev/mapper/nfs-data",
        ))
        self.assertTrue(result["success"])
        self.assertEqual(len(applied), 1)
        self.assertNotIn("ocf:linbit:drbd", applied[0])
        self.assertIn('group g-nfs-prod fs-state-nfs-prod fs-share-nfs-prod nfsserver-nfs-prod exportfs-nfs-prod vip-nfs-prod', applied[0])

    def test_export_monitor_timeout_exceeds_configured_stonith_timeout(self):
        cib = ('<cib><configuration><crm_config><cluster_property_set id="cluster-properties">'
               '<nvpair id="stonith-timeout" name="stonith-timeout" value="2min"/>'
               '</cluster_property_set></crm_config><resources/><constraints/></configuration></cib>')
        result, _commands, applied = self.execute(self.payload(), cib=cib)
        self.assertEqual(result["export_timeout_seconds"], 150)
        self.assertIn('timeout=150s', applied[0])

    def test_disabled_stonith_setting_prevents_any_nfs_configuration(self):
        cib = ('<cib><configuration><crm_config><cluster_property_set id="cluster-properties">'
               '<nvpair id="stonith-enabled" name="stonith-enabled" value="false"/>'
               '</cluster_property_set></crm_config><resources/><constraints/></configuration></cib>')
        with self.assertRaisesRegex(SystemExit, "stonith-enabled disabled"):
            self.execute(self.payload(), cib=cib)

    def test_preflight_checks_each_node_without_mutating_the_cib(self):
        result, commands, applied = self.execute(self.payload(preflight_only=True))
        self.assertTrue(result["success"])
        self.assertIn("checked_node", result)
        self.assertFalse(applied)
        self.assertFalse(any(command[:2] == ["crm", "configure"] for command in commands))
        self.assertFalse(any(command == ["cibadmin", "-Q"] for command in commands))

    def test_drbd_secondary_checks_replication_without_reading_block_devices(self):
        result, commands, applied = self.execute(
            self.payload(preflight_only=True),
            drbd_output="resource role:Secondary\\n disk:UpToDate\\n peer-disk:UpToDate\\n",
        )
        self.assertTrue(result["success"])
        self.assertFalse(result["drbd_primary"])
        self.assertFalse(any(command[0] == "blkid" for command in commands))
        self.assertFalse(applied)

    def test_shared_mode_requires_explicit_shared_storage_attestation(self):
        with self.assertRaisesRegex(SystemExit, "Confirm that both devices refer to the same externally shared block storage"):
            self.execute(self.payload(storage_mode="shared", state_device="/dev/disk/by-id/state", data_device="/dev/disk/by-id/data"))

    def test_drbd_mode_rejects_unsupported_node_count_and_unsynchronized_replica(self):
        with self.assertRaisesRegex(SystemExit, "supported only for a two-node cluster"):
            self.execute(self.payload(cluster_node_count=3))
        with self.assertRaisesRegex(SystemExit, "not UpToDate on every member"):
            self.execute(self.payload(), drbd_output="resource role:Primary\n disk:UpToDate\n peer-disk:Inconsistent\n")

    def test_profile_rejects_existing_vip_and_non_matching_filesystem(self):
        with self.assertRaisesRegex(SystemExit, "already assigned to a host interface"):
            self.execute(self.payload(), ip_output='[{"addr_info":[{"local":"192.0.2.50"}]}]')
        with self.assertRaisesRegex(SystemExit, "must already contain the selected ext4 filesystem"):
            self.execute(self.payload(), filesystem="xfs")

    def test_profile_refuses_to_take_over_an_independently_running_nfs_server(self):
        with self.assertRaisesRegex(SystemExit, "active outside this new Pacemaker profile"):
            self.execute(self.payload(), nfs_active=True)

    def test_existing_pacemaker_id_collision_prevents_any_write(self):
        cib = '<cib><configuration><crm_config/><resources><primitive id="g-nfs-prod"/></resources><constraints/></configuration></cib>'
        with self.assertRaisesRegex(SystemExit, "Pacemaker IDs already exist"):
            self.execute(self.payload(), cib=cib)


if __name__ == "__main__":
    unittest.main()

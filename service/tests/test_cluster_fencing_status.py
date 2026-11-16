"""Regression tests for SUSE SBD and Pacemaker STONITH status reporting."""

import ast
import contextlib
import io
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


def status_script() -> str:
    source = Path(__file__).resolve().parents[1] / "app.py"
    tree = ast.parse(source.read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "HA_CLUSTER_STATUS_SCRIPT"
            for target in node.targets
        ):
            return ast.literal_eval(node.value)
    raise AssertionError("HA_CLUSTER_STATUS_SCRIPT was not found")


class ClusterFencingStatusTests(unittest.TestCase):
    def run_status(self, sbd_result, quorum_text="Quorate: Yes", qdevice_result=None, target_results=None, second_node_name="node-b"):
        status_xml = (
            "<crm_mon><summary><current_dc>node-a</current_dc></summary>"
            "<nodes><node name='node-a' id='1' online='true'/>"
            f"<node name='{second_node_name}' id='2' online='true'/></nodes><resources/></crm_mon>"
        )

        commands = []

        def fake_run(command, **_kwargs):
            commands.append(command)
            if command[0] == "crm_mon":
                return SimpleNamespace(returncode=0, stdout=status_xml, stderr="")
            if command[:3] == ["cibadmin", "-Q", "-o"]:
                return SimpleNamespace(returncode=0, stdout="<resources/>", stderr="")
            if command[0] == "corosync-quorumtool":
                return SimpleNamespace(returncode=0, stdout=quorum_text, stderr="")
            if command == ["crm", "corosync", "status", "qdevice"]:
                return qdevice_result or SimpleNamespace(returncode=1, stdout="", stderr="QDevice status unavailable")
            if command[0] == "stonith_admin":
                if command[1:] == ["-L"]:
                    return SimpleNamespace(returncode=0, stdout="No STONITH devices configured", stderr="")
                if command[1] == "-l":
                    return (target_results or {}).get(command[2], SimpleNamespace(returncode=0, stdout="", stderr=""))
            if command[:3] == ["crm", "sbd", "status"]:
                return sbd_result
            raise AssertionError(f"Unexpected status command: {command}")

        output = io.StringIO()
        with patch("shutil.which", return_value="/usr/bin/mock"), \
             patch("subprocess.run", side_effect=fake_run), \
             patch("builtins.open", return_value=io.StringIO("cluster_name: test-ha\n")), \
             contextlib.redirect_stdout(output):
            exec(compile(status_script(), "<ha-cluster-status>", "exec"), {"__name__": "__main__"})
        return json.loads(output.getvalue()), commands

    def test_diskless_sbd_counts_as_fencing_without_a_stonith_resource(self):
        status, _commands = self.run_status(SimpleNamespace(
            returncode=0,
            stdout="Diskless SBD configured\nWatchdog info: /dev/watchdog0",
            stderr="",
        ))
        self.assertTrue(status["fencing"]["configured"])
        self.assertFalse(status["fencing"]["stonith_configured"])
        self.assertTrue(status["fencing"]["sbd"]["configured"])
        self.assertEqual(status["fencing"]["sbd"]["type"], "diskless")
        self.assertEqual(status["fencing"]["mechanism"], "SBD (diskless)")

    def test_unconfigured_sbd_and_empty_stonith_list_remain_unconfigured(self):
        status, _commands = self.run_status(SimpleNamespace(
            returncode=1, stdout="", stderr="SBD is not configured",
        ))
        self.assertTrue(status["fencing"]["available"])
        self.assertFalse(status["fencing"]["configured"])
        self.assertFalse(status["fencing"]["sbd"]["configured"])
        self.assertEqual(status["fencing"]["mechanism"], "")

    def test_sbd_query_error_is_reported_as_unknown_not_unconfigured(self):
        status, _commands = self.run_status(SimpleNamespace(
            returncode=1, stdout="", stderr="crm could not connect to the cluster",
        ))
        self.assertFalse(status["fencing"]["available"])
        self.assertFalse(status["fencing"]["sbd"]["available"])
        self.assertFalse(status["fencing"]["configured"])
        self.assertIn("could not connect", status["fencing"]["summary"])

    def test_qdevice_live_state_is_read_only_and_reported_when_configured(self):
        status, commands = self.run_status(
            SimpleNamespace(returncode=1, stdout="", stderr="SBD is not configured"),
            quorum_text="Quorate: Yes\nFlags: Quorate Qdevice",
            qdevice_result=SimpleNamespace(
                returncode=0,
                stdout=("Qdevice information\nModel: Net\nQdevice-net information\n"
                        "QNetd host: witness.example.test:5403\nTLS active: Yes\nState: Connected\n"),
                stderr="",
            ),
        )

        self.assertTrue(status["qdevice"]["configured"])
        self.assertTrue(status["qdevice"]["available"])
        self.assertTrue(status["qdevice"]["connected"])
        self.assertEqual(status["qdevice"]["qnetd_host"], "witness.example.test:5403")
        self.assertTrue(status["qdevice"]["tls_active"])
        self.assertIn(["crm", "corosync", "status", "qdevice"], commands)

    def test_qdevice_status_command_failure_does_not_claim_disconnected_or_unconfigured(self):
        status, _commands = self.run_status(
            SimpleNamespace(returncode=1, stdout="", stderr="SBD is not configured"),
            quorum_text="Quorate: Yes\nFlags: Quorate Qdevice",
        )

        self.assertTrue(status["qdevice"]["configured"])
        self.assertFalse(status["qdevice"]["available"])
        self.assertIsNone(status["qdevice"]["connected"])

    def test_qdevice_status_command_is_skipped_when_votequorum_reports_none(self):
        status, commands = self.run_status(
            SimpleNamespace(returncode=1, stdout="", stderr="SBD is not configured"),
            quorum_text="Quorate: Yes\nFlags: Quorate",
        )

        self.assertFalse(status["qdevice"]["configured"])
        self.assertTrue(status["qdevice"]["available"])
        self.assertNotIn(["crm", "corosync", "status", "qdevice"], commands)

    def test_reports_registered_fencing_coverage_per_node_without_triggering_fence(self):
        status, commands = self.run_status(
            SimpleNamespace(returncode=1, stdout="", stderr="SBD is not configured"),
            target_results={
                "node-a": SimpleNamespace(returncode=0, stdout="fence-node-a\n1 fence device found", stderr=""),
                "node-b": SimpleNamespace(returncode=0, stdout="No devices can terminate node-b", stderr=""),
            },
        )

        coverage = status["fencing"]["stonith_target_coverage"]
        self.assertTrue(coverage["available"])
        self.assertEqual(coverage["nodes"], [
            {"node": "node-a", "status": "covered", "devices": ["fence-node-a"]},
            {"node": "node-b", "status": "uncovered", "devices": []},
        ])
        self.assertIn(["stonith_admin", "-l", "node-a"], commands)
        self.assertIn(["stonith_admin", "-l", "node-b"], commands)
        self.assertFalse(any(command[0] == "stonith_admin" and command[1] in ("--fence", "-F", "--reboot", "-B") for command in commands))

    def test_keeps_coverage_unknown_when_query_fails_or_node_name_is_unsafe(self):
        status, commands = self.run_status(
            SimpleNamespace(returncode=1, stdout="", stderr="SBD is not configured"),
            target_results={"node-a": SimpleNamespace(returncode=1, stdout="", stderr="query failed")},
            second_node_name="node b",
        )
        coverage = status["fencing"]["stonith_target_coverage"]
        self.assertFalse(coverage["available"])
        self.assertEqual([node["status"] for node in coverage["nodes"]], ["unknown", "unknown"])
        self.assertFalse(any(command[0] == "stonith_admin" and "node b" in command for command in commands))


if __name__ == "__main__":
    unittest.main()

"""Exercise the read-only QDevice parser embedded in the host status script."""

import ast
import contextlib
import io
import json
import shutil
import subprocess
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


def load_status_script() -> str:
    source = Path(__file__).resolve().parents[1] / "app.py"
    tree = ast.parse(source.read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "HA_CLUSTER_STATUS_SCRIPT"
            for target in node.targets
        ):
            return ast.literal_eval(node.value)
    raise AssertionError("HA_CLUSTER_STATUS_SCRIPT was not found")


STATUS_SCRIPT = load_status_script()
CRM_XML = """<crm_mon><summary><current_dc>node-a</current_dc></summary><nodes>
<node name="node-a" id="1" online="true"/><node name="node-b" id="2" online="true"/>
</nodes><resources/></crm_mon>"""


def execute_status_script(quorum_text: str, qdevice_text: str = "State: Connected\nQNetd host: witness.example.test\nTLS active: Yes", qdevice_exit: int = 0):
    calls = []

    def run(command, **_kwargs):
        command = list(command)
        calls.append(command)
        if command[0] == "crm_mon":
            return SimpleNamespace(returncode=0, stdout=CRM_XML, stderr="")
        if command[0] == "cibadmin":
            return SimpleNamespace(returncode=0, stdout="<cib/>", stderr="")
        if command[0] == "corosync-quorumtool":
            return SimpleNamespace(returncode=0, stdout=quorum_text, stderr="")
        if command[:3] == ["crm", "corosync", "status"]:
            return SimpleNamespace(returncode=qdevice_exit, stdout=qdevice_text, stderr="")
        if command[0] == "stonith_admin":
            return SimpleNamespace(returncode=0, stdout="No devices configured", stderr="")
        if command[:2] == ["crm", "sbd"]:
            return SimpleNamespace(returncode=1, stdout="SBD is not configured", stderr="")
        raise AssertionError(f"Unexpected host command: {command!r}")

    output = io.StringIO()
    with patch.object(shutil, "which", return_value="/usr/sbin/tool"), \
         patch.object(subprocess, "run", side_effect=run), \
         contextlib.redirect_stdout(output):
        exec(STATUS_SCRIPT, {"__name__": "__main__"})
    return json.loads(output.getvalue()), calls


class HaClusterStatusQdeviceTests(unittest.TestCase):
    def test_reports_connection_host_and_tls_from_crmsh(self):
        result, calls = execute_status_script("Quorate: Yes\nFlags: Quorate Qdevice")
        self.assertEqual(result["qdevice"], {
            "available": True,
            "configured": True,
            "connected": True,
            "qnetd_host": "witness.example.test",
            "tls_active": True,
            "summary": "State: Connected\nQNetd host: witness.example.test\nTLS active: Yes",
        })
        self.assertIn(["crm", "corosync", "status", "qdevice"], calls)

    def test_does_not_query_qdevice_when_quorum_flags_do_not_show_a_witness(self):
        result, calls = execute_status_script("Quorate: Yes\nFlags: Quorate")
        self.assertFalse(result["qdevice"]["configured"])
        self.assertIsNone(result["qdevice"]["connected"])
        self.assertNotIn(["crm", "corosync", "status", "qdevice"], calls)

    def test_does_not_report_a_non_running_qdevice_vote_as_configured(self):
        result, _calls = execute_status_script("Quorate: Yes\nFlags: Quorate Qdevice NR")
        self.assertFalse(result["qdevice"]["configured"])

    def test_unavailable_crmsh_diagnostic_stays_unknown_instead_of_claiming_disconnected(self):
        result, _calls = execute_status_script(
            "Quorate: Yes\nFlags: Quorate Qdevice", "crmsh unavailable", qdevice_exit=1,
        )
        self.assertTrue(result["qdevice"]["configured"])
        self.assertFalse(result["qdevice"]["available"])
        self.assertIsNone(result["qdevice"]["connected"])


if __name__ == "__main__":
    unittest.main()

"""Tests for the explicit, rate-limited, read-only Pacemaker device probe."""

import ast
import contextlib
import io
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


def device_probe_script() -> str:
    source = Path(__file__).resolve().parents[1] / "app.py"
    tree = ast.parse(source.read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "HA_STONITH_DEVICE_STATUS_SCRIPT"
            for target in node.targets
        ):
            return ast.literal_eval(node.value)
    raise AssertionError("HA_STONITH_DEVICE_STATUS_SCRIPT was not found")


class ClusterFencingDeviceProbeTests(unittest.TestCase):
    def run_probe(self, query_result=None, configured=True, timeout=False):
        commands = []

        def fake_run(command, **_kwargs):
            commands.append(command)
            if command[0] == "crm_mon":
                return SimpleNamespace(returncode=0, stdout="<crm_mon><nodes><node name='node-a'/></nodes></crm_mon>", stderr="")
            if command[0] == "cibadmin":
                resources = "<resources><primitive id='fence-a' class='stonith'/></resources>" if configured else "<resources/>"
                return SimpleNamespace(returncode=0, stdout=resources, stderr="")
            if command[0] == "stonith_admin":
                if timeout:
                    from subprocess import TimeoutExpired
                    raise TimeoutExpired(command, 55, stderr="sensitive device output")
                return query_result or SimpleNamespace(returncode=0, stdout="status ok", stderr="")
            raise AssertionError(f"Unexpected command: {command}")

        output = io.StringIO()
        with patch("sys.argv", ["probe", "fence-a"]), \
             patch("shutil.which", return_value="/usr/sbin/mock"), \
             patch("subprocess.run", side_effect=fake_run), \
             contextlib.redirect_stdout(output):
            try:
                exec(compile(device_probe_script(), "<stonith-status-check>", "exec"), {"__name__": "__main__"})
            except SystemExit as error:
                self.assertEqual(error.code, 0)
        return json.loads(output.getvalue()), commands

    def test_status_query_uses_allowlisted_cib_resource_and_no_fence_action(self):
        result, commands = self.run_probe()
        query = next(command for command in commands if command[0] == "stonith_admin")
        self.assertEqual(query, ["stonith_admin", "--query", "fence-a", "--timeout=45"])
        self.assertEqual(result["status"], "query_succeeded")
        self.assertNotIn("status ok", json.dumps(result))
        self.assertFalse(any(command[0] == "stonith_admin" and command[1] in ("--fence", "-F", "--reboot", "-B") for command in commands))

    def test_failed_query_does_not_return_device_output(self):
        result, _commands = self.run_probe(SimpleNamespace(returncode=1, stdout="private endpoint", stderr="secret password"))
        self.assertEqual(result["status"], "query_failed")
        self.assertNotIn("private endpoint", json.dumps(result))
        self.assertNotIn("secret password", json.dumps(result))

    def test_unconfigured_resource_is_not_queried(self):
        result, commands = self.run_probe(configured=False)
        self.assertEqual(result["code"], "device_not_configured")
        self.assertFalse(any(command[0] == "stonith_admin" for command in commands))

    def test_timeout_is_reported_without_raw_stderr(self):
        result, _commands = self.run_probe(timeout=True)
        self.assertEqual(result["code"], "status_query_timeout")
        self.assertNotIn("sensitive device output", json.dumps(result))


if __name__ == "__main__":
    unittest.main()

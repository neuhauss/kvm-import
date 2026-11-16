"""Verify the SUSE QDevice/QNetd preparation scripts install only their packages."""

from __future__ import annotations

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


SOURCE = Path(__file__).resolve().parents[1] / "app.py"


def script(name: str) -> str:
    tree = ast.parse(SOURCE.read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == name for target in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError(f"{name} not found")


class QDevicePackageInstallScriptTests(unittest.TestCase):
    def run_script(self, script_name: str, installed: bool):
        calls = []

        def run(command, **_kwargs):
            command = list(command)
            calls.append(command)
            if command[:2] == ["rpm", "-q"]:
                return SimpleNamespace(returncode=0 if installed or len([c for c in calls if c[:2] == ["rpm", "-q"]]) > 1 else 1, stdout="", stderr="")
            if command[0] == "zypper":
                return SimpleNamespace(returncode=0, stdout="installed", stderr="")
            raise AssertionError(f"Unexpected command: {command!r}")

        output = io.StringIO()
        with patch.object(shutil, "which", return_value="/usr/bin/mock"), patch.object(subprocess, "run", side_effect=run), contextlib.redirect_stdout(output):
            try:
                exec(compile(script(script_name), f"<{script_name}>", "exec"), {"__name__": "__main__"})
            except SystemExit as exc:
                if exc.code not in (None, 0):
                    raise
        return json.loads(output.getvalue()), calls

    def test_qnetd_installs_only_the_server_package_and_never_manages_services(self):
        result, calls = self.run_script("QNETD_PACKAGE_INSTALL_SCRIPT", installed=False)
        self.assertEqual(result["status"], "installed")
        self.assertIn(["zypper", "--non-interactive", "install", "--no-recommends", "corosync-qnetd"], calls)
        self.assertTrue(all(command[0] != "systemctl" for command in calls))

    def test_qdevice_installs_only_the_node_package_and_never_manages_services(self):
        result, calls = self.run_script("QDEVICE_PACKAGE_INSTALL_SCRIPT", installed=False)
        self.assertEqual(result["status"], "installed")
        self.assertIn(["zypper", "--non-interactive", "install", "--no-recommends", "corosync-qdevice"], calls)
        self.assertTrue(all(command[0] != "systemctl" for command in calls))

    def test_already_installed_package_is_idempotent(self):
        for name, package in (("QNETD_PACKAGE_INSTALL_SCRIPT", "corosync-qnetd"), ("QDEVICE_PACKAGE_INSTALL_SCRIPT", "corosync-qdevice")):
            with self.subTest(package=package):
                result, calls = self.run_script(name, installed=True)
                self.assertEqual(result["status"], "already_installed")
                self.assertFalse(any(command[0] == "zypper" for command in calls))
                self.assertTrue(all(command[0] != "systemctl" for command in calls))


if __name__ == "__main__":
    unittest.main()

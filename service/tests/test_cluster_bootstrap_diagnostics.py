"""Safe, actionable bootstrap diagnostics without leaking SSH exception text."""

import ast
from pathlib import Path
from types import SimpleNamespace
import unittest


class AuthenticationException(Exception):
    pass


class BadHostKeyException(Exception):
    pass


class SSHException(Exception):
    pass


def load_error_classifier():
    source = Path(__file__).resolve().parents[1] / "app.py"
    tree = ast.parse(source.read_text())
    node = next(
        item for item in tree.body
        if isinstance(item, ast.FunctionDef) and item.name == "cluster_bootstrap_error_code"
    )
    namespace = {
        "paramiko": SimpleNamespace(
            AuthenticationException=AuthenticationException,
            BadHostKeyException=BadHostKeyException,
            SSHException=SSHException,
        ),
        "socket": SimpleNamespace(timeout=TimeoutError),
        "TimeoutError": TimeoutError,
        "OSError": OSError,
        "RuntimeError": RuntimeError,
    }
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(source), "exec"), namespace)
    return namespace["cluster_bootstrap_error_code"]


class ClusterBootstrapDiagnosticsTests(unittest.TestCase):
    def test_maps_transport_exceptions_to_safe_categories(self):
        classify = load_error_classifier()
        self.assertEqual(classify(AuthenticationException("password=secret")), "ssh_authentication")
        self.assertEqual(classify(BadHostKeyException("private host detail")), "ssh_host_key")
        self.assertEqual(classify(TimeoutError("internal address detail")), "ssh_timeout")
        self.assertEqual(classify(SSHException("private key path")), "ssh_connectivity")

    def test_maps_suse_preflight_failures_to_actionable_categories(self):
        classify = load_error_classifier()
        cases = {
            "The imported Linux account needs sudo access": "sudo_required",
            "The host is not on a supported SLES release": "unsupported_sles",
            "The active SLE HA product release could not be confirmed on every selected node": "ha_product_unconfirmed",
            "Selected nodes have different active SLE HA product releases": "ha_product_mismatch",
            "Host does not have the active SLE HA extension and required crmsh/Corosync tools": "ha_not_ready",
            "node-a is not time-synchronized": "time_sync",
            "node-a cannot reach QNetd at witness:5403/TCP": "qnetd_connectivity",
            "node-a cannot reach the SSH port of node-b": "peer_connectivity",
        }
        for message, expected in cases.items():
            with self.subTest(message=message):
                self.assertEqual(classify(RuntimeError(message)), expected)

    def test_never_returns_exception_text(self):
        classify = load_error_classifier()
        secret_detail = "Fresh preflight failed on node-a: password=do-not-leak 192.0.2.9"
        self.assertEqual(classify(RuntimeError(secret_detail)), "preflight_connectivity")
        self.assertNotIn("do-not-leak", classify(RuntimeError(secret_detail)))
        self.assertEqual(classify(Exception("arbitrary internal data")), "bootstrap_failed")


if __name__ == "__main__":
    unittest.main()

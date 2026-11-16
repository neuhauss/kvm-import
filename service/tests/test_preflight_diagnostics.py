"""Isolated tests for sanitized HA preflight validation diagnostics."""

import ast
import asyncio
from pathlib import Path
from types import SimpleNamespace
import unittest


class FakeResponse:
    def __init__(self):
        self.headers = {}


class FakeRequest:
    def __init__(self, path):
        self.url = SimpleNamespace(path=path)


class FakeValidationError:
    def __init__(self, errors):
        self._errors = errors

    def errors(self):
        return self._errors


class CapturingLogger:
    def __init__(self):
        self.messages = []

    def warning(self, message, *args):
        self.messages.append((message, args))


def load_handler():
    source_path = Path(__file__).resolve().parents[1] / "app.py"
    tree = ast.parse(source_path.read_text())
    handler_node = next(
        node for node in tree.body
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "log_preflight_validation_shape"
    )
    handler_node.decorator_list = []
    logger = CapturingLogger()

    async def delegate(_request, _exc):
        return FakeResponse()

    namespace = {
        "Request": FakeRequest,
        "RequestValidationError": FakeValidationError,
        "app": SimpleNamespace(version="0.7.141"),
        "performance_logger": logger,
        "request_validation_exception_handler": delegate,
    }
    exec(compile(ast.Module(body=[handler_node], type_ignores=[]), str(source_path), "exec"), namespace)
    return namespace["log_preflight_validation_shape"], logger


class PreflightDiagnosticTests(unittest.TestCase):
    def test_reports_api_version_and_input_type_without_logging_host_ids(self):
        handler, logger = load_handler()
        validation_error = FakeValidationError([{
            "loc": ("body", "host_ids"), "input": {"secret-host-id": "sensitive"}, "type": "list_type",
        }])
        response = asyncio.run(handler(FakeRequest("/kvm-api/clusters/preflight"), validation_error))

        self.assertEqual(response.headers["X-KVM-API-Version"], "0.7.141")
        self.assertEqual(response.headers["X-KVM-Preflight-Host-Ids-Type"], "dict")
        self.assertEqual(len(logger.messages), 1)
        self.assertNotIn("secret-host-id", repr(logger.messages))
        self.assertNotIn("sensitive", repr(logger.messages))

    def test_does_not_add_cluster_diagnostics_to_other_validation_errors(self):
        handler, logger = load_handler()
        response = asyncio.run(handler(FakeRequest("/kvm-api/vms"), FakeValidationError([])))

        self.assertEqual(response.headers, {})
        self.assertEqual(logger.messages, [])


if __name__ == "__main__":
    unittest.main()

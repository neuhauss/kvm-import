"""Contract tests for the HA preflight request model without API dependencies."""

import ast
import json
from pathlib import Path
import unittest

from pydantic import BaseModel, Field, ValidationError, field_validator


def load_preflight_request_model():
    source_path = Path(__file__).resolve().parents[1] / "app.py"
    tree = ast.parse(source_path.read_text())
    model_node = next(
        node for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "ClusterPreflightRequest"
    )
    namespace = {
        "Any": object,
        "BaseModel": BaseModel,
        "Field": Field,
        "field_validator": field_validator,
        "json": json,
    }
    exec(compile(ast.Module(body=[model_node], type_ignores=[]), str(source_path), "exec"), namespace)
    return namespace["ClusterPreflightRequest"]


ClusterPreflightRequest = load_preflight_request_model()


class ClusterPreflightRequestTests(unittest.TestCase):
    def test_accepts_a_normal_host_id_list(self):
        request = ClusterPreflightRequest(host_ids=["host-a", "host-b"])
        self.assertEqual(request.host_ids, ["host-a", "host-b"])

    def test_accepts_legacy_json_string_and_explicit_wrappers(self):
        host_ids = ["host-a", "host-b"]
        payloads = [
            json.dumps(host_ids),
            {"host_ids": host_ids},
            {"selected_host_ids": host_ids},
            {"ids": host_ids},
            {"value": host_ids},
            {"hosts": [{"id": "host-a"}, {"host_id": "host-b"}]},
            [{"id": "host-a"}, {"id": "host-b", "name": "Node B"}],
            {"host-a": True, "host-b": True},
        ]
        for payload in payloads:
            with self.subTest(payload=payload):
                self.assertEqual(ClusterPreflightRequest(host_ids=payload).host_ids, host_ids)

    def test_rejects_unrecognized_objects_instead_of_guessing_host_ids(self):
        with self.assertRaises(ValidationError):
            ClusterPreflightRequest(host_ids={"type": "click"})

    def test_rejects_unrecognized_entries_in_host_record_lists(self):
        with self.assertRaises(ValidationError):
            ClusterPreflightRequest(host_ids=[{"type": "click"}, {"type": "click"}])

    def test_requires_at_least_two_hosts(self):
        with self.assertRaises(ValidationError):
            ClusterPreflightRequest(host_ids=["host-a"])


if __name__ == "__main__":
    unittest.main()

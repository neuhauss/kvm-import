#!/usr/bin/env python3
"""Apply a large extension asset ConfigMap in API-safe server-side chunks."""

import argparse
from pathlib import Path
import subprocess
import tempfile

import yaml


parser = argparse.ArgumentParser()
parser.add_argument("--kubeconfig", required=True)
parser.add_argument("--context", required=True)
parser.add_argument("--file", required=True, type=Path)
args = parser.parse_args()

document = yaml.safe_load(args.file.read_text())
base = {key: document[key] for key in ("apiVersion", "kind", "metadata") if key in document}
kubectl = ["kubectl", "--kubeconfig", args.kubeconfig, "--context", args.context]

with tempfile.TemporaryDirectory(prefix="kvm-assets-apply-") as temp:
    temp_path = Path(temp)
    chunks = (("data", "kvm-assets-data"), ("binaryData", "kvm-assets-binary"))
    applied = 0
    for field, manager in chunks:
        values = document.get(field) or {}
        if not values:
            continue
        manifest = {**base, field: values}
        path = temp_path / f"{field}.yaml"
        path.write_text(yaml.safe_dump(manifest, sort_keys=False))
        subprocess.run(
            kubectl
            + [
                "apply",
                "--server-side",
                "--force-conflicts",
                f"--field-manager={manager}",
                "-f",
                str(path),
            ],
            check=True,
        )
        applied += 1

if not applied:
    raise SystemExit("The asset ConfigMap has no data or binaryData fields")

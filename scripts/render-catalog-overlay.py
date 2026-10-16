#!/usr/bin/env python3
"""Prepare an in-cluster overlay for the local Rancher extension catalog."""
import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
version = json.loads((ROOT / "pkg/kvm-manager/package.json").read_text())["version"]
chart_file = ROOT / "deploy/extension-catalog" / f"kvm-manager-{version}.tgz"
if not chart_file.is_file():
    raise SystemExit(f"Chart não encontrado: {chart_file}")

existing_index = yaml.safe_load((ROOT / "deploy/extension-catalog/index.yaml").read_text())
entries = existing_index.get("entries", {}).get("kvm-manager", [])
previous = next((item for item in entries if str(item.get("version")) != version), None)
current_chart = yaml.safe_load((ROOT / "charts/kvm-manager/Chart.yaml").read_text())

def catalog_entry(chart, archive, created):
    annotations = dict(chart.get("annotations", {}))
    annotations.update({
        "catalog.cattle.io/certified": "rancher",
        "catalog.cattle.io/os": "linux",
        "catalog.cattle.io/permits-os": "linux, windows",
        "catalog.cattle.io/scope": "management",
    })
    chart["annotations"] = annotations
    chart["created"] = created
    chart["digest"] = hashlib.sha256(archive.read_bytes()).hexdigest()
    chart["urls"] = [f"plugin/kvm-manager/kvm-manager-{chart['version']}.tgz"]
    return chart

now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
catalog_entries = [catalog_entry(dict(current_chart), chart_file, now)]
if previous:
    old_version = str(previous["version"])
    old_chart_file = ROOT / "deploy/extension-catalog" / f"kvm-manager-{old_version}.tgz"
    if old_chart_file.is_file():
        catalog_entries.append(catalog_entry(dict(previous), old_chart_file, previous.get("created", now)))

catalog_index = yaml.safe_dump({
    "apiVersion": "v1",
    "entries": {"kvm-manager": catalog_entries},
    "generated": now,
}, sort_keys=False, allow_unicode=True)
config_map = {
    "apiVersion": "v1",
    "kind": "ConfigMap",
    "metadata": {
        "name": "ui-extension-rancher-kvm-catalog-overlay",
        "namespace": "cattle-ui-plugin-system",
        "labels": {"app.kubernetes.io/part-of": "rancher-kvm"},
    },
    "data": {"index.yaml": catalog_index, "plugin-index.yaml": catalog_index},
    "binaryData": {f"kvm-manager-{version}.tgz": base64.b64encode(chart_file.read_bytes()).decode()},
}
(ROOT / "deploy/extension-catalog/catalog-overlay.yaml").write_text(
    yaml.safe_dump(config_map, sort_keys=False, width=1000)
)
print(f"Overlay interno pronto para kvm-manager {version}.")

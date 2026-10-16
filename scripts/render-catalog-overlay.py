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
chart_archives = {f"kvm-manager-{version}.tgz": chart_file}
if previous:
    old_version = str(previous["version"])
    old_chart_file = ROOT / "deploy/extension-catalog" / f"kvm-manager-{old_version}.tgz"
    if old_chart_file.is_file():
        catalog_entries.append(catalog_entry(dict(previous), old_chart_file, previous.get("created", now)))
        chart_archives[old_chart_file.name] = old_chart_file

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
    "binaryData": {
        name: base64.b64encode(archive.read_bytes()).decode()
        for name, archive in chart_archives.items()
    },
}
(ROOT / "deploy/extension-catalog/catalog-overlay.yaml").write_text(
    yaml.safe_dump(config_map, sort_keys=False, width=1000)
)

# The catalog serves files from ConfigMap keys mounted through subPath, so each
# released chart needs an explicit ConfigMap item and volume mount. Updating the
# overlay alone leaves the service serving its previous chart index and files.
catalog_server_path = ROOT / "deploy/extension-catalog/catalog-server.yaml"
server_docs = list(yaml.safe_load_all(catalog_server_path.read_text()))
for doc in server_docs:
    if doc.get("kind") != "Deployment":
        continue
    pod_spec = doc["spec"]["template"]["spec"]
    volume = next(v for v in pod_spec["volumes"] if v.get("name") == "catalog-overlay")
    volume["configMap"]["items"] = [
        {"key": "index.yaml", "path": "index.yaml"},
        {"key": "plugin-index.yaml", "path": "plugin-index.yaml"},
        *({"key": name, "path": name} for name in chart_archives),
    ]
    container = next(c for c in pod_spec["containers"] if c.get("name") == "catalog")
    mounts = [m for m in container["volumeMounts"] if m.get("subPath") not in chart_archives]
    mounts.extend({
        "name": "catalog-overlay",
        "mountPath": f"/home/plugin-server/plugin-contents/plugin/kvm-manager/{name}",
        "subPath": name,
        "readOnly": True,
    } for name in chart_archives)
    container["volumeMounts"] = mounts
catalog_server_path.write_text(yaml.safe_dump_all(server_docs, sort_keys=False))
print(f"Overlay interno pronto para kvm-manager {version}.")

#!/usr/bin/env python3
"""Render the API/UI ConfigMaps after building the extension bundle and chart."""
import base64
import json
import os
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
version = json.loads((ROOT / "pkg/kvm-manager/package.json").read_text())["version"]
bundle_dir = ROOT / "dist-pkg" / f"kvm-manager-{version}"
bundle_name = f"kvm-manager-{version}.umd.min.js"
bundle_js = sorted(bundle_dir.glob("*.js"))
chart_path = ROOT / "deploy/extension-catalog" / f"kvm-manager-{version}.tgz"
if not (bundle_dir / bundle_name).is_file() or not chart_path.is_file():
    raise SystemExit("Gere o bundle (yarn build-pkg) e o chart (helm package) antes de executar este script.")

api = {
    "apiVersion": "v1", "kind": "ConfigMap",
    "metadata": {"name": "kvm-api-source", "namespace": "rancher-kvm-registry"},
    "data": {
        "app.py": (ROOT / "service/app.py").read_text(),
        "requirements.txt": (ROOT / "service/requirements.txt").read_text(),
    },
}
(ROOT / "deploy/kvm-api-source-configmap.yaml").write_text(yaml.safe_dump(api, sort_keys=False, width=1000))

assets_path = ROOT / "deploy/kvm-extension-assets-configmap.yaml"
assets = yaml.safe_load(assets_path.read_text())
asset_files = sorted(bundle_dir.rglob("*.svg"))
asset_keys = {path: f"asset-{version}-{path.name}" for path in asset_files}
files = [f"plugin/{path.name}" for path in bundle_js]
files.append("plugin/package.json")
files.extend(f"plugin/{path.relative_to(bundle_dir).as_posix()}" for path in asset_files)
assets["data"][f"files-{version}.txt"] = "\n".join(files) + "\n"
assets["data"][f"package-{version}.json"] = (bundle_dir / "package.json").read_text()
for path in bundle_js:
    assets["data"][path.name] = path.read_text()
for path in asset_files:
    assets["data"][asset_keys[path]] = path.read_text()
# The assets ConfigMap is limited to 1 MiB. It only needs the currently served
# plugin bundle; historical Helm charts remain in binaryData for catalog use.
for key in list(assets["data"]):
    if key.startswith(("files-", "package-", "kvm-manager-", "asset-")):
        if key not in {f"files-{version}.txt", f"package-{version}.json", *(path.name for path in bundle_js), *asset_keys.values()}:
            del assets["data"][key]
assets["data"]["catalog-index.yaml"] = (ROOT / "deploy/extension-catalog/index.yaml").read_text()
assets.setdefault("binaryData", {})[f"catalog-chart-{version}.tgz"] = base64.b64encode(chart_path.read_bytes()).decode()
assets_path.write_text(yaml.safe_dump(assets, sort_keys=False, width=1000))

ui_path = ROOT / "deploy/ui-extension.yaml"
ui_docs = list(yaml.safe_load_all(ui_path.read_text()))
for doc in ui_docs:
    if doc.get("kind") == "Deployment" and doc.get("metadata", {}).get("name") == "kvm-extension-assets":
        items = doc["spec"]["template"]["spec"]["volumes"][0]["configMap"].setdefault("items", [])
        new_items = [
            (f"files-{version}.txt", f"kvm-manager/{version}/files.txt"),
            (f"package-{version}.json", f"kvm-manager/{version}/plugin/package.json"),
        ]
        new_items.extend((path.name, f"kvm-manager/{version}/plugin/{path.name}") for path in bundle_js)
        new_items.extend((asset_keys[path], f"kvm-manager/{version}/plugin/{path.relative_to(bundle_dir).as_posix()}") for path in asset_files)
        new_items.append(("catalog-index.yaml", "catalog/index.yaml"))
        for chart_key in assets.get("binaryData", {}):
            if chart_key.startswith("catalog-chart") and chart_key.endswith(".tgz"):
                chart_version = chart_key.removeprefix("catalog-chart").removesuffix(".tgz").lstrip("-")
                if not chart_version:
                    chart_version = "0.1.5"
                new_items.append((chart_key, f"catalog/kvm-manager-{chart_version}.tgz"))
        doc["spec"]["template"]["spec"]["volumes"][0]["configMap"]["items"] = [
            {"key": key, "path": path} for key, path in new_items
        ]
    if doc.get("kind") == "UIPlugin" and doc.get("metadata", {}).get("name") == "kvm-manager":
        doc["spec"]["plugin"]["version"] = version
        doc["spec"]["plugin"]["endpoint"] = f"http://kvm-extension-assets.rancher-kvm-registry.svc:8080/kvm-manager/{version}"
ui_path.write_text(yaml.safe_dump_all(ui_docs, sort_keys=False, width=1000))
print(f"ConfigMaps e UIPlugin atualizados para kvm-manager {version}.")

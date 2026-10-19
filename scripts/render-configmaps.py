#!/usr/bin/env python3
"""Render the API/UI ConfigMaps after building the extension bundle and chart."""
import base64
import gzip
import ipaddress
import json
import os
from pathlib import Path
from urllib.parse import urlsplit

import yaml

ROOT = Path(__file__).resolve().parents[1]
version = json.loads((ROOT / "pkg/kvm-manager/package.json").read_text())["version"]
public_origin = os.environ.get("RANCHER_PUBLIC_ORIGIN", "https://rancher.example.com").rstrip("/")
origin_url = urlsplit(public_origin)
if origin_url.scheme != "https" or not origin_url.netloc or origin_url.path not in ("", "/"):
    raise SystemExit("RANCHER_PUBLIC_ORIGIN must be an HTTPS origin without a path")
ingress_class = os.environ.get("KVM_INGRESS_CLASS", "nginx")
backend_namespace = os.environ.get("KVM_NAMESPACE", "rancher-kvm-registry")
bundle_dir = ROOT / "dist-pkg" / f"kvm-manager-{version}"
bundle_name = f"kvm-manager-{version}.umd.min.js"
bundle_js = sorted(bundle_dir.glob("*.js"))
compressed_bundle_files = set()
chart_path = ROOT / "deploy/extension-catalog" / f"kvm-manager-{version}.tgz"
if not (bundle_dir / bundle_name).is_file() or not chart_path.is_file():
    raise SystemExit("Build the extension bundle and chart before running this script.")

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
assets_name = f"kvm-extension-assets-{version.replace('.', '-') }"
assets["metadata"]["name"] = assets_name
asset_files = sorted(bundle_dir.rglob("*.svg"))
asset_keys = {path: f"asset-{version}-{path.name}" for path in asset_files}
files = [f"plugin/{path.name}" for path in bundle_js]
files.append("plugin/package.json")
files.extend(f"plugin/{path.relative_to(bundle_dir).as_posix()}" for path in asset_files)
assets["data"][f"files-{version}.txt"] = "\n".join(files) + "\n"
assets["data"][f"package-{version}.json"] = (bundle_dir / "package.json").read_text()
# Rancher's UIPlugin cache fetches package.json from the endpoint root, while
# the Dashboard's extension file proxy serves the bundle under /plugin/.
assets["data"][f"package-root-{version}.json"] = (bundle_dir / "package.json").read_text()
for path in bundle_js:
    assets["data"][path.name] = path.read_text()
for path in asset_files:
    assets["data"][asset_keys[path]] = path.read_text()
# The assets ConfigMap is limited to 1 MiB. Keep the current plugin bundle and
# only the current plus previous charts in the legacy catalog endpoint.
for key in list(assets["data"]):
    if key.startswith(("files-", "package-", "kvm-manager-", "asset-")):
        if key not in {f"files-{version}.txt", f"package-{version}.json", f"package-root-{version}.json", *(path.name for path in bundle_js), *asset_keys.values()}:
            del assets["data"][key]
assets["data"]["catalog-index.yaml"] = (ROOT / "deploy/extension-catalog/index.yaml").read_text()
binary_data = assets.setdefault("binaryData", {})
bundle_names = {path.name for path in bundle_js}
for key in list(binary_data):
    if key.startswith("kvm-manager-") and (key.endswith(".js") or key.endswith(".js.gz")) and key not in bundle_names and key not in {f"{name}.gz" for name in bundle_names}:
        del binary_data[key]
for path in bundle_js:
    # Store bundle files compressed in binaryData. This keeps the assets
    # ConfigMap below Kubernetes' 1 MiB object limit as the extension grows.
    # The asset Deployment inflates these files into its served directory.
    contents = path.read_bytes()
    assets["data"].pop(path.name, None)
    binary_data.pop(path.name, None)
    compressed_bundle_files.add(path.name)
    binary_data[f"{path.name}.gz"] = base64.b64encode(gzip.compress(contents, compresslevel=9, mtime=0)).decode()

previous_version = f"{version.rsplit('.', 1)[0]}.{int(version.rsplit('.', 1)[1]) - 1}"
kept_chart_versions = {version, previous_version}
for key in list(binary_data):
    if key.startswith("catalog-chart") and key.endswith(".tgz"):
        archived_version = key.removeprefix("catalog-chart").removesuffix(".tgz").lstrip("-") or "0.1.5"
        if archived_version not in kept_chart_versions:
            del binary_data[key]
for chart_version in kept_chart_versions:
    archived_chart = ROOT / "deploy/extension-catalog" / f"kvm-manager-{chart_version}.tgz"
    if archived_chart.is_file():
        chart_key = "catalog-chart.tgz" if chart_version == "0.1.5" else f"catalog-chart-{chart_version}.tgz"
        binary_data[chart_key] = base64.b64encode(archived_chart.read_bytes()).decode()

legacy_index = yaml.safe_load((ROOT / "deploy/extension-catalog/index.yaml").read_text())
legacy_entries = legacy_index.get("entries", {}).get("kvm-manager", [])
legacy_entries = [entry for entry in legacy_entries if str(entry.get("version")) in kept_chart_versions]
for entry in legacy_entries:
    entry["urls"] = [f"kvm-manager-{entry['version']}.tgz"]
legacy_index["entries"]["kvm-manager"] = legacy_entries
assets["data"]["catalog-index.yaml"] = yaml.safe_dump(legacy_index, sort_keys=False, allow_unicode=True, width=1000)
assets_path.write_text(yaml.safe_dump(assets, sort_keys=False, width=1000))

ui_path = ROOT / "deploy/ui-extension.yaml"
ui_docs = list(yaml.safe_load_all(ui_path.read_text()))
for doc in ui_docs:
    if doc.get("kind") == "Deployment" and doc.get("metadata", {}).get("name") == "kvm-extension-assets":
        config_map = doc["spec"]["template"]["spec"]["volumes"][0]["configMap"]
        config_map["name"] = assets_name
        items = config_map.setdefault("items", [])
        new_items = [
            (f"files-{version}.txt", f"kvm-manager/{version}/files.txt"),
            (f"package-root-{version}.json", f"kvm-manager/{version}/package.json"),
            (f"package-{version}.json", f"kvm-manager/{version}/plugin/package.json"),
        ]
        new_items.extend(
            (
                f"{path.name}.gz" if path.name in compressed_bundle_files else path.name,
                f"kvm-manager/{version}/plugin/{path.name}.gz" if path.name in compressed_bundle_files else f"kvm-manager/{version}/plugin/{path.name}",
            )
            for path in bundle_js
        )
        new_items.extend((asset_keys[path], f"kvm-manager/{version}/plugin/{path.relative_to(bundle_dir).as_posix()}") for path in asset_files)
        new_items.append(("catalog-index.yaml", "catalog/index.yaml"))
        for chart_key in assets.get("binaryData", {}):
            if chart_key.startswith("catalog-chart") and chart_key.endswith(".tgz"):
                chart_version = chart_key.removeprefix("catalog-chart").removesuffix(".tgz").lstrip("-")
                if not chart_version:
                    chart_version = "0.1.5"
                new_items.append((chart_key, f"catalog/kvm-manager-{chart_version}.tgz"))
        # The public Helm chart carries just the UI plugin files. It serves them
        # from an in-cluster assets Service and does not need the legacy chart catalog.
        helm_items = [
            {"key": key, "path": path}
            for key, path in new_items
            if key != "catalog-index.yaml" and not key.startswith("catalog-chart")
        ]
        helm_data = {item["key"]: assets["data"][item["key"]] for item in helm_items if item["key"] in assets["data"]}
        helm_binary = {item["key"]: binary_data[item["key"]] for item in helm_items if item["key"] in binary_data}
        chart_files = ROOT / "charts/kvm-manager/files"
        chart_files.mkdir(parents=True, exist_ok=True)
        (chart_files / "assets-data.yaml").write_text(
            yaml.safe_dump({"data": helm_data, "binaryData": helm_binary}, sort_keys=False, width=1000)
        )
        (chart_files / "assets-items.yaml").write_text(
            yaml.safe_dump(helm_items, sort_keys=False, width=1000)
        )
        doc["spec"]["template"]["spec"]["volumes"][0]["configMap"]["items"] = [
            {"key": key, "path": path} for key, path in new_items
        ]
        inflate_commands = [
            f"gzip -dc /tmp/www/kvm-manager/{version}/plugin/{name}.gz > /tmp/www/kvm-manager/{version}/plugin/{name} && rm /tmp/www/kvm-manager/{version}/plugin/{name}.gz"
            for name in sorted(compressed_bundle_files)
        ]
        init_assets = "mkdir -p /tmp/www && cp -R /usr/local/apache2/htdocs/. /tmp/www/"
        if inflate_commands:
            init_assets += " && " + " && ".join(inflate_commands)
        init_assets += (
            " && sed -e 's/^Listen 80$/Listen 8080/'"
            " -e 's#DocumentRoot \"/usr/local/apache2/htdocs\"#DocumentRoot \"/tmp/www\"#'"
            " -e 's#<Directory \"/usr/local/apache2/htdocs\">#<Directory \"/tmp/www\">#'"
            " -e 's/^#LoadModule deflate_module /LoadModule deflate_module /'"
            " -e '/^LoadModule deflate_module /a AddOutputFilterByType DEFLATE text/javascript application/javascript application/json text/css image/svg+xml'"
            " /usr/local/apache2/conf/httpd.conf > /tmp/httpd.conf"
            " && exec httpd -f /tmp/httpd.conf -DFOREGROUND"
        )
        doc["spec"]["template"]["spec"]["containers"][0]["args"] = [init_assets]
    if doc.get("kind") == "UIPlugin" and doc.get("metadata", {}).get("name") == "kvm-manager":
        doc["spec"]["plugin"]["version"] = version
        doc["spec"]["plugin"]["endpoint"] = f"{public_origin}/kvm-manager/{version}"
        # Versioned plugin URLs change per release; disable extension caching
        # so the Rancher UI does not keep loading the previous bundle.
        doc["spec"]["plugin"]["noCache"] = True
        doc["spec"]["plugin"].setdefault("metadata", {}).update({
            "catalog.cattle.io/display-name": "KVM",
            "catalog.cattle.io/ui-component": "plugins",
            "catalog.cattle.io/namespace": "cattle-ui-plugin-system",
        })
asset_ingress = next(
    (
        doc
        for doc in ui_docs
        if doc.get("kind") == "Ingress"
        and doc.get("metadata", {}).get("name") == "kvm-extension-assets"
    ),
    None,
)
if asset_ingress is None:
    asset_ingress = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "Ingress",
        "metadata": {
            "name": "kvm-extension-assets",
            "namespace": "rancher-kvm-registry",
            "labels": {
                "app.kubernetes.io/name": "kvm-extension-assets",
                "app.kubernetes.io/part-of": "rancher-kvm",
            },
        },
        "spec": {},
    }
    ui_docs.append(asset_ingress)
asset_ingress["spec"]["ingressClassName"] = ingress_class
asset_rule = {
    "http": {
        "paths": [
            {
                "path": "/kvm-manager",
                "pathType": "Prefix",
                "backend": {
                    "service": {
                        "name": "kvm-extension-assets",
                        "port": {"number": 8080},
                    }
                },
            }
        ]
    }
}
try:
    ipaddress.ip_address(origin_url.hostname or "")
except ValueError:
    asset_rule["host"] = origin_url.hostname
asset_ingress["spec"]["rules"] = [asset_rule]
ui_path.write_text(yaml.safe_dump_all(ui_docs, sort_keys=False, width=1000))
print(f"ConfigMaps, HTTPS asset route, and UIPlugin updated for kvm-manager {version}.")

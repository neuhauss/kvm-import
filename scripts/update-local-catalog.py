#!/usr/bin/env python3
"""Publish a freshly built chart to an existing extension-owned local catalog."""

import argparse
import base64
import gzip
import json
from pathlib import Path
import subprocess
import sys
import time
from datetime import datetime, timezone
import yaml

ROOT = Path(__file__).resolve().parents[1]


def kubectl(args: list[str], *, input_text: str | None = None) -> str:
    command = ["kubectl", "--kubeconfig", options.kubeconfig, "--context", options.context, *args]
    return subprocess.check_output(command, input=input_text, text=True, stderr=subprocess.PIPE)


parser = argparse.ArgumentParser()
parser.add_argument("--kubeconfig", required=True)
parser.add_argument("--context", required=True)
parser.add_argument("--version", required=True)
parser.add_argument("--catalog-namespace", default="cattle-ui-plugin-system")
parser.add_argument("--catalog-configmap", default="ui-extension-rancher-kvm-catalog-overlay")
parser.add_argument("--catalog-deployment", default="ui-extension-rancher-kvm-extension")
parser.add_argument("--clusterrepo", default="ui-extension-rancher-kvm-extension-charts")
parser.add_argument("--asset-service", default="kvm-extension-assets.rancher-kvm-registry.svc:8080")
parser.add_argument("--timeout", type=int, default=120)
options = parser.parse_args()

try:
    live = json.loads(kubectl(["get", "configmap", options.catalog_configmap, "-n", options.catalog_namespace, "-o", "json"]))
    kubectl(["get", "clusterrepo", options.clusterrepo, "-o", "json"])
    kubectl(["get", "deployment", options.catalog_deployment, "-n", options.catalog_namespace])
except subprocess.CalledProcessError:
    print("Local extension catalog not found; skipping its update.")
    sys.exit(0)

chart_index = yaml.safe_load((ROOT / "deploy/extension-catalog/index.yaml").read_text())
new_entries = chart_index.get("entries", {}).get("kvm-manager", [])
new_entry = next((entry for entry in new_entries if entry.get("version") == options.version), None)
if not new_entry:
    raise SystemExit(f"Version {options.version} is missing from deploy/extension-catalog/index.yaml")

data = live.setdefault("data", {})
catalog = yaml.safe_load(data.get("index.yaml") or data.get("plugin-index.yaml") or "apiVersion: v1\nentries: {}\n")
entries = catalog.setdefault("entries", {}).setdefault("kvm-manager", [])
new_entry = dict(new_entry)
new_entry["urls"] = [f"http://{options.asset_service}/catalog/kvm-manager-{options.version}.tgz"]
entries[:] = [entry for entry in entries if entry.get("version") != options.version]
entries.append(new_entry)
entries.sort(key=lambda entry: tuple(map(int, entry["version"].split("."))), reverse=True)
catalog["apiVersion"] = "v1"
catalog["generated"] = datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
catalog_text = yaml.safe_dump(catalog, sort_keys=False, allow_unicode=True)
patch = {"data": {"index.yaml": catalog_text, "plugin-index.yaml": catalog_text}}
kubectl(["patch", "configmap", options.catalog_configmap, "-n", options.catalog_namespace, "--type=merge", "-p", json.dumps(patch)])

# The catalog files are mounted with subPath, so restart only this extension-owned deployment.
kubectl(["rollout", "restart", f"deployment/{options.catalog_deployment}", "-n", options.catalog_namespace])
kubectl(["rollout", "status", f"deployment/{options.catalog_deployment}", "-n", options.catalog_namespace, f"--timeout={options.timeout}s"])

force_update = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
kubectl(["patch", "clusterrepo", options.clusterrepo, "--type=merge", "-p", json.dumps({"spec": {"forceUpdate": force_update}})])

deadline = time.monotonic() + options.timeout
while time.monotonic() < deadline:
    current = json.loads(kubectl(["get", "clusterrepo", options.clusterrepo, "-o", "json"]))
    config_name = current.get("status", {}).get("indexConfigMapName")
    if config_name:
        try:
            downloaded = json.loads(kubectl(["get", "configmap", config_name, "-n", "cattle-system", "-o", "json"]))
            compressed = base64.b64decode(downloaded.get("binaryData", {}).get("content", ""))
            remote_index = json.loads(gzip.decompress(compressed))
            if any(
                entry.get("version") == options.version and entry.get("digest") == new_entry.get("digest")
                for entry in remote_index.get("entries", {}).get("kvm-manager", [])
            ):
                print(f"Local extension catalog now serves KVM Manager {options.version}.")
                sys.exit(0)
        except (subprocess.CalledProcessError, ValueError, OSError, json.JSONDecodeError):
            pass
    time.sleep(2)

raise SystemExit(f"Timed out waiting for ClusterRepo {options.clusterrepo} to download version {options.version}.")

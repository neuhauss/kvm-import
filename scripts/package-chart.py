#!/usr/bin/env python3
"""Package the Helm chart and refresh its repository index without Helm CLI."""

from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import tarfile

import yaml

ROOT = Path(__file__).resolve().parents[1]
CHART_DIR = ROOT / "charts/kvm-manager"
REPO_DIR = ROOT / "deploy/extension-catalog"
CHART = yaml.safe_load((CHART_DIR / "Chart.yaml").read_text())
name = CHART["name"]
version = str(CHART["version"])
base_url = os.environ["CHART_REPO_URL"].rstrip("/")
archive = REPO_DIR / f"{name}-{version}.tgz"

with tarfile.open(archive, "w:gz", format=tarfile.PAX_FORMAT) as package:
    for path in sorted(CHART_DIR.rglob("*")):
        if path.is_file() and ".DS_Store" not in path.name:
            package.add(path, arcname=f"{name}/{path.relative_to(CHART_DIR).as_posix()}")

index_path = REPO_DIR / "index.yaml"
index = yaml.safe_load(index_path.read_text()) if index_path.exists() else {"apiVersion": "v1", "entries": {}}
entries = index.setdefault("entries", {}).setdefault(name, [])
for existing in entries:
    existing["urls"] = [f"{base_url}/{name}-{existing['version']}.tgz"]
entry = {key: value for key, value in CHART.items() if key in {
    "apiVersion", "name", "version", "description", "type", "appVersion", "deprecated", "home", "icon", "keywords", "maintainers", "sources", "annotations"
}}
entry.update({
    "created": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "digest": hashlib.sha256(archive.read_bytes()).hexdigest(),
    "urls": [f"{base_url}/{archive.name}"],
})
entries[:] = [item for item in entries if str(item.get("version")) != version]
entries.append(entry)
entries.sort(key=lambda item: tuple(int(part) if part.isdigit() else part for part in str(item["version"]).replace("-", ".").split(".")), reverse=True)
index["apiVersion"] = "v1"
index_path.write_text(yaml.safe_dump(index, sort_keys=False, allow_unicode=True))
print(f"Criado {archive.relative_to(ROOT)} e atualizado {index_path.relative_to(ROOT)}")

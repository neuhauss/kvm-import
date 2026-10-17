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
history_dir = Path(os.environ.get("CHART_REPO_HISTORY_DIR", "")) if os.environ.get("CHART_REPO_HISTORY_DIR") else None

# Keep previously published chart packages and index entries. Rancher/Helm needs
# the version history to offer upgrades and to support rollback.
history_index = None
if history_dir:
    previous_index = history_dir / "index.yaml"
    if previous_index.is_file():
        history_index = yaml.safe_load(previous_index.read_text()) or {}
    for old_archive in history_dir.glob(f"{name}-*.tgz"):
        target = REPO_DIR / old_archive.name
        if target != archive and not target.exists():
            target.write_bytes(old_archive.read_bytes())

with tarfile.open(archive, "w:gz", format=tarfile.PAX_FORMAT) as package:
    for path in sorted(CHART_DIR.rglob("*")):
        if path.is_file() and ".DS_Store" not in path.name:
            package.add(path, arcname=f"{name}/{path.relative_to(CHART_DIR).as_posix()}")

index_path = REPO_DIR / "index.yaml"
if history_dir:
    # In CI, the published Pages repository is the source of version history;
    # do not carry local preview indexes or their URLs into the public catalog.
    index = history_index or {"apiVersion": "v1", "entries": {}}
else:
    index = yaml.safe_load(index_path.read_text()) if index_path.exists() else {"apiVersion": "v1", "entries": {}}
entries = index.setdefault("entries", {}).setdefault(name, [])
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
unique_entries = {}
for item in entries:
    unique_entries[str(item.get("version"))] = item
entries[:] = list(unique_entries.values())
entries.sort(key=lambda item: tuple(int(part) if part.isdigit() else part for part in str(item["version"]).replace("-", ".").split(".")), reverse=True)
index["apiVersion"] = "v1"
index["generated"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
index_path.write_text(yaml.safe_dump(index, sort_keys=False, allow_unicode=True))
print(f"Created {archive.relative_to(ROOT)} and updated {index_path.relative_to(ROOT)}")

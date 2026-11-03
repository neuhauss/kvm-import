#!/usr/bin/env python3
"""Keep package and chart versions aligned, advancing patch past the live version."""

import argparse
import json
from pathlib import Path

import yaml
from semver import version_after, version_key

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "pkg/kvm-manager/package.json"
CHART = ROOT / "charts/kvm-manager/Chart.yaml"


parser = argparse.ArgumentParser()
parser.add_argument("--installed-version", default="")
parser.add_argument("--apply", action="store_true", help="write the synchronized versions")
args = parser.parse_args()

package = json.loads(PACKAGE.read_text())
chart = yaml.safe_load(CHART.read_text())
version = package["version"]
if args.installed_version and version_key(version) <= version_key(args.installed_version):
    version = version_after(args.installed_version)

if args.apply:
    package["version"] = version
    PACKAGE.write_text(json.dumps(package, indent=2) + "\n")
    chart["version"] = version
    chart["appVersion"] = version
    CHART.write_text(yaml.safe_dump(chart, sort_keys=False, allow_unicode=True))

print(version)

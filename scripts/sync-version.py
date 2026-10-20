#!/usr/bin/env python3
"""Keep package and chart versions aligned, advancing patch past the live version."""

import argparse
import json
from pathlib import Path
import re

import yaml

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "pkg/kvm-manager/package.json"
CHART = ROOT / "charts/kvm-manager/Chart.yaml"


def parts(version: str) -> tuple[int, int, int]:
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", version)
    if not match:
        raise ValueError(f"Expected a numeric semver version, got {version!r}")
    return tuple(map(int, match.groups()))


parser = argparse.ArgumentParser()
parser.add_argument("--installed-version", default="")
parser.add_argument("--apply", action="store_true", help="write the synchronized versions")
args = parser.parse_args()

package = json.loads(PACKAGE.read_text())
chart = yaml.safe_load(CHART.read_text())
version = package["version"]
if args.installed_version and parts(version) <= parts(args.installed_version):
    major, minor, patch = parts(args.installed_version)
    version = f"{major}.{minor}.{patch + 1}"

if args.apply:
    package["version"] = version
    PACKAGE.write_text(json.dumps(package, indent=2) + "\n")
    chart["version"] = version
    chart["appVersion"] = version
    CHART.write_text(yaml.safe_dump(chart, sort_keys=False, allow_unicode=True))

print(version)

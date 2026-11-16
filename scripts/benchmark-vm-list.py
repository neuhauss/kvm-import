#!/usr/bin/env python3
"""Benchmark VM-list address lookups with a local fake virsh executable."""

import argparse
import ast
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--runs", type=int, default=7)
args = parser.parse_args()
if not 1 <= args.runs <= 50:
    raise SystemExit("--runs must be between 1 and 50")

tree = ast.parse((ROOT / "service/app.py").read_text())
assignment = next(
    node for node in tree.body
    if isinstance(node, ast.Assign)
    and any(isinstance(target, ast.Name) and target.id == "VM_LIST_SCRIPT" for target in node.targets)
)
parallel_script = ast.literal_eval(assignment.value)
serial_marker = "ThreadPoolExecutor(max_workers=min(4, len(items)))"
if serial_marker not in parallel_script:
    raise SystemExit("VM_LIST_SCRIPT no longer contains the expected bounded lookup")
serial_script = parallel_script.replace(serial_marker, "ThreadPoolExecutor(max_workers=1)", 1)

fake_virsh = r'''#!/bin/sh
case "$*" in
  *"list --all --name"*)
    i=0
    while [ "$i" -lt 12 ]; do echo "vm-$i"; i=$((i + 1)); done
    ;;
  *"dominfo"*)
    sleep 0.005
    echo "State: running"
    echo "UUID: 123e4567-e89b-12d3-a456-426614174000"
    echo "CPU(s): 2"
    echo "Max memory: 1048576 KiB"
    echo "Autostart: enable"
    ;;
  *"domifaddr"*)
    sleep 0.04
    echo "1: vnet0: ipv4 192.0.2.1/24"
    ;;
esac
'''


with tempfile.TemporaryDirectory(prefix="kvm-vm-list-benchmark-") as directory:
    executable = Path(directory) / "virsh"
    executable.write_text(fake_virsh)
    executable.chmod(0o755)
    env = {**os.environ, "PATH": f"{directory}{os.pathsep}{os.environ['PATH']}"}

    for label, script in (("serial", serial_script), ("bounded-4", parallel_script)):
        samples = []
        for _ in range(args.runs):
            started = time.perf_counter()
            result = subprocess.run(
                [sys.executable, "-c", script],
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )
            samples.append((time.perf_counter() - started) * 1000)
            rows = json.loads(result.stdout)
            if len(rows) != 12 or any(row["ip_addresses"] != ["192.0.2.1"] for row in rows):
                raise SystemExit(f"{label} returned unexpected VM inventory data")
        print(f"{label}: median={statistics.median(samples):.1f}ms samples="
              f"{','.join(f'{sample:.1f}' for sample in samples)}")

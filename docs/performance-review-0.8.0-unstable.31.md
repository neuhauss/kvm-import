# Performance and engineering-practices review: 0.8.0-unstable.31

Review date: 2026-11-04
Baseline: 0.7.12
Previous completed review: 0.8.0-unstable.17
New releases since previous review: 14 (`.18` through `.31`)
Next scheduled review: after ten new releases beyond 0.8.0-unstable.31 (target 0.8.0-unstable.41)

## Reproducible bundle inspection

Compared checked-in production JavaScript artifacts using deterministic gzip
level 9:

| Artifact | 0.8.0-unstable.17 raw / gzip-9 | 0.8.0-unstable.31 raw / gzip-9 | Change |
| --- | ---: | ---: | ---: |
| All JavaScript chunks | 1,263,577 / 281,322 bytes | 1,514,857 / 346,496 bytes | +19.9% / +23.2% |
| Main entry | 258,475 / 45,917 bytes | 259,387 / 46,039 bytes | +0.35% / +0.27% |
| Cloud Native lazy chunk | 346,464 / 56,362 bytes | 383,877 / 61,917 bytes | +10.8% / +9.9% |
| VM terminal chunk | 9,542 / 3,360 bytes | 9,598 / 3,371 bytes | +0.59% / +0.33% |

The aggregate growth is mostly in lazy-loaded Cloud Native and console features;
the initial entry barely changed. Keep these routes lazy-loaded. The Cloud Native
chunk is still about 61 KiB gzip, so this review did not remove functionality or
dependencies solely to meet webpack's generic raw-size warning.

Reproduce the byte counts from the repository root:

```sh
python3 - <<'PY'
from pathlib import Path
import gzip
for version in ('0.8.0-unstable.17', '0.8.0-unstable.31'):
    files = sorted((Path('dist-pkg') / f'kvm-manager-{version}').glob('*.js'))
    print(version, len(files), sum(p.stat().st_size for p in files),
          sum(len(gzip.compress(p.read_bytes(), 9, mtime=0)) for p in files))
    for pattern in ('*.umd.min.js', '*.umd.min.kvm-cloud-native.js',
                    '*.umd.min.kvm-vm-console.js'):
        path = next(iter((Path('dist-pkg') / f'kvm-manager-{version}').glob(pattern)), None)
        if path:
            print(path.name, path.stat().st_size,
                  len(gzip.compress(path.read_bytes(), 9, mtime=0)))
PY
```

## Safe optimization applied

The VM list endpoint queried each VM's libvirt IP addresses sequentially. A
slow lease or guest-agent lookup therefore added its full timeout to every VM
before it in the list. The host-side inventory now runs those independent
read-only address lookups with a four-worker cap. `executor.map` preserves VM
ordering, and each VM still uses the same lease/agent fallback and returns the
same fields. The cap keeps concurrent read queries bounded on smaller hosts.

A local synthetic `virsh` benchmark exercised the actual embedded
`VM_LIST_SCRIPT` with 12 running VMs. The stub returned 5 ms `dominfo` and 40 ms
address lookups per VM. Seven runs measured a median of 729.1 ms serially and
315.5 ms with the four-worker bound (56.7% lower in this artificial workload).
Output was parsed and checked for all 12 VMs and the same IP address result.
These are simulated command-latency measurements, not claims about production
host performance.

Reproduce from the repository root with `python3 scripts/benchmark-vm-list.py
--runs 7`. The benchmark extracts the embedded script, substitutes a one-worker
executor for the serial comparison, and prepends a temporary fake `virsh` to
`PATH`. The fake returns 12 VMs, delays `dominfo` by 5 ms and each IP lookup by
40 ms, and is removed automatically after the run.

## Engineering-practices review

- SSH clients remain request-scoped and still require the imported host's
  pinned SSH key. This review found no evidence that a global connection pool
  would improve the current workload enough to justify longer-lived
  credentials and reconnect complexity.
- Existing concurrency limits remain bounded: host refresh uses two workers,
  queued host operations use at most three, and VM address inventory now uses
  at most four read-only `virsh` lookups at a time.
- Operation jobs and audit history retain their existing queue and retention
  limits. The host/VM activity query continues to use its composite target/time
  index from the previous review.
- No new third-party runtime dependency was added. No Rancher core or Harvester
  resource was changed.

## Validation

- The embedded VM inventory script was executed against a local fake `virsh`
  command for the before/after timing comparison; result count and addresses
  were checked.
- Python AST parsing and compilation of the embedded remote script passed.
- `git diff --check` passed.
- No full test suite was run for this scheduled review.
- No GitHub, Docker Hub, or cluster publication was performed.

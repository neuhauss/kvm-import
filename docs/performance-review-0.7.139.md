# Performance and engineering-practices review: 0.7.139

Review date: 2026-10-30
Baseline: 0.7.12
Previous completed review: 0.7.120
Scheduled target: 0.7.130
Reviewed release: 0.7.139
Next scheduled review: 0.7.149

## Reproducible bundle inspection

Compared the checked-in production package artifacts using deterministic gzip
level 9. Across all JavaScript chunks, 0.7.139 is 1,250,425 raw bytes / 278,264
gzip bytes, versus 1,171,954 / 261,868 for 0.7.120: +6.7% raw and +6.3%
compressed. The packaging layout changed: the main entry shrank from 533,571
bytes (88,582 gzip) to 258,268 (45,817 gzip), while Cloud Native is now a
separate lazy chunk at 337,780 (54,696 gzip). The xterm chunk is unchanged at
419,353 bytes (107,704 gzip; one gzip byte difference from the prior artifact).
This shifts administration code out of the main entry but does not reduce the
total downloaded code once the Cloud Native page is opened.

Reproduce with:

```sh
python3 - <<'PY'
from pathlib import Path
import gzip
for version in ('0.7.120', '0.7.139'):
    root = Path('dist-pkg') / f'kvm-manager-{version}'
    files = sorted(root.glob('*.js'))
    print(version, 'all-js', sum(p.stat().st_size for p in files),
          sum(len(gzip.compress(p.read_bytes(), 9, mtime=0)) for p in files))
    for path in files:
        if path.name.endswith('.umd.min.js') or path.name.endswith('.umd.min.kvm-cloud-native.js') or '.303.js' in path.name:
            data = path.read_bytes()
            print(path.name, len(data), len(gzip.compress(data, 9, mtime=0)))
PY
```

The current package build succeeds. Webpack still warns that the Cloud Native
chunk (about 330 KiB raw) and terminal chunk exceed its 244 KiB raw-asset
guideline. The terminal is lazy-loaded; keep that split. Avoid deleting
administration features just to satisfy the generic threshold without route
level loading and user impact measurements.

## Small safe optimizations applied

- `CloudNative.vue` now stores its six fixed log-filter regular expressions at
  module scope. Recomputing the filtered log view no longer allocates all six
  expressions each time; each log line is still tested with the same pattern
  and flags.
- `HOST_ADMIN_SCRIPT` now obtains the passwd entry list once and reuses that
  snapshot for account and group construction instead of asking NSS twice.
  This avoids a redundant account database lookup per full host inventory.

Validation: production UI package build completed; `service/app.py` compiled,
the embedded `HOST_ADMIN_SCRIPT` parsed independently, and `git diff --check`
passed. No cluster, GitHub, or Docker publication was performed.

## SSH/libvirt and rendering findings

- HTTP middleware measures total API route duration only. `run_sudo_python`
  executes the remote inventory through SSH, and the host inventory script
  invokes multiple `virsh` commands sequentially, including per-VM calls. This
  is a likely scale-sensitive path, but the existing timing cannot distinguish
  SSH setup from remote command time. Add phase timing (SSH connect, command,
  parse) with host ID/outcome only before redesigning transport or batching.
- Do not introduce a global SSH connection pool. The prior review found no
  evidence that SSH handshake time is the dominant cost; global reuse would
  add stale-session, credential-rotation, and concurrency risks. If phase data
  identifies repeated handshakes within one operation, evaluate request-scoped
  reuse with timeouts and cleanup.
- The frontend metrics refresh is already isolated from the heavier inventory
  route and runs every 30 seconds only while the page is visible. Preserve this
  separation; avoid polling the full administration inventory for CPU and
  memory cards.
- The current bundle’s total compressed size grew 6.3% since 0.7.120 even
  though the main entry became smaller. Future bundle work should target the
  Cloud Native lazy chunk and confirm that imported Rancher components are
  actually needed before changing dependencies.

## Engineering-practices review

No broad SSH/libvirt rewrite is justified by the available evidence. Preserve
pinned SSH host-key verification, bounded concurrency, and the extension-owned
API boundary. The next useful performance improvement is safe phase telemetry,
followed by a measured `virsh` batching experiment against representative VM
counts with parity checks for state, vCPU, memory, IP, and NIC details.

This review was performed against local artifacts and source; it made no live
cluster requests and changed no Rancher or Harvester resources.

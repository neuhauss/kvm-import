# Performance and engineering-practices review: 0.7.80

Review date: 2026-10-19

Baseline: 0.7.12
Previous completed review: 0.7.70
Review became due at: 0.7.80 (10 new patch versions)
Reviewed release: 0.7.80

## Reproducible bundle inspection

Measured the built JavaScript artifacts with Python's standard library and
deterministic gzip level 9 compression:

| Bundle | 0.7.70 raw / gzip-9 | 0.7.80 raw / gzip-9 | Change |
| --- | ---: | ---: | ---: |
| Main UI | 333,207 / 58,883 bytes | 393,177 / 67,484 bytes | +59,970 / +8,601 bytes |
| Chunk 148 | 48,528 / 16,234 bytes | 58,829 / 19,280 bytes | +10,301 / +3,046 bytes |
| Chunk 37 | 45,107 / 14,837 bytes | 54,572 / 17,640 bytes | +9,465 / +2,803 bytes |
| VM console chunk | 9,509 / 3,351 bytes | 9,509 / 3,351 bytes | unchanged |
| xterm chunk | 419,350 / 107,701 bytes | 419,350 / 107,698 bytes | unchanged / -3 bytes |
| All JS chunks, summed individually | 855,701 / 201,006 bytes | 935,437 / 215,453 bytes | +79,736 / +14,447 bytes |

The initial UI bundle grew 18.0% raw and 14.6% compressed over ten releases.
Across all chunks, growth was 9.3% raw and 7.2% compressed. The interactive
terminal's large xterm dependency remains split into its own chunk, so it does
not add to the initial UI download. This is visible growth, but compressed
payload remains moderate and the measurements do not identify a safe code
split that would preserve route behavior. No bundle change was made.

Reproduce with:

```sh
python3 - <<'PY'
from pathlib import Path
import gzip
for version in ('0.7.70', '0.7.80'):
    root = Path('dist-pkg') / f'kvm-manager-{version}'
    raw_total = gzip_total = 0
    print(version)
    for path in sorted(root.glob('*.js')):
        data = path.read_bytes()
        packed = len(gzip.compress(data, 9, mtime=0))
        raw_total += len(data)
        gzip_total += packed
        print(path.name, len(data), packed)
    print('all-js', raw_total, gzip_total)
PY
```

## Performance findings

- Host metrics are fetched through a lightweight endpoint, separate from the
  full administration inventory. The UI refreshes metrics every 30 seconds
  only while the page is visible and keeps one request in flight. This avoids
  repeatedly running the full inventory for dashboard metrics.
- Storage volumes and subscription extensions are loaded on demand. The
  terminal libraries remain split from the initial UI. These existing choices
  keep expensive or large features off the initial path.
- Full host inventory still performs many serial commands over one pinned SSH
  connection. It queries VM details and addresses, storage pools, libvirt
  networks, NetworkManager, services, accounts, repositories, security state,
  and SUSEConnect. Hosts with many resources can therefore take longer to
  refresh. Parallelizing remote commands without measurements on supported
  SUSE/libvirt versions could add host load or change failure behavior, so no
  change was made. A future optimization should first measure per-section
  latency on representative hosts and then load slower sections on demand.
- SSH authentication uses pinned host keys and bounded connection timeouts;
  remote administration requests also have operation-level timeouts. Reusing
  SSH sessions globally was not recommended because it adds lifecycle and
  credential handling complexity.

## Engineering-practices review

- API routes apply Rancher-derived permission levels, and the UI checks the
  matching capabilities before showing administrative actions.
- The extension redacts repository URL query strings and avoids persisting
  subscription registration codes. API responses disable caching.
- A few remote scripts have subprocess calls without their own timeout:
  `setenforce` in the SELinux route, and `useradd`, `userdel`, `usermod`, and
  `chpasswd` in account administration. Their enclosing SSH operations are
  bounded, but an explicit timeout on each child command would make failure
  handling more predictable if a host utility stalls. This was not changed in
  this performance-only review because it changes the failure mode; track it
  as a small reliability hardening item.
- FastAPI advertises version 0.7.73 in `service/app.py` while the extension
  package is 0.7.80. If API and extension versions are intended to represent
  one release, align that metadata in the next release; if they are purposely
  independent, document the versioning scheme.

## Outcome

No source optimization was justified by the available artifact measurements
and static inspection. The review is recorded without changing runtime code.
No tests were run. No deployment or publication to the cluster, GitHub, or
Docker Hub was performed.

Next scheduled performance review: after ten new versions beyond 0.7.80
(target 0.7.90).

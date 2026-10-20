# Performance review: 0.7.58

Review date: 2026-10-18

Baseline: 0.7.12
Previous completed review: 0.7.41 (resulting local version 0.7.42)
Reviewed version: 0.7.58

## Reproducible bundle inspection

Measured the checked-in build artifacts in `dist-pkg` with Python's standard
library (`gzip.compress(data, compresslevel=9, mtime=0)`). Compared the previous
review's resulting build (0.7.42) with 0.7.58:

| Bundle | 0.7.42 raw / gzip-9 | 0.7.58 raw / gzip-9 | Change |
| --- | ---: | ---: | ---: |
| Main UI | 306,509 / 53,887 bytes | 309,850 / 54,855 bytes | +3,341 / +968 bytes |
| VM console chunk | 9,079 / 3,280 bytes | 9,509 / 3,351 bytes | +430 / +71 bytes |
| xterm chunk | 419,350 / 107,701 bytes | 419,350 / 107,701 bytes | unchanged |

The console and xterm remain separate chunks. The main bundle grew by about
1.8% compressed since 0.7.42; this is small and does not justify a broader
component split by itself.

Reproduce with:

```sh
python - <<'PY'
from pathlib import Path
import gzip
for version in ('0.7.42', '0.7.58'):
    root = Path('dist-pkg') / f'kvm-manager-{version}'
    for name in (f'kvm-manager-{version}.umd.min.js',
                 f'kvm-manager-{version}.umd.min.kvm-vm-console.js',
                 f'kvm-manager-{version}.umd.min.303.js'):
        data = (root / name).read_bytes()
        print(version, name, len(data), len(gzip.compress(data, 9, mtime=0)))
PY
```

## Findings

- `CloudNative.vue` requests `/cloud-native` during initial page load. The
  remote inventory script gathers VM details, disks, filesystems, services,
  storage pools, libvirt networks, accounts, repositories, security status,
  subscription status, NetworkManager profiles, and host facts over one SSH
  session. It refreshes lightweight host metrics separately every 30 seconds,
  avoiding a full inventory scan on each metrics refresh.
- `HOST_ADMIN_SCRIPT` issues per-resource subprocesses for some inventories:
  `nmcli connection show` details once per connection, `passwd -S` once per
  account, libvirt `dominfo`/`vcpucount`/address queries per VM, and XML/info
  queries per storage pool or network. These are concrete latency candidates
  on hosts with many resources. Combining them safely depends on command output
  and feature availability across supported SUSE and libvirt versions, so this
  review does not change parsing or remote command behavior without
  representative-host measurements.
- Subscription extension discovery is a separate endpoint and is loaded when
  the Subscriptions section is selected, keeping its SUSEConnect operation out
  of initial page loading.
- VM detail and storage-volume discovery are on-demand. The console and xterm
  code remain split from the initial bundle.

## Outcome

No code optimization was made: the likely API wins require compatibility
validation against real SUSE host command output, and the measured bundle
growth is modest. Existing lazy loading and the lightweight metrics endpoint
already avoid repeating the heaviest work during background refresh. No build,
cluster deployment, or publication was performed for this review.

Next scheduled performance review: after ten new versions beyond 0.7.58
(target 0.7.68).

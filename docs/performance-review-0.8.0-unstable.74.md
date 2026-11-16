# Performance and engineering-practices review: 0.8.0-unstable.74

Review date: 2026-11-15
Previous completed review: 0.8.0-unstable.58
New releases since that review: 16 (`.59` through `.74`)
Scheduled checkpoint `.68` was passed; next review target: `.84`.

## Reproducible extension bundle inspection

Compared the packaged JavaScript from `.58` and `.74` using deterministic gzip
level 9. Source maps are excluded from the totals.

| Artifact | `.58` raw / gzip-9 | `.74` raw / gzip-9 | Change |
| --- | ---: | ---: | ---: |
| Initial extension entry | 12,068 / 4,906 bytes | 12,071 / 4,913 bytes | +0.02% / +0.14% |
| All extension JavaScript chunks (14 files) | 1,698,066 / 387,561 bytes | 1,888,999 / 424,219 bytes | +11.24% / +9.46% |
| Clusters page chunk | 278,912 / 44,536 bytes | 399,738 / 61,407 bytes | +43.32% / +37.88% |
| Cloud Native page chunk | 385,408 / 62,621 bytes | 385,408 / 62,621 bytes | no change |
| Hosts page chunk | 55,562 / 12,598 bytes | 55,562 / 12,597 bytes | no change |
| Deploy page chunk | 16,172 / 4,076 bytes | 16,172 / 4,077 bytes | no material change |

Reproduce from the repository root:

```sh
python3 - <<'PY'
from pathlib import Path
import gzip
for version in ('0.8.0-unstable.58', '0.8.0-unstable.74'):
    directory = Path('dist-pkg') / f'kvm-manager-{version}'
    files = sorted(directory.glob('*.js'))
    print(version, len(files), sum(p.stat().st_size for p in files),
          sum(len(gzip.compress(p.read_bytes(), 9, mtime=0)) for p in files))
    for pattern in ('*.umd.min.js', '*.umd.min.kvm-clusters.js',
                    '*.umd.min.kvm-cloud-native.js', '*.umd.min.kvm-hosts.js',
                    '*.umd.min.kvm-deploy.js'):
        path = next(iter(directory.glob(pattern)), None)
        if path:
            print(path.name, path.stat().st_size,
                  len(gzip.compress(path.read_bytes(), 9, mtime=0)))
PY
```

The plugin entry remains about 4.9 KiB compressed. The larger Clusters chunk
is deferred until that page is opened, so it does not increase the extension's
initial plugin entry. The growth reflects new HA planning, diagnostics, and
resource administration code; at 61.4 KiB compressed it is still modest, but
it is the clearest bundle to monitor. If it keeps growing, split infrequently
used diagnostics/editors into separate async chunks. The build also reports
large Rancher shell/vendor bundles and upstream `postcss-calc` warnings; those
are not KVM page chunks and should not be changed as part of this extension.

The generated UI asset server already sends `Cache-Control: public, max-age=31536000, immutable` for versioned extension paths and `no-cache` for the catalog index. This is the right cache boundary: versioned bundles can be cached while the catalog remains discoverable.

## Navigation and SSH inspection

Opening Clusters requests host readiness, permissions, saved plans, registered
SUSE HA clusters, and QNetd witnesses concurrently. The readiness endpoint
still fans out SSH checks to imported hosts, with at most three simultaneous
host checks, and then may read live cluster status. Previously the first-page
spinner waited for this SSH fan-out before rendering even saved plans and
clusters. The UI now loads local/API-backed plans and cluster records first,
then presents live host readiness and its errors separately as the SSH checks
finish. A guard prevents manual or periodic refresh from starting another
readiness fan-out while the first is still active. No redundant host-metrics
SSH request was found in the Clusters load path. Opening a verified live
cluster still requests status and diagnostics in parallel because both are
needed for its management views.

## Safety and operational correctness

The SUSE `VirtualDomain` workflow now runs as a durable operation that can be
resumed after a page refresh. Direct VM lifecycle, delete, snapshot, device,
autostart, graphics, and persistent-configuration operations check active
Pacemaker ownership before using libvirt. New VM creation also rejects a name
already assigned to a Pacemaker `VirtualDomain`. If Pacemaker is active but
its CIB or shared VM XML cannot be verified, the remote operation fails closed.
The check adds a small remote `systemctl`/CIB read only on VM mutations and
avoids simultaneous management by libvirt UI actions and Pacemaker.

## Validation and outcome

- `npm run test:ui`: 18/18 tests passed.
- Focused Python VirtualDomain/Pacemaker suites: 26/26 tests passed.
- `python3 -m py_compile service/app.py ...` and `git diff --check` passed.
- Production UI build completed. It retains upstream PostCSS warnings and
  Rancher shell/vendor asset-size warnings; the extension entry and named page
  chunks were emitted successfully.
- Full Python discovery was not completed because the environment's
  `TestClient` suite stalled under the available Python 3.14 runtime; the
  focused route/script tests above ran in the project test virtualenv.
- No GitHub, Docker Hub, Rancher, or Harvester changes were published or
  applied.

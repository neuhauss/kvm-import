# Performance and engineering-practices review: 0.7.103

Review date: 2026-10-19
Baseline: 0.7.12
Previous completed review: 0.7.80
Scheduled target: 0.7.90
Reviewed release: 0.7.103
Local optimized package: 0.7.104

## Reproducible bundle inspection

Measured production UI package artifacts using deterministic gzip level 9.
The local 0.7.103 artifact was built immediately before this review, and
0.7.104 was built after the change below.

| Artifact | 0.7.80 raw / gzip-9 | 0.7.103 raw / gzip-9 | 0.7.104 raw / gzip-9 |
| --- | ---: | ---: | ---: |
| Main UI bundle | 393,177 / 67,484 bytes | 906,038 / 188,469 bytes | 478,200 / 78,753 bytes |
| xterm chunk (`.303.js`) | 419,350 / 107,698 bytes | included in main bundle | 419,353 / 107,703 bytes |
| VM console wrapper | 9,509 / 3,351 bytes | included in main bundle | 9,512 / 3,353 bytes |

The 0.7.103 main bundle was 40.8% smaller raw and 58.2% smaller compressed in
0.7.104 after restoring lazy loading for the terminal. All emitted JavaScript
chunks together changed from 1,049,113 / 233,167 bytes to 1,050,140 / 234,507
bytes (raw / gzip-9), a 0.1% raw and 0.6% compressed increase. The optimization
therefore keeps terminal code available while deferring its download until the
user opens a terminal; it does not claim to reduce the total installed code.

Reproduce with:

```sh
python3 - <<'PY'
from pathlib import Path
import gzip
for version in ('0.7.80', '0.7.103', '0.7.104'):
    root = Path('dist-pkg') / f'kvm-manager-{version}'
    print(version)
    for path in sorted(root.glob('*.js')):
        data = path.read_bytes()
        print(path.name, len(data), len(gzip.compress(data, 9, mtime=0)))
PY
```

## Change

`Clusters.vue` imported `VmConsole.vue` synchronously, even though its terminal
is only rendered after the user explicitly opens it. That pulled the xterm
terminal libraries into the main extension bundle. The component now uses
Vue's `defineAsyncComponent` with the existing `kvm-vm-console` chunk name,
matching Cloud Native's lazy-loading behavior. The 0.7.104 build confirms that
both the terminal wrapper and xterm are separate chunks again.

## API and rendering review

- Full host inventory still uses one bounded SSH session and sequential remote
  inventory commands. Changing command concurrency without host-side latency
  measurements could increase load or alter partial-failure behavior, so no
  API change was justified here.
- Cluster readiness queries all registered hosts with a three-worker ceiling;
  preflight and template remediation are also bounded to three hosts. Host
  metrics remain on their separate 30-second path, and the UI avoids refreshing
  while hidden. These bounds and freshness semantics were preserved.
- The periodic cluster page refresh performs remote readiness checks every 60
  seconds. A cache could reduce SSH traffic, but would make add-on/service state
  stale after changes; no cache was added without a freshness contract.
- Large host inventories can still be slower than the small test cluster. The
  current code limits list rendering and loads some detail data on demand; no
  reproducible evidence supported broader query or rendering changes.

## Engineering-practices review

- The new import remains an extension-owned change and does not alter Rancher
  or Harvester code.
- The package build completed successfully. Webpack still reports the expected
  asset-size/runtime warnings; the terminal's large xterm dependency is now
  lazy-loaded again.
- `service/app.py` passed `python3 -m py_compile`, and `git diff --check` passed.
  No test suite was run as part of this scheduled review.
- No new SSH calls, host-side operations, or mutable API behavior were added.

## Outcome

One low-risk bundle optimization was implemented locally as version 0.7.104.
No optimization to API calls, queries, or periodic rendering was supported by
reproducible evidence in this review. Nothing was deployed to a cluster or
published to GitHub or Docker Hub.

Next scheduled performance review: after ten new versions beyond 0.7.103
(target 0.7.113).

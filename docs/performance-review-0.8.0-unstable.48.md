# Performance and engineering-practices review: 0.8.0-unstable.48

Review date: 2026-11-15
Baseline: 0.7.12
Previous completed review: 0.8.0-unstable.31
New releases since previous review: 17 (`.32` through `.48`)
Next scheduled review: after ten additional releases (target `.58`)

## Reproducible bundle inspection

The `.31` built JavaScript artifacts are no longer present in `dist-pkg`, so
the closest retained production build (`.44`) was compared with `.48`. Counts
use checked-in JavaScript files and deterministic gzip level 9:

| Artifact | 0.8.0-unstable.44 raw / gzip-9 | 0.8.0-unstable.48 raw / gzip-9 | Change |
| --- | ---: | ---: | ---: |
| All JavaScript chunks (11) | 1,558,033 / 355,784 bytes | 1,579,395 / 360,893 bytes | +1.37% / +1.44% |
| Main entry | 285,666 / 50,755 bytes | 287,710 / 51,448 bytes | +0.71% / +1.37% |
| Cloud Native lazy chunk | 384,021 / 61,962 bytes | 384,021 / 61,962 bytes | unchanged |
| VM terminal lazy chunk | 13,621 / 4,203 bytes | 13,621 / 4,204 bytes | unchanged raw / +1 byte gzip |

Reproduce from the repository root:

```sh
python3 - <<'PY'
from pathlib import Path
import gzip
for version in ('0.8.0-unstable.44', '0.8.0-unstable.48'):
    directory = Path('dist-pkg') / f'kvm-manager-{version}'
    files = sorted(directory.glob('*.js'))
    print(version, len(files), sum(p.stat().st_size for p in files),
          sum(len(gzip.compress(p.read_bytes(), 9, mtime=0)) for p in files))
    for pattern in ('*.umd.min.js', '*.umd.min.kvm-cloud-native.js',
                    '*.umd.min.kvm-vm-console.js'):
        path = next(iter(directory.glob(pattern)), None)
        if path:
            print(path.name, path.stat().st_size,
                  len(gzip.compress(path.read_bytes(), 9, mtime=0)))
PY
```

The feature-heavy Cloud Native route remains split into its own lazy chunk and
did not grow between the two retained builds. The small aggregate increase is
mainly in the entry and runtime chunks; the initial bundle remains about 51 KiB
gzip. Preserve route-level lazy loading.

## Navigation and host-call inspection

Inspected `pkg/kvm-manager/pages/CloudNative.vue` and the `/cloud-native` and
`/metrics` routes in `service/app.py`. The page already treats CPU, memory, and
load returned by its initial cloud-native inventory as fresh, and the
30-second/visibility refresh checks that timestamp before making another SSH
request. Thus the former duplicate metrics read on page open is not present.
Initial host inventory, host list, and permissions are fetched concurrently;
host activity is loaded after the primary inventory resolves. The API returns
the host inventory from one SSH invocation of the remote admin script, and
metrics refresh is a separate, intentionally lightweight SSH invocation.

No additional small, behavior-neutral optimization was clear from this review.
Parallelizing individual commands inside the large remote admin script could
reduce latency on some hosts, but it changes host load and failure/timeout
behavior and needs per-command timing plus host-level verification before it is
safe. Caching inventory would make administrative state stale unless paired
with invalidation for every mutation; that is a larger correctness change.
Those options are recorded as follow-up measurements, not applied here. No
end-to-end timing against a live KVM host was available in this review.

## Engineering-practices review

- Read-only fan-out for cluster preflight and inventory remains bounded, and
  the VM inventory's four-worker cap from the prior review remains in place.
- SSH connections remain request-scoped and host-key pinned; this review found
  no justification for a longer-lived connection pool.
- The browser's `no-store` option is scoped to API requests. Versioned plugin
  bundles stay independently cacheable, and Cloud Native/console code stays
  lazy-loaded.
- No new runtime dependency, unbounded concurrency, or unbounded polling was
  found in the reviewed navigation/data-loading paths.
- No Rancher core or Harvester resource was changed.

## Validation and outcome

- Reproduced raw and gzip bundle measurements for retained builds `.44` and
  `.48`; confirmed the Cloud Native chunk bytes are identical.
- Source-inspected the initial page load, metrics refresh gate, and matching
  API routes for duplicate SSH reads.
- No source changes were made: no low-risk optimization with a demonstrated
  benefit was identified without live-host timings. No test suite was run.
- No GitHub, Docker Hub, or cluster publication was performed.

# Performance and engineering-practices review: 0.8.0-unstable.58

Review date: 2026-11-15
Baseline: 0.7.12
Previous completed review: 0.8.0-unstable.48
New releases since previous review: 10 (`.49` through `.58`)
Next scheduled review: after ten additional releases (target `.68`)

## Reproducible bundle inspection

Compared the packaged Rancher extension JavaScript from `.48` and `.58` using
checked-in package artifacts and deterministic gzip level 9:

| Artifact | `.48` raw / gzip-9 | `.58` raw / gzip-9 | Change |
| --- | ---: | ---: | ---: |
| Initial plugin entry | 287,710 / 51,448 bytes | 12,068 / 4,906 bytes | -95.81% / -90.47% |
| All JavaScript chunks | 1,579,395 / 360,893 bytes (11 chunks) | 1,698,066 / 387,561 bytes (14 chunks) | +7.51% / +7.39% |
| Clusters page chunk | Included in initial entry | 278,912 / 44,536 bytes | Deferred until navigation |
| Hosts page chunk | Included in initial entry | 55,562 / 12,598 bytes | Deferred until navigation |
| Deploy page chunk | Included in initial entry | 16,172 / 4,076 bytes | Deferred until navigation |
| Cloud Native chunk | 384,021 / 61,962 bytes | 385,408 / 62,621 bytes | +0.36% / +1.06% |

The initial plugin entry had accumulated the full Hosts, Clusters, and Deploy
screens plus their page-specific code. These pages now use Vue's
`defineAsyncComponent` with dedicated webpack chunk names, matching the
existing lazy-loading pattern for Backups and Cloud Native. This sharply
reduces the JavaScript Rancher must parse when the extension starts. The
full-package increase is expected because code is now emitted into additional
versioned chunks; it does not mean all chunks are fetched on first load.

Reproduce from the repository root:

```sh
python3 - <<'PY'
from pathlib import Path
import gzip
for version in ('0.8.0-unstable.48', '0.8.0-unstable.58'):
    directory = Path('dist-pkg') / f'kvm-manager-{version}'
    files = sorted(directory.glob('*.js'))
    print(version, len(files), sum(p.stat().st_size for p in files),
          sum(len(gzip.compress(p.read_bytes(), 9, mtime=0)) for p in files))
    for pattern in ('*.umd.min.js', '*.umd.min.kvm-clusters.js',
                    '*.umd.min.kvm-hosts.js', '*.umd.min.kvm-deploy.js'):
        path = next(iter(directory.glob(pattern)), None)
        if path:
            print(path.name, path.stat().st_size,
                  len(gzip.compress(path.read_bytes(), 9, mtime=0)))
PY
```

## API, SSH, and UI-loading inspection

- Cluster setup already starts readiness, permission, and saved-plan requests in
  parallel. Cluster status and diagnostics are fetched only when an existing
  cluster is opened. No duplicate metrics call was found in that route.
- Host fan-out and long-running host operations remain bounded by explicit
  worker limits. SSH clients are created per request; this review found no
  evidence supporting a persistent connection pool or changing host-load and
  authentication semantics.
- No live KVM host was used for latency measurements. The available local
  Kubernetes contexts did not match the explicitly expected Rancher API
  endpoint, so no Kubernetes command was run and no infrastructure resource
  was changed.

## Validation and outcome

- `npm run test:ui`: 15/15 test files passed.
- Cluster bootstrap Python tests: 10/10 passed.
- Full Python test discovery ran 60 tests; 58 passed and two test modules could
  not import because `paramiko` and `pydantic` are not installed in the host
  Python environment. The targeted SUSE HA and bootstrap diagnostic suites
  passed.
- `python3 -m py_compile service/app.py` and `git diff --check` passed.
- `NODE_OPTIONS=--require=/tmp/kvm-build-no-netif.js CHART_REPO_URL=...`
  `scripts/package-release.sh` packaged `.58` successfully. The regular UI
  build also completed. Webpack still reports general Rancher entrypoint size
  and upstream CSS `postcss-calc` warnings; the extension package build now
  reports Clusters, Cloud Native, and xterm as deferred chunks.
- No GitHub, Docker Hub, Rancher, or Harvester changes were published or
  applied.

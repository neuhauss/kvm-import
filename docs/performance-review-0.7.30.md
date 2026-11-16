# Performance review: 0.7.30

Review date: 2026-10-17

Baseline: 0.7.12
Reviewed version: 0.7.30

## Scope and reproducible inspection

Inspected the extension bundle, VM console relay, host refresh paths, and the
cluster readiness endpoint. The bundle sizes below were measured from the
release output with Python's `gzip.compress(data, 9, mtime=0)`; source behavior
was inspected in `pkg/kvm-manager/pages/CloudNative.vue`,
`pkg/kvm-manager/pages/Clusters.vue`, and `service/app.py`.

| Bundle | Raw bytes | gzip-9 bytes | Loading behavior |
| --- | ---: | ---: | --- |
| Main UI | 215,151 | 38,450 | Initial extension bundle |
| xterm chunk | 419,350 | 107,699 | Separate async VM-console component |
| Other shared chunks (combined) | 44,413 | 15,968 | Webpack shared chunks |

The webpack size warning applies to the raw xterm chunk. The terminal component
is loaded with `defineAsyncComponent` and a named import, so xterm is not part
of the initial UI bundle. Its compressed transfer size is about 108 KB.

## Findings

- Cluster readiness checks run at most three SSH probes concurrently and
  refresh every 60 seconds only while the browser tab is visible.
- Host inventory refresh uses a bounded pool of two SSH probes. The cloud-native
  host metrics refresh runs every 30 seconds only while visible.
- VM list and details use bounded `virsh` subprocess timeouts. The VM console
  uses a 40 ms receive timeout while idle to keep terminal input responsive;
  replacing it with a longer polling interval would trade noticeable latency
  for a modest reduction in idle wakeups, so it was left unchanged.
- The xterm bundle is the largest concrete optimization opportunity, but it is
  already lazy-loaded. Further splitting or replacing it would add complexity
  without a clear user benefit at the current compressed size.

## Outcome

No code changes were made for performance in this review. Existing request
concurrency, polling visibility checks, command timeouts, and lazy loading
already bound the main resource costs. Revisit xterm size if more terminal
features materially increase the chunk or if production measurements show a
slow first-open experience.

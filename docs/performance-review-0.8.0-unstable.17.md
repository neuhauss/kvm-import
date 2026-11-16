# Performance and engineering-practices review: 0.8.0-unstable.17

Review date: 2026-11-04
Baseline: 0.7.12
Previous completed review: 0.7.139
Scheduled threshold: 0.7.149 (crossed by the 0.8.0-unstable line)
Reviewed release: 0.8.0-unstable.17
Next scheduled review: after ten new releases beyond 0.8.0-unstable.17 (target 0.8.0-unstable.27)

## Reproducible bundle inspection

Compared checked-in production JavaScript artifacts with deterministic gzip
level 9:

| Artifact | 0.7.139 raw / gzip-9 | 0.8.0-unstable.16 raw / gzip-9 | Change |
| --- | ---: | ---: | ---: |
| All JavaScript chunks | 1,250,425 / 278,264 bytes | 1,263,577 / 281,323 bytes | +1.05% / +1.10% |
| Main entry | 258,268 / 45,817 bytes | 258,475 / 45,917 bytes | +0.08% / +0.22% |
| Cloud Native lazy chunk | 337,780 / 54,696 bytes | 346,464 / 56,362 bytes | +2.57% / +3.05% |
| Terminal chunk | 9,512 / 3,353 bytes | 9,542 / 3,360 bytes | +0.32% / +0.21% |

Reproduce from the repository root:

```sh
python3 - <<'PY'
from pathlib import Path
import gzip
for version in ('0.7.139', '0.8.0-unstable.16'):
    files = sorted((Path('dist-pkg') / f'kvm-manager-{version}').glob('*.js'))
    print(version, sum(p.stat().st_size for p in files),
          sum(len(gzip.compress(p.read_bytes(), 9, mtime=0)) for p in files))
PY
```

The Cloud Native chunk remains above webpack's generic raw-size guideline, but
is lazy-loaded. The aggregate compressed growth is about 3 KiB since 0.7.139;
this review did not find a safe feature or dependency removal that would offset
it. Preserve route-level loading and use bundle-analyzer comparisons before
changing functionality.

## Safe optimization applied

Recent-activity queries are scoped by host and optionally VM. They previously
used a case-insensitive `LIKE` prefix, which prevented SQLite from reliably
using a target index. The API now uses the canonical UUID host prefix with
`GLOB`, and startup creates a composite `(target, occurred_at DESC)` index.
Host IDs are generated UUIDs and VM names cannot contain glob metacharacters,
so the prefix semantics are preserved. The existing time index remains for
the global audit view. This adds a small index-maintenance cost to audit writes
in exchange for indexed host/VM filtering.

A synthetic 500,000-row SQLite dataset, with a 1% host event share, measured
60 repetitions of the bounded 50-event query. Median execution was 0.856 ms
using the existing time index and `LIKE`, and 0.427 ms using the target index
and `GLOB` (about 50% lower in this dataset). `EXPLAIN QUERY PLAN` changed from
a full ordered scan of the time index to two target-index range searches and a
bounded temporary sort. These figures are a reproducible microbenchmark, not
a production latency claim.

Reproduce the synthetic query-plan and timing comparison with:

```sh
python3 - <<'PY'
import sqlite3, statistics, time
N = 500_000
db = sqlite3.connect(':memory:')
db.execute('PRAGMA temp_store=MEMORY')
db.execute('CREATE TABLE audit_events(id TEXT, occurred_at TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL, outcome TEXT NOT NULL)')
batch = []
for i in range(N):
    host = f'{i % 100:08x}-0000-4000-8000-000000000000'
    target = host if i % 20 == 0 else f'{host}/vm-{i % 31}'
    batch.append((str(i), f'{i:012d}', 'vm.start', target, 'success'))
    if len(batch) == 10_000:
        db.executemany('INSERT INTO audit_events VALUES(?,?,?,?,?)', batch)
        batch = []
if batch:
    db.executemany('INSERT INTO audit_events VALUES(?,?,?,?,?)', batch)
db.execute('CREATE INDEX idx_audit_events_occurred_at ON audit_events(occurred_at DESC)')
host = '00000007-0000-4000-8000-000000000000'
queries = {
    'before': ('SELECT occurred_at,action,target,outcome FROM audit_events WHERE target=? OR target LIKE ? ORDER BY occurred_at DESC LIMIT ?', (host, host+'/%', 50)),
    'after': ('SELECT occurred_at,action,target,outcome FROM audit_events WHERE target=? OR target GLOB ? ORDER BY occurred_at DESC LIMIT ?', (host, host+'/*', 50)),
}
for label in ('before', 'after'):
    if label == 'after':
        db.execute('CREATE INDEX idx_audit_events_target_occurred ON audit_events(target,occurred_at DESC)')
    sql, args = queries[label]
    print(label, db.execute('EXPLAIN QUERY PLAN '+sql, args).fetchall())
    samples = []
    for _ in range(60):
        started = time.perf_counter()
        db.execute(sql, args).fetchall()
        samples.append((time.perf_counter()-started)*1000)
    print(label, 'median_ms', round(statistics.median(samples), 3))
PY
```

## Engineering-practices review

- Keep SSH sessions request-scoped. The code has bounded concurrency for
  multi-host work; available evidence still does not justify global SSH pooling.
- Preserve operation-job bounds and the UI's reduced polling while waiting for
  long operations. The Cloud Native metrics refresh is separate from full
  inventory loading and pauses when the page is hidden.
- VM lifecycle actions continue to verify libvirt state, and destructive
  force-off remains a separate, explicitly reviewed UI action.
- The recent-activity endpoint still caps results at 100 and retains only
  bounded audit history. The new index does not change authorization or data
  returned by the endpoint.

## Validation

- Production extension package build completed for 0.8.0-unstable.17.
- UI test suite passed.
- API suite passed after adding the audit-scope/index regression test.
- Python syntax compilation, locale parsing, and `git diff --check` passed.
- No live KVM host or VM was accessed by the tests.
- No Rancher core or Harvester resource was changed.

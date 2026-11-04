# Performance and engineering-practices review: 0.7.70

Review date: 2026-10-19

Baseline: 0.7.12
Previous completed review: 0.7.58
Review became due at: 0.7.69 (11 patch versions after 0.7.58)
Reviewed release: 0.7.70

## Reproducible bundle inspection

Measured the built artifacts with Python's standard library using deterministic
gzip level 9 compression:

| Bundle | 0.7.58 raw / gzip-9 | 0.7.70 raw / gzip-9 | Change |
| --- | ---: | ---: | ---: |
| Main UI | 333,651 / 58,607 bytes | 333,207 / 58,883 bytes | -444 / +276 bytes |
| VM console chunk | 9,509 / 3,351 bytes | 9,509 / 3,351 bytes | unchanged |
| xterm chunk | 419,350 / 107,701 bytes | 419,350 / 107,701 bytes | unchanged |

The main bundle changed by less than 0.5% when compressed. The much larger
xterm chunk remains separate from the initial UI bundle. The build still emits
Webpack size/runtime warnings, but a broader split is not justified by these
measurements alone.

Reproduce with:

```sh
python3 - <<'PY'
from pathlib import Path
import gzip
for version in ('0.7.58', '0.7.70'):
    root = Path('dist-pkg') / f'kvm-manager-{version}'
    for name in (f'kvm-manager-{version}.umd.min.js',
                 f'kvm-manager-{version}.umd.min.kvm-vm-console.js',
                 f'kvm-manager-{version}.umd.min.303.js'):
        data = (root / name).read_bytes()
        print(version, name, len(data), len(gzip.compress(data, 9, mtime=0)))
PY
```

## Findings and change

- The Subscriptions tab called `/subscriptions/extensions` every time the user
  returned to it. That endpoint opens an SSH session and runs SUSEConnect to
  list add-ons. The UI already had an `extensionsLoaded` flag and an explicit
  Refresh status button, but the flag was not used to avoid duplicate reads.
- Version 0.7.70 reuses the fetched add-on list when returning to the same
  host's tab. The explicit refresh button and successful registration,
  deregistration, activation, or deactivation still force a fresh read. The
  cache is keyed by host ID and a failed read remains retryable. This avoids
  repeat SSH/SUSEConnect calls without suppressing deliberate refreshes or
  post-change verification.
- The full host inventory intentionally runs several bounded per-resource
  libvirt, NetworkManager, account, and repository commands over one SSH
  session. Combining those commands or parallelizing them may reduce latency,
  but changes output assumptions and host load across SUSE/libvirt versions.
  No safe representative-host evidence justified changing that behavior.
- Lightweight host metrics remain separate from full inventory refreshes, and
  VM detail, storage-volume, and console code remain on-demand or split into
  chunks.

## Engineering-practices review

- API write routes enforce Rancher-derived permission levels; frontend controls
  use the corresponding access level for affordances.
- Subscription registration codes are submitted with the requested operation
  and redacted from API failure diagnostics. No new secret persistence was
  introduced.
- SSH/libvirt and SUSEConnect operations retain bounded timeouts and API
  latency/failure logging. Avoiding speculative parallel remote commands
  preserves compatibility and reduces simultaneous host load.
- No additional actionable security, compatibility, or operational-practices
  issue was found during this targeted review.

## Outcome

The code change is limited to avoiding redundant add-on discovery on tab
re-entry. The extension package build completed, `service/app.py` passed Python
bytecode compilation, and `git diff --check` passed. No cluster deployment or
external publication was performed in this review.

Next scheduled performance review: after ten new versions beyond 0.7.70
(target 0.7.80).

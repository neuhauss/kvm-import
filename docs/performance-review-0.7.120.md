# Performance and engineering-practices review: 0.7.120

Review date: 2026-10-20
Baseline: 0.7.12
Previous completed review: 0.7.103
Scheduled target: 0.7.113
Reviewed release: 0.7.120
Local optimized package: none

## Reproducible bundle inspection

Measured the JavaScript package files from the local production artifacts with
deterministic gzip level 9:

| Artifact | 0.7.104 raw / gzip-9 | 0.7.120 raw / gzip-9 | Change |
| --- | ---: | ---: | ---: |
| Main UI bundle | 478,200 / 78,753 bytes | 533,571 / 88,582 bytes | +11.6% / +12.5% |
| All JavaScript chunks | 1,050,140 / 234,507 bytes | 1,171,954 / 261,868 bytes | +11.6% / +11.7% |
| xterm chunk | 419,353 / 107,703 bytes | 419,353 / 107,703 bytes | unchanged |

The terminal remains split into a lazy-loaded xterm chunk. The main bundle is
88.6 KiB compressed; this is a measurable increase, but the review did not
identify one safely removable dependency or UI feature. No bundle change is
recommended until an analyzer comparison identifies the source of growth and
the required functionality is assessed.

Reproduce with:

```sh
python3 - <<'PY'
from pathlib import Path
import gzip
for version in ('0.7.104', '0.7.120'):
    root = Path('dist-pkg') / f'kvm-manager-{version}'
    files = sorted(root.glob('*.js'))
    print(version, 'all-js', sum(p.stat().st_size for p in files),
          sum(len(gzip.compress(p.read_bytes(), 9, mtime=0)) for p in files))
    for path in files:
        if path.name.endswith('.umd.min.js') or '.303.js' in path.name:
            data = path.read_bytes()
            print(path.name, len(data), len(gzip.compress(data, 9, mtime=0)))
PY
```

## SSH/libvirt inspection and live latency evidence

- Host credentials are encrypted in the extension API database. Normal
  management connections pin and check the SSH host key. `run_sudo_python`
  opens one SSH connection for its remote script and closes it afterward.
- The full Cloud Native inventory is already batched into one SSH call, but
  its host-side script runs multiple `virsh` and operating-system commands;
  VM, storage-pool, network, account, repository, and subscription details are
  collected sequentially. Per-VM `virsh` calls grow with the number of VMs.
- Cluster readiness inspects up to three hosts concurrently. The template
  prerequisite resolver currently opens separate SSH connections for its
  readiness check and subsequent package/service operations. This is a
  candidate for request-scoped connection reuse, but it includes long-running
  package installation and should be changed only with phase measurements and
  reliable cleanup on timeout/disconnect.
- The existing API telemetry records total HTTP route duration, not SSH
  handshake and remote-command duration separately. In the live Rancher API
  logs (measured during an operator-authorized cluster review; endpoint and
  context intentionally omitted), the last-24-hour window contained 15 slow
  events and no HTTP 5xx failure events. Slow-event samples: Cloud Native 6
  calls, 1.75–2.16 s; cluster readiness 4 calls, 1.87–2.05 s; extension
  listing 1 call, 1.75 s; stale-host refresh 4 calls, 1.00–1.05 s. These are
  only events above the configured 1-second threshold, not the distribution
  of all requests. The telemetry cannot attribute these durations to SSH
  setup versus remote commands.

### Decision on the selected items

1. **Separate SSH and command timings first.** This is the next recommended
   change. Log only phase, duration, host record ID, and outcome; never log
   host address, credentials, command text, or command output. Keep total-route
   timing as a separate signal.
2. **Reuse an SSH transport only inside a single multi-step operation** if
   phase data shows repeated handshakes are material. Do not introduce a
   global connection pool: it adds stale-session, credential-rotation, and
   concurrency failure modes across requests.
3. **Evaluate native libvirt calls as a VM-only adapter**, not as a wholesale
   replacement for host administration. `qemu+ssh` still uses SSH transport;
   it may provide structured VM data and reduce CLI parsing, but requires
   verifying available bindings, credentials, authorization, and behavior on
   supported SUSE releases. Keep SSH for SLES management and as fallback until
   parity is demonstrated. Do not expose unencrypted libvirt TCP.

No SSH pooling or libvirt adapter was introduced in this review: live evidence
shows slow routes but does not isolate the SSH handshake as the cause. A code
change before phase instrumentation would be a guess and could change timeout,
retry, or partial-failure behavior.

## Engineering-practices review

- The inspected Rancher API and extension-assets deployments were each 1/1
  ready. No resource was read from or changed in Harvester.
- Cockpit's official developer guide says there is no public external REST API;
  continue using its documented embedding path for the Cockpit UI and
  extension-owned APIs for cloud-native operations.
- The service keeps the SSH boundary on the API side; browser code does not
  receive host credentials. Existing pinned-host-key validation and bounded
  concurrency should be preserved during any connection refactor.
- No code optimization was justified by isolated evidence in this review. The
  package version remains 0.7.120. Python syntax compilation and
  `git diff --check` passed.
- This scheduled review did not deploy or publish artifacts.

Next scheduled review: after ten new versions beyond 0.7.120 (target 0.7.130).

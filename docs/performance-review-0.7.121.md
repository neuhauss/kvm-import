# Performance and engineering review: 0.7.121

Review date: 2026-10-20

## Build measurements

Production build completed with Node.js 26.8.2 and the repository's locked dependencies.

| Bundle | Raw size | Gzip size |
| --- | ---: | ---: |
| Main UI | 521.07 KiB | 87.57 KiB |
| Terminal (separate chunk) | 409.52 KiB | 106.13 KiB |
| Other lazy chunks | 213.90 KiB combined | 64.12 KiB combined |

Webpack reports its recommended 244 KiB raw-asset threshold for the main UI and terminal bundles. The terminal remains a separate chunk, so it is fetched only when its feature is opened. The main bundle is 87.57 KiB compressed. Removing terminal capabilities or UI features solely to silence the raw-size warning would change functionality without a demonstrated user benefit.

## Review findings

- Cloud Native inventory is collected as a batched host operation. The remote script still invokes multiple `virsh` and operating-system commands sequentially, so request cost can grow with VM count.
- The API does not currently separate SSH connection time from remote command time in its measurements. Reusing SSH connections globally would add stale-session and credential-rotation behavior without evidence that connection setup is the bottleneck.
- Keep host credentials on the API side. Registration codes are only returned to users authorized to manage subscriptions; the UI masks the value until the user chooses to reveal it.
- Keep expensive terminal code in its lazy-loaded chunk. Revisit bundle composition with analyzer data before removing functionality or changing chunk loading.

## Changes included with this release

- The public chart packager rewrites every retained chart URL to the configured public chart-repository origin. This prevents stale preview or private-origin URLs from leaking into future published indexes while preserving chart versions and digests.
- Generated local catalog archives and preview metadata are ignored by Git, preventing accidental inclusion in community releases.
- No speculative SSH pooling, API transport replacement, or UI feature removal was made. The current evidence does not support those behavior-affecting changes.

## Validation

- Production Rancher extension bundle built successfully.
- Python syntax compilation passed for the API and release scripts.
- `git diff --check` passed.
- Helm CLI validation was unavailable in the local environment; the GitHub release workflow packages the chart from the same committed chart sources.

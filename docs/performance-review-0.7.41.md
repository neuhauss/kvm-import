# Performance review: 0.7.41

Review date: 2026-10-18

Baseline: 0.7.12
Reviewed version: 0.7.41
Resulting local version: 0.7.42

## Scope and reproducible inspection

Reviewed bundle output from `build-pkg.sh kvm-manager`, storage-volume enumeration in `STORAGE_VOLUMES_SCRIPT`, and data loading for VM Details in `CloudNative.vue`. Bundle values below are the build output from version 0.7.42 after the changes; the previous .7.41 build was 267.30 KiB / 46.51 KiB gzipped for the main UI and 409.52 KiB / 106.12 KiB gzipped for xterm.

| Bundle | Raw size | Gzipped size | Loading behavior |
| --- | ---: | ---: | --- |
| Main UI | 267.32 KiB | 46.50 KiB | Initial extension bundle |
| xterm | 409.52 KiB | 106.13 KiB | Separate async chunk |

The xterm chunk is large in raw form but remains lazy-loaded, so the initial UI does not download it until the terminal is opened. The build still reports webpack size/runtime warnings; a broader split would touch component boundaries and did not have enough evidence of user impact to justify the added complexity.

## Findings and changes

- `STORAGE_VOLUMES_SCRIPT.info()` ran three `virsh` subprocesses per volume (`vol-path`, `vol-info`, `vol-dumpxml`). Libvirt's volume XML exposes the target path for file-backed volumes. The script now reads `target/path` from that XML and falls back to `vol-path` when unavailable, avoiding one subprocess for the ordinary file-backed case. Format is read from the XML `<format type="…">` attribute, which also ensures the disk expansion guard identifies qcow2/raw volumes correctly. See the [libvirt storage volume XML reference](https://www.libvirt.org/formatstorage.html).
- Returning to VM Details → Devices repeated the storage-volume SSH request. The tab now loads the volume list once per page session; the expansion action still explicitly refreshes the list before presenting the form, and the API rechecks pool capacity and VM state before resizing.
- The `build-pkg.sh` output changed the main bundle by +0.02 KiB raw / -0.01 KiB gzipped from .7.41; the xterm chunk stayed the same raw size and changed +0.01 KiB gzipped. No bundle regression is measurable at this scale.
- Host inventory runs several independent OS/libvirt queries. No batching change was made because it needs measurements on supported SLES/libvirt versions to preserve compatibility and per-source error reporting.

## Outcome

The review produced two small call-count reductions and corrected volume metadata parsing required for safe disk expansion. Python module and embedded-script syntax, localization YAML, version alignment, and `git diff --check` were inspected successfully; the package build completed with existing webpack size warnings. No cluster or registry deployment was performed.

Next scheduled performance review: after ten new versions beyond 0.7.41 (target 0.7.51).

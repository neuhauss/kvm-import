# Interface design guidance

- Keep every user-facing interface inside this Rancher extension; do not modify Rancher or SUSE Virtualization source code.
- Match Rancher's Cluster Manager UI patterns: page-level create/edit flows, clear section headings and callouts, consistent field sizing and spacing, Rancher theme colors, and a persistent action footer for long forms.
- Reuse Rancher-provided button and theme styles where practical. Inputs, tables, dialogs, focus states, and feedback must remain legible in both light and dark themes.
- Keep labels, help text, buttons, validation, and errors localized through the Rancher locale selected by the user.
- Prefer accessible native form semantics, visible keyboard focus, and responsive layouts.

## SUSE HA integration

- For cluster and High Availability functionality, use SUSE Linux Enterprise components and workflows that SUSE documents and supports, including SLE HA, `crmsh`, Pacemaker, Corosync/knet, Hawk, QDevice/QNetd, and supported fencing/SBD options.
- Do not add dependencies on community cluster managers, third-party orchestration add-ons, or unsupported substitutes for the SUSE HA stack.
- Keep all Rancher-facing UI, API, permissions, and cluster workflows inside this extension. Do not modify Rancher or SUSE Virtualization source/configuration directly.
- Base implementation details on official SUSE documentation for the target SLES/SLE HA release, and distinguish host connectivity from actual HA/quorum/fencing readiness.

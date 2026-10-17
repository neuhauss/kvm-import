# Interface design guidance

- Keep every user-facing interface inside this Rancher extension; do not modify Rancher or SUSE Virtualization source code.
- Match Rancher's Cluster Manager UI patterns: page-level create/edit flows, clear section headings and callouts, consistent field sizing and spacing, Rancher theme colors, and a persistent action footer for long forms.
- Reuse Rancher-provided button and theme styles where practical. Inputs, tables, dialogs, focus states, and feedback must remain legible in both light and dark themes.
- Keep labels, help text, buttons, validation, and errors localized through the Rancher locale selected by the user.
- Prefer accessible native form semantics, visible keyboard focus, and responsive layouts.

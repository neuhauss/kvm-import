# Interface principles

The KVM extension's interface should feel native to Rancher Cluster Manager. Treat the Rancher UI as the design reference for all extension screens, not only the host list.

- Use Rancher-like page layouts and create/edit flows instead of small centered dialogs for primary workflows.
- Use clear page titles, section headers, concise informational callouts, aligned fields, and action bars that remain available on long forms.
- Use Rancher theme variables and button styles so controls work in both light and dark themes.
- Keep the interaction and copy localized to the active Rancher language.
- Keep all implementation contained in this repository's extension; never patch Rancher or SUSE Virtualization itself.

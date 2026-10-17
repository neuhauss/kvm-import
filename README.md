# Rancher KVM Manager

Rancher KVM Manager imports and administers existing KVM/libvirt hosts from Rancher. It does not install KVM or change the imported host's software configuration.

The extension provides host inventory and health details, VM inventory and serial consoles, storage and network views, service and log views, Cockpit access, SSH credential management, and an audit log. Its interface follows Rancher UI patterns and supports English and Brazilian Portuguese.

## Requirements

- Rancher 2.15 or later with Rancher UI Extensions 3.x enabled.
- Existing Linux hosts with KVM/libvirt and SSH access.
- A Kubernetes cluster with a default StorageClass, or a StorageClass selected for the API data PVC.
- A public API image from GHCR or Docker Hub, plus access to the Rancher HTTPS endpoint from the API pod.
- A trusted Rancher CA certificate and an SSH account on each host. The SSH account needs the privileges required for the selected administrative actions.

## Install

In Rancher, add this Helm repository under **Apps > Repositories**:

```text
https://neuhauss.github.io/kvm-import
```

Then find **KVM Manager** in **Apps > Charts** and install it. The chart installs the Rancher extension, API, and UI assets; set the Rancher URL and review storage and ingress values in the Rancher install form. See [INSTALLATION.md](INSTALLATION.md) for details. The manifests under `deploy/` are optional examples for maintainers and manual deployments.

## Security notes

- The API authenticates each request through Rancher Global Role Bindings. Configure viewer, VM operator, and host administrator Global Role IDs in the Helm values; `admin` remains the default host administrator role.
- SSH passwords, private keys, and key passphrases are encrypted in SQLite using `KVM_CREDENTIAL_KEY`.
- Keep the encryption key and the API data volume together in secure backups. Losing the key makes saved credentials unrecoverable.
- Verify SSH host fingerprints before trusting them. The UI can pin a host key during import when the operator explicitly enables that option.
- Cockpit access is proxied through an SSH tunnel. Rancher session cookies are not forwarded to the KVM host.
- The audit log records administrative actions without passwords or private keys. Events are indexed and retained for 90 days by default; configure retention with `rancher.auditRetentionDays`.

## Build and release

Development requirements: Node.js 24+, Yarn, Python 3, and PyYAML.

```sh
yarn install --frozen-lockfile
yarn build-pkg kvm-manager
```

To prepare a local release bundle and manifests:

```sh
CHART_REPO_URL=https://OWNER.github.io/REPOSITORY scripts/package-release.sh
```

For the short local preview workflow, see [LOCAL-DEPLOYMENT.md](docs/LOCAL-DEPLOYMENT.md). It packages, applies, waits, and verifies the extension in one command without publishing artifacts.

Publishing a GitHub Release tagged `kvm-manager-<version>` builds the API image on GHCR and publishes the extension chart to GitHub Pages. Make the GHCR package public for community installs. Docker Hub publishing is an optional secondary target and requires the repository secrets `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`.

## Contributing

Issues and pull requests are welcome. Keep changes inside this extension and its deployment examples; do not patch Rancher or SUSE Virtualization source code. See [UI-DESIGN-PRINCIPLES.md](UI-DESIGN-PRINCIPLES.md) for the interface conventions used by the project.

## License

No license has been selected for this repository yet. Until a license is added, copyright remains with the authors and reuse rights are not granted by default.

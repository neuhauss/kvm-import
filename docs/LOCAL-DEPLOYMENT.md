# Fast local deployment to Rancher

Use this workflow to build and preview an extension change in a Rancher cluster. It changes only KVM Manager resources. It does not restart or patch Rancher or SUSE Virtualization.

## Requirements

- Node.js 24+, Yarn, Python 3 with PyYAML, and `kubectl`.
- A kubeconfig that can reach the target cluster and a known Kubernetes context name.
- Existing KVM Manager resources installed in `rancher-kvm-registry` and `cattle-ui-plugin-system`.

## Deploy

From the repository root, run:

```sh
KUBECONFIG="/path/to/kubeconfig.yaml" \
KUBE_CONTEXT="your-rancher-context" \
EXPECTED_API_SERVER="https://rancher-api.example.com:6443" \
scripts/deploy-local.sh
```

The script displays the selected context, API server, and version, then asks for the word `deploy`. If the local version is not newer than the installed version, it advances the patch version in `package.json` and `Chart.yaml`. It then builds the UI package and Helm chart, renders the asset and API ConfigMaps, applies the extension manifests, waits for the plugin cache and asset deployment, and verifies the installed version.

The script compares the API source ConfigMap before applying it. It restarts the KVM API pod only when that source changed; UI-only edits leave the API pod running. When the extension-owned local chart catalog is present, the script updates its index and verifies that Rancher downloaded the new chart digest.

`KUBE_CONTEXT` and `EXPECTED_API_SERVER` are required. Copy the exact API server URL from the selected kubeconfig context; the script stops if it differs. This prevents a similarly named context from deploying the extension to another cluster.

Set `CHART_REPO_URL` when building artifacts intended for a public chart repository. Local preview defaults to a placeholder URL and does not publish anything.

## What the script updates

- `kvm-api-source` and its deployment, only when API source changes.
- The versioned KVM UI asset ConfigMap and `kvm-extension-assets` deployment.
- The `kvm-manager` UIPlugin.
- The extension-owned local chart catalog, when its ConfigMap, deployment, and ClusterRepo are installed.

The script does not change Rancher source, Rancher core deployments, SUSE Virtualization, or any KVM host.

## Optional scoped Rancher roles

The extension API enforces permissions independently of the UI. Existing installations keep their current mappings: `admin` is the default host administrator, and configured viewer, VM operator, or host operator roles retain their existing access. For narrower write access, set one or more Rancher Global Role IDs in the chart's `rancher` values:

- `networkOperatorGlobalRoles`
- `storageOperatorGlobalRoles`
- `softwareOperatorGlobalRoles` (repositories)
- `subscriptionOperatorGlobalRoles`
- `accountOperatorGlobalRoles`
- `serviceOperatorGlobalRoles`
- `clusterOperatorGlobalRoles`

For example, `networkOperatorGlobalRoles: ["kvm-network-operator"]` allows that role to manage host and libvirt networking without granting storage, account, subscription, or cluster administration. Assign only the permissions users need. These values map existing Rancher Global Roles; the extension does not create or edit roles in Rancher.

## Long operations and snapshot retention

Multi-host HA tooling and template prerequisite fixes return an operation ID and run concurrently with bounded host-level parallelism. The extension records per-host queued/running/result states in its own API database. A process restart marks interrupted tasks as failed so the UI does not report stale work as successful.

Snapshot retention is a manual review helper: it identifies dated snapshots older than the selected keep count for stopped VMs, then requires the operator to select and confirm each deletion batch. It does not run automatic cleanup or delete snapshots in the background.

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
scripts/deploy-local.sh
```

The script displays the selected context, API server, and version, then asks for the word `deploy`. If the local version is not newer than the installed version, it advances the patch version in `package.json` and `Chart.yaml`. It then builds the UI package and Helm chart, renders the asset and API ConfigMaps, applies the extension manifests, waits for the plugin cache and asset deployment, and verifies the installed version.

The script compares the API source ConfigMap before applying it. It restarts the KVM API pod only when that source changed; UI-only edits leave the API pod running. When the extension-owned local chart catalog is present, the script updates its index and verifies that Rancher downloaded the new chart digest.

To guard against selecting the wrong cluster, always set `KUBE_CONTEXT`. You can also set `EXPECTED_API_SERVER` to a hostname or URL fragment; the script stops if the selected server does not contain it.

```sh
KUBECONFIG="/path/to/kubeconfig.yaml" \
KUBE_CONTEXT="your-rancher-context" \
EXPECTED_API_SERVER="rancher.example.com" \
scripts/deploy-local.sh
```

Set `CHART_REPO_URL` when building artifacts intended for a public chart repository. Local preview defaults to a placeholder URL and does not publish anything.

## What the script updates

- `kvm-api-source` and its deployment, only when API source changes.
- The versioned KVM UI asset ConfigMap and `kvm-extension-assets` deployment.
- The `kvm-manager` UIPlugin.
- The extension-owned local chart catalog, when its ConfigMap, deployment, and ClusterRepo are installed.

The script does not change Rancher source, Rancher core deployments, SUSE Virtualization, or any KVM host.

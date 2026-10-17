# Install from the Rancher Extension Catalog

Rancher KVM Manager is distributed as a Rancher Helm chart. An administrator adds the chart repository once; users can then find and install **KVM Manager** from the Rancher catalog. The chart installs the Rancher UI plugin, API, and static UI assets together.

## For Rancher administrators

1. Open the Rancher UI and go to **Apps > Repositories** (the exact menu label can vary by Rancher version).
2. Add a repository with type **Helm** and use this URL:

   ```text
   https://neuhauss.github.io/kvm-import
   ```

3. Refresh the catalog. Open **Apps > Charts**, find **KVM Manager**, and select **Install**.
4. In the chart values, set `rancher.publicOrigin` to the HTTPS URL users use to open Rancher. Review the storage, ingress, and access settings below, then install.
5. When the chart finishes, refresh the Rancher page. The **KVM** entry appears in the navigation.

The backend needs network access to the Rancher API and SSH access to each existing KVM/libvirt host. The chart creates a persistent volume for the host inventory and an encryption key Secret for saved SSH credentials. Back up the volume and Secret together.

## Chart settings

Set these values in the Rancher chart installation form when they differ from the defaults:

| Value | Purpose |
| --- | --- |
| `rancher.publicOrigin` | HTTPS Rancher address used by browsers and the API. Replace the example value. |
| `rancher.apiUrl` | Optional API address reachable from the backend pod. Defaults to `rancher.publicOrigin`. |
| `rancher.caBundle` | Optional PEM CA bundle if Rancher uses a private CA. Leave empty for publicly trusted certificates. |
| `rancher.allowedGlobalRoles` | Rancher Global Roles allowed to administer imported hosts. Defaults to `admin`. |
| `backend.namespace` | Namespace for the API and asset server. Defaults to `rancher-kvm-registry`. |
| `backend.storage.size` | Persistent volume size for the API database. Defaults to `1Gi`. |
| `backend.storage.storageClassName` | Optional StorageClass. Empty uses the cluster default. |
| `backend.image.repository` | API image location. The default points to the published project image. Forks should change this to their own published image. |
| `ingress.enabled` | Creates routes for `/kvm-api`, `/kvm-cockpit`, and the extension assets at `/kvm-manager` on the configured Rancher host. |
| `ingress.className` | Ingress class used by this cluster. Defaults to `traefik`; change it if needed. |

For a Rancher installation using a private CA, paste the CA certificate chain into `rancher.caBundle`. Do not paste a private key. Ensure the selected StorageClass supports a single-writer persistent volume.

## Add an existing KVM host

After installation, open **KVM**, select **Add host**, and enter the host address and SSH credentials for an existing Linux KVM/libvirt server. This extension imports and administers an existing host; it does not install KVM or modify host packages. Verify the SSH host fingerprint or explicitly enable first-use key acceptance in the form.

The SSH account needs the permissions required by the requested actions. Allow outbound SSH from the API pod to the host, and allow the browser to reach Rancher over HTTPS.

## Update or remove

The Rancher chart catalog provides chart updates. Review each version's release notes before upgrading. The API uses a persistent volume and a generated credential encryption key; keep the PVC and Secret together when backing up or restoring. Do not delete the PVC or the `kvm-api-secrets` Secret as part of a routine extension update.

Uninstalling the chart removes its UI plugin and workloads. Persistent application data is protected from Helm deletion, so remove the retained PVC and Secret separately only when you intend to permanently erase the host inventory and saved credentials.

## Repository maintainer release steps

These steps are for maintainers publishing a new version, not for users installing it:

1. Update the extension and chart versions, then prepare the package with `CHART_REPO_URL=. scripts/package-release.sh`.
2. Push the source changes and create a GitHub Release named `kvm-manager-<version>`.
3. GitHub Actions builds the API image and publishes the chart repository to the `gh-pages` branch. The GHCR package must be public for a public community install.
4. Check the release workflow and verify that `https://neuhauss.github.io/kvm-import` serves the refreshed chart index.

The Docker Hub image is an optional secondary publishing target and requires the `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` repository secrets. Users do not need Docker Hub credentials to install from the Rancher chart repository.

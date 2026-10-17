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
| `rancher.viewerGlobalRoles` | Rancher Global Role IDs allowed to view hosts and inventories. Empty by default. |
| `rancher.vmOperatorGlobalRoles` | Rancher Global Role IDs allowed to view and operate VMs, including VM consoles and host refresh. Empty by default. |
| `rancher.allowedGlobalRoles` | Rancher Global Role IDs allowed to administer hosts. Defaults to `admin`; existing installations can keep this setting. Host administrators inherit all lower permissions. |
| `rancher.auditRetentionDays` | Number of days to retain audit events. Defaults to `90`; events are pruned when the API starts. |
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

## Rancher role mapping

Create custom Rancher **Global Roles** and assign them to users with Rancher Global Role Bindings. Configure the corresponding role IDs in the chart values. The access tiers are cumulative:

- Viewer: view host and VM inventories.
- VM Operator: viewer access plus VM lifecycle actions, VM consoles, and host refresh.
- Host Admin: all previous access plus host import, edit, removal, Cockpit, terminal, and host configuration changes.

The API enforces these permissions for HTTP and WebSocket requests; hiding controls in the UI does not replace backend authorization. This release applies permissions globally to the KVM extension. Host-by-host or namespace/project scoping is not implemented.

Example chart values (replace the entries with the IDs of Global Roles created in your Rancher instance):

```yaml
rancher:
  viewerGlobalRoles: [kvm-viewer]
  vmOperatorGlobalRoles: [kvm-vm-operator]
  allowedGlobalRoles: [admin, kvm-host-admin]
  auditRetentionDays: 90
```

## Update or remove

The Helm repository is checked by Rancher periodically. After a maintainer publishes a new GitHub Release, refresh the repository in **Apps > Repositories** (or wait for its refresh interval). Rancher then lists the new KVM Manager chart version under **Apps > Installed Apps**, where an administrator can review the version and apply the upgrade. No Rancher core files or manual ConfigMap edits are part of this update flow. Review each version's release notes before upgrading. The API uses a persistent volume and a generated credential encryption key; keep the PVC and Secret together when backing up or restoring. Do not delete the PVC or the `kvm-api-secrets` Secret as part of a routine extension update.

Uninstalling the chart removes its UI plugin and workloads. Persistent application data is protected from Helm deletion, so remove the retained PVC and Secret separately only when you intend to permanently erase the host inventory and saved credentials.

## Repository maintainer release steps

These steps are for maintainers publishing a new version, not for users installing it:

1. Update the extension and chart versions together, build and review the release package locally, then push the source changes.
2. Create and publish a GitHub Release tagged `kvm-manager-<version>`.
3. GitHub Actions builds the API image and publishes the chart package and merged version index to the `gh-pages` branch. Previous chart versions remain available for upgrades and rollback; local preview files are excluded. The GHCR package must be public for a public community install.
4. Check both release workflows. Then confirm that `https://OWNER.github.io/REPOSITORY/index.yaml` lists the new version. Rancher sees it on the next repository refresh.

The Docker Hub image is an optional secondary publishing target and requires the `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` repository secrets. Users do not need Docker Hub credentials to install from the Rancher chart repository.

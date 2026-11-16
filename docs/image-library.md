# Host image library

The Cloud Native interface includes an **Images** area for each imported KVM host. It stores ISO installers and standalone QCOW2 templates inside a running, directory-based libvirt storage pool on that host.

## Add an image

1. Open a host, then select **Images**.
2. Choose **Upload image**, provide a display name and category, select a running directory pool, and choose an `.iso` or `.qcow2` file.
3. Optionally add operating-system, version, and description metadata, then upload.

Uploads are streamed to the host over the host's pinned SSH connection, limited to 8 GiB, and checked with SHA-256. ISO files must contain an ISO 9660 volume descriptor. QCOW2 files must be standalone and must not use a backing file. Upload and delete actions require the `storage_admin` Rancher role; users with host visibility can browse the catalog.

## Use an image for a VM

In **Create VM**, select **Use image library** in the boot-source step and choose an item:

- ISO files are attached as read-only installation media. The wizard creates a new boot disk with the requested size.
- QCOW2 templates are copied into a new independent disk in the selected VM storage pool. The original catalog image is left unchanged. The new disk uses the template's virtual size and can be expanded later from VM device administration.

The VM creation job reports progress while the image is validated and the disk is created. The selected virtual network and storage pool must be active, and the target pool must have enough free capacity. Image deletion is blocked while the image is attached to a VM.

The first release supports ISO and QCOW2 files up to 8 GiB and directory-backed pools. It does not currently provide deduplication, cross-host replication, remote object storage, or resumable uploads.

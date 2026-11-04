# VM backup support

The extension now provides a first functional backup path to Amazon S3 and S3-compatible object storage.

## Available now

- Save S3 destinations with static access keys (encrypted by the extension API's Fernet key) or the API container's AWS workload identity/credential chain.
- Test bucket access before using a destination.
- Create a manual archive for a VM that is powered off.
- Stream the archive from the host over its pinned SSH connection and upload it with S3 multipart upload, limiting API memory use to the configured multipart chunk plus transfer buffers.
- Apply SSE-S3 or SSE-KMS on multipart upload where configured.
- Catalog archive size, creation time, host/VM identity, and SHA-256 digest; download or delete the archive.

The archive contains the inactive libvirt domain XML and local regular-file disks in qcow2 or raw format without a backing chain. The current implementation rejects powered-on VMs, non-file/block/network sources, backing chains, and unsupported disk formats. Snapshots are not exported. Keep the VM powered off until the job reports success.

## Not available yet

There are no schedules, retention policies, NFS destinations, guest quiescing, automatic integrity re-read, or in-extension restore workflow. Downloading an archive is not the same as restoring a VM. Do not claim recovery readiness until a restore procedure is implemented and verified.

## Operational requirements

- Keep the API credential-encryption key stable and backed up; replacing it makes stored destination keys undecryptable.
- Grant the API identity only the bucket actions it needs: `s3:ListBucket` for connection checks, multipart create/upload/complete/abort, object read, and object deletion. Add KMS permissions when using SSE-KMS.
- For S3-compatible endpoints, use HTTPS with a certificate trusted by the API runtime. Path-style addressing is available for providers that require it.
- A host backup requires sudo access over the registered, pinned SSH connection, libvirt tools, `qemu-img`, and read access to VM disk files.

## Next implementation steps

1. Add resumable/interruption-aware transfer state and a periodic integrity verification that re-reads the object.
2. Add a restore review flow that validates free space, host compatibility, network mapping, VM name conflicts, and overwrite behavior before creating anything.
3. Add server-side schedules and retention only after durable operation state and scheduler ownership are defined.
4. Add NFS as a separately secured destination adapter after defining durable mount credentials and recovery behavior.

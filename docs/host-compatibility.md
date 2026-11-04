# KVM host compatibility

## Extension import baseline

The import preflight recognizes these SUSE Linux Enterprise Server release
streams when SSH and `virsh` are available:

- SLES 15 SP3 through SP7 (`VERSION_ID` 15.3 through 15.7)
- SLES 16.0

This is an extension compatibility baseline, not a statement about current
product lifecycle or entitlement. SUSE support follows the lifecycle for each
product and service pack.

The preflight displays the discovered `virsh`/libvirt version. The extension
does not pin a libvirt upstream version: SUSE documents support in terms of the
SLES release stream and requires supported QEMU/libvirt packages to come from
the official SUSE repositories. PackageHub optional QEMU/libvirt subpackages
and plug-ins are not considered a supported baseline. Other distributions or
unrecognized SLES releases are allowed to continue after a warning, because
the extension only connects to an existing host and cannot determine the
vendor's support entitlement.

SUSE references:

- [SLES 16.0 Virtualization Support](https://documentation.suse.com/sles/16.0/html/SLES-virtualization-support/index.html) lists SLES 15 SP3–SP7 and SLES 16.0 as supported KVM host environments, and requires supported QEMU/libvirt packages from official SUSE repositories.
- [SLES 15 SP7 Virtualization Guide](https://documentation.suse.com/en-us/sles/15-SP7/single-html/SLES-virtualization/index.html) describes the KVM host requirements and supported package sources.

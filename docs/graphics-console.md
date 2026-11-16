# VM graphical console

VM Details provides a browser-based VNC console for running VMs that have a
libvirt VNC graphics device. The extension uses noVNC in the browser and opens
an SSH `direct-tcpip` channel to the VNC display on the imported KVM host.

The console requires:

- The VM is running and has a `graphics type='vnc'` device.
- The VNC display listens on a loopback address on the KVM host.
- The imported SSH account can run the required libvirt query with sudo and
  the SSH server permits local TCP forwarding to loopback.

VMs created by the extension receive a loopback-only VNC device by default.
For an existing VM without another graphics protocol, use **Enable VNC
graphics** in VM Details while the VM is powered off, then start it. The
extension does not change a VM that already uses SPICE or another protocol.

The API rejects non-loopback VNC targets and does not expose or publish the
host's VNC port. A VNC password, when configured on the VM, is requested in the
console and held only for that browser session. The extension does not record
the screen, keyboard or mouse input, or VNC password. Opening and closing the
session is recorded in the extension audit log.

The current browser console supports VNC. SPICE-only VMs need a separate
SPICE-compatible browser client and are not exposed through this endpoint.

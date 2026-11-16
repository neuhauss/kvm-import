export type QDeviceStatusInput = {
  available?: boolean;
  configured?: boolean;
  connected?: boolean | null;
};

export type QDevicePresentation = {
  label: 'qdeviceConnected' | 'qdeviceDisconnected' | 'qdeviceNotConfigured' | 'qdeviceStatusUnknown';
  className: 'ready' | 'unreachable' | 'warning-state' | '';
};

/** Distinguish absent configuration from a failed or unknown live status. */
export function qdevicePresentation(status?: QDeviceStatusInput | null): QDevicePresentation {
  if (!status) return { label: 'qdeviceStatusUnknown', className: 'warning-state' };
  if (!status.configured) {
    return status.available
      ? { label: 'qdeviceNotConfigured', className: '' }
      : { label: 'qdeviceStatusUnknown', className: 'warning-state' };
  }
  if (!status.available || status.connected == null) return { label: 'qdeviceStatusUnknown', className: 'warning-state' };
  return status.connected
    ? { label: 'qdeviceConnected', className: 'ready' }
    : { label: 'qdeviceDisconnected', className: 'unreachable' };
}

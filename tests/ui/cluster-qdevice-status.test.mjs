import assert from 'node:assert/strict';
import test from 'node:test';
import { qdevicePresentation } from '../../pkg/kvm-manager/utils/cluster-qdevice.ts';

test('reports an unconfigured witness neutrally when the quorum tool is available', () => {
  assert.deepEqual(qdevicePresentation({ available: true, configured: false }), {
    label: 'qdeviceNotConfigured', className: '',
  });
});

test('does not call a configured witness connected when live status is unavailable', () => {
  assert.deepEqual(qdevicePresentation({ available: false, configured: true, connected: null }), {
    label: 'qdeviceStatusUnknown', className: 'warning-state',
  });
});

test('shows connected and disconnected QNetd states distinctly', () => {
  assert.deepEqual(qdevicePresentation({ available: true, configured: true, connected: true }), {
    label: 'qdeviceConnected', className: 'ready',
  });
  assert.deepEqual(qdevicePresentation({ available: true, configured: true, connected: false }), {
    label: 'qdeviceDisconnected', className: 'unreachable',
  });
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { hasPromotableMonitorRoles, validateClusterMonitorOperations } from '../../pkg/kvm-manager/utils/cluster-monitor-operations.ts';

test('accepts ordinary and role-specific SUSE monitor operations', () => {
  const result = validateClusterMonitorOperations([
    { interval: '30s', role: 'Unpromoted' },
    { interval: '1min', role: 'Promoted', timeout: '20s' },
  ]);
  assert.equal(result.ok, true);
  if (result.ok) assert.deepEqual(result.operations.map((item) => item.role), ['Unpromoted', 'Promoted']);
  assert.equal(validateClusterMonitorOperations([{ interval: '0', role: 'Stopped' }]).ok, true);
});

test('rejects missing, duplicate, malformed, or excessive monitor operations', () => {
  assert.deepEqual(validateClusterMonitorOperations([]), { ok: false, reason: 'count' });
  assert.equal(validateClusterMonitorOperations([{ interval: '30s', role: '' }, { interval: '30', role: 'Promoted' }]).ok, false);
  assert.deepEqual(validateClusterMonitorOperations([{ interval: '-1s', role: '' }]), { ok: false, reason: 'interval' });
  assert.deepEqual(validateClusterMonitorOperations([{ interval: '30s', role: '', timeout: 'bad' }]), { ok: false, reason: 'timeout' });
  assert.equal(validateClusterMonitorOperations(Array.from({ length: 17 }, (_, i) => ({ interval: `${i + 1}s`, role: '' }))).ok, false);
});

test('operation IDs are retained only when valid and unique', () => {
  assert.equal(validateClusterMonitorOperations([
    { operation_id: 'mon-a', interval: '30s', role: '' },
    { operation_id: 'mon-b', interval: '60s', role: 'Promoted' },
  ]).ok, true);
  assert.deepEqual(validateClusterMonitorOperations([
    { operation_id: 'mon-a', interval: '30s', role: '' },
    { operation_id: 'mon-a', interval: '60s', role: 'Promoted' },
  ]), { ok: false, reason: 'id' });
});

test('recognizes current and legacy SUSE HA role-qualified monitor pairs', () => {
  assert.equal(hasPromotableMonitorRoles([
    { interval: '30s', role: 'Unpromoted' },
    { interval: '60s', role: 'Promoted' },
  ]), true);
  assert.equal(hasPromotableMonitorRoles([
    { interval: '30s', role: 'Slave' },
    { interval: '1min', role: 'Master' },
  ]), true);
  assert.equal(hasPromotableMonitorRoles([{ interval: '30s', role: 'Promoted' }]), false);
  assert.equal(hasPromotableMonitorRoles([
    { interval: '30s', role: '' },
    { interval: '60s', role: 'Promoted' },
  ]), false);
  assert.equal(hasPromotableMonitorRoles([
    { interval: '30s', role: 'Unpromoted' },
    { interval: '30s', role: 'Promoted' },
  ]), false);
  assert.equal(validateClusterMonitorOperations([
    { interval: '30s', role: 'Started' },
    { interval: '30s', role: 'Stopped' },
  ]).ok, true);
});

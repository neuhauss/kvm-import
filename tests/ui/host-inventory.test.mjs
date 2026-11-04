import assert from 'node:assert/strict';
import test from 'node:test';
import { filterHostInventory, hostIdentity, isHostInventoryStale, summarizeHostInventory } from '../../pkg/kvm-manager/utils/host-inventory.ts';

test('host health summary counts readiness and stale inventory independently', () => {
  const now = Date.parse('2026-10-30T12:00:00Z');
  const summary = summarizeHostInventory([
    { name: 'kvm-one', status: 'ready', last_checked_at: '2026-10-30T11:59:00Z' },
    { name: 'kvm-two', status: 'unreachable', last_checked_at: '2026-10-30T11:50:00Z' },
    { name: 'kvm-three', status: 'unknown' },
  ], now);

  assert.deepEqual(summary, { total: 3, ready: 1, unreachable: 1, unknown: 1, stale: 2 });
});

test('missing or invalid check timestamps are stale; recent checks are current', () => {
  const now = Date.parse('2026-10-30T12:00:00Z');
  assert.equal(isHostInventoryStale({}, now), true);
  assert.equal(isHostInventoryStale({ last_checked_at: 'not-a-date' }, now), true);
  assert.equal(isHostInventoryStale({ last_checked_at: '2026-10-30T11:58:00Z' }, now), false);
});

test('host identity distinguishes the Rancher display name from the detected hostname', () => {
  assert.deepEqual(hostIdentity({ name: 'test-kvm-host', hostname: 'test-kvm-node-01' }), {
    displayName: 'test-kvm-host', detectedHostname: 'test-kvm-node-01',
  });
  assert.deepEqual(hostIdentity({ name: 'kvm-sles-01', hostname: 'kvm-sles-01' }), {
    displayName: 'kvm-sles-01', detectedHostname: '',
  });
  assert.deepEqual(hostIdentity({ name: '', hostname: 'kvm-sles-02' }), {
    displayName: 'kvm-sles-02', detectedHostname: '',
  });
});

test('inventory filters combine text search with state and stale status', () => {
  const now = Date.parse('2026-10-30T12:00:00Z');
  const hosts = [
    { id: 'one', name: 'production-kvm', hostname: 'node-01', address: '192.0.2.10', status: 'ready', last_checked_at: '2026-10-30T11:59:00Z' },
    { id: 'two', name: 'lab-kvm', hostname: 'node-02', address: '192.0.2.11', status: 'unreachable', last_checked_at: '2026-10-30T11:50:00Z' },
  ];

  assert.deepEqual(filterHostInventory(hosts, 'NODE-02', 'all', now).map((host) => host.id), ['two']);
  assert.deepEqual(filterHostInventory(hosts, '192.0.2', 'ready', now).map((host) => host.id), ['one']);
  assert.deepEqual(filterHostInventory(hosts, '', 'stale', now).map((host) => host.id), ['two']);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { canManageClusterOperations } from '../../pkg/kvm-manager/utils/cluster-permissions.ts';

test('cluster admin can manage clusters', () => {
  assert.equal(canManageClusterOperations({ canManageClusters: true }), true);
});

test('host admin can manage clusters through the API host-admin tier', () => {
  assert.equal(canManageClusterOperations({ canAdministerHost: true }), true);
});

test('host-resource permission alone does not expose cluster mutations', () => {
  assert.equal(canManageClusterOperations({ canManageHostResources: true }), false);
});

test('missing, false, or malformed permissions fail closed', () => {
  assert.equal(canManageClusterOperations({}), false);
  assert.equal(canManageClusterOperations({ canManageClusters: false, canAdministerHost: false }), false);
  assert.equal(canManageClusterOperations({ canManageClusters: 'true' }), false);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { moveClusterGroupMember, toggleClusterGroupMember, validClusterGroupSelection } from '../../pkg/kvm-manager/utils/cluster-groups.ts';

test('accepts a single-member SUSE resource group and valid ordered members', () => {
  assert.equal(validClusterGroupSelection('service-group', ['service']), true);
  assert.equal(validClusterGroupSelection('service-group', ['fs', 'vip', 'app']), true);
  assert.equal(validClusterGroupSelection('service-group', Array.from({ length: 33 }, (_, i) => `r${i}`)), true);
});

test('rejects invalid group IDs, empty and oversized membership, invalid IDs and duplicates', () => {
  assert.equal(validClusterGroupSelection('bad id', ['app']), false);
  assert.equal(validClusterGroupSelection('group', []), false);
  assert.equal(validClusterGroupSelection('group', ['app', 'app']), false);
  assert.equal(validClusterGroupSelection('group', ['bad id']), false);
  assert.equal(validClusterGroupSelection('group', Array.from({ length: 129 }, (_, i) => `r${i}`)), false);
});

test('selection toggles without duplication and preserves start-order semantics', () => {
  assert.deepEqual(toggleClusterGroupMember(['fs', 'app'], 'vip', true), ['fs', 'app', 'vip']);
  assert.deepEqual(toggleClusterGroupMember(['fs', 'app'], 'fs', true), ['app', 'fs']);
  assert.deepEqual(toggleClusterGroupMember(['fs', 'app'], 'fs', false), ['app']);
});

test('moves members within bounds and leaves invalid moves unchanged', () => {
  assert.deepEqual(moveClusterGroupMember(['fs', 'vip', 'app'], 2, -1), ['fs', 'app', 'vip']);
  assert.deepEqual(moveClusterGroupMember(['fs', 'vip', 'app'], 0, -1), ['fs', 'vip', 'app']);
  assert.deepEqual(moveClusterGroupMember(['fs', 'vip', 'app'], 3, -1), ['fs', 'vip', 'app']);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { cloneMetadataKeys, validClusterCloneDeletion, validClusterCloneSelection, validateCloneMetadataDraft } from '../../pkg/kvm-manager/utils/cluster-clones.ts';

const stoppedPrimitive = { id: 'replica', agent: 'ocf:heartbeat:Stateful', active: false, managed: true };

test('allows a valid stopped standalone primitive in a clone', () => {
  assert.equal(validClusterCloneSelection('replica-clone', 'replica', [stoppedPrimitive]), true);
  assert.equal(validClusterCloneSelection('web-clone', 'web-group', [{ id: 'web-group', agent: 'group', active: false, managed: true }]), true);
});

test('rejects malformed or duplicate IDs and unknown children', () => {
  assert.equal(validClusterCloneSelection('bad id', 'replica', [stoppedPrimitive]), false);
  assert.equal(validClusterCloneSelection('replica', 'replica', [stoppedPrimitive]), false);
  assert.equal(validClusterCloneSelection('replica-clone', 'missing', [stoppedPrimitive]), false);
});

test('rejects active, unmanaged, nested, grouped, wrapper, and fencing candidates', () => {
  const invalid = [
    { ...stoppedPrimitive, active: true },
    { ...stoppedPrimitive, managed: false },
    { ...stoppedPrimitive, parent_id: 'parent' },
    { ...stoppedPrimitive, group_id: 'group' },
    { ...stoppedPrimitive, agent: 'clone' },
    { ...stoppedPrimitive, agent: 'stonith:external/sbd' },
  ];
  for (const resource of invalid) assert.equal(validClusterCloneSelection('replica-clone', 'replica', [resource]), false);
});

test('allows deleting only a stopped top-level single-primitive clone', () => {
  const clone = { id: 'replica-clone', agent: 'clone', active: false, managed: true, children: ['replica'] };
  const child = { id: 'replica', agent: 'ocf:heartbeat:Stateful', active: false, managed: true, parent_id: 'replica-clone' };
  assert.equal(validClusterCloneDeletion(clone, [clone, child]), true);
  for (const invalidClone of [
    { ...clone, active: true }, { ...clone, failed: true }, { ...clone, managed: false },
    { ...clone, parent_id: 'outer' }, { ...clone, children: ['replica', 'other'] },
  ]) assert.equal(validClusterCloneDeletion(invalidClone, [invalidClone, child]), false);
  for (const invalidChild of [
    { ...child, active: true }, { ...child, failed: true }, { ...child, managed: false },
    { ...child, agent: 'group' }, { ...child, agent: 'stonith:fence_sbd' }, { ...child, parent_id: 'other-clone' },
  ]) assert.equal(validClusterCloneDeletion(clone, [clone, invalidChild]), false);
});

test('cluster page exposes standard and promotable clone choices with review before apply', () => {
  const source = readFileSync(new URL('../../pkg/kvm-manager/pages/Clusters.vue', import.meta.url), 'utf8');
  assert.match(source, /action: 'create_clone'/);
  assert.match(source, /clone_type: editor\.clone_type/);
  assert.match(source, /action: 'edit_clone'/);
  assert.match(source, /action: 'delete_clone'/);
  assert.match(source, /validClusterCloneDeletion/);
  assert.match(source, /reviewDeleteClone/);
  assert.match(source, /clone_metadata_editable/);
  assert.match(source, /@input="setCloneMetadataInput\(field\.key, \$event\)"/);
  assert.match(source, /this\.cloneEditor\.metadata\[key\] = input\.value/);
  assert.match(source, /pendingResourceMutation/);
  assert.match(source, /v-if="pendingResourceMutation"/);
  assert.match(source, /clonePromotableHelp/);
});

test('clone options validation accepts only documented safe values and clone-type fields', () => {
  assert.deepEqual(cloneMetadataKeys('standard'), ['clone-max','clone-node-max','globally-unique','notify','interleave']);
  const valid = validateCloneMetadataDraft('promotable', {
    'clone-max': '3', 'clone-node-max': '', 'globally-unique': 'true', notify: 'false', interleave: '',
    'promoted-max': '1', 'promoted-node-max': '1',
  });
  assert.equal(valid.ok, true);
  assert.equal(validateCloneMetadataDraft('standard', { ...valid.metadata, promotable: 'true' }).ok, false);
  assert.equal(validateCloneMetadataDraft('standard', { 'clone-max': '4097' }).ok, false);
  assert.equal(validateCloneMetadataDraft('standard', { notify: 'yes' }).ok, false);
  assert.equal(validateCloneMetadataDraft('standard', null).ok, false);
});

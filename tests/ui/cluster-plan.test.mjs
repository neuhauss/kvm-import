import test from 'node:test';
import assert from 'node:assert/strict';
import { clusterPlanPayload, clusterPreflightPayload, isCorosyncNetworkPlanReady, isPreflightHostListValidationError, normalizePreflightHostIds, preflightHostListReceivedType, restoreClusterPlanDraft } from '../../pkg/kvm-manager/utils/cluster-plan.ts';

test('preflight selection always resolves to a clean host ID list, even when Vue passes a click event', () => {
  assert.deepEqual(normalizePreflightHostIds({ type: 'click' }, [' host-a ', 'host-b', 'host-a', '', null]), ['host-a', 'host-b']);
  assert.deepEqual(normalizePreflightHostIds(['host-c', 3, ' host-d '], ['host-a']), ['host-c', 'host-d']);
  assert.deepEqual(normalizePreflightHostIds([{ id: ' host-e ' }, { host_id: 'host-f' }, { type: 'click' }], []), ['host-e', 'host-f']);
  assert.deepEqual(normalizePreflightHostIds({ type: 'click' }, { host_id: 'host-a' }), []);
});

test('preflight payload serializes a normalized host ID array and a string QNetd value', () => {
  const payload = clusterPreflightPayload({ type: 'click' }, [' host-a ', 'host-b', 'host-a'], ' witness.example.invalid ');
  assert.deepEqual(payload, { host_ids: ['host-a', 'host-b'], qnetd_host: 'witness.example.invalid' });
  assert.ok(Array.isArray(payload.host_ids));
});

test('preflight identifies host_ids list validation separately from host connectivity errors', () => {
  assert.equal(isPreflightHostListValidationError('host_ids: Input should be a valid list'), true);
  assert.equal(isPreflightHostListValidationError('host_ids: list_type'), true);
  assert.equal(isPreflightHostListValidationError('host_ids: Expected a list of host IDs; received object.'), true);
  assert.equal(preflightHostListReceivedType('host_ids: Expected a list of host IDs; received object.'), 'object');
  assert.equal(preflightHostListReceivedType('host_ids: Input should be a valid list'), '');
  assert.equal(preflightHostListReceivedType('host_ids: Input should be a valid list', 'dict'), 'object');
  assert.equal(preflightHostListReceivedType('host_ids: Input should be a valid list', 'object'), 'object');
  assert.equal(preflightHostListReceivedType('host_ids: received string', 'object'), 'object');
  assert.equal(isPreflightHostListValidationError('The selected host could not be reached over SSH'), false);
});

test('cluster draft payload is an explicit allow-list without secrets or preflight evidence', () => {
  const payload = clusterPlanPayload({
    clusterType: 'suse-ha',
    name: 'ha-lab', hostIds: ['host-a', 'host-b'], templateId: 'nfs', step: 3,
    quorum: 'qdevice', qnetdHost: 'witness.example.invalid', qnetdOutsideCluster: true,
    fencing: 'sbd', corosyncNetworks: ['10.20.0.0/24'], corosyncNetworkReviewed: true,
  });

  assert.deepEqual(Object.keys(payload).sort(), [
    'cluster_type', 'corosync_network_reviewed', 'corosync_networks', 'fencing',
    'host_ids', 'name', 'qnetd_host', 'qnetd_outside_cluster', 'quorum', 'step', 'template_id',
  ]);
  assert.equal(payload.cluster_type, 'suse-ha');
  assert.deepEqual(payload.host_ids, ['host-a', 'host-b']);
  assert.deepEqual(payload.corosync_networks, ['10.20.0.0/24']);
  assert.equal(payload.corosync_network_reviewed, true);
  assert.equal('password' in payload, false);
  assert.equal('preflight_results' in payload, false);
  assert.equal('ssh_private_key' in payload, false);
});

test('cluster plan payload preserves the selected cluster type instead of converting KVM groups into SUSE HA plans', () => {
  const payload = clusterPlanPayload({
    clusterType: 'kvm-virtualization', name: 'virt-lab', hostIds: ['host-a', 'host-b'],
    templateId: '', step: 0, quorum: 'pending', qnetdHost: '', qnetdOutsideCluster: false,
    fencing: 'pending', corosyncNetworks: [], corosyncNetworkReviewed: false,
  });

  assert.equal(payload.cluster_type, 'kvm-virtualization');
});

test('resuming a plan keeps only available hosts and forces preflight from an early wizard step', () => {
  const plan = {
    id: 'plan-id', name: 'ha-lab', cluster_type: 'suse-ha',
    host_ids: ['host-a', 'removed-host'], template_id: 'nfs', step: 4,
    config: { quorum: 'qdevice', qnetd_host: 'witness.example.invalid', qnetd_outside_cluster: true, fencing: 'sbd', corosync_networks: ['10.20.0.0/24'], corosync_network_reviewed: true },
    state: 'draft', preflight_required: true, updated_at: '2026-11-14T12:00:00Z',
  };

  assert.deepEqual(restoreClusterPlanDraft(plan, new Set(['host-a', 'host-b'])), {
    id: 'plan-id', clusterType: 'suse-ha', name: 'ha-lab', templateId: 'nfs', hostIds: ['host-a'],
    step: 1, quorum: 'qdevice', qnetdHost: 'witness.example.invalid',
    qnetdOutsideCluster: true, fencing: 'sbd', corosyncNetworks: ['10.20.0.0/24'],
    corosyncNetworkReviewed: false, preflightRequired: true,
  });
});

test('resuming a KVM virtualization draft preserves its type for type-specific routing', () => {
  const plan = {
    id: 'virt-plan', name: 'virt-lab', cluster_type: 'kvm-virtualization',
    host_ids: ['host-a', 'host-b'], template_id: null, step: 2,
    config: { quorum: 'pending', qnetd_host: '', qnetd_outside_cluster: false, fencing: 'pending' },
    state: 'draft', preflight_required: true, updated_at: '2026-11-14T12:00:00Z',
  };

  assert.equal(restoreClusterPlanDraft(plan, new Set(['host-a', 'host-b'])).clusterType, 'kvm-virtualization');
});

test('Corosync plan requires explicit review, distinct live subnets, and permits operator-guided manual addressing', () => {
  const candidates = ['10.20.0.0/24', '192.0.2.0/24'];
  assert.equal(isCorosyncNetworkPlanReady('10.20.0.0/24', '192.0.2.0/24', true, candidates), true);
  assert.equal(isCorosyncNetworkPlanReady('10.20.0.0/24', '', true, candidates), true);
  assert.equal(isCorosyncNetworkPlanReady('', '', true, []), true);
  assert.equal(isCorosyncNetworkPlanReady('10.20.0.0/24', '', false, candidates), false);
  assert.equal(isCorosyncNetworkPlanReady('', '192.0.2.0/24', true, candidates), false);
  assert.equal(isCorosyncNetworkPlanReady('10.20.0.0/24', '10.20.0.0/24', true, candidates), false);
  assert.equal(isCorosyncNetworkPlanReady('10.30.0.0/24', '', true, candidates), false);
});

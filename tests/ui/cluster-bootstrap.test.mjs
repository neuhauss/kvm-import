import assert from 'node:assert/strict';
import test from 'node:test';
import { bootstrapErrorTranslationKey, bootstrapJoinProgress, clusterHaProductReadiness, clusterJoinCommand, needsBootstrapCredentialHardening, qdeviceBootstrapReady } from '../../pkg/kvm-manager/utils/cluster-bootstrap.ts';

test('SUSE crm cluster join includes the first node SSH username and registered address', () => {
  assert.equal(
    clusterJoinCommand({ username: 'sles', address: '192.0.2.10' }),
    "sudo crm cluster join -c 'sles@192.0.2.10'",
  );
});

test('cluster join command safely quotes special characters in a node target', () => {
  assert.equal(
    clusterJoinCommand({ username: "ops'admin", address: 'kvm-node.example.invalid' }),
    "sudo crm cluster join -c 'ops'\\''admin@kvm-node.example.invalid'",
  );
});

test('cluster join command rejects hosts without the required SUSE bootstrap identity', () => {
  assert.throws(() => clusterJoinCommand({ username: '', address: '192.0.2.10' }));
  assert.throws(() => clusterJoinCommand({ username: 'sles', address: ' ' }));
});

test('credential hardening reminder is shown only after successful first-node initialization', () => {
  assert.equal(needsBootstrapCredentialHardening('init', 0), true);
  assert.equal(needsBootstrapCredentialHardening('join', 0), false);
  assert.equal(needsBootstrapCredentialHardening('init', 1), false);
  assert.equal(needsBootstrapCredentialHardening('init', null), false);
});

test('bootstrap error codes resolve only to known localized messages', () => {
  assert.equal(bootstrapErrorTranslationKey('ssh_authentication'), 'clusters.bootstrapErrorSshAuthentication');
  assert.equal(bootstrapErrorTranslationKey('operation_conflict'), 'clusters.bootstrapOperationConflict');
  assert.equal(bootstrapErrorTranslationKey('ha_product_mismatch'), 'clusters.bootstrapErrorHaProductMismatch');
  assert.equal(bootstrapErrorTranslationKey('ha_product_unconfirmed'), 'clusters.bootstrapErrorHaProductUnconfirmed');
  assert.equal(bootstrapErrorTranslationKey('unknown-server-value'), 'clusters.bootstrapErrorGeneric');
  assert.equal(bootstrapErrorTranslationKey(undefined), 'clusters.bootstrapErrorGeneric');
});


test('cluster initialization requires one confirmed active SLE HA product release on every selected node', () => {
  const results = [
    { status: 'checked', checks: { ha_active: true, ha_product: 'sle-ha/15.6/x86_64' } },
    { status: 'checked', checks: { ha_active: true, ha_product: 'sle-ha/15.6/x86_64' } },
  ];
  assert.equal(clusterHaProductReadiness(results, 2), 'ready');
  assert.equal(clusterHaProductReadiness([{ ...results[0] }, { status: 'checked', checks: { ha_active: true, ha_product: 'sle-ha/15.7/x86_64' } }], 2), 'mismatch');
  assert.equal(clusterHaProductReadiness([{ ...results[0] }, { status: 'checked', checks: { ha_active: true } }], 2), 'unknown');
  assert.equal(clusterHaProductReadiness([{ ...results[0] }, { status: 'checked', checks: { ha_active: false, ha_product: 'sle-ha/15.6/x86_64' } }], 2), 'unknown');
  assert.equal(clusterHaProductReadiness(results.slice(0, 1), 2), 'incomplete');
  assert.equal(clusterHaProductReadiness([{ ...results[0] }, { status: 'error' }], 2), 'incomplete');
});

test('cluster bootstrap advances joins one at a time only after live membership confirms each node', () => {
  const ids = ['node-a', 'node-b', 'node-c'];
  const result = (host_id, host_name, members, overrides = {}) => ({
    host_id, host_name, status: 'checked',
    checks: { cluster_configured: true, cluster_detected: true, cluster_name: 'ha-lab', cluster_members: members, ...overrides },
  });
  const initialized = [
    result('node-a', 'node-a', ['node-a']),
    result('node-b', 'node-b', []),
    result('node-c', 'node-c', []),
  ];
  assert.deepEqual(bootstrapJoinProgress(ids, initialized, 'ha-lab'), {
    initialized: true, joinedHostIds: ['node-a'], nextHostId: 'node-b', completed: false,
  });

  const nodeBJoined = [
    initialized[0],
    result('node-b', 'node-b', ['node-a', 'node-b']),
    initialized[2],
  ];
  assert.deepEqual(bootstrapJoinProgress(ids, nodeBJoined, 'ha-lab'), {
    initialized: true, joinedHostIds: ['node-a', 'node-b'], nextHostId: 'node-c', completed: false,
  });

  const allJoined = [
    result('node-a', 'node-a', ['node-a', 'node-b', 'node-c']),
    result('node-b', 'node-b', ['node-a', 'node-b', 'node-c']),
    result('node-c', 'node-c', ['node-a', 'node-b', 'node-c']),
  ];
  assert.deepEqual(bootstrapJoinProgress(ids, allJoined, 'ha-lab'), {
    initialized: true, joinedHostIds: ids, nextHostId: null, completed: true,
  });
});

test('bootstrap progress does not infer membership from configured files or a different cluster', () => {
  const ids = ['node-a', 'node-b'];
  const initializedAnchor = { host_id: 'node-a', host_name: 'node-a', status: 'checked', checks: { cluster_configured: true, cluster_detected: true, cluster_name: 'ha-lab', cluster_members: ['node-a'] } };
  const unconfirmed = { host_id: 'node-b', host_name: 'node-b', status: 'checked', checks: { cluster_configured: true, cluster_detected: false, cluster_name: 'ha-lab', cluster_members: [] } };
  assert.deepEqual(bootstrapJoinProgress(ids, [initializedAnchor, unconfirmed], 'ha-lab'), {
    initialized: true, joinedHostIds: ['node-a'], nextHostId: 'node-b', completed: false,
  });
  assert.equal(bootstrapJoinProgress(ids, [initializedAnchor, { ...unconfirmed, checks: { ...unconfirmed.checks, cluster_detected: true, cluster_name: 'other' } }], 'ha-lab').joinedHostIds.length, 1);
  assert.equal(bootstrapJoinProgress(ids, [initializedAnchor], 'ha-lab').nextHostId, 'node-b');
  assert.equal(bootstrapJoinProgress(ids, [initializedAnchor], '').initialized, false);
});

test('QDevice setup requires a complete, identity-consistent live cluster preflight', () => {
  const input = {
    clusterType: 'suse-ha',
    quorumPlan: 'qdevice',
    topologyReady: true,
    selectedHostIds: ['node-a', 'node-b'],
    hosts: [
      { id: 'node-a', name: 'node-a', hostname: 'node-a', username: 'sles' },
      { id: 'node-b', name: 'node-b', hostname: 'node-b', username: 'sles' },
    ],
    plannedClusterName: 'ha-lab',
    preflightResults: [
      { host_id: 'node-a', status: 'checked', checks: { compatibility_supported: true, ha_active: true, time_synchronized: true, tools: { crm: true, crm_mon: true, 'corosync-cfgtool': true }, qdevice_package_installed: true, cluster_configured: true, cluster_detected: true, cluster_name: 'ha-lab', cluster_members: ['node-a', 'node-b'], ssh_peer_connectivity: [{ reachable: true, hosts_file_entry_present: true }] } },
      { host_id: 'node-b', status: 'checked', checks: { compatibility_supported: true, ha_active: true, time_synchronized: true, tools: { crm: true, crm_mon: true, 'corosync-cfgtool': true }, qdevice_package_installed: true, cluster_configured: true, cluster_detected: true, cluster_name: 'ha-lab', cluster_members: ['node-a', 'node-b'], ssh_peer_connectivity: [{ reachable: true, hosts_file_entry_present: true }] } },
    ],
    liveClusterStatus: { cluster_name: 'ha-lab', qdevice: { configured: false } },
  };
  assert.equal(qdeviceBootstrapReady(input), true);
  assert.equal(qdeviceBootstrapReady({ ...input, preflightResults: input.preflightResults.map((item, index) => index ? item : { ...item, checks: { ...item.checks, qdevice_package_installed: false } }) }), false);
  assert.equal(qdeviceBootstrapReady({ ...input, hosts: input.hosts.map((host, index) => index ? { ...host, username: 'different-user' } : host) }), false);
  assert.equal(qdeviceBootstrapReady({ ...input, preflightResults: [input.preflightResults[0], { ...input.preflightResults[1], host_id: 'node-a' }] }), false);
  assert.equal(qdeviceBootstrapReady({ ...input, liveClusterStatus: { cluster_name: 'ha-lab', qdevice: { configured: true } } }), false);
  assert.equal(qdeviceBootstrapReady({ ...input, quorumPlan: 'standard' }), false);
});

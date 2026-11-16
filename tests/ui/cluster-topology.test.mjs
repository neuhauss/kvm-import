import assert from 'node:assert/strict';
import test from 'node:test';
import { areClusterPeersReachable, clusterFencingReadiness, clusterQuorumGuidance, isClusterTopologyReady, isQnetdReachableFromNodes, isQnetdReadyForBootstrap, qnetdBootstrapEndpoint, quorumRecommendationDefaults, recommendedClusterQuorum, sharedCorosyncNetworkCandidates } from '../../pkg/kvm-manager/utils/cluster-topology.ts';

test('fencing advisor marks SBD only as a candidate when every node has read-only watchdog evidence', () => {
  const results = ['node-a', 'node-b', 'node-c'].map(() => ({ status: 'checked', checks: {
    watchdog_devices: ['/dev/watchdog0'],
    watchdog_details: [{ path: '/dev/watchdog0', driver: 'iTCO_wdt', identity: 'Intel TCO WatchDog' }],
    watchdog_query: { available: true, ok: true, device_path: '/dev/watchdog0' },
  } }));
  assert.equal(clusterFencingReadiness(results, 3), 'sbd-candidate');
  assert.equal(clusterFencingReadiness(results.slice(0, 2), 3), 'incomplete');
  assert.equal(clusterFencingReadiness([{ ...results[0], status: 'error' }, ...results.slice(1)], 3), 'incomplete');
  assert.equal(clusterFencingReadiness([results[0], { status: 'checked', checks: { watchdog_devices: ['/dev/watchdog0'], watchdog_details: [{ path: '/dev/watchdog0', driver: 'softdog', identity: 'Software Watchdog' }], watchdog_query: { available: true, ok: true, device_path: '/dev/watchdog0' } } }, results[2]], 3), 'design-review');
  const hostWithTwoWatchdogs = { status: 'checked', checks: {
    watchdog_devices: ['/dev/watchdog0', '/dev/watchdog1'],
    watchdog_details: [
      { path: '/dev/watchdog0', driver: 'softdog', identity: 'Software Watchdog' },
      { path: '/dev/watchdog1', driver: 'iTCO_wdt', identity: 'Intel TCO Watchdog' },
    ],
    watchdog_query: { available: true, ok: true, device_path: '/dev/watchdog0' },
  } };
  assert.equal(clusterFencingReadiness([results[0], hostWithTwoWatchdogs, results[2]], 3), 'design-review');
  assert.equal(clusterFencingReadiness([results[0], { ...hostWithTwoWatchdogs, checks: { ...hostWithTwoWatchdogs.checks, watchdog_query: { available: true, ok: true } } }, results[2]], 3), 'design-review');
  assert.equal(clusterFencingReadiness([results[0], { ...hostWithTwoWatchdogs, checks: { ...hostWithTwoWatchdogs.checks, watchdog_query: { available: true, ok: true, device_path: '/dev/watchdog1' } } }, results[2]], 3), 'sbd-candidate');
  assert.equal(clusterFencingReadiness([results[0], { status: 'checked', checks: { watchdog_devices: ['/dev/watchdog0'], watchdog_query: { available: true, ok: true } } }, results[2]], 3), 'design-review');
  assert.equal(clusterFencingReadiness([results[0], { status: 'checked', checks: { watchdog_devices: ['/dev/watchdog0'], watchdog_query: { available: true, ok: false } } }, results[2]], 3), 'design-review');
  assert.equal(clusterFencingReadiness([results[0], { status: 'checked', checks: { watchdog_devices: ['/dev/watchdog0'], watchdog_query: { available: false, ok: false } } }, results[2]], 3), 'design-review');
});

test('quorum guidance matches live cluster size and avoids a false two-node warning', () => {
  assert.equal(clusterQuorumGuidance(2), 'two-node');
  assert.equal(clusterQuorumGuidance(4), 'even');
  assert.equal(clusterQuorumGuidance(3), 'odd');
  assert.equal(clusterQuorumGuidance(0), 'unknown');
  assert.equal(clusterQuorumGuidance(Number.NaN), 'unknown');
});

test('SUSE quorum recommendation prefers QDevice for even node counts and majority for odd counts', () => {
  assert.equal(recommendedClusterQuorum(2), 'qdevice');
  assert.equal(recommendedClusterQuorum(4), 'qdevice');
  assert.equal(recommendedClusterQuorum(3), 'standard');
  assert.equal(recommendedClusterQuorum(5), 'standard');
  assert.equal(recommendedClusterQuorum(1), 'unknown');
  assert.equal(recommendedClusterQuorum(Number.NaN), 'unknown');
});

test('applying quorum guidance never pre-confirms external QNetd placement', () => {
  assert.deepEqual(quorumRecommendationDefaults(2), { quorum: 'qdevice', qnetdOutsideCluster: false });
  assert.deepEqual(quorumRecommendationDefaults(3), { quorum: 'standard', qnetdOutsideCluster: false });
  assert.deepEqual(quorumRecommendationDefaults(1), { quorum: 'unknown', qnetdOutsideCluster: false });
});

test('QNetd bootstrap endpoint uses the cluster Linux account unless it is root', () => {
  assert.equal(qnetdBootstrapEndpoint('sles', 'witness.example.test'), 'sles@witness.example.test');
  assert.equal(qnetdBootstrapEndpoint(' root ', '192.0.2.20'), '192.0.2.20');
  assert.equal(qnetdBootstrapEndpoint('', ' witness.example.test '), 'witness.example.test');
  assert.equal(qnetdBootstrapEndpoint('sles', ''), '');
});

const base = {
  name: 'ha-lab',
  quorum: 'qdevice',
  fencing: 'sbd',
  qnetdHost: 'witness.example.test',
  qnetdOutsideCluster: true,
  nodeNames: ['node-1', 'node-2'],
  nodeAddresses: ['192.0.2.11', '192.0.2.12'],
};

test('QDevice topology is ready only with an external QNetd witness', () => {
  assert.equal(isClusterTopologyReady(base), true);
  assert.equal(isClusterTopologyReady({ ...base, qnetdHost: '' }), false);
  assert.equal(isClusterTopologyReady({ ...base, qnetdOutsideCluster: false }), false);
});

test('cluster bootstrap requires an explicit supported fencing choice', () => {
  assert.equal(isClusterTopologyReady({ ...base, fencing: 'manual' }), false);
  assert.equal(isClusterTopologyReady({ ...base, fencing: 'pending' }), false);
  assert.equal(isClusterTopologyReady({ ...base, fencing: 'hardware' }), true);
});

test('QNetd witness cannot be one of the selected cluster nodes', () => {
  assert.equal(isClusterTopologyReady({ ...base, qnetdHost: 'NODE-1' }), false);
  assert.equal(isClusterTopologyReady({ ...base, qnetdHost: 'node-1.' }), false);
  assert.equal(isClusterTopologyReady({ ...base, qnetdHost: '192.0.2.12' }), false);
  assert.equal(isClusterTopologyReady({ ...base, qnetdHost: '2001:0db8:0:0::2', nodeAddresses: ['2001:db8::2'] }), false);
});

test('standard quorum remains available without a QNetd witness', () => {
  assert.equal(isClusterTopologyReady({ ...base, quorum: 'standard', qnetdHost: '', qnetdOutsideCluster: false }), true);
});

test('QDevice bootstrap requires the same QNetd endpoint reachable from every checked node', () => {
  const checks = ['node-1', 'node-2'].map(() => ({ status: 'checked', checks: {
    qnetd_tcp_connectivity: { host: 'witness.example.test', port: 5403, reachable: true },
  } }));
  assert.equal(isQnetdReachableFromNodes('witness.example.test', checks, 2), true);
  assert.equal(isQnetdReachableFromNodes('WITNESS.example.test.', checks, 2), true);
  assert.equal(isQnetdReachableFromNodes('other.example.test', checks, 2), false);
  assert.equal(isQnetdReachableFromNodes('witness.example.test', checks.slice(0, 1), 2), false);
  assert.equal(isQnetdReachableFromNodes('witness.example.test', [checks[0], { status: 'checked', checks: { qnetd_tcp_connectivity: { host: 'witness.example.test', port: 5403, reachable: false } } }], 2), false);
});

test('QNetd TCP reachability does not block first init but is required before joining nodes', () => {
  const checks = ['node-1', 'node-2'].map(() => ({ status: 'checked', checks: {
    qnetd_tcp_connectivity: { host: 'witness.example.test', port: 5403, reachable: false },
  } }));
  assert.equal(isQnetdReadyForBootstrap('init', 'qdevice', 'witness.example.test', checks, 2), true);
  assert.equal(isQnetdReadyForBootstrap('join', 'qdevice', 'witness.example.test', checks, 2), false);
  assert.equal(isQnetdReadyForBootstrap('join', 'standard', '', checks, 2), true);
  checks.forEach((result) => { result.checks.qnetd_tcp_connectivity.reachable = true; });
  assert.equal(isQnetdReadyForBootstrap('join', 'qdevice', 'witness.example.test', checks, 2), true);
});

test('cluster workload templates require each node to reach every peer over SSH', () => {
  const results = [
    { status: 'checked', checks: { ssh_peer_connectivity: [{ reachable: true, hosts_file_entry_present: true }, { reachable: true, hosts_file_entry_present: true }] } },
    { status: 'checked', checks: { ssh_peer_connectivity: [{ reachable: true, hosts_file_entry_present: true }, { reachable: true, hosts_file_entry_present: true }] } },
    { status: 'checked', checks: { ssh_peer_connectivity: [{ reachable: true, hosts_file_entry_present: true }, { reachable: true, hosts_file_entry_present: true }] } },
  ];
  assert.equal(areClusterPeersReachable(results, 3), true);
  assert.equal(areClusterPeersReachable(results.slice(0, 2), 3), false);
  assert.equal(areClusterPeersReachable([{ ...results[0], checks: { ssh_peer_connectivity: [{ reachable: true, hosts_file_entry_present: true }] } }, ...results.slice(1)], 3), false);
  assert.equal(areClusterPeersReachable([{ ...results[0], checks: { ssh_peer_connectivity: [{ reachable: false, hosts_file_entry_present: true }, { reachable: true, hosts_file_entry_present: true }] } }, ...results.slice(1)], 3), false);
  assert.equal(areClusterPeersReachable([{ ...results[0], checks: { ssh_peer_connectivity: [{ reachable: true, hosts_file_entry_present: false }, { reachable: true, hosts_file_entry_present: true }] } }, ...results.slice(1)], 3), false);
  assert.equal(areClusterPeersReachable([{ ...results[0], checks: { ssh_peer_connectivity: [{ reachable: true }, { reachable: true }] } }, ...results.slice(1)], 3), false);
  assert.equal(areClusterPeersReachable([{ ...results[0], status: 'error' }, ...results.slice(1)], 3), false);
});

test('a hosts-file IP different from the SSH management address is advisory when the node name is mapped', () => {
  const results = ['node-a', 'node-b'].map(() => ({ status: 'checked', checks: {
    ssh_peer_connectivity: [{ reachable: true, hosts_file_entry_present: true, hosts_file_address_matches_ssh_address: false }],
  } }));
  assert.equal(areClusterPeersReachable(results, 2), true);
});

test('shared network discovery reports CIDRs present on every checked host with interface names', () => {
  const results = [
    { host_name: 'node-a', status: 'checked', checks: { interfaces: [{ name: 'bond0.100', subnets: ['10.20.0.0/24', '2001:db8:1::/64'], dynamic_subnets: ['10.20.0.0/24'] }, { name: 'eth1', subnets: ['192.0.2.0/24'] }] } },
    { host_name: 'node-b', status: 'checked', checks: { interfaces: [{ name: 'bond1.100', subnets: ['10.20.0.0/24'] }, { name: 'eth2', subnets: ['192.0.2.0/24'] }] } },
  ];
  assert.deepEqual(sharedCorosyncNetworkCandidates(results, 2), [
    { subnet: '10.20.0.0/24', dynamicHosts: ['node-a'], hosts: [{ hostName: 'node-a', interfaces: ['bond0.100'] }, { hostName: 'node-b', interfaces: ['bond1.100'] }] },
    { subnet: '192.0.2.0/24', dynamicHosts: [], hosts: [{ hostName: 'node-a', interfaces: ['eth1'] }, { hostName: 'node-b', interfaces: ['eth2'] }] },
  ]);
});

test('shared network discovery does not treat partial or failed preflight as a candidate', () => {
  const results = [
    { host_name: 'node-a', status: 'checked', checks: { interfaces: [{ name: 'eth0', subnets: ['10.0.0.0/24'] }] } },
    { host_name: 'node-b', status: 'checked', checks: { interfaces: [{ name: 'eth0', subnets: ['10.1.0.0/24'] }] } },
  ];
  assert.deepEqual(sharedCorosyncNetworkCandidates(results, 2), []);
  assert.deepEqual(sharedCorosyncNetworkCandidates(results.slice(0, 1), 2), []);
  assert.deepEqual(sharedCorosyncNetworkCandidates([{ ...results[0] }, { ...results[1], status: 'error' }], 2), []);
});

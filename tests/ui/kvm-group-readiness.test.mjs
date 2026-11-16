import test from 'node:test';
import assert from 'node:assert/strict';
import { assessKvmGroupInventory, availableKvmGroupHosts } from '../../pkg/kvm-manager/utils/kvm-group-readiness.ts';

test('group creation only offers ready hosts that are not already assigned to a group', () => {
  const hosts = [
    { id: 'a', status: 'ready' },
    { id: 'b', status: 'ready' },
    { id: 'c', status: 'disconnected' },
  ];
  const groups = [{ host_ids: ['a'] }, { host_ids: 'malformed' }];
  assert.deepEqual(availableKvmGroupHosts(hosts, groups).map((host) => host.id), ['b']);
});

test('group assessment compares only ready hosts and keeps shared resources explicitly unverified', () => {
  const result = assessKvmGroupInventory({ hosts: [
    { host_id: 'a', host_name: 'node-a', status: 'ready', metrics: { architecture: 'x86_64', cpu_count: 8, memory_total_kib: 16000, memory_available_kib: 8000 }, vms: [{ state: 'running' }, { state: 'paused' }], storage_pools: [{ name: 'images', target: '/var/lib/libvirt/images' }], libvirt_networks: [{ name: 'prod', forward_mode: 'bridge', bridge: 'br0' }] },
    { host_id: 'b', host_name: 'node-b', status: 'ready', metrics: { architecture: 'x86_64', cpu_count: 12, memory_total_kib: 32000, memory_available_kib: 12000 }, vms: [{ state: 'shut off' }], storage_pools: [{ name: 'images', target: '/mnt/local/images' }], libvirt_networks: [{ name: 'prod', forward_mode: 'bridge', bridge: 'br1' }] },
  ] });

  assert.equal(result.architectureCompatible, true);
  assert.equal(result.totalVcpus, 20);
  assert.equal(result.totalMemoryKib, 48000);
  assert.deepEqual(result.commonStoragePools, ['images']);
  assert.deepEqual(result.commonNetworks, ['prod']);
  assert.equal(result.commonStoragePoolDetails[0].configurationMatches, false);
  assert.equal(result.commonStoragePoolDetails[0].filesystemIdentityMatches, null);
  assert.deepEqual(result.commonStoragePoolDetails[0].entries.map((entry) => entry.target), ['/var/lib/libvirt/images', '/mnt/local/images']);
  assert.equal(result.commonNetworkDetails[0].configurationMatches, false);
  assert.deepEqual(result.commonNetworkDetails[0].entries.map((entry) => entry.bridge), ['br0', 'br1']);
  assert.equal(result.virtualMachineCount, 3);
  assert.equal(result.runningVirtualMachineCount, 1);
  assert.equal(result.sharedStorageVerified, false);
  assert.equal(result.physicalNetworkVerified, false);
  assert.equal(result.migrationEnabled, false);
});

test('matching storage and libvirt network definitions are reported without asserting shared access', () => {
  const result = assessKvmGroupInventory({ hosts: [
    { host_id: 'a', host_name: 'node-a', status: 'ready', storage_pools: [{ name: 'shared', type: 'dir', target: '/srv/vms/', state: 'running' }], libvirt_networks: [{ name: 'guest', forward_mode: 'nat', bridge: 'virbr10', state: 'active' }] },
    { host_id: 'b', host_name: 'node-b', status: 'ready', storage_pools: [{ name: 'shared', type: 'DIR', target: '/srv/vms', state: 'running' }], libvirt_networks: [{ name: 'guest', forward_mode: 'NAT', bridge: 'virbr10', state: 'active' }] },
  ] });

  assert.equal(result.commonStoragePoolDetails[0].configurationMatches, true);
  assert.equal(result.commonNetworkDetails[0].configurationMatches, true);
  assert.deepEqual(result.commonStoragePoolDetails[0].entries.map((entry) => entry.state), ['active', 'active']);
  assert.deepEqual(result.commonNetworkDetails[0].entries.map((entry) => entry.state), ['active', 'active']);
  assert.equal(result.inactiveStoragePoolCount, 0);
  assert.equal(result.unknownStoragePoolStateCount, 0);
  assert.equal(result.inactiveLibvirtNetworkCount, 0);
  assert.equal(result.unknownLibvirtNetworkStateCount, 0);
  assert.equal(result.sharedStorageVerified, false);
  assert.equal(result.physicalNetworkVerified, false);
  assert.equal(result.migrationEnabled, false);
});

test('inactive and unknown libvirt resources are counted without treating them as shared or usable', () => {
  const result = assessKvmGroupInventory({ hosts: [
    { host_id: 'a', host_name: 'node-a', status: 'ready', storage_pools: [{ name: 'images', type: 'dir', target: '/srv/images', state: 'inactive' }], libvirt_networks: [{ name: 'guest', state: 'inactive' }] },
    { host_id: 'b', host_name: 'node-b', status: 'ready', storage_pools: [{ name: 'images', type: 'dir', target: '/srv/images' }], libvirt_networks: [{ name: 'guest', state: 'mystery' }] },
  ] });

  assert.equal(result.inactiveStoragePoolCount, 1);
  assert.equal(result.unknownStoragePoolStateCount, 1);
  assert.equal(result.inactiveLibvirtNetworkCount, 1);
  assert.equal(result.unknownLibvirtNetworkStateCount, 1);
  assert.deepEqual(result.commonNetworkDetails[0].entries.map((entry) => entry.state), ['inactive', 'unknown']);
  assert.equal(result.sharedStorageVerified, false);
  assert.equal(result.migrationEnabled, false);
});

test('unknown pool type or missing targets never count as a matching storage definition', () => {
  const result = assessKvmGroupInventory({ hosts: [
    { host_id: 'a', host_name: 'node-a', status: 'ready', storage_pools: [{ name: 'incomplete', type: 'unknown', target: '' }] },
    { host_id: 'b', host_name: 'node-b', status: 'ready', storage_pools: [{ name: 'incomplete', type: 'unknown', target: '' }] },
  ] });
  assert.equal(result.commonStoragePoolDetails[0].configurationMatches, false);
});

test('bridge device names are compared case-sensitively', () => {
  const result = assessKvmGroupInventory({ hosts: [
    { host_id: 'a', host_name: 'node-a', status: 'ready', libvirt_networks: [{ name: 'guest', forward_mode: 'bridge', bridge: 'br0' }] },
    { host_id: 'b', host_name: 'node-b', status: 'ready', libvirt_networks: [{ name: 'guest', forward_mode: 'bridge', bridge: 'BR0' }] },
  ] });
  assert.equal(result.commonNetworkDetails[0].configurationMatches, false);
});

test('bridge presence is reported per host without inferring VLAN or path reachability', () => {
  const result = assessKvmGroupInventory({ hosts: [
    { host_id: 'a', host_name: 'node-a', status: 'ready', libvirt_networks: [{ name: 'guest', forward_mode: 'bridge', bridge: 'br0' }], network_interfaces: [{ ifname: 'br0', operstate: 'UP', mtu: 9000 }] },
    { host_id: 'b', host_name: 'node-b', status: 'ready', libvirt_networks: [{ name: 'guest', forward_mode: 'bridge', bridge: 'br0' }], network_interfaces: [] },
  ] });
  assert.equal(result.commonNetworkDetails[0].bridgeEntries[0].present, true);
  assert.equal(result.commonNetworkDetails[0].bridgeEntries[0].mtu, 9000);
  assert.equal(result.commonNetworkDetails[0].bridgeEntries[1].present, false);
  assert.equal(result.commonNetworkDetails[0].bridgePresentOnAll, false);
  assert.equal(result.physicalNetworkVerified, false);
});

test('storage assessment maps pool targets to the closest reported filesystem mount', () => {
  const result = assessKvmGroupInventory({ hosts: [
    { host_id: 'a', host_name: 'node-a', status: 'ready', storage_pools: [{ name: 'images', type: 'dir', target: '/srv/vms/images', state: 'running' }], filesystems: [
      { device: '/dev/sda2', type: 'xfs', mountpoint: '/' },
      { device: 'nas.example:/exports/vms', type: 'nfs4', mountpoint: '/srv/vms' },
      { device: 'nas.example:/exports/images', type: 'nfs4', mountpoint: '/srv/vms/images' },
    ] },
    { host_id: 'b', host_name: 'node-b', status: 'ready', storage_pools: [{ name: 'images', type: 'dir', target: '/srv/vms/images', state: 'running' }], filesystems: [
      { device: '/dev/sdb2', type: 'xfs', mountpoint: '/' },
      { device: 'nas.example:/exports/images', type: 'nfs4', mountpoint: '/srv/vms/images' },
    ] },
  ] });

  assert.equal(result.commonStoragePoolDetails[0].filesystemIdentityMatches, true);
  assert.equal(result.commonStoragePoolDetails[0].sharedNfsCandidate, true);
  assert.deepEqual(result.commonStoragePoolDetails[0].mountEntries.map((entry) => entry.mountpoint), ['/srv/vms/images', '/srv/vms/images']);
  assert.equal(result.sharedStorageVerified, false);
  assert.equal(result.migrationEnabled, false);

  const inactive = assessKvmGroupInventory({ hosts: [
    { host_id: 'a', host_name: 'node-a', status: 'ready', storage_pools: [{ name: 'images', type: 'dir', target: '/srv/vms/images', state: 'running' }], filesystems: [{ device: 'nas.example:/exports/images', type: 'nfs4', mountpoint: '/srv/vms/images' }] },
    { host_id: 'b', host_name: 'node-b', status: 'ready', storage_pools: [{ name: 'images', type: 'dir', target: '/srv/vms/images', state: 'inactive' }], filesystems: [{ device: 'nas.example:/exports/images', type: 'nfs4', mountpoint: '/srv/vms/images' }] },
  ] });
  assert.equal(inactive.commonStoragePoolDetails[0].sharedNfsCandidate, false);
});

test('different reported backing sources remain visible as a mismatch', () => {
  const result = assessKvmGroupInventory({ hosts: [
    { host_id: 'a', host_name: 'node-a', status: 'ready', storage_pools: [{ name: 'images', type: 'dir', target: '/srv/vms' }], filesystems: [{ device: 'nas-a:/exports/vms', type: 'nfs4', mountpoint: '/srv' }] },
    { host_id: 'b', host_name: 'node-b', status: 'ready', storage_pools: [{ name: 'images', type: 'dir', target: '/srv/vms' }], filesystems: [{ device: 'nas-b:/exports/vms', type: 'nfs4', mountpoint: '/srv' }] },
  ] });
  assert.equal(result.commonStoragePoolDetails[0].filesystemIdentityMatches, false);
});

test('mismatched architectures and failed hosts prevent a ready compatibility result', () => {
  const mismatch = assessKvmGroupInventory({ hosts: [
    { host_id: 'a', host_name: 'node-a', status: 'ready', metrics: { architecture: 'x86_64' } },
    { host_id: 'b', host_name: 'node-b', status: 'ready', metrics: { architecture: 'aarch64' } },
  ] });
  assert.equal(mismatch.architectureMismatch, true);
  assert.equal(mismatch.architectureCompatible, false);

  const unknownArchitecture = assessKvmGroupInventory({ hosts: [
    { host_id: 'a', host_name: 'node-a', status: 'ready', metrics: { architecture: 'x86_64' } },
    { host_id: 'b', host_name: 'node-b', status: 'ready', metrics: {} },
  ] });
  assert.equal(unknownArchitecture.architectureCompatible, false);
  assert.equal(unknownArchitecture.architecture, '');

  const unavailable = assessKvmGroupInventory({ hosts: [
    { host_id: 'a', host_name: 'node-a', status: 'ready', metrics: { architecture: 'x86_64' } },
    { host_id: 'b', host_name: 'node-b', status: 'error', metrics: { architecture: 'x86_64' }, storage_pools: [{ name: 'images' }] },
  ] });
  assert.equal(unavailable.readyForComparison, false);
  assert.deepEqual(unavailable.commonStoragePools, []);
});

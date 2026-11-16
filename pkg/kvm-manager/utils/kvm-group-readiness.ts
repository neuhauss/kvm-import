export type KvmGroupInventoryHost = {
  host_id: string;
  host_name: string;
  status: string;
  metrics?: {
    architecture?: string;
    cpu_count?: number;
    memory_total_kib?: number;
    memory_available_kib?: number;
  };
  vms?: Array<{ state?: string }>;
  filesystems?: Array<{ device?: string; type?: string; mountpoint?: string }>;
  network_interfaces?: Array<{ ifname?: string; name?: string; mtu?: number; operstate?: string }>;
  storage_pools?: Array<{ name: string; type?: string; target?: string; state?: string }>;
  libvirt_networks?: Array<{ name: string; state?: string; forward_mode?: string; bridge?: string; ipv4_address?: string; ipv4_netmask?: string }>;
};

export type KvmGroupInventory = { hosts?: KvmGroupInventoryHost[] };

export type KvmGroupHostOption = { id: string; status: string };
export type KvmGroupMembership = { host_ids?: unknown };

/** Only ready hosts that are not already claimed by another extension-managed group can be selected. */
export function availableKvmGroupHosts(hosts: KvmGroupHostOption[], groups: KvmGroupMembership[]): KvmGroupHostOption[] {
  const claimedIds = new Set(groups.flatMap((group) => Array.isArray(group.host_ids)
    ? group.host_ids.filter((id): id is string => typeof id === 'string')
    : []));
  return hosts.filter((host) => host.status === 'ready' && !claimedIds.has(host.id));
}

function commonNames(hosts: KvmGroupInventoryHost[], values: (host: KvmGroupInventoryHost) => Array<{ name: string }> | undefined): string[] {
  if (hosts.length < 2 || hosts.some((host) => host.status !== 'ready')) return [];
  const sets = hosts.map((host) => new Set((values(host) || []).map((item) => item.name).filter(Boolean)));
  return [...sets[0]].filter((name) => sets.every((set) => set.has(name))).sort((a, b) => a.localeCompare(b));
}

function normalizedPath(value: string | undefined): string {
  const path = (value || '').trim().replace(/\\/g, '/').replace(/\/{2,}/g, '/');
  if (!path) return '';
  return path.replace(/\/$/, '') || '/';
}

function normalizedLibvirtState(value: string | undefined): 'active' | 'inactive' | 'unknown' {
  const state = (value || '').trim().toLowerCase();
  if (state === 'running' || state === 'active') return 'active';
  if (state === 'inactive') return 'inactive';
  return 'unknown';
}

function filesystemForTarget(target: string | undefined, filesystems: KvmGroupInventoryHost['filesystems']) {
  const normalizedTarget = normalizedPath(target);
  if (!normalizedTarget || !Array.isArray(filesystems)) return undefined;
  return filesystems
    .filter((filesystem) => {
      const mountpoint = normalizedPath(filesystem.mountpoint);
      return mountpoint && (mountpoint === '/' || normalizedTarget === mountpoint || normalizedTarget.startsWith(`${mountpoint}/`));
    })
    .sort((left, right) => normalizedPath(right.mountpoint).length - normalizedPath(left.mountpoint).length)[0];
}

/** Compare only host-reported facts. Matching names never prove shared storage or L2 connectivity. */
export function assessKvmGroupInventory(inventory: KvmGroupInventory | null | undefined) {
  const hosts = Array.isArray(inventory?.hosts) ? inventory.hosts : [];
  const readyHosts = hosts.filter((host) => host.status === 'ready');
  const hostArchitectures = readyHosts.map((host) => host.metrics?.architecture?.trim() || '');
  const architectures = [...new Set(hostArchitectures.filter(Boolean))];
  const allArchitecturesKnown = readyHosts.length === hosts.length && hostArchitectures.every(Boolean);
  const architectureKnown = allArchitecturesKnown && hosts.length >= 2 && architectures.length === 1;
  const architectureMismatch = readyHosts.length === hosts.length && architectures.length > 1;
  const commonStoragePools = commonNames(hosts, (host) => host.storage_pools);
  const commonNetworks = commonNames(hosts, (host) => host.libvirt_networks);
  const commonStoragePoolDetails = commonStoragePools.map((name) => {
    const entries = hosts.map((host) => ({
      hostName: host.host_name,
      pool: (host.storage_pools || []).find((item) => item.name === name),
    }));
    const mountEntries = entries.map(({ hostName, pool }, index) => {
      const filesystem = filesystemForTarget(pool?.target, hosts[index]?.filesystems);
      return {
        hostName,
        type: filesystem?.type || '',
        source: filesystem?.device || '',
        mountpoint: filesystem?.mountpoint || '',
      };
    });
    const types = entries.map(({ pool }) => (pool?.type || '').trim().toLowerCase());
    const targets = entries.map(({ pool }) => normalizedPath(pool?.target));
    const mountIdentities = mountEntries.map((entry) => {
      const values = [entry.type, entry.source, normalizedPath(entry.mountpoint)];
      return values.every((value) => value.trim()) ? values.map((value) => value.trim()).join('\u0000') : '';
    });
    const configurationMatches = types.every((type) => type && type !== 'unknown') && new Set(types).size === 1 && targets.every(Boolean) && new Set(targets).size === 1;
    const filesystemIdentityMatches = mountIdentities.every(Boolean) ? new Set(mountIdentities).size === 1 : null;
    const sharedNfsCandidate = configurationMatches && filesystemIdentityMatches === true &&
      entries.every(({ pool }) => ['dir', 'netfs'].includes((pool?.type || '').trim().toLowerCase()) && normalizedLibvirtState(pool?.state) === 'active') &&
      mountEntries.every((entry) => /^nfs(?:4)?$/i.test(entry.type) && Boolean(entry.source.trim()) && Boolean(normalizedPath(entry.mountpoint)));
    return {
      name,
      entries: entries.map(({ hostName, pool }) => ({ hostName, type: pool?.type || '', target: pool?.target || '', state: normalizedLibvirtState(pool?.state) })),
      mountEntries,
      configurationMatches,
      filesystemIdentityMatches,
      sharedNfsCandidate,
    };
  });
  const commonNetworkDetails = commonNetworks.map((name) => {
    const entries = hosts.map((host) => ({
      hostName: host.host_name,
      network: (host.libvirt_networks || []).find((item) => item.name === name),
    }));
    const modes = entries.map(({ network }) => (network?.forward_mode || '').trim().toLowerCase());
    // Linux bridge device names are case-sensitive; only libvirt's enum is folded.
    const bridges = entries.map(({ network }) => (network?.bridge || '').trim());
    const bridgeEntries = entries.map(({ hostName, network }, index) => {
      const bridge = (network?.bridge || '').trim();
      const interfaces = hosts[index]?.network_interfaces;
      const iface = bridge && Array.isArray(interfaces) ? interfaces.find((item) => (item.ifname || item.name || '').trim() === bridge) : undefined;
      return {
        hostName,
        bridge,
        present: bridge && Array.isArray(interfaces) ? Boolean(iface) : null,
        operstate: iface?.operstate || '',
        mtu: Number.isFinite(iface?.mtu) ? Number(iface?.mtu) : null,
      };
    });
    return {
      name,
      entries: entries.map(({ hostName, network }) => ({ hostName, mode: network?.forward_mode || '', bridge: network?.bridge || '', state: normalizedLibvirtState(network?.state) })),
      bridgeEntries,
      bridgePresentOnAll: bridgeEntries.every((entry) => entry.present === true) ? true : bridgeEntries.some((entry) => entry.present === false) ? false : null,
      configurationMatches: modes.every(Boolean) && new Set(modes).size === 1 && bridges.every(Boolean) && new Set(bridges).size === 1,
    };
  });
  const virtualMachines = hosts.flatMap((host) => (host.vms || []).map((vm) => ({ ...vm, host_id: host.host_id, host_name: host.host_name })));
  const poolStates = readyHosts.flatMap((host) => (host.storage_pools || []).map((pool) => normalizedLibvirtState(pool.state)));
  const networkStates = readyHosts.flatMap((host) => (host.libvirt_networks || []).map((network) => normalizedLibvirtState(network.state)));
  return {
    hostCount: hosts.length,
    readyHostCount: readyHosts.length,
    architecture: architectureKnown ? architectures[0] : '',
    architectureCompatible: architectureKnown,
    architectureMismatch,
    totalVcpus: readyHosts.reduce((sum, host) => sum + (Number.isFinite(host.metrics?.cpu_count) ? Number(host.metrics?.cpu_count) : 0), 0),
    totalMemoryKib: readyHosts.reduce((sum, host) => sum + (Number.isFinite(host.metrics?.memory_total_kib) ? Number(host.metrics?.memory_total_kib) : 0), 0),
    availableMemoryKib: readyHosts.reduce((sum, host) => sum + (Number.isFinite(host.metrics?.memory_available_kib) ? Number(host.metrics?.memory_available_kib) : 0), 0),
    commonStoragePools,
    commonStoragePoolDetails,
    commonNetworks,
    commonNetworkDetails,
    inactiveStoragePoolCount: poolStates.filter((state) => state === 'inactive').length,
    unknownStoragePoolStateCount: poolStates.filter((state) => state === 'unknown').length,
    inactiveLibvirtNetworkCount: networkStates.filter((state) => state === 'inactive').length,
    unknownLibvirtNetworkStateCount: networkStates.filter((state) => state === 'unknown').length,
    virtualMachineCount: virtualMachines.length,
    runningVirtualMachineCount: virtualMachines.filter((vm) => /^(?:running|idle)$/i.test(vm.state || '')).length,
    readyForComparison: hosts.length >= 2 && readyHosts.length === hosts.length,
    sharedStorageVerified: false as const,
    physicalNetworkVerified: false as const,
    migrationEnabled: false as const,
  };
}

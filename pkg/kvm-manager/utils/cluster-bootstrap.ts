export type BootstrapHost = {
  address: string;
  username: string;
};

export type BootstrapJoinPreflightResult = {
  host_id: string;
  host_name: string;
  status?: string;
  checks?: {
    cluster_configured?: boolean;
    cluster_detected?: boolean;
    cluster_name?: string;
    cluster_members?: string[];
  };
};

export type BootstrapJoinProgress = {
  initialized: boolean;
  joinedHostIds: string[];
  nextHostId: string | null;
  completed: boolean;
};

/**
 * Advance SUSE's interactive join workflow one node at a time, using fresh
 * per-node crm_mon membership rather than assuming a terminal exit means join
 * succeeded. The first incomplete node remains the next step.
 */
export function bootstrapJoinProgress(
  selectedHostIds: string[],
  preflightResults: BootstrapJoinPreflightResult[],
  plannedClusterName: string,
): BootstrapJoinProgress {
  if (selectedHostIds.length < 2 || !plannedClusterName.trim()) {
    return { initialized: false, joinedHostIds: [], nextHostId: null, completed: false };
  }
  const byHostId = new Map(preflightResults.map((result) => [result.host_id, result]));
  const normalize = (value: string) => value.trim().toLowerCase().replace(/\.$/, '');
  const first = byHostId.get(selectedHostIds[0]);
  const firstName = normalize(first?.host_name || '');
  const anchorChecks = first?.checks;
  const initialized = first?.status === 'checked' && Boolean(firstName) &&
    anchorChecks?.cluster_configured === true && anchorChecks.cluster_detected === true &&
    normalize(anchorChecks.cluster_name || '') === normalize(plannedClusterName);
  if (!initialized) {
    return { initialized: false, joinedHostIds: [], nextHostId: null, completed: false };
  }

  const joinedHostIds = [selectedHostIds[0]];
  const requiredMembers = [firstName];
  for (const hostId of selectedHostIds.slice(1)) {
    const result = byHostId.get(hostId);
    const name = normalize(result?.host_name || '');
    const checks = result?.checks;
    const members = new Set((checks?.cluster_members || []).map(normalize));
    const joined = result?.status === 'checked' && Boolean(name) &&
      checks?.cluster_configured === true && checks.cluster_detected === true &&
      normalize(checks.cluster_name || '') === normalize(plannedClusterName) &&
      requiredMembers.every((member) => members.has(member)) && members.has(name);
    if (!joined) {
      return { initialized: true, joinedHostIds, nextHostId: hostId, completed: false };
    }
    joinedHostIds.push(hostId);
    requiredMembers.push(name);
  }
  return { initialized: true, joinedHostIds, nextHostId: null, completed: true };
}

/** SUSE documents a default hacluster credential after a successful init. */
export function needsBootstrapCredentialHardening(operation: string, exitStatus: number | null): boolean {
  return operation === 'init' && exitStatus === 0;
}

const bootstrapErrorKeys: Record<string, string> = {
  operation_conflict: 'clusters.bootstrapOperationConflict',
  ssh_authentication: 'clusters.bootstrapErrorSshAuthentication',
  ssh_host_key: 'clusters.bootstrapErrorSshHostKey',
  ssh_timeout: 'clusters.bootstrapErrorSshTimeout',
  ssh_connectivity: 'clusters.bootstrapErrorSshConnectivity',
  sudo_required: 'clusters.bootstrapErrorSudo',
  unsupported_sles: 'clusters.bootstrapErrorUnsupportedSles',
  ha_product_unconfirmed: 'clusters.bootstrapErrorHaProductUnconfirmed',
  ha_product_mismatch: 'clusters.bootstrapErrorHaProductMismatch',
  ha_not_ready: 'clusters.bootstrapErrorHaNotReady',
  time_sync: 'clusters.bootstrapErrorTimeSync',
  qnetd_connectivity: 'clusters.bootstrapErrorQnetd',
  qdevice_already_configured: 'clusters.bootstrapErrorQdeviceAlreadyConfigured',
  qdevice_preflight: 'clusters.bootstrapErrorQdevicePreflight',
  peer_name_resolution: 'clusters.bootstrapErrorPeerNames',
  peer_connectivity: 'clusters.bootstrapErrorPeerConnectivity',
  existing_cluster_configuration: 'clusters.bootstrapErrorExistingCluster',
  initialize_first_node: 'clusters.bootstrapErrorInitializeFirst',
  cluster_membership_mismatch: 'clusters.bootstrapErrorMembershipMismatch',
  preflight_connectivity: 'clusters.bootstrapErrorPreflightConnectivity',
};

export type HaProductPreflightResult = {
  status?: string;
  checks?: { ha_active?: boolean; ha_product?: string };
};

export type QDeviceBootstrapReadinessInput = {
  clusterType: string;
  quorumPlan: string;
  topologyReady: boolean;
  selectedHostIds: string[];
  hosts: Array<{ id: string; name: string; hostname?: string; username?: string }>;
  plannedClusterName: string;
  preflightResults: Array<{
    host_id: string;
    status?: string;
    checks?: {
      compatibility_supported?: boolean;
      ha_active?: boolean;
      time_synchronized?: boolean;
      qdevice_package_installed?: boolean | null;
      tools?: Record<string, boolean>;
      cluster_configured?: boolean;
      cluster_detected?: boolean;
      cluster_name?: string;
      cluster_members?: string[];
      ssh_peer_connectivity?: Array<{ reachable?: boolean; hosts_file_entry_present?: boolean }>;
    };
  }>;
  liveClusterStatus?: { cluster_name?: string; qdevice?: { configured?: boolean } } | null;
};

/** Require matching selected nodes, SSH identities, and fresh live SUSE preflight before QDevice setup. */
export function qdeviceBootstrapReady(input: QDeviceBootstrapReadinessInput): boolean {
  const { selectedHostIds, hosts, preflightResults, plannedClusterName } = input;
  if (input.clusterType !== 'suse-ha' || input.quorumPlan !== 'qdevice' || !input.topologyReady || selectedHostIds.length < 2) return false;
  if (hosts.length !== selectedHostIds.length || hosts.some((host) => !selectedHostIds.includes(host.id))) return false;
  const orderedHosts = selectedHostIds.map((id) => hosts.find((host) => host.id === id));
  if (orderedHosts.some((host) => !host)) return false;
  const usernames = orderedHosts.map((host) => host!.username?.trim() || '');
  if (usernames.some((name) => !name) || new Set(usernames).size !== 1) return false;

  const expectedNames = orderedHosts.map((host) => (host!.hostname || host!.name).trim().toLowerCase());
  if (expectedNames.some((name) => !name) || new Set(expectedNames).size !== expectedNames.length) return false;
  if (preflightResults.length !== selectedHostIds.length) return false;
  const resultsByHost = new Map(preflightResults.map((result) => [result.host_id, result]));
  if (resultsByHost.size !== selectedHostIds.length || selectedHostIds.some((id) => !resultsByHost.has(id))) return false;

  const ready = selectedHostIds.every((id) => {
    const result = resultsByHost.get(id)!;
    const checks = result.checks;
    const peers = checks?.ssh_peer_connectivity || [];
    const members = (checks?.cluster_members || []).map((name) => name.trim().toLowerCase());
    return result.status === 'checked' && checks?.compatibility_supported && checks?.ha_active && checks?.time_synchronized &&
      checks?.tools?.crm && checks?.tools?.crm_mon && checks?.tools?.['corosync-cfgtool'] &&
      checks?.qdevice_package_installed === true &&
      checks?.cluster_configured && checks?.cluster_detected && checks?.cluster_name === plannedClusterName &&
      expectedNames.every((name) => members.includes(name)) && peers.length === selectedHostIds.length - 1 &&
      peers.every((peer) => peer.reachable && peer.hosts_file_entry_present === true);
  });
  if (!ready) return false;
  const live = input.liveClusterStatus;
  return !(live?.cluster_name === plannedClusterName && live.qdevice?.configured);
}

/** A fresh init preflight needs one confirmed SLE HA product on every node. */
export function clusterHaProductReadiness(results: HaProductPreflightResult[], expectedNodes: number): 'incomplete' | 'unknown' | 'mismatch' | 'ready' {
  if (expectedNodes < 2 || results.length !== expectedNodes || results.some((result) => result.status !== 'checked')) return 'incomplete';
  const products = results.map((result) => result.checks?.ha_product?.trim() || '');
  if (results.some((result) => !result.checks?.ha_active) || products.some((product) => !product.toLowerCase().startsWith('sle-ha/'))) return 'unknown';
  return new Set(products).size === 1 ? 'ready' : 'mismatch';
}

/** Resolve server diagnostics through a fixed translation allow-list. */
export function bootstrapErrorTranslationKey(code: unknown): string {
  return typeof code === 'string' ? bootstrapErrorKeys[code] || 'clusters.bootstrapErrorGeneric' : 'clusters.bootstrapErrorGeneric';
}

function shellArg(value: string): string {
  return `'${value.replace(/'/g, "'\\''")}'`;
}

/** Build the SUSE crmsh join command using the first node's SSH identity. */
export function clusterJoinCommand(firstHost: BootstrapHost): string {
  const username = firstHost.username.trim();
  const address = firstHost.address.trim();
  if (!username || !address) {
    throw new Error('The first cluster node must have an SSH username and address.');
  }
  return `sudo crm cluster join -c ${shellArg(`${username}@${address}`)}`;
}

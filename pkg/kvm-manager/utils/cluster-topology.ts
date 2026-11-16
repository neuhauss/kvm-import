export interface ClusterTopologyInput {
  name: string;
  quorum: string;
  fencing: string;
  qnetdHost: string;
  qnetdOutsideCluster: boolean;
  nodeNames: string[];
  nodeAddresses: string[];
}

export interface QnetdPreflightResult {
  status?: string;
  checks?: {
    qnetd_tcp_connectivity?: { host: string; port: number; reachable: boolean } | null;
  };
}

export interface PeerPreflightResult {
  status?: string;
  checks?: {
    ssh_peer_connectivity?: { reachable: boolean; hosts_file_entry_present?: boolean; hosts_file_address_matches_ssh_address?: boolean | null }[];
  };
}

export interface FencingPreflightResult {
  status?: string;
  checks?: {
    watchdog_devices?: unknown[];
    watchdog_details?: Array<{ path?: string; driver?: string; identity?: string }>;
    watchdog_query?: { available?: boolean; ok?: boolean; device_path?: string };
  };
}

/**
 * Give a cautious SBD hint only when every selected host's successful, read-only
 * SBD query identifies the same hardware watchdog reported by sysfs. A hardware
 * watchdog elsewhere on the host is not evidence that SBD selected it. This does
 * not prove a production SBD design is complete or test whether fencing works.
 */
export function clusterFencingReadiness(results: FencingPreflightResult[], expectedNodes: number): 'incomplete' | 'sbd-candidate' | 'design-review' {
  if (expectedNodes < 2 || results.length !== expectedNodes || results.some((result) => result.status !== 'checked')) return 'incomplete';
  const sbdCandidate = results.every((result) => {
    const query = result.checks?.watchdog_query;
    if (query?.available !== true || query.ok !== true || !query.device_path) return false;
    const selected = (result.checks?.watchdog_details || []).filter((device) => device.path === query.device_path);
    if (selected.length !== 1) return false;
    const driver = selected[0].driver?.trim().toLowerCase() || '';
    const identity = selected[0].identity?.trim().toLowerCase() || '';
    return Boolean(driver && driver !== 'softdog' && !identity.includes('software watchdog'));
  });
  return sbdCandidate ? 'sbd-candidate' : 'design-review';
}

/** Select quorum guidance that matches the number of live cluster members. */
export function clusterQuorumGuidance(nodeCount: number): 'unknown' | 'two-node' | 'even' | 'odd' {
  if (!Number.isInteger(nodeCount) || nodeCount < 1) return 'unknown';
  if (nodeCount === 2) return 'two-node';
  return nodeCount % 2 === 0 ? 'even' : 'odd';
}

/** Recommend QDevice for even node counts, following SUSE HA guidance. */
export function recommendedClusterQuorum(nodeCount: number): 'unknown' | 'qdevice' | 'standard' {
  if (!Number.isInteger(nodeCount) || nodeCount < 2) return 'unknown';
  return nodeCount % 2 === 0 ? 'qdevice' : 'standard';
}

/** Applying a quorum suggestion never attests that the witness is external. */
export function quorumRecommendationDefaults(nodeCount: number): { quorum: 'unknown' | 'qdevice' | 'standard'; qnetdOutsideCluster: false } {
  return { quorum: recommendedClusterQuorum(nodeCount), qnetdOutsideCluster: false };
}

/** Show the SUSE bootstrap endpoint in the same-user form required by sudo-based setups. */
export function qnetdBootstrapEndpoint(username: string, host: string): string {
  const account = username.trim();
  const endpoint = host.trim();
  if (!endpoint) return '';
  return account && account !== 'root' ? `${account}@${endpoint}` : endpoint;
}

function normalized(value: string): string {
  const endpoint = value.trim().toLowerCase().replace(/\.$/, '');
  if (!endpoint.includes(':')) return endpoint;
  try {
    return new URL(`http://[${endpoint.replace(/^\[|\]$/g, '')}]`).hostname.replace(/^\[|\]$/g, '');
  } catch {
    return endpoint;
  }
}

/**
 * Validate the choices that the wizard can verify locally. This does not
 * prove that QNetd is reachable or configured; it only catches missing or
 * self-hosted witness plans before the operator opens crm cluster init.
 */
export function isClusterTopologyReady(input: ClusterTopologyInput): boolean {
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(input.name.trim())) return false;
  if (!['qdevice', 'standard'].includes(input.quorum)) return false;
  if (!['sbd', 'hardware'].includes(input.fencing)) return false;

  if (input.quorum !== 'qdevice') return true;

  const witness = normalized(input.qnetdHost);
  if (!witness || !input.qnetdOutsideCluster) return false;
  const clusterNodes = [...input.nodeNames, ...input.nodeAddresses].map(normalized).filter(Boolean);
  return !clusterNodes.includes(witness);
}

/** Require fresh TCP/5403 evidence from every selected node for QDevice plans. */
export function isQnetdReachableFromNodes(host: string, results: QnetdPreflightResult[], expectedNodes: number): boolean {
  const witness = normalized(host).replace(/\.$/, '');
  if (!witness || expectedNodes < 2 || results.length !== expectedNodes) return false;
  return results.every((result) => {
    const check = result.status === 'checked' ? result.checks?.qnetd_tcp_connectivity : null;
    return Boolean(check?.reachable && check.port === 5403 && normalized(check.host).replace(/\.$/, '') === witness);
  });
}

/** QNetd may start during the first SUSE init; require port 5403 for later joins. */
export function isQnetdReadyForBootstrap(operation: 'init' | 'join', quorum: string, host: string, results: QnetdPreflightResult[], expectedNodes: number): boolean {
  return operation === 'init' || quorum !== 'qdevice' || isQnetdReachableFromNodes(host, results, expectedNodes);
}

/** Require every selected node to reach every peer and have its name mapped. */
export function areClusterPeersReachable(results: (PeerPreflightResult | undefined)[], expectedNodes: number): boolean {
  if (expectedNodes < 2 || results.length !== expectedNodes) return false;
  return results.every((result) => {
    const peers = result?.status === 'checked' ? result.checks?.ssh_peer_connectivity : null;
    return Boolean(peers && peers.length === expectedNodes - 1 && peers.every((peer) => peer.reachable && peer.hosts_file_entry_present === true));
  });
}

export type PreflightNetworkResult = {
  host_name?: string;
  status?: string;
  checks?: { interfaces?: Array<{ name?: string; subnets?: string[]; dynamic_subnets?: string[] }> };
};

/**
 * Find configured IP subnets reported by every checked node. This is only a
 * discovery hint: a matching subnet does not prove Corosync reachability, L2
 * adjacency, firewall policy, or suitability for production.
 */
export function sharedCorosyncNetworkCandidates(results: PreflightNetworkResult[], expectedNodes: number): Array<{ subnet: string; hosts: Array<{ hostName: string; interfaces: string[] }>; dynamicHosts: string[] }> {
  if (expectedNodes < 2 || results.length !== expectedNodes || results.some((result) => result.status !== 'checked')) return [];

  const networksByHost = results.map((result) => {
    const networks = new Map<string, { interfaces: Set<string>; dynamic: boolean }>();
    for (const item of result.checks?.interfaces || []) {
      const name = item.name?.trim() || '';
      for (const value of item.subnets || []) {
        const subnet = value.trim();
        if (!subnet) continue;
        if (!networks.has(subnet)) networks.set(subnet, { interfaces: new Set(), dynamic: false });
        if (name) networks.get(subnet)!.interfaces.add(name);
        if ((item.dynamic_subnets || []).includes(subnet)) networks.get(subnet)!.dynamic = true;
      }
    }
    return networks;
  });
  const shared = [...networksByHost[0].keys()].filter((subnet) => networksByHost.every((networks) => networks.has(subnet))).sort();
  return shared.map((subnet) => ({
    subnet,
    hosts: results.map((result, index) => ({ hostName: result.host_name?.trim() || `node ${index + 1}`, interfaces: [...(networksByHost[index].get(subnet)?.interfaces || [])].sort() })),
    dynamicHosts: results.flatMap((result, index) => networksByHost[index].get(subnet)?.dynamic ? [result.host_name?.trim() || `node ${index + 1}`] : []),
  }));
}

export type ClusterPlanType = 'suse-ha' | 'kvm-virtualization';
export type ClusterPlanQuorum = 'pending' | 'qdevice' | 'standard';
export type ClusterPlanFencing = 'pending' | 'sbd' | 'hardware' | 'manual';

export type ClusterPlanDraft = {
  id: string;
  name: string;
  cluster_type: ClusterPlanType;
  host_ids: string[];
  template_id: string | null;
  step: number;
  config: {
    quorum: ClusterPlanQuorum;
    qnetd_host: string;
    qnetd_outside_cluster: boolean;
    fencing: ClusterPlanFencing;
    corosync_networks?: string[];
    corosync_network_reviewed?: boolean;
  };
  state: 'draft';
  preflight_required: true;
  updated_at: string;
};

export type ClusterPlanForm = {
  clusterType: ClusterPlanType;
  name: string;
  hostIds: string[];
  templateId: string;
  step: number;
  quorum: ClusterPlanQuorum;
  qnetdHost: string;
  qnetdOutsideCluster: boolean;
  fencing: ClusterPlanFencing;
  corosyncNetworks: string[];
  corosyncNetworkReviewed: boolean;
};

/** Protect API payloads from click events or stale/non-array UI state. */
export function normalizePreflightHostIds(selection: unknown, fallback: unknown): string[] {
  const candidates = Array.isArray(selection) ? selection : fallback;
  if (!Array.isArray(candidates)) return [];
  const ids = candidates.map((candidate) => {
    if (typeof candidate === 'string') return candidate;
    if (candidate && typeof candidate === 'object' && !Array.isArray(candidate)) {
      const record = candidate as Record<string, unknown>;
      const id = typeof record.id === 'string' ? record.id : record.host_id;
      return typeof id === 'string' ? id : '';
    }
    return '';
  });
  return [...new Set(ids.map((id) => id.trim()).filter(Boolean))];
}

/** Build the only supported preflight wire format, even if a UI event is passed by mistake. */
export function clusterPreflightPayload(selection: unknown, fallback: unknown, qnetdHost = '') {
  return {
    host_ids: normalizePreflightHostIds(selection, fallback),
    qnetd_host: typeof qnetdHost === 'string' ? qnetdHost.trim() : '',
  };
}

/** Recognize the Pydantic error that indicates UI and API request-shape drift. */
export function isPreflightHostListValidationError(message: string): boolean {
  return /(?:host_ids|host ids).{0,100}(?:input should be a valid list|valid list|expected a list|list_type)/i.test(message);
}

export function preflightHostListReceivedType(message: string, responseType = ''): string {
  const safeTypes: Record<string, string> = {
    object: 'object', dict: 'object', string: 'string', str: 'string',
    number: 'number', int: 'number', float: 'number', boolean: 'boolean',
    bool: 'boolean', null: 'null', nonetype: 'null', unknown: 'unknown',
  };
  const headerType = responseType.trim().toLowerCase();
  if (safeTypes[headerType]) return safeTypes[headerType];
  return message.match(/\breceived (object|string|number|boolean|null|unknown)\b/i)?.[1].toLowerCase() || '';
}

/** Explicit allow-list prevents credentials, SSH details and stale checks leaking into saved drafts. */
export function clusterPlanPayload(form: ClusterPlanForm) {
  return {
    name: form.name,
    cluster_type: form.clusterType,
    host_ids: [...form.hostIds],
    template_id: form.templateId || null,
    step: Math.max(0, Math.min(4, form.step)),
    quorum: form.quorum,
    qnetd_host: form.qnetdHost,
    qnetd_outside_cluster: form.qnetdOutsideCluster,
    fencing: form.fencing,
    corosync_networks: [...form.corosyncNetworks],
    corosync_network_reviewed: form.corosyncNetworkReviewed,
  };
}

/** A resumed draft always returns to a safe stage; callers must run preflight again. */
export function restoreClusterPlanDraft(plan: ClusterPlanDraft, knownHostIds: Set<string>) {
  return {
    id: plan.id,
    clusterType: plan.cluster_type,
    name: plan.name,
    templateId: plan.template_id || '',
    hostIds: plan.host_ids.filter((id) => knownHostIds.has(id)),
    step: Math.min(plan.step, 1),
    quorum: plan.config.quorum,
    qnetdHost: plan.config.qnetd_host,
    qnetdOutsideCluster: plan.config.qnetd_outside_cluster,
    fencing: plan.config.fencing,
    corosyncNetworks: plan.config.corosync_networks || [],
    // A previous checkbox is not carried forward as current network evidence.
    corosyncNetworkReviewed: false,
    preflightRequired: true as const,
  };
}

/** Require current candidate subnets and a fresh operator attestation for bootstrap. */
export function isCorosyncNetworkPlanReady(
  ring0: string,
  ring1: string,
  reviewed: boolean,
  candidateSubnets: string[],
): boolean {
  if (!reviewed || (ring1 && !ring0) || (ring0 && ring0 === ring1)) return false;
  return [ring0, ring1].filter(Boolean).every((subnet) => candidateSubnets.includes(subnet));
}

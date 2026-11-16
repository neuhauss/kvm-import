export type ClusterWorkloadTemplate = 'service' | 'vm' | 'web' | 'nfs';
export type NfsStorageMode = 'drbd' | 'shared';
export type WorkloadUnitCheck = { installed?: boolean; active?: string };

const TEMPLATE_REQUIRED_AGENTS: Record<Exclude<ClusterWorkloadTemplate, 'nfs'>, readonly string[]> = {
  service: ['heartbeat:IPaddr2'],
  vm: ['heartbeat:VirtualDomain'],
  web: ['heartbeat:apache', 'heartbeat:IPaddr'],
};
const NFS_BASE_AGENTS = ['heartbeat:Filesystem', 'heartbeat:nfsserver', 'heartbeat:exportfs', 'heartbeat:IPaddr2'] as const;

/** OCF resource agents needed for the selected SUSE HA workload profile. */
export function clusterTemplateRequiredAgents(template: string, nfsStorageMode: NfsStorageMode = 'drbd'): readonly string[] {
  if (template === 'nfs') return nfsStorageMode === 'drbd' ? ['linbit:drbd', ...NFS_BASE_AGENTS] : NFS_BASE_AGENTS;
  return Object.prototype.hasOwnProperty.call(TEMPLATE_REQUIRED_AGENTS, template)
    ? TEMPLATE_REQUIRED_AGENTS[template as Exclude<ClusterWorkloadTemplate, 'nfs'>]
    : [];
}

/** Require every selected node to report every agent for the chosen topology. */
export function clusterTemplateAgentsPresent(
  template: string,
  hostAgents: readonly (readonly string[])[],
  nfsStorageMode: NfsStorageMode = 'drbd',
): boolean {
  const required = clusterTemplateRequiredAgents(template, nfsStorageMode);
  return hostAgents.length > 0 && required.every((agent) => hostAgents.every((installed) => installed.includes(agent)));
}

const TEMPLATE_FIRST_RESOURCES: Record<ClusterWorkloadTemplate, { resourceId: string; agent: string }> = {
  service: { resourceId: 'ha-service', agent: '' },
  vm: { resourceId: 'ha-vm', agent: 'ocf:heartbeat:VirtualDomain' },
  web: { resourceId: 'ha-web', agent: 'ocf:heartbeat:apache' },
  nfs: { resourceId: 'ha-nfs', agent: 'ocf:heartbeat:Filesystem' },
};

/** Build an editable first-resource draft without assuming optional agents exist on the live cluster. */
export function clusterResourceDraftForTemplate(template: ClusterWorkloadTemplate, installedAgents: readonly string[]) {
  const recipe = TEMPLATE_FIRST_RESOURCES[template];
  const agentAvailable = Boolean(recipe.agent && installedAgents.includes(recipe.agent));
  return {
    resource_id: recipe.resourceId,
    agent: agentAvailable ? recipe.agent : '',
    suggested_agent: recipe.agent,
    suggested_agent_unavailable: Boolean(recipe.agent && !agentAvailable),
  };
}

/**
 * Return explicit package/unit availability. Legacy preflight responses only
 * reported whether a service was active, which is not a safe HA prerequisite.
 */
export function workloadServiceInstalled(
  checks: { workload_service_units?: Record<string, WorkloadUnitCheck>; workload_services?: Record<string, boolean> } | null | undefined,
  serviceName: string,
): boolean | null {
  if (!checks) return null;
  const unit = checks.workload_service_units?.[serviceName];
  if (typeof unit?.installed === 'boolean') return unit.installed;
  return checks.workload_services?.[serviceName] === true ? true : null;
}

/** Aggregate a cross-host prerequisite while preserving unavailable evidence. */
export function aggregateWorkloadServiceAvailability(statuses: readonly (boolean | null)[]): boolean | null {
  if (statuses.includes(false)) return false;
  return statuses.length > 0 && statuses.every((status) => status === true) ? true : null;
}

/** Unknown service evidence needs review; it is not a positive template match. */
export function workloadServiceRequirementFit(
  installed: boolean | null,
  preflightChecked: boolean,
): 'ready' | 'missing' | 'review_required' | 'not_checked' {
  if (!preflightChecked) return 'not_checked';
  if (installed === true) return 'ready';
  return installed === false ? 'missing' : 'review_required';
}

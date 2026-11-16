export type ClusterCloneCandidate = {
  id: string;
  active: boolean;
  failed?: boolean;
  managed: boolean;
  agent?: string;
  parent_id?: string;
  group_id?: string;
  children?: string[];
};

export type ClusterCloneType = 'standard' | 'promotable';

export const cloneMetadataKeys = (type: ClusterCloneType): string[] => [
  'clone-max', 'clone-node-max', 'globally-unique', 'notify', 'interleave',
  ...(type === 'promotable' ? ['promoted-max', 'promoted-node-max'] : []),
];

export function validateCloneMetadataDraft(type: ClusterCloneType, source: unknown) {
  if (!source || typeof source !== 'object' || Array.isArray(source)) return { ok: false as const, reason: 'invalid' as const };
  const input = source as Record<string, unknown>;
  const allowed = new Set(cloneMetadataKeys(type));
  if (Object.keys(input).some((key) => !allowed.has(key))) return { ok: false as const, reason: 'invalid' as const };
  const metadata: Record<string, string> = {};
  for (const key of allowed) {
    const raw = input[key] ?? '';
    if (typeof raw !== 'string') return { ok: false as const, reason: 'invalid' as const };
    const value = raw.trim();
    if (!value) {
      metadata[key] = '';
      continue;
    }
    if (['clone-max', 'clone-node-max', 'promoted-max', 'promoted-node-max'].includes(key)) {
      if (!/^[1-9][0-9]{0,3}$/.test(value) || Number(value) > 4096) return { ok: false as const, reason: 'number' as const };
    } else if (!['true', 'false'].includes(value.toLowerCase())) {
      return { ok: false as const, reason: 'boolean' as const };
    }
    metadata[key] = value;
  }
  return { ok: true as const, metadata };
}

const resourceIdPattern = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/;

export function validClusterCloneSelection(
  cloneId: string,
  childId: string,
  resources: readonly ClusterCloneCandidate[],
): boolean {
  if (!resourceIdPattern.test(cloneId) || !resourceIdPattern.test(childId) || cloneId === childId) return false;
  return resources.some((resource) => resource.id === childId
    && resource.managed
    && Boolean(resource.agent)
    && !resource.active
    && !resource.parent_id
    && !resource.group_id
    && (resource.agent === 'group' || (resource.agent !== 'clone'
      && resource.agent !== 'promotable clone'
      && resource.agent !== 'stonith'
      && !resource.agent?.startsWith('stonith:'))));
}

/** Only offer deletion for a stopped, top-level clone of one standalone primitive. */
export function validClusterCloneDeletion(
  clone: ClusterCloneCandidate | null | undefined,
  resources: readonly ClusterCloneCandidate[],
): boolean {
  if (!clone || !['clone', 'promotable clone'].includes(clone.agent || '')
    || !clone.managed || clone.active || clone.failed || clone.parent_id
    || !Array.isArray(clone.children) || clone.children.length !== 1) return false;
  const child = resources.find((resource) => resource.id === clone.children?.[0]);
  return Boolean(child && child.parent_id === clone.id && child.managed && !child.active && !child.failed
    && child.agent && child.agent !== 'group' && child.agent !== 'clone' && child.agent !== 'promotable clone'
    && child.agent !== 'stonith' && !child.agent.startsWith('stonith:'));
}

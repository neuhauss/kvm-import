export type HostInventoryFacts = {
  name: string;
  hostname?: string;
  status: 'ready' | 'unreachable' | 'unknown';
  last_checked_at?: string;
};

export const HOST_INVENTORY_STALE_AFTER_MS = 3 * 60 * 1000;

export function isHostInventoryStale(host: Pick<HostInventoryFacts, 'last_checked_at'>, now = Date.now()): boolean {
  if (!host.last_checked_at) return true;
  const checkedAt = Date.parse(host.last_checked_at);
  return !Number.isFinite(checkedAt) || now - checkedAt > HOST_INVENTORY_STALE_AFTER_MS;
}

export function summarizeHostInventory<T extends HostInventoryFacts>(hosts: T[], now = Date.now()) {
  return hosts.reduce((summary, host) => {
    summary.total += 1;
    summary[host.status] += 1;
    if (isHostInventoryStale(host, now)) summary.stale += 1;
    return summary;
  }, { total: 0, ready: 0, unreachable: 0, unknown: 0, stale: 0 });
}

export function filterHostInventory<T extends HostInventoryFacts & { address?: string }>(
  hosts: T[],
  search: string,
  state: 'all' | 'ready' | 'unreachable' | 'unknown' | 'stale',
  now = Date.now(),
): T[] {
  const term = search.trim().toLowerCase();
  return hosts.filter((host) => {
    const identity = hostIdentity(host);
    const matchesSearch = !term || `${identity.displayName} ${host.hostname || ''} ${host.address || ''}`.toLowerCase().includes(term);
    const matchesState = state === 'all' || (state === 'stale' ? isHostInventoryStale(host, now) : host.status === state);
    return matchesSearch && matchesState;
  });
}

export function hostIdentity(host: { name?: string; hostname?: string }) {
  const displayName = host.name?.trim() || host.hostname?.trim() || '—';
  const detectedHostname = host.hostname?.trim();
  return {
    displayName,
    detectedHostname: detectedHostname && detectedHostname !== displayName ? detectedHostname : '',
  };
}

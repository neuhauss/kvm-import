export type ClusterMonitorOperation = {
  operation_id?: string;
  interval: string;
  role: '' | 'Started' | 'Stopped' | 'Promoted' | 'Unpromoted' | 'Master' | 'Slave';
  timeout?: string;
};

export type ClusterMonitorValidation =
  | { ok: true; operations: ClusterMonitorOperation[] }
  | { ok: false; reason: 'count' | 'interval' | 'timeout' | 'duplicate_interval' | 'role' | 'id' };

function durationSeconds(value: string, allowZero = false): number | null {
  const match = value.trim().match(/^(\d+)(s|min|h)?$/);
  if (!match) return null;
  const amount = Number(match[1]);
  const multiplier = match[2] === 'min' ? 60 : match[2] === 'h' ? 3600 : 1;
  const seconds = amount * multiplier;
  return Number.isSafeInteger(seconds) && (allowZero ? seconds >= 0 : seconds > 0) && seconds <= 86400 ? seconds : null;
}

const allowedRoles = new Set(['', 'Started', 'Stopped', 'Promoted', 'Unpromoted', 'Master', 'Slave']);
const idPattern = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;

export function validateClusterMonitorOperations(rows: readonly ClusterMonitorOperation[]): ClusterMonitorValidation {
  if (rows.length < 1 || rows.length > 16) return { ok: false, reason: 'count' };
  const seenIntervals: Array<{ seconds: number; role: ClusterMonitorOperation['role'] }> = [];
  const seenIds = new Set<string>();
  const operations: ClusterMonitorOperation[] = [];
  for (const row of rows) {
    const interval = durationSeconds(row.interval, true);
    if (interval === null) return { ok: false, reason: 'interval' };
    if (row.timeout && durationSeconds(row.timeout) === null) return { ok: false, reason: 'timeout' };
    if (!allowedRoles.has(row.role)) return { ok: false, reason: 'role' };
    if (seenIntervals.some((seen) => seen.seconds === interval && (seen.role === row.role || !seen.role || !row.role))) return { ok: false, reason: 'duplicate_interval' };
    seenIntervals.push({ seconds: interval, role: row.role });
    if (row.operation_id) {
      if (!idPattern.test(row.operation_id)) return { ok: false, reason: 'id' };
      if (seenIds.has(row.operation_id)) return { ok: false, reason: 'id' };
      seenIds.add(row.operation_id);
    }
    operations.push({
      ...(row.operation_id ? { operation_id: row.operation_id } : {}),
      interval: row.interval.trim(),
      role: row.role,
      ...(row.timeout?.trim() ? { timeout: row.timeout.trim() } : {}),
    });
  }
  return { ok: true, operations };
}

export function hasPromotableMonitorRoles(rows: readonly ClusterMonitorOperation[]): boolean {
  const validation = validateClusterMonitorOperations(rows);
  if (!validation.ok) return false;
  const hasDistinctPair = (promoted: ClusterMonitorOperation['role'], unpromoted: ClusterMonitorOperation['role']) => {
    const promotedInterval = validation.operations.find((operation) => operation.role === promoted)?.interval;
    const unpromotedInterval = validation.operations.find((operation) => operation.role === unpromoted)?.interval;
    return promotedInterval !== undefined && unpromotedInterval !== undefined && durationSeconds(promotedInterval, true) !== durationSeconds(unpromotedInterval, true);
  };
  return hasDistinctPair('Promoted', 'Unpromoted') || hasDistinctPair('Master', 'Slave');
}
